"""Before/after comparison (plan D3).

Only NEW problems count. Both versions of every file go into ONE temporary tree so a single
container run scans both. Files are written under INDEXED directories — `before/0001/<name>`,
`after/0001/<name>` — keeping the original base name only for a manifest the scanner recognises
(setup.py, ...), else `file<ext>`; the Tree maps each index back to the real repo path. So no
awkward repository file name (newlines, colons, edge whitespace, non-UTF-8 bytes) ever reaches the
scanner or the list file, and no reserved name (a generated companion) can make it skip a file. Findings are mapped back through that index and compared
as multisets keyed `(finding_type, algorithm, pq_status)` per file; line numbers are never part
of the key. A finding that maps to no tree entry is counted (`Comparison.unmatched`), never
silently dropped.

Where "before" and "after" come from (always read by object id, never `rev:path` syntax):
- Agent mode: before = the blob at the session's pinned baseline commit (`git ls-tree`);
  after = the working-tree file, which must resolve inside the repository.
- Commit mode (`--staged`): `git diff --cached --raw -M` gives both object ids: before = the
  HEAD blob of the old path, after = the index blob. Deletes are skipped; unmerged entries are
  noted; renames compare against the old path's HEAD blob.

A file absent from "before" has an empty baseline: every finding in it is new.
Caps: at most MAX_FILES files and MAX_FILE_BYTES per file per check; anything skipped is
counted in a note, never silently.
"""
import os
import re
import shutil
import subprocess
import tempfile
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

# The local scan's accepted code extensions plus the config set it reads when the guard asks
# (QRYPTIVE_SCAN_INCLUDE_CONFIG=1). Binary certificate/key formats are left out: the guard
# skips binary files.
CODE_EXTENSIONS = frozenset({".py", ".pyw", ".java", ".go", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"})
CONFIG_EXTENSIONS = frozenset({".tf", ".yaml", ".yml", ".conf"})
ACCEPTED_EXTENSIONS = CODE_EXTENSIONS | CONFIG_EXTENSIONS
_SKIPPED_SUFFIXES = (".d.ts", ".d.mts", ".d.cts", ".min.js", ".min.mjs", ".min.cjs")

MAX_FILES = 500
# The scanner skips a code file over 1,000,000 CHARACTERS of decoded text (scan_batch_core's early
# filter), measured after the senders' decode (decode_like_scanner). No character takes more than 4
# bytes, so a file over 4,000,000 bytes is always over the limit: that is the cheap read ceiling, and
# the exact character test runs on everything under it.
# (The scanner allows a MANIFEST — setup.py, package.json, ... — up to 10 MB. The guard applies the
# 1,000,000-character code limit to every file, so it pre-skips a few very large manifests the
# scanner would read: conservative, and noted, never silently.)
SCANNER_MAX_CHARS = 1_000_000
MAX_FILE_BYTES = 4 * SCANNER_MAX_CHARS
# ... and skips a file whose text, byte-order mark dropped, is under 10 non-blank characters.
SCANNER_MIN_STRIPPED_CHARS = 10
MAX_TOTAL_BYTES = 50 * 1024 * 1024  # both sides, all files, one check

BEFORE = "before"
AFTER = "after"
NOTE_NO_GIT = "no git history, all findings treated as new"
NOTE_NO_COMMITS = "no commits yet, all findings treated as new"
NOTE_BASELINE_GONE = "the session's starting commit no longer exists; compared against HEAD instead"

# Never hand secrets to git (or to any hook / fsmonitor it might run).
SCRUBBED_ENV = ("QRYPTIVE_SCANNER_KEY", "QRYPTIVE_SCAN_PASS")
_GIT_TIMEOUT = 30
_OID_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_REGULAR_MODES = (b"100644", b"100755")
_ZERO_OID_RE = re.compile(rb"^0+$")
# The 100-character cap routes any longer base name to the neutral "file<ext>" name.
_SAFE_BASENAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,99}\Z")

# The base names scan_batch_core's MANIFEST pass recognises (its `_MANIFEST_NAMES`, compared
# lower-cased, plus any `*.csproj`). These are the ONLY base names the scan tree keeps: every other
# file gets the neutral "file<ext>" name, so no reserved name (a generated companion such as
# crypto_provider.py, a declaration file) can make the scanner skip what an agent wrote. Held in
# step with the scanner by tests/test_contract_manifest_names.py.
MANIFEST_BASENAMES = frozenset({
    'requirements.txt', 'pipfile', 'pipfile.lock', 'pyproject.toml', 'poetry.lock',
    'setup.py', 'setup.cfg', 'package.json', 'package-lock.json', 'yarn.lock',
    'go.mod', 'go.sum', 'cargo.toml', 'cargo.lock', 'gemfile', 'gemfile.lock',
    'composer.json', 'composer.lock', 'pom.xml', 'build.gradle', 'build.gradle.kts',
    'packages.config',
})
MANIFEST_SUFFIXES = (".csproj",)


def keeps_base_name(base: str) -> bool:
    if not _SAFE_BASENAME.fullmatch(base):
        return False
    low = base.lower()
    return low in MANIFEST_BASENAMES or low.endswith(MANIFEST_SUFFIXES)


def is_minified_or_declaration(rel_path: str) -> bool:
    """A minified bundle or a type-declaration file: the scanner skips these, so the guard drops
    them too, but always says so (never silently)."""
    return rel_path.lower().endswith(_SKIPPED_SUFFIXES)


def is_scannable(rel_path: str) -> bool:
    low = rel_path.lower()
    if low.endswith(_SKIPPED_SUFFIXES):
        return False
    return os.path.splitext(low)[1] in ACCEPTED_EXTENSIONS


def is_code(name: str) -> bool:
    return os.path.splitext(name.lower())[1] in CODE_EXTENSIONS


def valid_oid(value) -> bool:
    return isinstance(value, str) and bool(_OID_RE.match(value))


def safe_rel(rel_path: str) -> Optional[str]:
    """A normalised repo-relative POSIX path, or None if it is absolute or escapes the root.
    Splits on "/" only: a backslash is an ordinary character in a repository file name."""
    rel = rel_path
    if not rel or rel.startswith("/"):
        return None
    parts = [p for p in rel.split("/") if p not in ("", ".")]
    if not parts or any(p == ".." for p in parts):
        return None
    return "/".join(parts)


def find_git_root(start) -> Optional[Path]:
    """Walk up from `start` looking for a `.git` entry. No subprocess (record must be fast)."""
    try:
        p = Path(start).resolve()
    except (OSError, ValueError):
        return None
    if p.is_file():
        p = p.parent
    for candidate in (p, *p.parents):
        if (candidate / ".git").exists():
            return candidate
    return None


class GitError(Exception):
    pass


def git_env() -> dict:
    env = {k: v for k, v in os.environ.items() if k not in SCRUBBED_ENV}  # GIT_INDEX_FILE is kept
    env.update(GIT_OPTIONAL_LOCKS="0", LC_ALL="C", GIT_LITERAL_PATHSPECS="1")
    return env


def _git(repo, *args, input_bytes=None):
    return subprocess.run(["git", "-C", str(repo), "-c", "core.quotepath=off",
                           "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", *args],
                          capture_output=True, timeout=_GIT_TIMEOUT, env=git_env(), input=input_bytes)


def head_commit(repo) -> Optional[str]:
    try:
        r = _git(repo, "rev-parse", "--verify", "-q", "HEAD^{commit}")
    except (OSError, subprocess.SubprocessError):
        return None
    out = r.stdout.decode("ascii", "replace").strip()
    return out if r.returncode == 0 and valid_oid(out) else None


def pin_value(repo) -> Optional[str]:
    """The commit to pin as a session's baseline: HEAD, or None when the repository genuinely has
    no commits yet (the empty tree). Raises GitError when git cannot tell — the caller must then
    leave the session unpinned rather than pin "no commits" by mistake."""
    try:
        r = _git(repo, "rev-parse", "--verify", "-q", "HEAD^{commit}")
        out = r.stdout.decode("ascii", "replace").strip()
        if r.returncode == 0 and valid_oid(out):
            return out
        unborn = _git(repo, "symbolic-ref", "-q", "HEAD")
        git_dir = _git(repo, "rev-parse", "--git-dir")
    except (OSError, subprocess.SubprocessError) as exc:
        raise GitError(f"git could not run ({type(exc).__name__})")
    if r.returncode == 1 and unborn.returncode == 0 and git_dir.returncode == 0:
        branch = unborn.stdout.decode("utf-8", "replace").strip()
        check = _git(repo, "rev-parse", "--verify", "-q", branch)
        if check.returncode == 1:
            return None  # a named branch with no commit: a fresh repository
    raise GitError("git could not read the current commit")


def commit_exists(repo, commit: str) -> bool:
    if not valid_oid(commit):
        return False
    try:
        return _git(repo, "cat-file", "-e", f"{commit}^{{commit}}").returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _empty_tree(repo) -> str:
    r = _git(repo, "hash-object", "-t", "tree", "--stdin", input_bytes=b"")
    out = r.stdout.decode("ascii", "replace").strip()
    if r.returncode != 0 or not valid_oid(out):
        raise GitError("git hash-object failed")
    return out


def _z_list(data: bytes) -> List[str]:
    return [os.fsdecode(p) for p in data.split(b"\0") if p]


def changed_since(repo, commit: Optional[str]) -> List[str]:
    """Paths that differ from `commit` in the working tree, plus untracked, not-ignored files.
    Catches files written by tools that never fire an edit hook (shell redirects, sed -i)."""
    paths = set()
    if commit:
        r = _git(repo, "diff", "--name-only", "--no-renames", "-z", commit, "--")
        if r.returncode != 0:
            raise GitError("git diff failed")
        paths.update(_z_list(r.stdout))
        r = _git(repo, "ls-files", "--others", "--exclude-standard", "-z")
    else:
        r = _git(repo, "ls-files", "--cached", "--others", "--exclude-standard", "-z")
    if r.returncode != 0:
        raise GitError("git ls-files failed")
    paths.update(_z_list(r.stdout))
    return sorted(paths)


def ls_tree_blobs(repo, commit: str, rel_paths: Iterable[str]) -> Dict[str, str]:
    """{repo-relative path: blob oid} for regular files at `commit` (literal pathspecs)."""
    paths = list(rel_paths)
    if not paths:
        return {}
    r = _git(repo, "ls-tree", "-r", "-z", "--full-tree", commit, "--", *paths)
    if r.returncode != 0:
        raise GitError("git ls-tree failed")
    out = {}
    for entry in r.stdout.split(b"\0"):
        if not entry or b"\t" not in entry:
            continue
        meta, path = entry.split(b"\t", 1)
        parts = meta.split(b" ")
        if len(parts) == 3 and parts[0] in _REGULAR_MODES and parts[1] == b"blob":
            out[os.fsdecode(path)] = parts[2].decode("ascii")
    return out


def blob_sizes(repo, oids: Iterable[str]) -> Dict[str, int]:
    """{oid: size} for blobs that exist."""
    wanted = sorted({o for o in oids if valid_oid(o)})
    if not wanted:
        return {}
    r = _git(repo, "cat-file", "--batch-check", input_bytes=("\n".join(wanted) + "\n").encode())
    if r.returncode != 0:
        raise GitError("git cat-file --batch-check failed")
    out = {}
    for line in r.stdout.splitlines():
        parts = line.split(b" ")
        if len(parts) == 3 and parts[1] == b"blob":
            out[parts[0].decode("ascii")] = int(parts[2])
    return out


def cat_blobs(repo, oids: Iterable[str]) -> Tuple[Dict[str, bytes], set]:
    """({oid: bytes}, {oids over MAX_FILE_BYTES}). Missing objects are simply absent."""
    sizes = blob_sizes(repo, oids)
    too_big = {o for o, n in sizes.items() if n > MAX_FILE_BYTES}
    readable = sorted(o for o in sizes if o not in too_big)
    if not readable:
        return {}, too_big
    r = _git(repo, "cat-file", "--batch", input_bytes=("\n".join(readable) + "\n").encode())
    if r.returncode != 0:
        raise GitError("git cat-file --batch failed")
    data, pos, out = r.stdout, 0, {}
    while pos < len(data):
        nl = data.index(b"\n", pos)
        header = data[pos:nl].split(b" ")
        pos = nl + 1
        if len(header) != 3:
            continue  # "<oid> missing"
        size = int(header[2])
        out[header[0].decode("ascii")] = data[pos:pos + size]
        pos += size + 1
    return out, too_big


def blob_at(repo, commit: Optional[str], rel: str) -> Optional[bytes]:
    if not commit:
        return None
    oid = ls_tree_blobs(repo, commit, [rel]).get(rel)
    return cat_blobs(repo, [oid])[0].get(oid) if oid else None


def decode_like_scanner(raw: bytes) -> str:
    """The text the scanner sees: the senders' rule (github-action/entrypoint.py `_decode_text` +
    `_universal_newlines`, itself mirroring the platform's SupportedFileFilter.decodeText). UTF-16
    with a byte-order mark (either endian) is UTF-16; a UTF-8 mark is dropped; everything else is
    UTF-8; malformed input is replaced; CRLF and lone CR become LF."""
    if raw[:2] == b"\xff\xfe":
        text = raw[2:].decode("utf-16-le", errors="replace")
    elif raw[:2] == b"\xfe\xff":
        text = raw[2:].decode("utf-16-be", errors="replace")
    elif raw[:3] == b"\xef\xbb\xbf":
        text = raw[3:].decode("utf-8", errors="replace")
    else:
        text = raw.decode("utf-8", errors="replace")
    return text.replace("\r\n", "\n").replace("\r", "\n")


def scanner_skip_reason(data: bytes) -> Optional[str]:
    """Why the scanner would skip this file without examining it, or None. Measured on v1.0.26 and
    read from scan_batch_core: under 10 non-blank characters once a leading byte-order mark is
    dropped ("empty"), or over 1,000,000 characters ("too_large") — both on the decoded text."""
    if len(data) > MAX_FILE_BYTES:
        return "too_large"
    text = decode_like_scanner(data)
    if text.startswith("\ufeff"):
        text = text[1:]
    if len(text) > SCANNER_MAX_CHARS:
        return "too_large"
    if len(text.strip()) < SCANNER_MIN_STRIPPED_CHARS:
        return "empty"
    return None


def scanner_would_skip(data: bytes) -> bool:
    return scanner_skip_reason(data) is not None


def _is_binary(data: bytes) -> bool:
    """NUL in the decoded text: so UTF-16 with a byte-order mark (full of NUL bytes) is text."""
    return "\0" in decode_like_scanner(data[:16384])


_SKIP_WORDING = {
    "outside": "{n} file(s) not checked: they resolve outside the repository (symbolic link)",
    "too_large": "{n} file(s) not checked: over {max_chars:,} characters (the scanner's limit)",
    "empty": "{n} file(s) not checked: empty or under 10 characters (the scanner skips these)",
    "over_limit": "{n} file(s) not checked: over the {max} file limit for one check",
    "unreadable_name": "{n} file(s) not checked: their names cannot be represented",
    "unmerged": "{n} file(s) not checked: unresolved merge conflicts",
    "binary": "{n} file(s) not checked: binary content",
    "total_cap": "{n} file(s) not checked: over the {total_mb} MB total for one check",
}


@dataclass
class Tree:
    root: Path
    scan_list: List[str] = field(default_factory=list)  # safe names: "before/0001.py", ...
    paths: List[str] = field(default_factory=list)  # repo-relative paths with an "after" side
    notes: List[str] = field(default_factory=list)
    names: Dict[str, str] = field(default_factory=dict)  # "0001.py" -> repo-relative path
    skipped: Dict[str, int] = field(default_factory=dict)
    total_bytes: int = 0
    changed: set = field(default_factory=set)  # repo paths whose "after" differs from "before"
    changes_seen: int = 0  # staged changes before any filtering (commit mode): 0 = nothing staged
    deletions: int = 0  # staged deletions (commit mode)
    not_kept: int = 0  # staged paths the `keep` predicate rejected (commit mode)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.cleanup()
        return False

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def skip(self, why: str, n: int = 1):
        self.skipped[why] = self.skipped.get(why, 0) + n

    def finish(self):
        for why, n in self.skipped.items():
            self.notes.append(_SKIP_WORDING[why].format(n=n, max=MAX_FILES,
                                                        max_chars=SCANNER_MAX_CHARS,
                                                        total_mb=f"{MAX_TOTAL_BYTES / 1048576:g}"))

    @property
    def skipped_total(self) -> int:
        return sum(self.skipped.values())

    def add(self, rel: str, before: Optional[bytes], after: bytes):
        if _is_binary(after):
            self.skip("binary")
            return
        try:
            os.fsencode(rel)
        except UnicodeError:
            self.skip("unreadable_name")
            return
        why = scanner_skip_reason(after)
        if why:
            self.skip(why)
            return
        if before is not None and (_is_binary(before) or scanner_would_skip(before)):
            before = None  # the scanner would report nothing for it: an empty baseline is the same
        size = len(after) + (len(before) if before is not None else 0)
        if self.total_bytes + size > MAX_TOTAL_BYTES:
            self.skip("total_cap")
            return
        self.total_bytes += size
        # Only a manifest base name (setup.py, ...) is kept, inside its own index directory, so the
        # scanner's manifest pass still runs. Everything else — reserved companion names, awkward
        # names (newline, colon, spaces) — becomes the neutral "file<ext>".
        base = rel.rsplit("/", 1)[-1]
        if not keeps_base_name(base):
            ext = os.path.splitext(rel)[1].lower()
            base = "file" + (ext if re.match(r"^\.[a-z0-9]{1,10}$", ext) else "")
        name = f"{len(self.names) + 1:04d}/{base}"
        self.names[name] = rel
        if before is not None:
            self._put(BEFORE, name, before)
        self._put(AFTER, name, after)
        self.paths.append(rel)
        if before is None or before != after:
            self.changed.add(rel)

    def _put(self, side: str, name: str, data: bytes):
        dest = self.root / side / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        self.scan_list.append(f"{side}/{name}")

    def lookup(self, file_value) -> Optional[Tuple[str, str, str]]:
        """(side, safe name, repo-relative path) for a finding's `file`, or None."""
        path = str(file_value or "")
        for prefix in ("/work/", "./"):
            if path.startswith(prefix):
                path = path[len(prefix):]
        side, _, name = path.partition("/")
        if side not in (BEFORE, AFTER) or name not in self.names or f"{side}/{name}" not in self.scan_list:
            return None
        return side, name, self.names[name]


def _new_tree() -> Tree:
    return Tree(root=Path(tempfile.mkdtemp(prefix="qryptive-guard-")))


def _inside(real: str, root_real: str) -> bool:
    return real == root_real or real.startswith(root_real.rstrip(os.sep) + os.sep)


def build_agent_tree(repo, rel_paths, baseline_commit: Optional[str], is_git: bool) -> Tree:
    """Working-tree "after" against the pinned commit's "before". Removed on exit, and on any
    exception while building."""
    tree = _new_tree()
    try:
        root_real = os.path.realpath(str(repo))
        commit = baseline_commit if valid_oid(baseline_commit) else None
        if not is_git:
            tree.notes.append(NOTE_NO_GIT)
            commit = None
        elif commit and not commit_exists(repo, commit):
            tree.notes.append(NOTE_BASELINE_GONE)
            commit = head_commit(repo)
        elif not commit:
            # Pinned when the repository had no commits: "before" is the EMPTY tree. Never the
            # current HEAD — the agent may have made the first commit itself.
            tree.notes.append(NOTE_NO_COMMITS)

        chosen: List[Tuple[str, str]] = []
        for raw in sorted(set(rel_paths)):
            rel = safe_rel(raw)
            if rel is None:
                continue
            try:
                os.fsencode(rel)
            except UnicodeError:
                tree.skip("unreadable_name")
                continue
            src = os.path.join(root_real, rel)
            if os.path.islink(src) and _inside(os.path.realpath(src), root_real):
                continue  # a link inside the repo: its target is checked in its own right
            real = os.path.realpath(src)
            if not _inside(real, root_real):
                tree.skip("outside")
                continue
            if not os.path.isfile(real):
                continue  # deleted in the working tree, or a directory: skipped
            try:
                if os.stat(real).st_size > MAX_FILE_BYTES:
                    tree.skip("too_large")
                    continue
            except OSError:
                continue
            chosen.append((rel, real))
        if len(chosen) > MAX_FILES:
            tree.skip("over_limit", len(chosen) - MAX_FILES)
            chosen = chosen[:MAX_FILES]

        oids = ls_tree_blobs(repo, commit, [r for r, _ in chosen]) if commit else {}
        blobs, _ = cat_blobs(repo, oids.values()) if oids else ({}, set())
        for rel, real in chosen:
            try:
                with open(real, "rb") as fh:
                    after = fh.read(MAX_FILE_BYTES + 1)
            except OSError:
                continue
            if len(after) > MAX_FILE_BYTES:
                tree.skip("too_large")
                continue
            tree.add(rel, blobs.get(oids.get(rel, "")), after)
        tree.finish()
        return tree
    except BaseException:
        tree.cleanup()
        raise


def staged_changes(repo) -> List[dict]:
    """Index against HEAD (or the empty tree), renames detected, with both object ids."""
    head = head_commit(repo)
    base = head or _empty_tree(repo)
    r = _git(repo, "diff", "--cached", "--raw", "-z", "-M", "--no-abbrev", base, "--")
    if r.returncode != 0:
        raise GitError("git diff --cached failed")
    tokens = r.stdout.split(b"\0")
    out, i = [], 0
    while i < len(tokens):
        meta = tokens[i]
        if not meta.startswith(b":"):
            i += 1
            continue
        fields = meta[1:].split(b" ")
        if len(fields) < 5:
            break
        src_mode, dst_mode, src_oid, dst_oid, status = fields[:5]
        code = status[:1].decode("ascii", "replace")
        if code in ("R", "C"):
            if i + 2 >= len(tokens):
                break
            old, new = tokens[i + 1], tokens[i + 2]
            i += 3
        else:
            if i + 1 >= len(tokens):
                break
            old = new = tokens[i + 1]
            i += 2
        out.append({"status": code, "old": os.fsdecode(old), "new": os.fsdecode(new),
                    "src_mode": src_mode, "dst_mode": dst_mode,
                    "src_oid": None if _ZERO_OID_RE.match(src_oid) else src_oid.decode("ascii"),
                    "dst_oid": None if _ZERO_OID_RE.match(dst_oid) else dst_oid.decode("ascii")})
    return out


def build_staged_tree(repo, keep=None) -> Tree:
    """Index "after" against HEAD "before" (exactly what is being committed). `keep`, when
    given, decides which repo-relative paths are scanned at all."""
    tree = _new_tree()
    try:
        if not head_commit(repo):
            tree.notes.append(NOTE_NO_COMMITS)
        chosen = []
        unmerged = set()
        changes = staged_changes(repo)
        tree.changes_seen = len(changes)
        for ch in changes:
            rel = safe_rel(ch["new"])
            if ch["status"] == "U":
                if rel is not None and (keep is None or keep(rel)):
                    unmerged.add(rel)
                continue
            if ch["status"] == "D":
                tree.deletions += 1
                continue
            if rel is None or (keep is not None and not keep(rel)):
                tree.not_kept += 1
                continue
            if ch["dst_mode"] not in _REGULAR_MODES or not ch["dst_oid"]:
                continue  # symbolic link or submodule
            before_oid = None
            if ch["status"] in ("M", "R", "T") and ch["src_mode"] in _REGULAR_MODES:
                before_oid = ch["src_oid"]
            chosen.append((rel, before_oid, ch["dst_oid"]))
        if unmerged:
            tree.skip("unmerged", len(unmerged))
        sizes = blob_sizes(repo, [a for _, _, a in chosen])
        fitting = []
        for item in chosen:
            if sizes.get(item[2], 0) > MAX_FILE_BYTES:
                tree.skip("too_large")
            else:
                fitting.append(item)
        chosen = fitting
        if len(chosen) > MAX_FILES:
            tree.skip("over_limit", len(chosen) - MAX_FILES)
            chosen = chosen[:MAX_FILES]
        blobs, _ = cat_blobs(repo, [o for _, b, a in chosen for o in (b, a) if o])
        for rel, before_oid, after_oid in chosen:
            after = blobs.get(after_oid)
            if after is None:
                continue
            tree.add(rel, blobs.get(before_oid) if before_oid else None, after)
        tree.finish()
        return tree
    except BaseException:
        tree.cleanup()
        raise


def finding_key(f: dict) -> tuple:
    return (str(f.get("finding_type") or ""), str(f.get("algorithm") or ""), str(f.get("pq_status") or ""))


def _line_of(f: dict) -> int:
    try:
        return int(f.get("line") or 0)
    except (TypeError, ValueError):
        return 0


@dataclass
class Comparison:
    new: List[dict] = field(default_factory=list)
    unchanged: List[dict] = field(default_factory=list)
    unmatched: int = 0  # findings whose file maps to no tree entry


def split_findings(tree: Tree, findings) -> Tuple[Dict[str, Dict[str, List[Tuple[str, dict]]]], int]:
    """Group findings by repo-relative path and side, mapping the indexed names back. Returns
    ({rel: {side: [(safe name, finding)]}}, number of findings that matched no tree entry)."""
    out: Dict[str, Dict[str, list]] = {}
    unmatched = 0
    for f in findings:
        if not isinstance(f, dict):
            unmatched += 1
            continue
        hit = tree.lookup(f.get("file") or f.get("file_path"))
        if hit is None:
            unmatched += 1
            continue
        side, name, rel = hit
        g = dict(f)
        g["file"] = rel
        g["file_path"] = rel
        out.setdefault(rel, {BEFORE: [], AFTER: []})[side].append((name, g))
    return out, unmatched


def _source_line(tree: Tree, side: str, name: str, line: int, cache: dict) -> str:
    key = (side, name)
    if key not in cache:
        try:
            cache[key] = decode_like_scanner((tree.root / side / name).read_bytes()).splitlines()
        except OSError:
            cache[key] = []
    lines = cache[key]
    return lines[line - 1].strip() if 0 < line <= len(lines) else ""


def compare(tree: Tree, findings) -> Comparison:
    """New = per file and key, the "after" findings beyond the "before" count. Which of the
    "after" findings are the new ones is decided by matching unchanged source lines first, so
    the reported line is the one the agent actually added."""
    grouped, unmatched = split_findings(tree, findings)
    result = Comparison(unmatched=unmatched)
    cache: dict = {}
    for rel, sides in sorted(grouped.items()):
        before_by_key = defaultdict(list)
        for name, f in sides[BEFORE]:
            before_by_key[finding_key(f)].append((name, f))
        after_by_key = defaultdict(list)
        for name, f in sides[AFTER]:
            after_by_key[finding_key(f)].append((name, f))
        for key, afters in after_by_key.items():
            afters = sorted(afters, key=lambda nf: _line_of(nf[1]))
            befores = before_by_key.get(key, [])
            n_new = len(afters) - len(befores)
            if n_new <= 0:
                result.unchanged.extend(f for _, f in afters)
                continue
            before_text = defaultdict(int)
            for name, b in befores:
                before_text[_source_line(tree, BEFORE, name, _line_of(b), cache)] += 1
            matched, unmatched_after = [], []
            for name, a in afters:
                t = _source_line(tree, AFTER, name, _line_of(a), cache)
                if before_text.get(t, 0) > 0:
                    before_text[t] -= 1
                    matched.append(a)
                else:
                    unmatched_after.append(a)
            # unmatched_after >= n_new always (matched <= len(befores)).
            result.new.extend(unmatched_after[:n_new])
            result.unchanged.extend(matched + unmatched_after[n_new:])
    return result
