"""Policy file (`.qryptive-guard.json`, plan D5).

Rules:
- Missing file -> defaults, silently.
- Unreadable or non-object JSON -> defaults, and ONE visible notice saying so. The guard never
  skips checking because of a bad policy file, and never falls back to defaults silently.
- Unknown keys -> ignored, with ONE notice naming them all.
- An `allow` entry without a non-empty `reason` (or matching nothing in particular) is dropped
  with a notice naming it; the rest of the policy still applies.
"""
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

POLICY_FILENAME = ".qryptive-guard.json"
MODES = ("feedback", "warn", "off")
_KNOWN_KEYS = {"mode", "scan_on_edit", "strict_commit", "checkin", "ignore_paths", "allow"}
_PREFIX = "Qryptive guard:"


def _glob_regex(pattern: str):
    """Translate a path glob: `**/` = any directories (or none), `**` = anything,
    `*` = anything except `/`, `?` = one character except `/`."""
    out = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("^" + "".join(out) + "$")


class PathGlob:
    """One glob. A pattern ending in `/` means "everything under this directory". A pattern with
    no `/` also matches a file's base name at any depth (`*.gen.py`)."""

    def __init__(self, pattern: str):
        self.pattern = pattern
        p = pattern.strip()
        while p.startswith("./"):
            p = p[2:]
        p = p.lstrip("/")
        if p.endswith("/"):
            p = p + "**"
        self._basename_only = "/" not in p
        self._re = _glob_regex(p)

    def matches(self, rel_path: str) -> bool:
        rel = rel_path.replace("\\", "/").lstrip("/")
        if self._re.match(rel):
            return True
        if self._basename_only:
            return bool(self._re.match(rel.rsplit("/", 1)[-1]))
        return False


@dataclass
class AllowEntry:
    algorithm: Optional[str]
    path: Optional[str]
    reason: str

    def matches(self, finding: dict) -> bool:
        if self.algorithm is not None:
            if str(finding.get("algorithm") or "").strip().lower() != self.algorithm.strip().lower():
                return False
        if self.path is not None:
            if not PathGlob(self.path).matches(str(finding.get("file") or "")):
                return False
        return True


@dataclass
class Policy:
    mode: str = "feedback"
    scan_on_edit: bool = False
    strict_commit: bool = False
    checkin: bool = True
    ignore_paths: List[str] = field(default_factory=list)
    allow: List[AllowEntry] = field(default_factory=list)
    notices: List[str] = field(default_factory=list)

    @property
    def is_off(self) -> bool:
        return self.mode == "off"

    def is_ignored(self, rel_path: str) -> bool:
        return any(PathGlob(p).matches(rel_path) for p in self.ignore_paths)

    def allowed(self, finding: dict) -> bool:
        return any(a.matches(finding) for a in self.allow)


def _describe_entry(entry) -> str:
    if not isinstance(entry, dict):
        return repr(entry)[:60]
    parts = []
    for k in ("algorithm", "path"):
        if k in entry:
            parts.append(f"{k}={str(entry[k])[:60]}")
    return "{" + ", ".join(parts) + "}" if parts else "{}"


def read_bytes(repo_root) -> Optional[bytes]:
    path = Path(repo_root) / POLICY_FILENAME
    try:
        return path.read_bytes() if path.is_file() else None
    except OSError:
        return b"\0unreadable"


def load(repo_root) -> Policy:
    return parse(read_bytes(repo_root))


def parse(raw: Optional[bytes]) -> Policy:
    pol = Policy()
    if raw is None:
        return pol
    try:
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("not a JSON object")
    except (ValueError, UnicodeDecodeError):
        pol.notices.append(f"{_PREFIX} policy file unreadable, using defaults ({POLICY_FILENAME}).")
        return pol

    unknown = sorted(k for k in data if k not in _KNOWN_KEYS)
    if unknown:
        pol.notices.append(f"{_PREFIX} unknown key(s) in {POLICY_FILENAME} ignored: {', '.join(unknown)}.")

    if "mode" in data:
        if data["mode"] in MODES:
            pol.mode = data["mode"]
        else:
            pol.notices.append(f"{_PREFIX} mode must be one of feedback, warn, off; using feedback.")

    for key in ("scan_on_edit", "strict_commit", "checkin"):
        if key in data:
            if isinstance(data[key], bool):
                setattr(pol, key, data[key])
            else:
                pol.notices.append(f"{_PREFIX} {key} must be true or false; using the default.")

    if "ignore_paths" in data:
        raw = data["ignore_paths"]
        if isinstance(raw, list) and all(isinstance(x, str) and x.strip() for x in raw):
            pol.ignore_paths = list(raw)
        else:
            pol.notices.append(f"{_PREFIX} ignore_paths must be a list of path patterns; ignored.")

    if "allow" in data:
        raw = data["allow"]
        if not isinstance(raw, list):
            pol.notices.append(f"{_PREFIX} allow must be a list; ignored.")
            raw = []
        for entry in raw:
            ok = isinstance(entry, dict)
            reason = entry.get("reason") if ok else None
            algorithm = entry.get("algorithm") if ok else None
            epath = entry.get("path") if ok else None
            if ok and not (isinstance(reason, str) and reason.strip()):
                pol.notices.append(f"{_PREFIX} allow entry {_describe_entry(entry)} dropped: it has no reason.")
                continue
            if ok and algorithm is None and epath is None:
                pol.notices.append(f"{_PREFIX} allow entry {_describe_entry(entry)} dropped: it names no algorithm or path.")
                continue
            if not ok or (algorithm is not None and not isinstance(algorithm, str)) \
                    or (epath is not None and not isinstance(epath, str)):
                pol.notices.append(f"{_PREFIX} allow entry {_describe_entry(entry)} dropped: it is malformed.")
                continue
            pol.allow.append(AllowEntry(algorithm=algorithm, path=epath, reason=reason.strip()))
    return pol


def _entry_text(a: AllowEntry) -> str:
    return f"{a.algorithm or 'any algorithm'} at {a.path or 'any path'}"


def describe_change(old: Optional[bytes], new: Optional[bytes]) -> Optional[str]:
    """One warning line when the policy file differs from the session's starting commit, naming
    what changed: mode, allow entries added, ignore paths added (and checkin / strict_commit).
    Makes an agent loosening or switching off its own guard visible to the person."""
    if old == new:
        return None
    o, n = parse(old), parse(new)
    parts = []
    if old is None:
        parts.append("file created")
    if new is None:
        parts.append("file deleted")
    if o.mode != n.mode:
        parts.append(f"mode {o.mode} -> {n.mode}")
    old_allow = {(a.algorithm, a.path) for a in o.allow}
    added = [a for a in n.allow if (a.algorithm, a.path) not in old_allow]
    if added:
        parts.append("allow entries added: " + "; ".join(_entry_text(a) for a in added))
    ignored = [p for p in n.ignore_paths if p not in o.ignore_paths]
    if ignored:
        parts.append("ignore_paths added: " + ", ".join(ignored))
    for key in ("checkin", "strict_commit"):
        if getattr(o, key) != getattr(n, key):
            parts.append(f"{key} {str(getattr(o, key)).lower()} -> {str(getattr(n, key)).lower()}")
    detail = "; ".join(parts) if parts else "content edited"
    return f"Qryptive guard: WARNING: {POLICY_FILENAME} changed during this session ({detail})."
