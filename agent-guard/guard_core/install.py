"""Install and uninstall the guard's hooks (plan D12).

The rules, for every agent:
- The guard's own entries are recognised by a fixed marker: a hook command that runs
  `qryptive_guard.py`, or, for git, a `# qryptive-guard` line in the hook script.
- Install merges into an existing config file and never replaces or deletes anything a person
  wrote. A second install finds its own entries and changes nothing.
- A config file that is not valid JSON, or not the expected shape, is refused and left as it was.
- A git hook that is not the guard's is refused, with the line to add by hand.
- Uninstall removes only the guard's own entries, and deletes a file only when the guard created it
  (recorded in a small ledger in the guard's state directory) and nothing else is left in it.
- Every write is atomic (temp file + rename in the same directory) and keeps the file's mode; a
  symlinked config is written through, so the link stays a link.
"""
import json
import os
import re
import shlex
import subprocess
import tempfile
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from guard_core import state

AGENTS = ("claude-code", "cursor", "git")
GIT_MARKER = "# qryptive-guard"
OWN_TOKEN = "qryptive_guard.py"
GUARD_PATH = Path(__file__).resolve().parent.parent / "qryptive_guard.py"
ADAPTERS = GUARD_PATH.parent / "adapters"
PLACEHOLDER = '"__QRYPTIVE_GUARD__"'
PLUGIN_PATH = '"${CLAUDE_PLUGIN_ROOT}/agent-guard/qryptive_guard.py"'
# Every agent hook command runs the guard inside this POSIX wrapper (`sh -c WRAPPER qryptive-guard
# <guard> <args>`): a missing guard or python3, or ANY non-zero exit (a crash, SIGTERM, Python's own
# exit 2 for a missing script), becomes one "did NOT run" line on stderr and exit 0. Claude Code
# reads exit 2 from a Stop hook as "block", so without this a deleted worktree or a rolled-over
# plugin cache would block every turn for ever. The adapter files carry this exact text.
WRAPPER = 'g=$1; shift; if [ ! -f "$g" ] || ! command -v python3 >/dev/null 2>&1; then echo "Qryptive guard: check did NOT run: python3 or the guard ($g) is missing. Your edits were not checked." >&2; exit 0; fi; python3 "$g" "$@" || { echo "Qryptive guard: check did NOT run: the guard stopped unexpectedly. Your edits were not checked." >&2; exit 0; }'
WRAPPER_ARGV0 = "qryptive-guard"
# The only argument lists the installer writes; an entry is the guard's only if it has one of them.
OWN_ARGS = {("record",), ("record", "--format", "cursor"), ("check", "--format", "claude-code"),
            ("check", "--format", "cursor")}
_GIT_TIMEOUT = 10


class Refused(Exception):
    """Nothing was changed; the message says why and what a person can do instead."""


def _quoted_guard() -> str:
    return shlex.quote(str(GUARD_PATH))


def _fill(command: str, token: str) -> str:
    if token not in command:
        raise Refused(f"the adapter template is damaged (no {token} in its command); nothing was changed")
    return command.replace(token, _quoted_guard())


# --- JSON configs (Claude Code, Cursor) ---------------------------------------------------

def _claude_template() -> dict:
    hooks = json.loads((ADAPTERS / "claude-code" / "hooks.json").read_text(encoding="utf-8"))["hooks"]
    for groups in hooks.values():
        for g in groups:
            for h in g["hooks"]:
                h["command"] = _fill(h["command"], PLUGIN_PATH)
    return hooks


def _cursor_template() -> dict:
    hooks = json.loads((ADAPTERS / "cursor" / "hooks.json").read_text(encoding="utf-8"))["hooks"]
    for entries in hooks.values():
        for e in entries:
            e["command"] = _fill(e["command"], PLACEHOLDER)
    return hooks


def _is_own_command(cmd) -> bool:
    """Only the exact shape the installer writes: `sh -c WRAPPER qryptive-guard <.../qryptive_guard.py>
    <known args>`. A person's hook that merely mentions qryptive_guard.py is never the guard's."""
    if not isinstance(cmd, str):
        return False
    try:
        argv = shlex.split(cmd)
    except ValueError:
        return False
    return (len(argv) >= 6 and argv[:4] == ["sh", "-c", WRAPPER, WRAPPER_ARGV0]
            and (argv[4] == OWN_TOKEN or argv[4].endswith("/" + OWN_TOKEN))
            and tuple(argv[5:]) in OWN_ARGS)


def command_for(*args: str) -> str:
    """The exact command the installer writes for this guard and these arguments."""
    return " ".join(["sh -c", shlex.quote(WRAPPER), WRAPPER_ARGV0, _quoted_guard(), *args])


def _fresh_command(cmd) -> Optional[str]:
    """For one of the guard's own commands, the command this guard writes today for the same
    arguments (so an entry left by a guard at an older path is updated in place); else None."""
    if not _is_own_command(cmd):
        return None
    return command_for(*shlex.split(cmd)[5:])


def _refresh(entry):
    """`entry` with every own command pointed at the current guard. Never touches other hooks."""
    if not isinstance(entry, dict):
        return entry
    out = dict(entry)
    fresh = _fresh_command(out.get("command"))
    if fresh is not None:
        out["command"] = fresh
    if isinstance(out.get("hooks"), list):
        out["hooks"] = [_refresh(h) for h in out["hooks"]]
    return out


def _claude_strip(group) -> Tuple[object, bool]:
    """(the group without the guard's hooks, or None if nothing else is left; whether it had any)."""
    hooks = group.get("hooks") if isinstance(group, dict) else None
    if not isinstance(hooks, list):
        return group, False
    keep = [h for h in hooks if not (isinstance(h, dict) and _is_own_command(h.get("command")))]
    if len(keep) == len(hooks):
        return group, False
    if not keep:
        return None, True
    out = dict(group)
    out["hooks"] = keep
    return out, True


def _cursor_strip(entry) -> Tuple[object, bool]:
    if isinstance(entry, dict) and _is_own_command(entry.get("command")):
        return None, True
    return entry, False


_JSON_AGENTS = {
    # agent: (config path under the repo, skeleton for a new file, template, strip-one-entry)
    "claude-code": (Path(".claude") / "settings.local.json", lambda: {"hooks": {}}, _claude_template, _claude_strip),
    "cursor": (Path(".cursor") / "hooks.json", lambda: {"version": 1, "hooks": {}}, _cursor_template, _cursor_strip),
}


class _Changed(Exception):
    """The file changed between the read and the rename; the caller re-reads once."""


def _sig(path: Path):
    """(mtime_ns, size) of the real file, or None when it does not exist."""
    try:
        st = os.stat(os.path.realpath(path))
        return (st.st_mtime_ns, st.st_size)
    except FileNotFoundError:
        return None


def _inside(child, root) -> bool:
    """Is `child` (after symlinks) inside `root`? A path on another drive is not."""
    try:
        real_root = os.path.realpath(root)
        return os.path.commonpath([os.path.realpath(child), real_root]) == real_root
    except ValueError:
        return False


def _is_git(root: Path) -> bool:
    return (root / ".git").exists()


def _tracked(root: Path, path: Path) -> bool:
    if not _is_git(root):
        return False
    rel = os.path.relpath(os.path.realpath(path), os.path.realpath(root))
    return _git(root, "ls-files", "--error-unmatch", "--", rel).returncode == 0


def _ignored(root: Path, path: Path) -> bool:
    rel = os.path.relpath(os.path.realpath(path), os.path.realpath(root))
    return _git(root, "check-ignore", "-q", "--", rel).returncode == 0


def _read_json(path: Path, rel: str):
    """(data or None when absent, raw text, signature). Refuses anything unexpected."""
    sig = _sig(path)
    if sig is None:
        if path.is_symlink():
            raise Refused(f"{rel} is a broken symlink; nothing was changed")
        return None, "", None
    raw = path.read_text(encoding="utf-8")
    try:
        data = json.loads(raw)
    except ValueError as exc:
        raise Refused(f"{rel} is not valid JSON ({exc}); nothing was changed. Fix it, then run this again")
    if not isinstance(data, dict):
        raise Refused(f"{rel} does not hold a JSON object; nothing was changed")
    hooks = data.get("hooks", {})
    if not isinstance(hooks, dict) or not all(isinstance(v, list) for v in hooks.values()):
        raise Refused(f'{rel} has a "hooks" value of an unexpected shape; nothing was changed')
    return data, raw, sig


def _atomic_write(path: Path, text: str, mode: Optional[int] = None, expect="unchecked") -> None:
    """Write through a symlink to its target, via a temp file + rename in the same directory.
    With `expect` (a `_sig` value), the file is re-checked just before the rename and _Changed is
    raised, with nothing written, if someone else changed it since it was read."""
    real = Path(os.path.realpath(path))
    real.parent.mkdir(parents=True, exist_ok=True)
    if mode is None:
        mode = (real.stat().st_mode & 0o7777) if real.exists() else 0o644
    fd, tmp = tempfile.mkstemp(prefix=".qryptive-guard-", dir=str(real.parent))
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        if expect != "unchecked" and _sig(real) != expect:
            raise _Changed()
        os.replace(tmp, real)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _indent(raw: str) -> int:
    """The file's own indentation when it is 2 or 4 spaces, else 2."""
    m = re.search(r'^\{[ \t]*\r?\n( +)"', raw)
    return len(m.group(1)) if m and len(m.group(1)) in (2, 4) else 2


def _dump(data: dict, indent: int = 2) -> str:
    return json.dumps(data, indent=indent, ensure_ascii=False) + "\n"


# The ledger: which files the guard created, and where it added the "hooks" key, so uninstall can
# tell the guard's own additions from a person's. Kept in the guard's state directory.
_LEDGER_KINDS = ("created", "added_hooks_key")


def _ledger_path() -> Path:
    return state.guard_root() / "installed-files.json"


def _ledger() -> dict:
    try:
        data = json.loads(_ledger_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    return {k: [p for p in data.get(k, []) if isinstance(p, str)] if isinstance(data.get(k), list) else []
            for k in _LEDGER_KINDS}


def _ledger_set(kind: str, path: Path, on: bool) -> None:
    try:
        data = _ledger()
        real = os.path.realpath(path)
        items = set(data[kind]) - {real}
        if on:
            items.add(real)
        data[kind] = sorted(items)
        p = _ledger_path()
        state._ensure_dir(p.parent)
        state.atomic_write_json(p, data)
    except OSError:
        pass  # without the record, uninstall leaves the guard's empty additions: the safe direction


def _ledger_has(kind: str, path: Path) -> bool:
    return os.path.realpath(path) in _ledger()[kind]


def _ledger_forget(path: Path) -> None:
    for kind in _LEDGER_KINDS:
        _ledger_set(kind, path, False)


def _check_location(agent: str, root: Path, path: Path, rel: str, installing: bool) -> None:
    """The config must really live in this repository (not, through a symlink, in a person's global
    Claude/Cursor settings or anywhere else) and must not be a file git tracks, because the
    entries name this machine's absolute path to the guard."""
    target = os.path.realpath(path)
    if not _inside(target, root):
        step = ("Add these hooks to it yourself:\n  " + json.dumps(_JSON_AGENTS[agent][2]())
                if installing else "Remove the guard's entries from it yourself.")
        raise Refused(f"{rel} leads to {target}, outside this repository, so the guard will not edit it; "
                      f"nothing was changed. {step}")
    if installing and _tracked(root, path):
        raise Refused(f"{rel} is tracked by git, and the guard's entries name this machine's path, so they "
                      f"would be committed; nothing was changed. Untrack it, or add the hooks yourself somewhere git ignores")


def _install_json_once(agent: str, root: Path) -> str:
    rel_path, skeleton, template, strip = _JSON_AGENTS[agent]
    path, rel = root / rel_path, str(rel_path)
    _check_location(agent, root, path, rel, installing=True)
    data, raw, sig = _read_json(path, rel)
    created = data is None
    if created:
        data = skeleton()
    added_key = "hooks" not in data
    hooks = data.setdefault("hooks", {})
    added, updated = [], []
    for event, entries in template().items():
        existing = hooks.get(event, [])
        if any(strip(e)[1] for e in existing):
            fresh = [_refresh(e) for e in existing]
            if fresh != existing:  # written by a guard at another path: point it here
                hooks[event] = fresh
                updated.append(event)
            continue
        hooks[event] = existing + entries
        added.append(event)
    if not added and not updated:
        return f"Qryptive guard is already installed in {rel}; nothing was changed."
    _atomic_write(path, _dump(data, _indent(raw)), expect=sig)
    if created:
        _ledger_set("created", path, True)
    elif added_key:
        _ledger_set("added_hooks_key", path, True)
    parts = []
    if added:
        parts.append(f"Qryptive guard {'created' if created else 'added to'} {rel} ({', '.join(added)}).")
    if updated:
        parts.append(f"Qryptive guard updated the guard path in {rel} ({', '.join(updated)}).")
    return " ".join(parts) + _commit_warning(agent, root, path)


def _commit_warning(agent: str, root: Path, path: Path) -> str:
    """Cursor's project hooks file is often committed: say so when git would pick it up."""
    if agent != "cursor" or not _is_git(root) or _tracked(root, path) or _ignored(root, path):
        return ""
    rel = os.path.relpath(path, root)
    return (f"\nWarning: {rel} is not ignored by git, so it is easy to commit by accident; it names this "
            f"machine's path to the guard. Add it to .gitignore or .git/info/exclude.")


def _uninstall_json_once(agent: str, root: Path) -> str:
    rel_path, skeleton, _template, strip = _JSON_AGENTS[agent]
    path, rel = root / rel_path, str(rel_path)
    _check_location(agent, root, path, rel, installing=False)
    data, raw, sig = _read_json(path, rel)
    if data is None:
        return f"Qryptive guard: nothing to remove ({rel} does not exist)."
    hooks = data.get("hooks", {})
    removed = []
    for event in list(hooks):
        kept, had = [], False
        for e in hooks[event]:
            rest, own = strip(e)
            had = had or own
            if rest is not None:
                kept.append(rest)
        if not had:
            continue
        removed.append(event)
        if kept:
            hooks[event] = kept
        else:
            del hooks[event]
    if not removed:
        return f"Qryptive guard: nothing to remove in {rel}."
    if data == skeleton() and _ledger_has("created", path) and not path.is_symlink():
        if _sig(path) != sig:
            raise _Changed()
        os.unlink(path)
        _ledger_forget(path)
        return f"Qryptive guard removed {rel}, which it had created."
    if hooks == {} and "hooks" in data and _ledger_has("added_hooks_key", path):
        del data["hooks"]
    _atomic_write(path, _dump(data, _indent(raw)), expect=sig)
    if "hooks" not in data:
        _ledger_set("added_hooks_key", path, False)
    return f"Qryptive guard removed its entries from {rel} ({', '.join(removed)})."


def _retrying(fn: Callable[[str, Path], str], agent: str, root: Path) -> str:
    """Run a read-merge-write; if the file changed underneath it, re-read once, then refuse."""
    for _ in range(2):
        try:
            return fn(agent, root)
        except _Changed:
            continue
    raise Refused(f"{_JSON_AGENTS[agent][0]} kept changing while the guard edited it; nothing was changed. "
                  f"Run this again when nothing else is writing it")


def _install_json(agent: str, root: Path) -> str:
    return _retrying(_install_json_once, agent, root)


def _uninstall_json(agent: str, root: Path) -> str:
    return _retrying(_uninstall_json_once, agent, root)


# --- git pre-commit -----------------------------------------------------------------------

def _git(root: Path, *args) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True,
                          timeout=_GIT_TIMEOUT)


def _manual_line() -> str:
    return f"python3 {_quoted_guard()} check --staged || exit $?"


def _shared_note(root: Path) -> str:
    r = _git(root, "worktree", "list", "--porcelain")
    count = sum(1 for line in r.stdout.splitlines() if line.startswith("worktree ")) if r.returncode == 0 else 0
    if count > 1:
        return f" This hook is shared by all {count} worktrees of this repository."
    return ""


def _hooks_dir(root: Path, installing: bool = True) -> Tuple[Path, str]:
    """(where git runs hooks for this repository, a note when the hook is shared). Honours
    core.hooksPath; refuses a hooks path outside the repository, or one inside the working tree
    that git would let someone commit."""
    r = _git(root, "config", "--get", "core.hooksPath")
    if r.returncode == 0 and r.stdout.strip():
        raw = os.path.expanduser(r.stdout.strip())
        d = Path(os.path.realpath(raw if os.path.isabs(raw) else root / raw))
        if not _inside(d, root):
            step = (f"To check commits here, add this line to {d / 'pre-commit'} yourself:\n  {_manual_line()}"
                    if installing else f"Remove the guard's line from {d / 'pre-commit'} yourself if you added it.")
            raise Refused(f"core.hooksPath points to {d}, outside this repository, so a hook there runs for "
                          f"other repositories too; nothing was changed. {step}")
        hook = d / "pre-commit"
        if installing and not _ignored(root, hook):
            raise Refused(f"core.hooksPath is {d}, inside the working tree, and git does not ignore "
                          f"{hook}, so the guard's hook (which names this machine's path) could be committed; "
                          f"nothing was changed. Ignore that file in .gitignore, or add this line to your own "
                          f"hook:\n  {_manual_line()}")
        return d, ""
    r = _git(root, "rev-parse", "--git-common-dir")
    if r.returncode != 0 or not r.stdout.strip():
        raise Refused("git could not find this repository's hooks directory; nothing was changed")
    common = Path(os.path.realpath(r.stdout.strip() if os.path.isabs(r.stdout.strip()) else root / r.stdout.strip()))
    d = Path(os.path.realpath(common / "hooks"))
    if not _inside(d, common):
        step = (f"To check commits here, add this line to {d / 'pre-commit'} yourself:\n  {_manual_line()}"
                if installing else f"Remove the guard's line from {d / 'pre-commit'} yourself if you added it.")
        raise Refused(f"this repository's hooks directory is a link to {d}, outside its git directory (a shared "
                      f"template folder, perhaps), so a hook there may run for other repositories too; nothing "
                      f"was changed. {step}")
    return d, _shared_note(root)


_GUARD_LINE = re.compile(r"^GUARD=.*$", re.MULTILINE)


def _normalised_shim(text: str) -> str:
    """The shim with its one guard-path line blanked, so a shim from a guard at another path
    still compares equal to the one this guard writes."""
    return _GUARD_LINE.sub("GUARD=", text, count=1)


def _shim_state(text: str, shim: Optional[str]) -> str:
    """'current', 'stale' (the guard's shim with another path) or 'other'."""
    if shim is None:
        return "other"
    if text == shim:
        return "current"
    if _GUARD_LINE.search(text) and _normalised_shim(text) == _normalised_shim(shim):
        return "stale"
    return "other"


def _is_marked(text: str) -> bool:
    return GIT_MARKER in (line.strip() for line in text.splitlines())


def _shim() -> str:
    return _fill((ADAPTERS / "git" / "pre-commit").read_text(encoding="utf-8"), PLACEHOLDER)


def _require_git(root: Path) -> None:
    if not _is_git(root):
        raise Refused(f"{root} is not a git repository; nothing was changed")


def _install_git(root: Path) -> str:
    _require_git(root)
    d, shared = _hooks_dir(root)
    hook = d / "pre-commit"
    shim = _shim()
    if hook.exists() or hook.is_symlink():
        sig = _sig(hook)  # before the read: any change after it is caught at the rename
        text = hook.read_text(encoding="utf-8", errors="replace") if hook.exists() else ""
        kind = "other" if hook.is_symlink() else _shim_state(text, shim)
        if kind == "current":
            return f"Qryptive guard is already installed in {hook}; nothing was changed.{shared}"
        if kind == "stale":
            try:
                _atomic_write(hook, shim, mode=0o755, expect=sig)
            except _Changed:
                raise Refused(f"{hook} changed while the guard was updating it; nothing was changed. Run this again")
            return f"Qryptive guard updated the guard path in {hook}.{shared}"
        if _is_marked(text):
            raise Refused(f"{hook} carries the guard's marker but is not the hook this guard writes (edited by "
                          f"hand, or written by a guard at another path), so it was left as it was. Remove it "
                          f"yourself, then run install again")
        raise Refused(f"{hook} already exists and is not the Qryptive guard's, so it was left as it was. "
                      f"To check commits, add this line to it yourself:\n  {_manual_line()}")
    try:
        _atomic_write(hook, shim, mode=0o755, expect=None)
    except _Changed:
        raise Refused(f"{hook} appeared while the guard was writing it; nothing was changed. Run this again")
    return f"Qryptive guard created {hook}.{shared}"


def _uninstall_git(root: Path) -> str:
    _require_git(root)
    d, shared = _hooks_dir(root, installing=False)
    hook = d / "pre-commit"
    if not (hook.exists() or hook.is_symlink()):
        return f"Qryptive guard: nothing to remove ({hook} does not exist)."
    sig = _sig(hook)  # before the read, re-checked just before the unlink
    text = hook.read_text(encoding="utf-8", errors="replace") if hook.exists() else ""
    if not hook.is_symlink() and _shim_state(text, _shim_or_none()) in ("current", "stale"):
        if _sig(hook) != sig:
            raise Refused(f"{hook} changed while the guard was removing it; nothing was changed. Run this again")
        os.unlink(hook)
        return f"Qryptive guard removed {hook}, which it had created.{shared}"
    if _is_marked(text):
        return (f"Qryptive guard: {hook} carries the guard's marker but is not the hook this guard writes, "
                f"so it was left as it was. Remove it yourself if it is no longer wanted.")
    return f"Qryptive guard: {hook} is not the Qryptive guard's, so it was left as it was."


def _shim_or_none() -> Optional[str]:
    try:
        return _shim()
    except (OSError, Refused):
        return None


# --- entry --------------------------------------------------------------------------------

def run(action: str, agent: str, root: Path) -> Tuple[bool, str]:
    """(done, message). `done` is False when the guard refused and changed nothing."""
    table: dict = {
        ("install", "git"): lambda: _install_git(root),
        ("uninstall", "git"): lambda: _uninstall_git(root),
        ("install", "claude-code"): lambda: _install_json("claude-code", root),
        ("uninstall", "claude-code"): lambda: _uninstall_json("claude-code", root),
        ("install", "cursor"): lambda: _install_json("cursor", root),
        ("uninstall", "cursor"): lambda: _uninstall_json("cursor", root),
    }
    fn: Callable[[], str] = table[(action, agent)]
    try:
        return True, fn()
    except Refused as exc:
        return False, f"Qryptive guard: {exc}"
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"Qryptive guard: could not {action} ({type(exc).__name__}: {exc}); nothing was changed"
