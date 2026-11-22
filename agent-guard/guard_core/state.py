"""Session state, edit queue and the feedback loop bound (plan D8, D11).

Location: ${XDG_STATE_HOME:-~/.local/state}/qryptive/guard/<sha256(realpath(repo_root))[:16]>/<session>.json
Directory mode 700, files 600. Every write is atomic (temp file + rename in the same directory)
and every read-modify-write happens under an fcntl lock, so two hooks firing at once are
harmless. This module is the sole writer of guard state.

Session file shape:
  baseline_commit / baseline_pinned  the commit pinned at the session's first record
  queue        {repo-relative path: time recorded}  (a set; re-recording only refreshes the time)
  rounds       {round key: feedback rounds emitted}  (round key includes the file path)
  last_result  what the last check did, for `status`
"""
import contextlib
import fcntl
import hashlib
import json
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Callable, Iterable, List, Optional, Tuple

MAX_ROUNDS = 3
MAX_SESSION_BLOCKS = 6  # blocking checks per session, across all findings (plan D8)
PRUNE_AFTER_SECONDS = 7 * 86400
_LOCK_WAIT_SECONDS = 10.0
_SESSION_RE = re.compile(r"^[A-Za-z0-9._-]{1,80}$")


def guard_root() -> Path:
    base = os.environ.get("XDG_STATE_HOME") or os.path.join(os.path.expanduser("~"), ".local", "state")
    return Path(base) / "qryptive" / "guard"


def repo_key(repo_root) -> str:
    return hashlib.sha256(os.path.realpath(str(repo_root)).encode("utf-8", "surrogateescape")).hexdigest()[:16]


def safe_session(session: Optional[str]) -> str:
    s = (session or "default").strip() or "default"
    if _SESSION_RE.match(s) and s not in (".", ".."):
        return s
    return "h-" + hashlib.sha256(s.encode("utf-8", "surrogateescape")).hexdigest()[:24]


def _ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    root = guard_root()
    for p in (root, path):
        if p.exists():
            os.chmod(p, 0o700)


def atomic_write_json(path: Path, data) -> None:
    """Write JSON via a temp file in the same directory, mode 600, then rename over `path`."""
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


@contextlib.contextmanager
def _flock(lock_path: Path):
    fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        deadline = time.monotonic() + _LOCK_WAIT_SECONDS
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() > deadline:
                    raise TimeoutError("guard state is locked by another process")
                time.sleep(0.01)
        yield
    finally:
        os.close(fd)  # closing releases the lock


class JsonStore:
    """One JSON file with a sibling lock file. `locked()` yields the parsed data and writes it
    back atomically only if the block exits normally; an exception leaves the file untouched."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.dir = self.path.parent
        self.lock_path = self.path.with_suffix(".lock")

    def _load(self) -> dict:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def read(self) -> dict:
        return self._normalise(self._load())

    def _normalise(self, data: dict) -> dict:
        return data

    @contextlib.contextmanager
    def locked(self):
        _ensure_dir(self.dir)
        with _flock(self.lock_path):
            data = self._normalise(self._load())
            yield data
            atomic_write_json(self.path, data)


class SessionStore(JsonStore):
    def __init__(self, repo_root, session: Optional[str]):
        self.repo_root = os.path.realpath(str(repo_root))
        self.session = safe_session(session)
        super().__init__(guard_root() / repo_key(self.repo_root) / f"{self.session}.json")

    def _normalise(self, data: dict) -> dict:
        data.setdefault("version", 1)
        data.setdefault("repo_root", self.repo_root)
        data.setdefault("session", self.session)
        if not isinstance(data.get("queue"), dict):
            data["queue"] = {}
        if not isinstance(data.get("rounds"), dict):
            data["rounds"] = {}
        data.setdefault("baseline_commit", None)
        data.setdefault("baseline_pinned", False)
        return data


def renewal_store() -> JsonStore:
    """Machine-wide renewal bookkeeping (`last_renewal_attempt`), shared by every repo/session so
    renewal happens at most once a day per machine."""
    return JsonStore(guard_root() / "renewal.json")


def session_files(repo_root) -> List[Path]:
    d = guard_root() / repo_key(repo_root)
    try:
        return sorted((p for p in d.glob("*.json") if not p.name.startswith(".")),
                      key=lambda p: p.stat().st_mtime, reverse=True)
    except OSError:
        return []


def pin_baseline(store: SessionStore, pin: Callable[[], Optional[str]]) -> bool:
    """Pin the session's baseline commit if it is not pinned yet (git call outside the lock).
    If `pin` raises (git could not tell), the session stays UNPINNED so a later record or check
    pins it — "git failed" is never stored as "no commits". Returns whether it is pinned."""
    if store.read().get("baseline_pinned"):
        return True
    try:
        value = pin()
    except Exception:  # noqa: BLE001 - leave unpinned; the caller reports it
        return False
    with store.locked() as st:
        if not st.get("baseline_pinned"):
            st["baseline_commit"] = value
            st["baseline_pinned"] = True
    return True


def try_pin(store: SessionStore, pin: Callable[[], Optional[str]]) -> bool:
    try:
        return pin_baseline(store, pin)
    except Exception:  # noqa: BLE001 - must never fail an edit
        return False


def record(store: SessionStore, rel_path: str, pin: Callable[[], Optional[str]]) -> bool:
    """Add one edited path to the session queue; pin the baseline commit on the first record.
    The pin (a git call) runs OUTSIDE the lock so concurrent hooks never wait on git. Returns
    whether the session is pinned afterwards (False when git could not read the commit)."""
    pinned = pin_baseline(store, pin)
    with store.locked() as st:
        st["queue"][rel_path] = time.time()
    return pinned


def ensure_pinned(st: dict, pin: Callable[[], Optional[str]]) -> None:
    if not st.get("baseline_pinned"):
        st["baseline_commit"] = pin()
        st["baseline_pinned"] = True


def round_key(f: dict) -> str:
    return "\x1f".join(str(f.get(k) or "") for k in ("file", "finding_type", "algorithm", "pq_status"))


def decide_rounds(st: dict, feedback: Iterable[dict]) -> Tuple[List[dict], List[dict]]:
    """Split feedback findings into (emit, demoted). Each distinct key counts ONE round per call,
    however many findings share it; a key already fed back MAX_ROUNDS times is demoted to
    warn-only. Mutates `st` — call inside `locked()` so the count lands in the same atomic write
    as the rest of the check's result."""
    rounds = st.setdefault("rounds", {})
    emit, demoted = [], []
    decided = {}
    for f in feedback:
        k = round_key(f)
        if k not in decided:
            if int(rounds.get(k, 0)) >= MAX_ROUNDS:
                decided[k] = False
            else:
                rounds[k] = int(rounds.get(k, 0)) + 1
                decided[k] = True
        (emit if decided[k] else demoted).append(f)
    return emit, demoted


def decide_session_cap(st: dict, emit: List[dict]) -> Tuple[List[dict], bool]:
    """The per-session bound: at most MAX_SESSION_BLOCKS checks may block in one session, however
    many different findings the agent introduces. Returns (emit, capped). When the cap is already
    reached, nothing is emitted and `capped` is True; otherwise a non-empty `emit` counts one
    blocking round. Mutates `st` — call inside `locked()`, in the same write as the round counts."""
    used = int(st.get("blocking_rounds", 0) or 0)
    if used >= MAX_SESSION_BLOCKS:
        return [], True
    if emit:
        st["blocking_rounds"] = used + 1
    return emit, False


def decide_warnings(st: dict, items: Iterable[dict], tag: str = "warn") -> List[dict]:
    """Warn-only items are shown ONCE per session per key; returns those not shown before and
    marks them shown. Mutates `st` (call inside `locked()`)."""
    shown = st.setdefault("warned", {})
    out, seen_now = [], set()
    for f in items:
        k = tag + "\x1f" + round_key(f)
        if k in shown and k not in seen_now:
            continue
        if k not in shown:
            shown[k] = time.time()
            seen_now.add(k)
        out.append(f)
    return out


def complete_check(st: dict, covered: Iterable[str], with_new: Iterable[str], started_at: float) -> None:
    """A completed check: a covered file leaves the queue only if it had nothing new, and only if
    it was not re-recorded after the check started (that newer edit was not scanned)."""
    covered = set(covered)
    keep = set(with_new)
    queue = st.setdefault("queue", {})
    for path in list(queue):
        if path in covered and path not in keep and float(queue[path]) <= started_at:
            del queue[path]


def record_result(st: dict, result: dict) -> None:
    r = dict(result)
    r.setdefault("when", time.time())
    st["last_result"] = r


def prune(now: Optional[float] = None) -> int:
    """Remove session/lock files not modified for 7 days. Never touches a live session."""
    now = time.time() if now is None else now
    root = guard_root()
    removed = 0
    try:
        repo_dirs = [d for d in root.iterdir() if d.is_dir()]
    except OSError:
        return 0
    for d in repo_dirs:
        try:
            entries = list(d.iterdir())
        except OSError:
            continue
        for p in sorted(entries, key=lambda e: e.suffix != ".json"):  # session files first
            if p.suffix not in (".json", ".lock"):
                continue
            if p.suffix == ".lock" and (d / (p.stem + ".json")).exists():
                continue  # a lock is pruned only once its session file is gone
            try:
                if now - p.stat().st_mtime > PRUNE_AFTER_SECONDS:
                    p.unlink()
                    removed += 1
            except OSError:
                continue
        with contextlib.suppress(OSError):
            d.rmdir()  # only succeeds when empty
    return removed


def try_record(store: SessionStore, rel_path: str, pin: Callable[[], Optional[str]]) -> Optional[str]:
    """`record` that never raises (an edit must never fail because of the guard). Returns one
    line to print on failure, else None."""
    try:
        if record(store, rel_path, pin):
            return None
        return ("Qryptive guard: git could not read the current commit; this edit is queued and the "
                "comparison start will be set at the next edit or check.")
    except Exception as exc:  # noqa: BLE001 - deliberately broad: record must never fail an edit
        return f"Qryptive guard: could not record this edit ({type(exc).__name__}); the end-of-turn check still runs."
