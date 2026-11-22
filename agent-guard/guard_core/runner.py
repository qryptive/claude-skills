"""Running the local scanner image, and keeping its scan pass fresh (plan D6, D7).

Docker: one `docker run` per check, mirroring the /qryptive-scan skill's run block:
`--rm --platform linux/amd64 --network none`, a read-only mount of the temp tree at /work,
`MALLOC_ARENA_MAX=2`, never `SCANNER_MAX_WORKERS`, plus `QRYPTIVE_SCAN_INCLUDE_CONFIG=1`. The
scan pass travels as `-e QRYPTIVE_SCAN_PASS` (by name; its value is only in the child
environment, never in argv). The image is never pulled: `preflight` checks `docker image
inspect` first, and the run itself passes `--pull never` (Docker 20.10 or newer); a missing
image is "could not run". If the guard is interrupted (timeout, SIGTERM, any exception) while
the container runs, the named container is killed.

Scan pass: read from where the skill keeps it. Renewed at most once a day, only when under two
days remain (or the expiry cannot be read), with one 5-second check-in that sends only
{"client":"guard","scanner_version":...}. A failed renewal never blocks while the saved pass is
valid. Nothing here ever prints or stores the pass or the scanner key.
"""
import base64
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

from . import baseline, state

DEFAULT_IMAGE = "ghcr.io/qryptive/pqc-scanner:v1"
DEFAULT_PLATFORM_URL = "https://app.qryptive.ai"
CHECKIN_TIMEOUT_SECONDS = 5
RENEW_WHEN_UNDER_SECONDS = 2 * 86400
RENEW_AT_MOST_EVERY_SECONDS = 86400
PASS_SKEW_SECONDS = 300  # the scanner's own allowance
SCAN_TIMEOUT_SECONDS = 600
INSPECT_TIMEOUT_SECONDS = 20
LIST_FILE = ".qryptive-guard-files"

SIGNIN = "no scan pass is saved on this machine; run /qryptive-scan once to sign in"
EXPIRED = "the saved scan pass has expired; run /qryptive-scan once to sign in again"


class CannotRun(Exception):
    """The check could not run. `reason` is one plain sentence fragment, safe to show."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


# --- Docker -------------------------------------------------------------------------------

def image() -> str:
    return os.environ.get("QRYPTIVE_SCANNER_IMAGE") or DEFAULT_IMAGE


def _docker() -> str:
    exe = shutil.which("docker")
    if not exe:
        raise CannotRun("Docker is not installed (no docker command found)")
    return exe


def _docker_failure(stderr: str, rc: int) -> CannotRun:
    low = (stderr or "").lower()
    if "unknown flag" in low:
        return CannotRun("Docker 20.10 or newer is needed")
    if "no such image" in low or "no such object" in low or "unable to find image" in low \
            or "pull access denied" in low or ("pull" in low and "never" in low):
        return CannotRun("the scanner image is not on this machine; run /qryptive-scan once to download it")
    if "cannot connect to the docker daemon" in low or "is the docker daemon running" in low \
            or "docker daemon is not running" in low or "error during connect" in low:
        return CannotRun("Docker is not running")
    return CannotRun(f"Docker could not start the scanner (exit {rc})")


def preflight(img: str) -> Optional[str]:
    """Check Docker is up and the image is cached (never pulls). Returns the image's version
    label, or None if it has none."""
    exe = _docker()
    try:
        r = subprocess.run([exe, "image", "inspect", "--format",
                            '{{index .Config.Labels "org.opencontainers.image.version"}}', img],
                           capture_output=True, text=True, timeout=INSPECT_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        raise CannotRun("Docker is not responding")
    except OSError:
        raise CannotRun("Docker could not be started")
    if r.returncode != 0:
        raise _docker_failure(r.stderr, r.returncode)
    version = (r.stdout or "").strip()
    return version if version and version != "<no value>" else None


@dataclass
class ScanResult:
    findings: List[dict]
    files_scanned: int
    incomplete: bool = False
    unreadable: int = 0  # entries in the scanner's findings list that were not objects
    by_design: dict = field(default_factory=dict)  # scan-list entry -> the scanner's by-design reason
    # Repo-relative config files the image did not read (an image that predates config scanning).
    # They are never "checked": the caller reports them as not checked.
    unread_config: set = field(default_factory=set)


def docker_args(tree_root: Path, img: str, name: str) -> List[str]:
    return ["run", "--rm", "--pull", "never", "--name", name,
            "--platform", "linux/amd64", "--network", "none",
            "-e", "MALLOC_ARENA_MAX=2",
            "-e", "QRYPTIVE_SCAN_INCLUDE_CONFIG=1",
            "-e", "QRYPTIVE_SCAN_REPORT_FILES=1",
            "-e", f"QRYPTIVE_SCAN_FILES_PATH=/work/{LIST_FILE}",
            "-e", "QRYPTIVE_SCAN_PASS",
            "-v", f"{tree_root}:/work:ro",
            img, "scan", "/work"]


_GATE_REASONS = {
    20: "the scanner has no sign-in pass; run /qryptive-scan once to sign in",
    21: "the scan pass is not valid; run /qryptive-scan once to sign in again",
    22: "the scan pass has expired; run /qryptive-scan once while online",
}


def run_scan(tree, img: str, pass_value: str, timeout: int = SCAN_TIMEOUT_SECONDS) -> ScanResult:
    """ONE container run over the before/after tree. Valid JSON results or CannotRun — an empty
    or broken result is never read as clean."""
    exe = _docker()
    (Path(tree.root) / LIST_FILE).write_text("\n".join(tree.scan_list) + "\n", encoding="utf-8")
    name = f"qryptive-guard-{uuid.uuid4().hex[:12]}"
    env = dict(os.environ)
    env["QRYPTIVE_SCAN_PASS"] = pass_value or ""
    try:
        proc = subprocess.Popen([exe, *docker_args(Path(tree.root), img, name)], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, env=env)
    except OSError:
        raise CannotRun("Docker could not be started")
    finished = False
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
        finished = True
    except subprocess.TimeoutExpired:
        raise CannotRun(f"the scan took longer than {timeout} seconds and was stopped")
    finally:
        if not finished:  # timeout, SIGTERM (SystemExit), Ctrl-C, anything: never leave it running
            _stop(exe, proc, name)
    r = subprocess.CompletedProcess(proc.args, proc.returncode, stdout, stderr)
    if r.returncode in _GATE_REASONS:
        raise CannotRun(_GATE_REASONS[r.returncode])
    if r.returncode == 125:
        raise _docker_failure(r.stderr, r.returncode)
    if r.returncode != 0:
        raise CannotRun(f"the scanner crashed (exit {r.returncode})")
    try:
        data = json.loads(r.stdout or "")
    except ValueError:
        data = None
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        raise CannotRun("the scanner crashed: it returned no readable results")
    try:
        files_scanned = int(data.get("files_scanned") or 0)
    except (TypeError, ValueError):
        files_scanned = 0
    code_entries = [e for e in tree.scan_list if baseline.is_code(e)]
    reported = data.get("scanned_files")
    by_design = _by_design(data.get("skipped_by_design"), set(tree.scan_list))
    config_entries = [e for e in tree.scan_list if not baseline.is_code(e)]
    unread_entries = []
    if isinstance(reported, list):
        # Exact per-file coverage: every code file listed must have been examined, or skipped by
        # the scanner's own design (e.g. a generated companion). Anything else — a timeout, an
        # error — is in neither list. A config file the image did not read is not a failure (an
        # image may predate config scanning) but it is never counted as checked.
        seen = {str(p) for p in reported}
        missing = set(code_entries) - seen - set(by_design)
        if missing:
            raise CannotRun(f"the scanner did not scan {len(missing)} of the {len(code_entries)} "
                            f"code file(s) it was given")
        unread_entries = [e for e in config_entries if e not in seen and e not in by_design]
    elif files_scanned < len(code_entries):
        # An older image without scanned_files: the count is the best available floor.
        raise CannotRun(f"the scanner checked {files_scanned} of the {len(code_entries)} code file(s) it was given")
    elif files_scanned < len(tree.scan_list):
        # Fewer files than given and every code file accounted for: it cannot say WHICH config
        # files it read, so none of them counts as checked.
        unread_entries = config_entries
    unread_config = set()
    for e in unread_entries:
        hit = tree.lookup(e)
        if hit is not None:
            unread_config.add(hit[2])
    incomplete = "results may be incomplete" in (r.stderr or "")
    findings = [f for f in data["findings"] if isinstance(f, dict)]
    return ScanResult(findings=findings, files_scanned=files_scanned, incomplete=incomplete,
                      unreadable=len(data["findings"]) - len(findings), by_design=by_design,
                      unread_config=unread_config)


_REASON_TOKEN = re.compile(r"^[a-z0-9_]{1,40}$")


def _by_design(raw, listed: set) -> dict:
    """{scan-list entry: reason} from the scanner's skipped_by_design. Only entries the guard
    actually listed count; a reason outside the ledger's token shape reads "unknown_reason"."""
    out = {}
    if not isinstance(raw, list):
        return out
    for item in raw:
        if not isinstance(item, dict) or str(item.get("path")) not in listed:
            continue
        reason = item.get("reason")
        out[str(item["path"])] = reason if isinstance(reason, str) and _REASON_TOKEN.match(reason) else "unknown_reason"
    return out


def _stop(exe: str, proc, name: str) -> None:
    for action in (lambda: proc.kill(), lambda: proc.wait(timeout=5),
                   lambda: subprocess.run([exe, "kill", name], capture_output=True, timeout=30)):
        try:
            action()
        except Exception:  # noqa: BLE001 - best effort while already failing
            pass


# --- Scan pass ------------------------------------------------------------------------------

def config_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return Path(base) / "qryptive"


def pass_path() -> Path:
    return config_dir() / "scan-pass"


def read_pass() -> Optional[str]:
    try:
        value = pass_path().read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError):
        return None
    return value or None


def pass_expiry(value: Optional[str]) -> Optional[int]:
    """The pass's `exp` claim (epoch seconds), read without verifying. None if unreadable."""
    if not value:
        return None
    parts = value.split(".")
    if len(parts) != 4 or parts[0] != "qsp1":
        return None
    seg = parts[2]
    try:
        payload = json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
        exp = payload.get("exp") if isinstance(payload, dict) else None
        return exp if isinstance(exp, int) and not isinstance(exp, bool) else None
    except (ValueError, TypeError):
        return None


def resolve_key() -> Tuple[Optional[str], Optional[str], Optional[int]]:
    """(key, source, file mtime) — the env var first, then the saved key file."""
    env = (os.environ.get("QRYPTIVE_SCANNER_KEY") or "").strip()
    if env:
        return env, "env", None
    p = config_dir() / "scanner-key"
    try:
        key = p.read_text(encoding="utf-8").strip()
        return (key or None), "file", p.stat().st_mtime_ns
    except (OSError, UnicodeDecodeError):
        return None, None, None


def _write_pass(value: str) -> None:
    d = config_dir()
    old = os.umask(0o077)
    try:
        d.mkdir(parents=True, exist_ok=True, mode=0o700)
    finally:
        os.umask(old)
    fd, tmp = tempfile.mkstemp(prefix=".scan-pass-", dir=str(d))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(value)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, d / "scan-pass")
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect: it would carry the scanner key to another address."""

    def redirect_request(self, *args, **kwargs):
        return None


def _checkin_url() -> Tuple[Optional[str], bool]:
    base = (os.environ.get("QRYPTIVE_PLATFORM_URL") or DEFAULT_PLATFORM_URL).rstrip("/")
    u = urllib.parse.urlparse(base)
    loopback = u.hostname in ("localhost", "127.0.0.1", "::1")
    if u.scheme == "https" or (u.scheme == "http" and loopback):
        return base + "/api/scanner/checkin", loopback
    return None, loopback


def _checkin(key: str, scanner_version: Optional[str]) -> Tuple[str, Optional[str]]:
    """One check-in. Returns (outcome, new pass): outcome in renewed / rejected / failed / insecure."""
    url, loopback = _checkin_url()
    if url is None:
        return "insecure", None
    body = {"client": "guard"}
    if scanner_version:
        body["scanner_version"] = scanner_version
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"X-Scanner-Key": key, "Content-Type": "application/json"})
    handlers = [_NoRedirect()]
    if loopback:
        handlers.append(urllib.request.ProxyHandler({}))
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(req, timeout=CHECKIN_TIMEOUT_SECONDS) as resp:
            raw = resp.read(65536)
    except urllib.error.HTTPError as e:
        return ("rejected" if e.code == 401 else "failed"), None
    except Exception:  # noqa: BLE001 - timeouts, refused connections, TLS errors: all "failed"
        return "failed", None
    # The platform is trusted over https (redirects are refused above), so the returned pass is
    # taken as issued; its expiry is still checked before it replaces the saved one.
    try:
        data = json.loads(raw.decode("utf-8"))
        new = data.get("pass") if isinstance(data, dict) else None
    except (ValueError, UnicodeDecodeError):
        new = None
    if not isinstance(new, str) or pass_expiry(new) is None:
        return "failed", None
    return "renewed", new


def _renewal_due(pass_value: Optional[str], now: float) -> bool:
    exp = pass_expiry(pass_value)
    return exp is None or exp - now < RENEW_WHEN_UNDER_SECONDS


def _usable(pass_value: Optional[str], now: float) -> bool:
    if not pass_value:
        return False
    exp = pass_expiry(pass_value)
    # An unreadable expiry is the scanner's call to make, not ours.
    return exp is None or exp >= now - PASS_SKEW_SECONDS


def _days_left(pass_value: Optional[str], now: float) -> Optional[int]:
    exp = pass_expiry(pass_value)
    return None if exp is None else max(0, int((exp - now) // 86400))


def _claim_attempt(now: float, key_source: str, key_mtime: Optional[int]) -> Optional[str]:
    """Under the machine-wide renewal lock: decide whether to call, and record the attempt BEFORE
    calling, so a crash or a concurrent check can never cause a second call the same day.
    Returns None when the call should go ahead, else why not."""
    try:
        with state.renewal_store().locked() as st:
            rej = st.get("rejected_key")
            if isinstance(rej, dict) and rej.get("source") == key_source and rej.get("mtime_ns") == key_mtime \
                    and key_source == "file":
                return "rejected"
            last = float(st.get("last_renewal_attempt") or 0)
            if now - last < RENEW_AT_MOST_EVERY_SECONDS:
                return "recent"
            st["last_renewal_attempt"] = now
            return None
    except (OSError, TimeoutError, ValueError):
        return "locked"


def _note_rejected(key_source: str, key_mtime: Optional[int]) -> None:
    try:
        with state.renewal_store().locked() as st:
            st["rejected_key"] = {"source": key_source, "mtime_ns": key_mtime}
    except (OSError, TimeoutError):
        pass


def ensure_pass(pol, scanner_version: Optional[str], now: Optional[float] = None) -> Tuple[str, List[str]]:
    """The pass to hand the container, renewing it first if due. Returns (pass, notes). Raises
    CannotRun when there is no usable pass."""
    now = time.time() if now is None else now
    notes: List[str] = []
    current = read_pass()

    if _renewal_due(current, now):
        if not pol.checkin:
            if current and _usable(current, now):
                days = _days_left(current, now)
                if days is not None:
                    notes.append(f"Qryptive guard: scan pass expires in {days} day(s); run /qryptive-scan once.")
        else:
            key, source, mtime = resolve_key()
            if not key:
                if current and _usable(current, now):
                    notes.append("Qryptive guard: scan pass expires soon and no scanner key is saved; "
                                 "run /qryptive-scan once.")
            else:
                why_not = _claim_attempt(now, source, mtime)
                if why_not is None:
                    outcome, new = _checkin(key, scanner_version)
                    if outcome == "renewed":
                        cur_exp, new_exp = pass_expiry(current), pass_expiry(new)
                        if new_exp is None or new_exp <= now or (cur_exp is not None and new_exp <= cur_exp):
                            notes.append("Qryptive guard: the renewed scan pass was not newer than the "
                                         "saved one; kept the saved one.")
                        else:
                            try:
                                _write_pass(new)
                                current = read_pass()  # re-read: another writer may have landed after us
                            except OSError:
                                notes.append("Qryptive guard: could not save the renewed scan pass; "
                                             "using the saved one.")
                    elif outcome == "rejected":
                        _note_rejected(source, mtime)
                        notes.append("Qryptive guard: the scanner key was rejected; run /qryptive-scan "
                                     "once to sign in again.")
                    elif outcome == "insecure":
                        notes.append("Qryptive guard: QRYPTIVE_PLATFORM_URL is not https, so the scan "
                                     "pass was not renewed.")
                    elif _usable(current, now):
                        notes.append("Qryptive guard: could not renew the scan pass; using the saved one.")
                elif why_not == "rejected":
                    notes.append("Qryptive guard: the scanner key was rejected; run /qryptive-scan once "
                                 "to sign in again.")

    if not current:
        raise CannotRun(SIGNIN)
    if not _usable(current, now):
        raise CannotRun(EXPIRED)
    return current, notes
