#!/usr/bin/env python3
"""Qryptive agent edit guard — a rule-based local check on the cryptography a coding agent writes.

  qryptive_guard.py record  [--file PATH] [--session ID] [--repo DIR] [--format F]  (after each edit)
  qryptive_guard.py check   [--session ID] [--repo DIR] [--staged] [--format F]   (end of turn / commit)
  qryptive_guard.py status  [--session ID] [--repo DIR]
  qryptive_guard.py install   <claude-code|cursor|git> [--repo DIR]
  qryptive_guard.py uninstall <claude-code|cursor|git> [--repo DIR]

Hook payloads (JSON on stdin) supply the edited path, session id and working directory when the
flags are absent. Exit codes: 0 clean (or nothing to demand), 2 new problems found (feedback),
3 the check could not run. With --format claude-code or cursor, `check` answers in that agent's
hook protocol instead and always exits 0 (see _deliver). Nothing scanned, found or counted ever leaves the machine; the only
network call is the scan-pass renewal (see guard_core/runner.py).

This file is glue: every decision lives in guard_core/.
"""
import argparse
import json
import os
import select
import signal
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from guard_core import baseline, classify, policy, render, state  # noqa: E402

EXIT_CLEAN, EXIT_PROBLEMS, EXIT_CANNOT_RUN = 0, 2, 3
COMMIT_SESSION = "commit"
# By-design skips that depend only on content; any other reason on a changed file fails closed.
BY_DESIGN_NOTE_ONLY = frozenset({"empty_or_short"})


# --- Input --------------------------------------------------------------------------------

PAYLOAD_DEADLINE_SECONDS = 1.0
PAYLOAD_TOO_LARGE = "_qryptive_payload_too_large"
TOO_LARGE_NOTE = ("Qryptive guard: the hook payload was over 4 MB, so this edit was not recorded from it; "
                  "the end-of-turn check still finds changed files through git.")
_PAYLOAD_MAX_BYTES = 4 * 1024 * 1024


def _parse_payload(buf: bytes):
    try:
        data = json.loads(buf.decode("utf-8")) if buf.strip() else None
    except (ValueError, UnicodeDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _read_payload() -> dict:
    """The hook's JSON payload from stdin. Returns at once on a TTY or EOF, as soon as a complete
    JSON object has arrived, and in any case within about one second: an open stdin that never
    sends anything can never hang a hook. Never raises."""
    try:
        stdin = sys.stdin
        if stdin is None or stdin.isatty():
            return {}
        fd = stdin.fileno()
    except Exception:  # noqa: BLE001 - no usable stdin (e.g. under a test harness)
        return {}
    buf = b""
    end = time.monotonic() + PAYLOAD_DEADLINE_SECONDS
    try:
        while len(buf) < _PAYLOAD_MAX_BYTES:
            remaining = end - time.monotonic()
            if remaining <= 0:
                break
            ready, _, _ = select.select([fd], [], [], remaining)
            if not ready:
                break
            chunk = os.read(fd, 65536)
            if not chunk:
                break  # EOF
            buf += chunk
            parsed = _parse_payload(buf)
            if parsed is not None:
                return parsed
    except Exception:  # noqa: BLE001 - a bad payload must never fail a hook
        pass
    parsed = _parse_payload(buf)
    if parsed is None and len(buf) >= _PAYLOAD_MAX_BYTES:
        return {PAYLOAD_TOO_LARGE: True}  # never parsed silently as "nothing"
    return parsed or {}


def _payload_cwd(payload: dict):
    cwd = payload.get("cwd")
    if isinstance(cwd, str) and cwd:
        return cwd
    roots = payload.get("workspace_roots")
    if isinstance(roots, list) and roots and isinstance(roots[0], str):
        return roots[0]
    return None


def _payload_session(payload: dict):
    for k in ("session_id", "conversation_id"):
        v = payload.get(k)
        if isinstance(v, str) and v:
            return v
    return None


def _payload_file(payload: dict):
    ti = payload.get("tool_input")
    if isinstance(ti, dict):
        for k in ("file_path", "notebook_path", "path"):
            if isinstance(ti.get(k), str) and ti[k]:
                return ti[k]
    v = payload.get("file_path")
    return v if isinstance(v, str) and v else None


def _resolve_root(start):
    """(repo root, is_git). The git root above `start`, else `start` itself."""
    start = os.path.realpath(start or os.getcwd())
    root = baseline.find_git_root(start)
    return (str(root), True) if root else (start, False)


def _emit(text: str, to_stderr: bool) -> None:
    if text:
        print(text, file=sys.stderr if to_stderr else sys.stdout)


# --- Agent hook protocols -----------------------------------------------------------------
# The ONLY place an agent's hook protocol lives (plan D1): the adapters are config that name a
# format, nothing more. Exit 3 ("could not run") never blocks an agent (D6).

FORMATS = ("plain", "claude-code", "cursor")


def _deliver(fmt: str, code: int, message: str, visible: bool = False) -> int:
    """Print a check outcome in the agent's protocol and return the process exit code.

    plain: the message on stdout (problems on stderr) and the guard's own exit code.
    claude-code: problems -> one `{"decision":"block","reason":...}` line on stdout, exit 0 (the
      agent continues and fixes them; measured in Task 0). Anything worth a person's attention
      (could not run, warnings) -> `{"systemMessage": ...}`, which Claude Code shows the person
      without blocking. The message always goes to stderr too; a clean turn prints nothing on stdout.
    cursor: problems -> `{"followup_message": ...}` on stdout, exit 0; anything else -> `{}`
      on stdout and the message on stderr (Cursor documents no non-blocking user message for stop).
    """
    if fmt == "plain":
        _emit(message, code == EXIT_PROBLEMS)
        return code
    if code == EXIT_PROBLEMS:
        key = {"claude-code": None, "cursor": "followup_message"}[fmt]
        out = {"decision": "block", "reason": message} if key is None else {key: message}
        print(json.dumps(out))
        return EXIT_CLEAN
    if fmt == "claude-code":
        if visible and message:
            print(json.dumps({"systemMessage": message}))
    else:
        print("{}")
    _emit(message, True)
    return EXIT_CLEAN


# --- record -------------------------------------------------------------------------------

def cmd_record(args) -> int:
    try:
        payload = {} if (args.file and args.session and args.repo) else _read_payload()
        if payload.get(PAYLOAD_TOO_LARGE):
            if not args.file:
                print(TOO_LARGE_NOTE, file=sys.stderr if args.format == "cursor" else sys.stdout)
                return EXIT_CLEAN
            payload = {}  # fall back to --file (and --session / --repo when given)
        start = args.repo or _payload_cwd(payload) or os.getcwd()
        root, is_git = _resolve_root(start)
        store = state.SessionStore(root, args.session or _payload_session(payload))
        pin = (lambda: baseline.pin_value(root)) if is_git else (lambda: None)
        if policy.load(root).is_off:
            # Still pin: if the guard is switched back on later in the session, the comparison
            # must start from before this edit.
            state.try_pin(store, pin)
            return EXIT_CLEAN
        file_arg = args.file or _payload_file(payload)
        if not file_arg:
            return EXIT_CLEAN
        abs_path = file_arg if os.path.isabs(file_arg) else os.path.join(start, file_arg)
        rel = os.path.relpath(os.path.realpath(abs_path), root)
        rel = baseline.safe_rel(rel)
        if rel is None:
            return EXIT_CLEAN  # outside the repository: ignored
        line = state.try_record(store, rel, pin=pin)
    except Exception as exc:  # noqa: BLE001 - an edit must never fail because of the guard
        line = f"Qryptive guard: could not record this edit ({type(exc).__name__}); the end-of-turn check still runs."
    if line:
        # Cursor reads a hook's stdout as JSON; its one-line notes go to stderr instead.
        print(line, file=sys.stderr if args.format == "cursor" else sys.stdout)
    return EXIT_CLEAN


# --- check --------------------------------------------------------------------------------

def _scannable(pol, dropped=None):
    """Keep-predicate for candidate paths. Minified/declaration files are dropped (as the scanner
    drops them) and collected in `dropped` so the message can say how many were not checked."""
    def keep(rel):
        if pol.is_ignored(rel):
            return False
        if baseline.is_minified_or_declaration(rel):
            if dropped is not None:
                dropped.add(rel)
            return False
        return baseline.is_scannable(rel)
    return keep


def _minified_note(dropped, notes) -> int:
    if dropped:
        notes.append(f"{len(dropped)} minified/declaration file(s) not checked")
    return len(dropped)


def _summary(message: str) -> str:
    return message.splitlines()[0] if message else ""


def _save_result(store, result: dict) -> None:
    try:
        with store.locked() as st:
            state.record_result(st, result)
    except Exception:  # noqa: BLE001 - reporting must not hide the real outcome
        pass


def _partition(comparison, pol):
    from guard_core.runner import CannotRun
    if comparison.unmatched:
        raise CannotRun(f"the scanner reported {comparison.unmatched} finding(s) for files it was not "
                        f"given, so its results cannot be trusted")
    new = classify.apply_allow(comparison.new, pol)
    feedback = [f for f in new if classify.classify(f) == classify.FEEDBACK]
    warn = [f for f in new if classify.classify(f) == classify.WARN]
    existing = sum(1 for f in classify.apply_allow(comparison.unchanged, pol)
                   if classify.classify(f) == classify.FEEDBACK)
    return feedback, warn, existing


def _scan_tree(tree, pol, notes):
    """Docker preflight, pass, ONE container run, comparison. Returns (feedback, warn, existing,
    unread): `unread` is how many files the image did not read (never counted as checked)."""
    from guard_core import runner
    if not tree.scan_list:
        return [], [], 0, 0
    img = runner.image()
    version = runner.preflight(img)
    pass_value, pass_notes = runner.ensure_pass(pol, version)
    notes += pass_notes
    result = runner.run_scan(tree, img, pass_value)
    if result.unreadable:
        notes.append(f"{result.unreadable} entr(ies) in the scanner output were not findings and were ignored")
    by_reason, name_keyed = {}, set()
    for entry, reason in result.by_design.items():
        hit = tree.lookup(entry)
        if hit is None:
            continue
        side, _, rel = hit
        by_reason.setdefault(reason, set()).add(rel)
        if reason not in BY_DESIGN_NOTE_ONLY and side == baseline.AFTER and rel in tree.changed:
            name_keyed.add(rel)
    if name_keyed:
        # A skip keyed on something other than content (a reserved name, say) on a file changed this
        # turn is a way round the check: fail closed. The tree's neutral names should prevent it.
        raise runner.CannotRun(f"the scanner skipped {len(name_keyed)} changed file(s) without reading them "
                               f"({', '.join(sorted(r for r, p in by_reason.items() if p & name_keyed))})")
    for reason, paths in sorted(by_reason.items()):
        notes.append(f"not checked: {reason} ({len(paths)} file(s))")
    if result.unread_config:
        notes.append(f"{len(result.unread_config)} config file(s) not checked: this scanner image does not "
                     f"read config files (run /qryptive-scan to update it)")
    feedback, warn, existing = _partition(baseline.compare(tree, result.findings), pol)
    if result.incomplete:
        if not feedback:
            raise runner.CannotRun("the scan finished only partly, so a clean result cannot be trusted")
        notes.append("the scan finished only partly; more problems may exist")
    return feedback, warn, existing, len(result.unread_config)


def _policy_change_note(root, is_git, start):
    """A warning when the policy file differs from where the comparison starts. `start` is
    ("pinned", commit-or-None) for a session — None meaning the empty tree — or ("head", None)."""
    if not is_git:
        return None
    try:
        kind, commit = start
        if kind != "pinned" or (commit is not None and not baseline.valid_oid(commit)):
            commit = baseline.head_commit(root)
            if not commit:
                return None
        old = baseline.blob_at(root, commit, policy.POLICY_FILENAME) if commit else None
        return policy.describe_change(old, policy.read_bytes(root))
    except Exception:  # noqa: BLE001 - a warning helper must not stop the check
        return None


def _pinned_baseline(store, root, is_git, notes):
    """(queued paths, baseline commit) after making sure the session has a valid pin."""
    pin = (lambda: baseline.pin_value(root)) if is_git else (lambda: None)
    with store.locked() as st:
        commit = st.get("baseline_commit")
        if st.get("baseline_pinned") and commit is not None and not baseline.valid_oid(commit):
            notes.append("the session's starting commit record was unreadable; re-pinned to HEAD")
            st["baseline_pinned"] = False
        state.ensure_pinned(st, pin)
        return dict(st["queue"]), st["baseline_commit"]


def _cannot_run_reason(exc) -> str:
    """One wording path for every 'could not run' cause, agent and commit mode alike."""
    from guard_core.runner import CannotRun
    if isinstance(exc, CannotRun):
        return exc.reason
    if isinstance(exc, baseline.GitError):
        return f"git could not read the repository: {exc}"
    return f"git could not read the repository ({type(exc).__name__})"


def _check_agent(args, payload, root, is_git, pol, notes):
    from guard_core.runner import CannotRun
    store = state.SessionStore(root, args.session or _payload_session(payload))
    started = time.time()
    try:
        queued, base = _pinned_baseline(store, root, is_git, notes)
        candidates = set(queued)
        if is_git:
            candidates |= set(baseline.changed_since(root, base))
        dropped = set()
        keep = _scannable(pol, dropped)
        # A deleted minified file is not "not checked": count only those still present.
        files = sorted(p for p in candidates if baseline.safe_rel(p) and keep(p))
        dropped = {p for p in dropped if baseline.safe_rel(p) and os.path.isfile(os.path.join(root, p))}
        # Changed files still present that the guard does not read (type or ignore_paths), so a
        # "not checked" total matches what the person changed.
        other_types = len({p for p in candidates if baseline.safe_rel(p) and p not in files and p not in dropped
                           and os.path.isfile(os.path.join(root, p))})
        extra = _minified_note(dropped, notes)

        feedback, warn, existing, checked, skipped = [], [], 0, 0, extra
        if files:
            with baseline.build_agent_tree(root, files, base, is_git) as tree:
                notes += tree.notes
                feedback, warn, existing, unread = _scan_tree(tree, pol, notes)
                checked, skipped = len(tree.paths) - unread, tree.skipped_total + extra + unread
        if pol.mode == "warn":
            warn, feedback = feedback + warn, []

        with store.locked() as st:  # round counts, shown-warnings and the queue land in ONE write
            capped = state.decide_session_cap(st, [])[1]
            if capped:
                emit, demoted = [], []
                capped_shown = state.decide_warnings(st, feedback, tag="capped")
            else:
                emit, demoted = state.decide_rounds(st, feedback)
                emit = state.decide_session_cap(st, emit)[0]
                capped_shown = []
            open_warnings = len(demoted) + len(warn) + (len(feedback) if capped else 0)
            demoted = state.decide_warnings(st, demoted, tag="demoted")
            warn_shown = state.decide_warnings(st, warn)
            with_new = {f.get("file") for f in feedback + warn}
            state.complete_check(st, covered=queued, with_new=with_new, started_at=started)
            visible = True  # worth a person's attention even when nothing is demanded of the agent
            if capped_shown:
                message = render.session_capped(feedback, state.MAX_SESSION_BLOCKS, notes=notes)
            elif emit or demoted or warn_shown:
                message = render.problems(emit=emit, demoted=demoted, warn=warn_shown, existing=existing,
                                          notes=notes)
            elif open_warnings:
                message, visible = render.quiet(open_warnings, checked, notes=notes), False
            elif checked == 0 and skipped:
                message = render.not_checked(skipped, notes=notes, other_types=other_types)
            elif checked == 0:  # a count of 0 is never a clean verdict
                message = render.nothing_checked(notes=notes) if candidates else render.no_changes(notes=notes)
                visible = False
            else:
                message, visible = render.clean(checked, notes=notes), False
            code = EXIT_PROBLEMS if emit else EXIT_CLEAN
            state.record_result(st, {"ran": True, "exit": code, "files_checked": checked,
                                     "summary": _summary(message), "mode": "agent"})
    except (CannotRun, baseline.GitError, subprocess.SubprocessError, OSError) as exc:
        message = render.cannot_run(_cannot_run_reason(exc), notes=notes)
        _save_result(store, {"ran": False, "exit": EXIT_CANNOT_RUN, "summary": _summary(message), "mode": "agent"})
        code, visible = EXIT_CANNOT_RUN, True
    return _deliver(args.format, code, message, visible)


def _check_staged(root, is_git, pol, notes):
    from guard_core.runner import CannotRun
    store = state.SessionStore(root, COMMIT_SESSION)
    try:
        if not is_git:
            raise CannotRun("this is not a git repository")
        feedback, warn, existing, checked, skipped, changes_seen, deletions, other_types = [], [], 0, 0, 0, 0, 0, 0
        dropped = set()
        with baseline.build_staged_tree(root, keep=_scannable(pol, dropped)) as tree:
            extra = _minified_note(dropped, notes)
            notes += tree.notes
            feedback, warn, existing, unread = _scan_tree(tree, pol, notes)
            checked, skipped = len(tree.paths) - unread, tree.skipped_total + extra + unread
            changes_seen, deletions = tree.changes_seen, tree.deletions
            other_types = max(0, tree.not_kept - len(dropped))
        if pol.mode == "warn":
            warn, feedback = feedback + warn, []
        if feedback or warn:
            message = render.problems(emit=feedback, demoted=[], warn=warn, existing=existing,
                                      notes=notes, staged=True)
        elif checked == 0 and skipped:
            message = render.not_checked(skipped, staged=True, notes=notes, other_types=other_types)
        elif checked == 0:  # a count of 0 is never a clean verdict
            if changes_seen and changes_seen == deletions:
                message = render.only_deletions(notes=notes)
            elif changes_seen:
                message = render.nothing_checked(staged=True, notes=notes)
            else:
                message = render.no_changes(staged=True, notes=notes)
        else:
            message = render.clean(checked, staged=True, notes=notes)
        code = EXIT_PROBLEMS if feedback else EXIT_CLEAN
        _save_result(store, {"ran": True, "exit": code, "files_checked": checked,
                             "summary": _summary(message), "mode": "staged"})
    except (CannotRun, baseline.GitError, subprocess.SubprocessError, OSError) as exc:
        # Git failures, git timeouts and blob read errors fail open exactly like CannotRun.
        message = render.cannot_run(_cannot_run_reason(exc), staged=True, strict=pol.strict_commit, notes=notes)
        _save_result(store, {"ran": False, "exit": EXIT_CANNOT_RUN, "summary": _summary(message), "mode": "staged"})
        # A commit is blocked by an infrastructure failure only under strict_commit (D6).
        code = EXIT_CANNOT_RUN if pol.strict_commit else EXIT_CLEAN
    _emit(message, code == EXIT_PROBLEMS)
    return code


def cmd_check(args) -> int:
    try:
        payload = {} if (args.session and args.repo) or args.staged else _read_payload()
        too_large = bool(payload.pop(PAYLOAD_TOO_LARGE, False))
        root, is_git = _resolve_root(args.repo or _payload_cwd(payload) or os.getcwd())
        pol = policy.load(root)
        notes = list(pol.notices)
        if too_large:
            notes.append("the hook payload was over 4 MB and was ignored")
        start = ("head", None)
        if not args.staged:
            st = state.SessionStore(root, args.session or _payload_session(payload)).read()
            if st.get("baseline_pinned"):
                start = ("pinned", st.get("baseline_commit"))
        change = _policy_change_note(root, is_git, start)
        if change:
            notes.insert(0, change)
        if pol.is_off:
            return _deliver("plain" if args.staged else args.format, EXIT_CLEAN, render.off(notes=notes))
        try:
            state.prune()
        except Exception:  # noqa: BLE001 - housekeeping only
            pass
        if args.staged:
            return _check_staged(root, is_git, pol, notes)
        return _check_agent(args, payload, root, is_git, pol, notes)
    except Exception as exc:  # noqa: BLE001 - never report "clean" when the guard itself broke
        strict = False
        if args.staged:
            try:  # an unreadable policy counts as strict_commit off
                strict = policy.load(_resolve_root(args.repo or os.getcwd())[0]).strict_commit
            except Exception:  # noqa: BLE001
                strict = False
        message = render.cannot_run(f"the guard hit an internal error ({type(exc).__name__})",
                                    staged=args.staged, strict=strict)
        if not args.staged:
            return _deliver(args.format, EXIT_CANNOT_RUN, message, visible=True)
        print(message)
        # Commit mode fails open unless strict_commit is on, like every other "could not run".
        return EXIT_CANNOT_RUN if strict else EXIT_CLEAN


# --- status -------------------------------------------------------------------------------

def cmd_status(args) -> int:
    root, _ = _resolve_root(args.repo or os.getcwd())
    pol = policy.load(root)
    if pol.is_off:
        print(render.off())
    files = state.session_files(root)
    if args.session:
        want = state.SessionStore(root, args.session).path
        files = [p for p in files if p == want]
    for p in files:
        store = state.SessionStore(root, p.stem)
        data = store.read()
        last = data.get("last_result")
        if not isinstance(last, dict):
            continue
        when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(last.get("when") or 0)))
        ran = "ran" if last.get("ran") else "did NOT run"
        print(f"Qryptive guard: last check ({data.get('session')}, {when}) {ran}: {last.get('summary', '')}")
        print(f"  {len(data.get('queue') or {})} file(s) queued for the next check.")
        return EXIT_CLEAN
    print("Qryptive guard has not run a check in this repository yet.")
    return EXIT_CLEAN


# --- install / uninstall ------------------------------------------------------------------

def cmd_install(args) -> int:
    """Exit 0 done (or nothing to do), 1 refused with nothing changed."""
    from guard_core import install
    root, _ = _resolve_root(args.repo or os.getcwd())
    done, message = install.run(args.cmd, args.agent, Path(root))
    print(message)
    return 0 if done else 1


# --- entry --------------------------------------------------------------------------------

def _parser():
    p = argparse.ArgumentParser(prog="qryptive_guard.py", description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("record", "check", "status"):
        sp = sub.add_parser(name)
        sp.add_argument("--repo", help="repository directory (default: the hook's cwd, else this directory)")
        sp.add_argument("--session", help="session id (default: from the hook payload, else 'default')")
        if name == "record":
            sp.add_argument("--file", help="the edited file (default: from the hook payload)")
        if name in ("record", "check"):
            sp.add_argument("--format", choices=FORMATS, default="plain",
                            help="hook protocol to answer in (default plain; --staged always answers plain)")
        if name == "check":
            sp.add_argument("--staged", action="store_true",
                            help="check what is staged for commit (index against HEAD)")
    for name in ("install", "uninstall"):
        sp = sub.add_parser(name, help=f"{name} the guard's hooks for one agent (never touches other hooks)")
        sp.add_argument("agent", choices=("claude-code", "cursor", "git"))
        sp.add_argument("--repo", help="repository directory (default: this directory)")
    return p


def _on_sigterm(signum, frame):
    # Turn SIGTERM into SystemExit so `finally` blocks run: the temp tree is removed and a
    # running scan container is killed.
    raise SystemExit(EXIT_CANNOT_RUN)


def main(argv=None) -> int:
    try:
        previous = signal.signal(signal.SIGTERM, _on_sigterm)
    except ValueError:
        previous = None  # not the main thread (embedded use); nothing to install
    agent_format = _agent_format(sys.argv[1:] if argv is None else argv)
    try:
        code = _dispatch(argv)
    except SystemExit as exc:  # SIGTERM, or anything else that raised SystemExit
        if not agent_format:
            raise
        code = exc.code if isinstance(exc.code, int) else EXIT_CANNOT_RUN
    finally:
        if previous is not None:
            signal.signal(signal.SIGTERM, previous)
    # An agent's hook protocol is spoken on stdout; the exit code never blocks (Claude Code reads
    # exit 2 from Stop as "block"). The adapters' wrapper maps any exit to 0 as well.
    return EXIT_CLEAN if agent_format else code


def _agent_format(argv) -> bool:
    """True when the command line asks for an agent's hook protocol (even if it does not parse)."""
    argv = list(argv or [])
    for i, a in enumerate(argv):
        if a == "--format" and i + 1 < len(argv) and argv[i + 1] in FORMATS[1:]:
            return True
        if a.startswith("--format=") and a.split("=", 1)[1] in FORMATS[1:]:
            return True
    return False


def _dispatch(argv) -> int:
    try:
        args = _parser().parse_args(argv)
    except SystemExit as e:
        # --help exits 0; a usage error must not read as exit 2 ("new problems found").
        return EXIT_CLEAN if not e.code else EXIT_CANNOT_RUN
    if args.cmd == "record":
        return cmd_record(args)
    if args.cmd == "check":
        return cmd_check(args)
    if args.cmd in ("install", "uninstall"):
        return cmd_install(args)
    return cmd_status(args)


if __name__ == "__main__":
    sys.exit(main())
