"""What the agent (or the person) sees (plan D9).

At most 10 lines, most severe first. Each item names the file, line, algorithm and kind, and
ends with the finding's own migration recommendation when it carries one — the guard never
invents a recommendation. Source text (`context`, snippets, scanner messages) is never echoed.
"Could not run" wording never uses security wording, and vice versa (D6).
"""
import re
from typing import Iterable, List, Optional

MAX_LINES = 10
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]+")
_ALGORITHM_UNSAFE = re.compile(r"[^A-Za-z0-9._/+-]")
FOOTER = 'Fix these, or add an "allow" entry with a reason to .qryptive-guard.json.'
_NOTE_PREFIX = "Qryptive guard: "


def _clean(value, limit: int) -> str:
    """One printable line: control characters flattened, undecodable characters replaced (so
    printing can never fail), whitespace collapsed, length capped."""
    s = str(value if value is not None else "")
    s = s.encode("utf-8", "replace").decode("utf-8", "replace")
    s = _CONTROL.sub(" ", s).strip()
    s = re.sub(r"\s+", " ", s)
    return s if len(s) <= limit else s[: limit - 1] + "…"


def _token(value, limit: int = 40) -> str:
    """Algorithm / kind text: only [A-Za-z0-9._/+-], at most `limit` characters."""
    return _ALGORITHM_UNSAFE.sub("", str(value if value is not None else ""))[:limit]


def _recommendation(f: dict) -> Optional[str]:
    rec = f.get("migration_recommendation")
    if isinstance(rec, dict):
        target = rec.get("target")
        if isinstance(target, str) and target.strip():
            return _clean(target, 60)
    return None


def _severity_rank(f: dict) -> int:
    return _SEVERITY_ORDER.get(str(f.get("severity") or "").lower(), 5)


def _item(f: dict, suffix: str = "") -> str:
    path = _clean(f.get("file") or f.get("file_path") or "?", 80)
    line = f.get("line")
    where = f"{path}:{line}" if isinstance(line, int) and not isinstance(line, bool) else path
    algorithm = _token(f.get("algorithm")) or "unknown algorithm"
    kind = _token(f.get("finding_type"), 20)
    text = f"  {where}  {algorithm}" + (f" ({kind})" if kind else "")
    rec = _recommendation(f)
    if rec:
        text += f"  -> {rec}"
    return text + suffix


def _sorted(items: Iterable[dict]) -> List[dict]:
    return sorted(items, key=lambda f: (_severity_rank(f), str(f.get("file") or ""),
                                        f.get("line") if isinstance(f.get("line"), int) else 0))


def _note(n) -> str:
    text = str(n if n is not None else "")
    if text.startswith(_NOTE_PREFIX):
        text = text[len(_NOTE_PREFIX):]
    return "  note: " + _clean(text, 160)


def _assemble(header: str, notes: Iterable[str], items: List[str], footer: List[str]) -> str:
    """Header, notes, items, footer — never more than MAX_LINES lines. Notes and items are both
    trimmed with an "...and N more" line; at least one item line survives when there are items."""
    note_lines = [_note(n) for n in notes if str(n or "").strip()]
    budget = MAX_LINES - 1 - len(footer)
    max_notes = budget - (1 if items else 0)
    if len(note_lines) > max_notes:
        keep = max(0, max_notes - 1)
        note_lines = note_lines[:keep] + [f"  note: ...and {len(note_lines) - keep} more note(s)"]
    room = budget - len(note_lines)
    if len(items) > room:
        shown = items[: max(0, room - 1)]
        shown.append(f"  ...and {len(items) - len(shown)} more")
        items = shown
    return "\n".join([_clean(header, 200)] + note_lines + items + footer)


def problems(emit, demoted, warn, existing: int, notes: Iterable[str] = (), staged: bool = False) -> str:
    """The findings message. `emit` = fed back to the agent; `demoted` = fed back 3 times
    already; `warn` = shown, not demanded."""
    emit, demoted, warn = _sorted(emit), _sorted(demoted), _sorted(warn)
    scope = "this commit adds" if staged else "this turn added"
    if emit:
        header = (f"Qryptive: {scope} quantum-vulnerable cryptography "
                  f"({len(emit)} new, {existing} already there before).")
    else:
        n = len(demoted) + len(warn)
        header = f"Qryptive (warning only): {scope} {n} cryptography item(s) to review."
    items = [_item(f) for f in emit]
    items += [_item(f, "  (warning: the agent did not resolve this after 3 attempts)") for f in demoted]
    items += [_item(f, "  (warning only)") for f in warn]
    return _assemble(header, notes, items, [FOOTER] if emit else [])


def session_capped(open_items, cap: int, notes: Iterable[str] = ()) -> str:
    """The per-session bound was reached: list what is still open, demand nothing."""
    items = _sorted(open_items)
    header = (f"Qryptive (warning only): the guard stopped asking after {cap} rounds; "
              f"{len(items)} problem(s) still open.")
    return _assemble(header, notes, [_item(f) for f in items], [])


def cannot_run(reason: str, staged: bool = False, strict: bool = False, notes: Iterable[str] = ()) -> str:
    what = "this commit was" if staged else "your edits were"
    text = f"Qryptive guard: check did NOT run: {_clean(reason, 120)}. {what.capitalize()} not checked."
    # Its own line, inside the budget, so the header cap can never cut it off.
    footer = ["The commit is blocked because strict_commit is on in .qryptive-guard.json."] if staged and strict else []
    return _assemble(text, notes, [], footer)


def not_checked(skipped: int, staged: bool = False, notes: Iterable[str] = (), other_types: int = 0) -> str:
    """Nothing was scanned because every candidate file was skipped: never worded as clean.
    `other_types` counts changed files of a type the guard does not read, so the total matches
    what the person changed."""
    scope = "this commit" if staged else "this turn"
    notes = list(notes)
    if other_types:
        notes.append(f"{other_types} changed file(s) are not a type the guard reads")
    return _assemble(f"Qryptive guard: not checked: all {skipped + other_types} changed file(s) in {scope} were "
                     f"skipped (see notes), so nothing was scanned.", notes, [], [])


def nothing_checked(staged: bool = False, notes: Iterable[str] = ()) -> str:
    """Files changed, but none is a type the guard reads: never worded as clean."""
    where = "in this commit" if staged else "changed this turn"
    return _assemble(f"Qryptive guard: nothing checked: no file {where} is a type the guard reads.",
                     notes, [], [])


def only_deletions(notes: Iterable[str] = ()) -> str:
    """A commit that only deletes files: nothing to check, and not a clean verdict."""
    return _assemble("Qryptive guard: no files added or changed in this commit (only deletions), so there "
                     "was nothing to check.", notes, [], [])


def no_changes(staged: bool = False, notes: Iterable[str] = ()) -> str:
    """Nothing changed at all: never worded as clean either."""
    where = "in this commit" if staged else "this turn"
    return _assemble(f"Qryptive guard: no changed files {where}, so there was nothing to check.", notes, [], [])


def clean(files_checked: int, staged: bool = False, notes: Iterable[str] = ()) -> str:
    scope = "this commit" if staged else "this turn"
    return _assemble(f"Qryptive guard: no new quantum-vulnerable cryptography in {scope} "
                     f"({files_checked} file(s) checked).", notes, [], [])


def quiet(open_items: int, files_checked: int, notes: Iterable[str] = ()) -> str:
    """Nothing to demand and nothing not already shown this session."""
    if files_checked == 0:
        return _assemble(f"Qryptive guard: nothing checked this turn ({open_items} earlier warning(s) still "
                         f"open, see `status`).", notes, [], [])
    return _assemble(f"Qryptive guard: nothing new to report ({files_checked} file(s) checked; "
                     f"{open_items} earlier warning(s) still open, see `status`).", notes, [], [])


def off(notes: Iterable[str] = ()) -> str:
    return _assemble("Qryptive guard is off for this repository (mode: off in .qryptive-guard.json).",
                     notes, [], [])
