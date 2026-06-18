---
name: qryptive-scan
description: Scan the current repo for quantum-vulnerable cryptography (Python/Java/Go). Fully local — code never leaves the machine. No account required.
---

# Qryptive Scan

Detect quantum-vulnerable cryptography locally. **Read-only. No network. No API key.**

## Steps

1. **Docker preflight.** Run `docker info` (quietly). If Docker is not installed or not
   running, tell the user how to install/start it and STOP. Do not print a traceback.

2. **Resolve the scanner image, then check for updates WITHOUT auto-applying them.**

   Resolve which image to run:
   - If `QRYPTIVE_SCANNER_IMAGE` is set, use it **verbatim** and SKIP the update check
     (this is the reproducible/CI pin, e.g. `ghcr.io/qryptive/pqc-scanner:v1.0.0`).
   - Otherwise the image is `ghcr.io/qryptive/pqc-scanner:v1` (the moving channel).

   Then:
   - **If the image is not cached locally** (`docker image inspect "$IMAGE"` fails): pull it once —
     `docker pull --platform linux/amd64 "$IMAGE"`. If the pull fails (offline), tell the user and STOP.
   - **If it IS cached AND** the update check is not skipped (no `QRYPTIVE_SCANNER_IMAGE` pin and
     `QRYPTIVE_SKIP_UPDATE_CHECK` != `1`): run the following bash snippet verbatim, then act **only
     on the `VERDICT=` token** it prints. Never conclude "up to date" by eyeballing raw digest text —
     the token is the only authoritative signal.

     ```bash
     IMAGE="ghcr.io/qryptive/pqc-scanner:v1"

     # Local: index digest of the pulled image. Filter by this repo — an image tagged from
     # multiple registries can have >1 RepoDigest; using index 0 is unsafe.
     LOCAL=$(docker inspect "$IMAGE" --format '{{range .RepoDigests}}{{println .}}{{end}}' 2>/dev/null \
             | grep '^ghcr.io/qryptive/pqc-scanner@' | head -1 | sed 's/.*@//')

     # Remote: top-level OCI index digest. printf-wrap defeats buildx's bare-template
     # default-formatter trap (a bare '{{.Manifest.Digest}}' triggers a full human dump, not a
     # clean digest). NEVER fall back to 'docker manifest inspect' — it returns the per-platform
     # child manifest digest, which can never equal the index digest → permanent false UPDATE_AVAILABLE.
     REMOTE=$(docker buildx imagetools inspect "$IMAGE" --format '{{ printf "%s" .Manifest.Digest }}' 2>/dev/null \
              | grep -m1 -Eo 'sha256:[a-f0-9]{64}')
     # Defense-in-depth: if the printf path yields nothing (very old buildx), anchor on the
     # top-level "Digest:" label in the human dump (first match, label-anchored, stable).
     if [ -z "$REMOTE" ]; then
       REMOTE=$(docker buildx imagetools inspect "$IMAGE" 2>/dev/null \
                | grep -m1 '^Digest:' | grep -Eo 'sha256:[a-f0-9]{64}')
     fi

     if [ -z "$REMOTE" ] || [ -z "$LOCAL" ]; then
       VERDICT="CHECK_FAILED"
     elif [ "$LOCAL" = "$REMOTE" ]; then
       VERDICT="UP_TO_DATE"
     else
       VERDICT="UPDATE_AVAILABLE"
     fi
     echo "LOCAL=$LOCAL"
     echo "REMOTE=$REMOTE"
     echo "VERDICT=$VERDICT"
     ```

     Act on the `VERDICT=` token:
     - **`UP_TO_DATE`** → run the cached image, no prompt.
     - **`CHECK_FAILED`** → run the cached image, but print one visible line so the failure is not
       silent (a silent check-failure would allow future format changes to permanently suppress the
       update prompt without any indication):
       ```
       ℹ️  Couldn't check for scanner updates (offline or registry unreachable); using your cached image.
       ```
     - **`UPDATE_AVAILABLE`** → a newer scanner is available. Show the user their current version
       (`docker inspect "$IMAGE" --format '{{index .Config.Labels "org.opencontainers.image.version"}}'`)
       and ASK:
       ```
       ℹ️  A newer Qryptive scanner is available. You're on <current version>.
           What's new: https://github.com/qryptive/claude-skills/releases
           Update now? [y/N]  (default: keep your current version)
       ```
       - On **yes** → `docker pull --platform linux/amd64 "$IMAGE"`, then run the new image.
       - On **no / no answer** → run the cached image unchanged. Do NOT pull.
   - **If the update check is skipped** (pin set, or `QRYPTIVE_SKIP_UPDATE_CHECK=1`): run the cached
     image as-is (never auto-pull).

   NEVER pull a new image without either (a) nothing being cached, or (b) explicit user consent.

2.4. **Pre-flight magnitude gate (host-side only — no container).**

   Count scannable files on the host to warn the user before a potentially very long scan. This step
   runs the `find` command directly on the host, using the same scan root that Step 3 will mount. It
   NEVER starts the container.

   Set the scan root:
   ```bash
   ROOT="${ROOT:-$PWD}"
   ```
   (In diff mode, Step 2.5 sets `ROOT` to the repo root. In whole-repo mode, `ROOT` defaults to
   `$PWD`. Either way, this step uses whatever `ROOT` is at this point in the flow.)

   Count `.py`, `.pyw`, `.java`, and `.go` files. When inside a git repo (and
   `QRYPTIVE_SCAN_EXCLUDE_DIRS` is not set), use `git ls-files` so the count honours
   `.gitignore` and matches what Step 3 will actually scan. Fall back to `find` otherwise.

   ```bash
   if [ -z "$QRYPTIVE_SCAN_EXCLUDE_DIRS" ] && \
        git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
     # Git-aware count: tracked files + untracked-not-gitignored, honours .gitignore
     N=$(git -C "$ROOT" ls-files --cached --others --exclude-standard \
           | grep -cEi '\.(py|pyw|java|go)$' || echo 0)
     TOP=$(git -C "$ROOT" ls-files --cached --others --exclude-standard \
             | grep -Ei '\.(py|pyw|java|go)$' \
             | sed "s|^$ROOT/||" | cut -d/ -f1 | sort | uniq -c | sort -rn | head -10)
   else
     # Fallback: filesystem walk pruning heavy dirs (used when not in git or custom excludes set)
     N=$(find "$ROOT" \
         \( -name .git -o -name node_modules -o -name venv -o -name .venv \
            -o -name __pycache__ -o -name dist -o -name build -o -name .claude \
            -o -name target -o -name out -o -name vendor -o -name site-packages \
            -o -name .tox -o -name .gradle \) -prune \
         -o -type f \( -name '*.py' -o -name '*.pyw' -o -name '*.java' -o -name '*.go' \) -print \
         2>/dev/null | wc -l | tr -d ' ')
     TOP=$(find "$ROOT" \
         \( -name .git -o -name node_modules -o -name venv -o -name .venv \
            -o -name __pycache__ -o -name dist -o -name build -o -name .claude \
            -o -name target -o -name out -o -name vendor -o -name site-packages \
            -o -name .tox -o -name .gradle \) -prune \
         -o -type f \( -name '*.py' -o -name '*.pyw' -o -name '*.java' -o -name '*.go' \) -print \
         2>/dev/null \
       | sed "s|^$ROOT/||" | cut -d/ -f1 | sort | uniq -c | sort -rn | head -10)
   fi
   ```

   Report: **"Found N scannable files."**

   When N is large it also helps to surface where the bulk lives — include the `$TOP`
   breakdown in the message so the user can see which directories dominate.

   **Note:** this magnitude gate applies to the **whole-repo (default) scan**. In diff mode
   (Step 2.5) the scan is already limited to changed files, so this count is a loose upper-bound
   estimate of the whole repo and the threshold warning can be ignored for diff-mode runs.

   **Note:** when `QRYPTIVE_SCAN_EXCLUDE_DIRS` is set the fallback `find` path is used, so the
   count may be higher than the actual scan scope — it can only over-estimate, never under-warn.

   **Threshold: if `N > 5000` AND `QRYPTIVE_SKIP_PREFLIGHT` is not `1`**, warn the user and offer
   these choices before proceeding:

   > ⚠️  This repo contains **N** scannable files. A whole-repo scan of this size can take a long
   > time (potentially 30+ minutes on a large monorepo). What would you like to do?
   >
   > 1. **Narrow the scan** — `cd` into a subdirectory and re-run `/qryptive-scan` from there,
   >    or specify a subfolder as the mount root.
   > 2. **Diff mode** — `/qryptive-scan diff` scans only the files changed on the current branch
   >    (usually tens or hundreds of files, not thousands).
   > 3. **Customize excluded dirs** — the scanner already excludes a default set of build/tool/IDE
   >    dirs (`dist`, `build`, `target`, `vendor`, `coverage`, `.next`, `.gradle`, `.claude`, etc.).
   >    To use a different set, set `QRYPTIVE_SCAN_EXCLUDE_DIRS=<comma,separated,dir,names>` and
   >    re-run — your list **replaces** the defaults (`.git`, `node_modules`, `venv`, `__pycache__`
   >    are always excluded regardless). Example: `QRYPTIVE_SCAN_EXCLUDE_DIRS=tests,spikes`.
   > 4. **Proceed with the full scan** — it will stream progress so you can see it moving.

   Wait for the user's choice before proceeding.

   If `N <= 5000` OR `QRYPTIVE_SKIP_PREFLIGHT=1`, proceed silently to the next step.

2.5. **Diff-only mode (opt-in).** If the user invoked the skill as `diff` (e.g.
   `/qryptive-scan diff` or `/qryptive-scan diff <base-ref>`), scan only the files changed on the
   current branch. Otherwise skip this step and scan the whole repo (default).

   Run this on the **host** (you have git; the container does not need it):
   ```bash
   ROOT=$(git rev-parse --show-toplevel)            # mount the repo root, not $PWD
   if [ -n "$BASE_ARG" ]; then
     BASE="$BASE_ARG"
   else
     BASE=$(git rev-parse --abbrev-ref origin/HEAD 2>/dev/null | sed 's@^origin/@@')
     [ -z "$BASE" ] && BASE=main
     if   git rev-parse --verify -q "origin/$BASE" >/dev/null; then BASE="origin/$BASE"
     elif git rev-parse --verify -q origin/master   >/dev/null; then BASE="origin/master"
     elif git rev-parse --verify -q master          >/dev/null; then BASE="master"
     fi
   fi
   CHANGED=$( { git diff --name-only --diff-filter=d "$BASE"...HEAD;
                git diff --name-only --diff-filter=d --cached;
                git diff --name-only --diff-filter=d; } | sort -u )
   QRYPTIVE_SCAN_FILES=$(printf '%s\n' "$CHANGED" | grep -Ei '\.(py|pyw|java|go)$' || true)
   ```
   - If `git rev-parse --show-toplevel` fails (not a git repo) or `$BASE` cannot be resolved, tell the
     user diff mode is unavailable and offer a whole-repo scan instead — do not run the container.
   - If `QRYPTIVE_SCAN_FILES` is empty, tell the user there are no changed scannable files and stop.
   - Otherwise, in Step 3 mount `$ROOT` (not `$PWD`) and pass `-e QRYPTIVE_SCAN_FILES="$QRYPTIVE_SCAN_FILES"`.
   - The scan reads **whole files**, not just changed lines — a changed file is scanned in full.

3. **Scan the repo (local, no network) — streaming progress.**

   Tell the user the scan is starting. Create two temp files — one for the JSON results and one for
   the live progress log. **macOS/BSD `mktemp` only substitutes TRAILING `X`s**, so the template
   must end in `X`s with nothing after them:
   ```bash
   # Create result + progress files. macOS/BSD mktemp needs the X's at the END of the template.
   OUT=$(mktemp /tmp/qryptive-scan-result.XXXXXX)
   PROGRESS=$(mktemp /tmp/qryptive-scan-progress.XXXXXX)
   echo "RESULT_FILE=$OUT"
   echo "PROGRESS_FILE=$PROGRESS"
   ```

   **IMPORTANT — each Bash tool call is a fresh shell.** The `$OUT` and `$PROGRESS` variables are
   gone the moment that shell exits. Note the **literal paths** printed by the `echo` lines above
   (e.g. `RESULT_FILE=/tmp/qryptive-scan-result.ab12cd`) and use those **literal paths verbatim**
   in every subsequent poll and read Bash call — do NOT use `$OUT` or `$PROGRESS` variable names
   in later tool calls (they will be empty in a new shell).

   Run the scan as a **background Bash task** (use the Bash tool with `run_in_background=true`).
   Define `OUT`/`PROGRESS` and run the `docker run` command **in the same Bash invocation** so the
   redirections see the variables, and redirect stdout to `$OUT` and **stderr to `$PROGRESS`** —
   NEVER to `/dev/null`. Stderr carries the scanner's per-chunk `found N files to scan` and
   `scanned X/Y files...` progress lines; sending it to `/dev/null` was the root cause of the
   2+ hour silent-hang incident.

   ```bash
   # Whole-repo (default): MOUNT="$PWD". Diff mode (Step 2.5): MOUNT="$ROOT".
   MOUNT="${ROOT:-$PWD}"

   # Git-aware whole-repo file selection: when in a git repo and no custom exclude dirs are set,
   # populate QRYPTIVE_SCAN_FILES from git ls-files so .gitignore is honoured automatically.
   # Skipped when: diff mode already set QRYPTIVE_SCAN_FILES (Step 2.5), or user set
   # QRYPTIVE_SCAN_EXCLUDE_DIRS (their explicit list takes precedence), or not a git repo.
   if [ -z "$QRYPTIVE_SCAN_FILES" ] && [ -z "$QRYPTIVE_SCAN_EXCLUDE_DIRS" ] && \
        git -C "$MOUNT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
     QRYPTIVE_SCAN_FILES=$(git -C "$MOUNT" ls-files --cached --others --exclude-standard \
                             | grep -Ei '\.(py|pyw|java|go)$' || true)
   fi

   OUT=$(mktemp /tmp/qryptive-scan-result.XXXXXX)
   PROGRESS=$(mktemp /tmp/qryptive-scan-progress.XXXXXX)
   echo "RESULT_FILE=$OUT"
   echo "PROGRESS_FILE=$PROGRESS"
   docker run --rm --platform linux/amd64 --network none \
     -e SCANNER_DUMP_CONTEXT=true \
     -e MALLOC_ARENA_MAX=2 \
     ${QRYPTIVE_SCAN_FILES:+-e QRYPTIVE_SCAN_FILES="$QRYPTIVE_SCAN_FILES"} \
     ${QRYPTIVE_SCAN_EXCLUDE_DIRS:+-e QRYPTIVE_SCAN_EXCLUDE_DIRS="$QRYPTIVE_SCAN_EXCLUDE_DIRS"} \
     -v "$MOUNT":/work:ro \
     "$IMAGE" scan /work >"$OUT" 2>"$PROGRESS"
   ```

   `--platform linux/amd64` is REQUIRED — the image is amd64-only; on Apple-Silicon Macs it
   runs under Docker's emulation. Without the flag, `docker pull` fails with
   `no matching manifest for linux/arm64`. The flag is a no-op on amd64 Linux hosts.

   `MALLOC_ARENA_MAX=2` keeps memory flat on large repos. **Do NOT set `SCANNER_MAX_WORKERS`** — the
   scanner's per-file pool MUST stay at 1 (shared signal/gate state is not thread-safe; raising it
   produces non-deterministic finding counts). Speed comes from batching, not parallelism.

   **While the background task runs, poll for progress** every 60–90 seconds: read the last line of
   the progress file using its **literal path** from the `PROGRESS_FILE=...` line printed above
   (e.g. `tail -n 1 /tmp/qryptive-scan-progress.ab12cd`) and relay it to the user so they can see
   the scan moving. The scanner emits lines like `found N files to scan` near the start, then
   `scanned X/Y files...` as it progresses through batches. Keep polling until the background task
   completes.

   **When the background task completes:**
   - Read the result using its **literal path** from the `RESULT_FILE=...` line (e.g.
     `cat /tmp/qryptive-scan-result.ab12cd`). If the file is empty or not valid JSON, the scan
     failed (container may have crashed or been OOM-killed). Read the progress file for error
     details and report a scan failure — do NOT report "no findings / clean repo" when the output
     file is empty or malformed.
   - If the result file contains a valid JSON object, proceed to Step 4. The format is:
     `{ "files_scanned": N, "findings": [...] }`. Each finding carries a repo-relative `file`
     plus `line`. Stderr may also contain a `results may be incomplete` warning on partial failure
     — surface this to the user if present.

4. **Resolve ambiguous findings locally (you are the LLM).** For any finding whose
   resolution is `unresolved`, use the dumped 5-ring context already in the JSON to determine
   the algorithm/crypto-object. If you cannot determine it confidently, leave it `unresolved`
   — never guess. Tag each with `resolution_source` ∈ {deterministic, llm, unresolved}.

5. **Report.** Present:
   - Crypto findings vs. asset inventory (split by `finding_type`).
   - Per finding: algorithm, confidence, `file:line`, resolution source.
   - A PQ-readiness summary (crypto findings only).
   - Any `unresolved` findings, listed honestly.
   - If this was a diff-only scan (Step 2.5), state clearly that it was a **partial scan** of the files
     changed vs `<base>`, and that the PQ-readiness summary covers only those files — not the whole repo.

6. **Optional sync / activation.**
   - **If `QRYPTIVE_API_KEY` is set:** POST results to
     `${QRYPTIVE_PLATFORM_URL:-https://app.qryptive.ai}/api/github-action/scan-results` with
     header `X-API-Key: $QRYPTIVE_API_KEY` and body
     `{repo, branch, commit_sha, files_scanned, findings}`. If it fails, warn but keep the local
     report — sync is additive.
   - **If `QRYPTIVE_API_KEY` is NOT set:** offer activation. Tell the user, in one sentence, that
     syncing needs a free Qryptive login and that you would send **only their work email** to
     create it — their **source code still never leaves this machine**. Ask for explicit consent.
     - **On consent + a work email:** POST
       `${QRYPTIVE_PLATFORM_URL:-https://app.qryptive.ai}/api/onboarding/request` with JSON
       `{"email": "<their email>", "source": "cli-scan"}`. Then relay the server's `message`
       verbatim (corporate domains get an instant one-click login link; personal-email domains
       are told a work email grants instant access or the team will follow up). If the POST fails
       or times out, warn and print the fallback block below.
     - **On decline, an invalid email after one re-prompt, or any failure:** print exactly:
       ```
       ℹ️  Results stayed fully local — nothing was sent anywhere.

       To sync later: get a key at https://app.qryptive.ai/settings/agent-access,
       run  export QRYPTIVE_API_KEY=qk_...  and re-run /qryptive-scan.
       ```

## Rules
- This skill NEVER sends source code anywhere. With `QRYPTIVE_API_KEY` set it syncs results (step 6); without a key it may send only a work email, with explicit user consent, to create a free login — source code never leaves the machine in either case.
- This skill contains NO crypto knowledge — all detection logic lives in the image.
- **Default directory exclusions:** the scanner automatically excludes common build/tool/IDE dirs — `dist`, `build`, `target`, `out`, `vendor`, `coverage`, `.next`, `.nuxt`, `.tox`, `.gradle`, `.mvn`, `.idea`, `.vscode`, `.pytest_cache`, `.mypy_cache`, `.ruff_cache`, `.cache`, `.claude` — so customers see only their source code without any configuration. The permanent floor (`.git`, `node_modules`, `__pycache__`, `venv`, `.venv`, `site-packages`) is always excluded.
- **`.gitignore` is honoured automatically** in a git repo. In whole-repo mode (default), the skill uses `git ls-files` to build the file list — tracked files plus untracked-not-gitignored files. Gitignored paths (build artefacts, OSS eval corpora, generated output) are never scanned. Diff mode inherits the same behaviour via `git diff`. If git is unavailable, the skill falls back to a filesystem walk with the default excluded dirs.
- `QRYPTIVE_SCAN_EXCLUDE_DIRS=<comma-separated dir names>` customizes the exclusion set. Setting this **bypasses git-mode** and falls back to a filesystem walk with your list **replacing** the defaults (e.g. `QRYPTIVE_SCAN_EXCLUDE_DIRS=tests,spikes` skips `tests/` and `spikes/` but no longer skips `dist/` etc.). The floor dirs are always excluded regardless. Useful when you want to include a default-excluded dir (e.g. a `dist/` with hand-authored crypto source) or add your own heavy dirs. The env var is passed through to the container in Step 3.
- `QRYPTIVE_SKIP_PREFLIGHT=1` bypasses the Step 2.4 magnitude warning entirely. Useful for users who always want the full scan and don't need the up-front file-count gate.
