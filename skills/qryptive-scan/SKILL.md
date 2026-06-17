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
     `QRYPTIVE_SKIP_UPDATE_CHECK` != `1`): compare the local image digest to the remote digest
     **without downloading layers**:
     - Local: `docker inspect "$IMAGE" --format '{{index .RepoDigests 0}}'`
     - Remote: `docker buildx imagetools inspect "$IMAGE" --format '{{.Manifest.Digest}}'`
       (fallback if `buildx imagetools` is unavailable: `docker manifest inspect "$IMAGE"` and read the
       top-level digest). If BOTH remote lookups fail (offline), skip silently and run the cached image.
     - Compare the `sha256:…` values.
       - **Same** → run the cached image, no prompt.
       - **Different** → a newer scanner is available. Show the user their current version
         (`docker inspect "$IMAGE" --format '{{index .Config.Labels "org.opencontainers.image.version"}}'`)
         and this line, then ASK:
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

   Count `.py`, `.pyw`, `.java`, and `.go` files, pruning the same heavy directories the container
   skips so the number is realistic:
   ```bash
   N=$(find "$ROOT" \
       \( -name .git -o -name node_modules -o -name venv -o -name .venv \
          -o -name __pycache__ -o -name dist -o -name build -o -name .claude \
          -o -name target -o -name out -o -name vendor -o -name site-packages \
          -o -name .tox -o -name .gradle \) -prune \
       -o -type f \( -name '*.py' -o -name '*.pyw' -o -name '*.java' -o -name '*.go' \) -print \
       2>/dev/null | wc -l | tr -d ' ')
   ```

   Report: **"Found N scannable files."**

   When N is large it also helps to surface where the bulk lives. Run a quick top-subdirectory
   breakdown and include it in the message (so the user can see which directories dominate):
   ```bash
   find "$ROOT" \
       \( -name .git -o -name node_modules -o -name venv -o -name .venv \
          -o -name __pycache__ -o -name dist -o -name build -o -name .claude \
          -o -name target -o -name out -o -name vendor -o -name site-packages \
          -o -name .tox -o -name .gradle \) -prune \
       -o -type f \( -name '*.py' -o -name '*.pyw' -o -name '*.java' -o -name '*.go' \) -print \
       2>/dev/null \
     | sed "s|^$ROOT/||" | cut -d/ -f1 | sort | uniq -c | sort -rn | head -10
   ```

   **Note:** this magnitude gate applies to the **whole-repo (default) scan**. In diff mode
   (Step 2.5) the scan is already limited to changed files, so this count is a loose upper-bound
   estimate of the whole repo and the threshold warning can be ignored for diff-mode runs.

   **Note:** this host-side count does not apply `QRYPTIVE_SCAN_EXCLUDE_DIRS` (the container
   enforces it), so the count may be higher than the actual scan scope when that variable is set —
   it can only over-estimate, never under-warn.

   **Threshold: if `N > 5000` AND `QRYPTIVE_SKIP_PREFLIGHT` is not `1`**, warn the user and offer
   these choices before proceeding:

   > ⚠️  This repo contains **N** scannable files. A whole-repo scan of this size can take a long
   > time (potentially 30+ minutes on a large monorepo). What would you like to do?
   >
   > 1. **Narrow the scan** — `cd` into a subdirectory and re-run `/qryptive-scan` from there,
   >    or specify a subfolder as the mount root.
   > 2. **Diff mode** — `/qryptive-scan diff` scans only the files changed on the current branch
   >    (usually tens or hundreds of files, not thousands).
   > 3. **Exclude heavy dirs** — set `QRYPTIVE_SCAN_EXCLUDE_DIRS=<comma,separated,dir,names>`
   >    (e.g. vendored test corpora, generated code directories) and re-run. The container honors
   >    this env var and will skip those directory names wherever they appear under the scan root.
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
- `QRYPTIVE_SCAN_EXCLUDE_DIRS=<comma-separated dir names>` skips additional directories inside the scan root (e.g. vendored test corpora, generated-code subtrees). Useful for huge monorepos where a known-clean subtree dominates the file count. The env var is passed through to the container in Step 3 and honored by the scanner.
- `QRYPTIVE_SKIP_PREFLIGHT=1` bypasses the Step 2.4 magnitude warning entirely. Useful for users who always want the full scan and don't need the up-front file-count gate.
