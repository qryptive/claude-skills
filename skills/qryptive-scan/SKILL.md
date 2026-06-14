---
name: qryptive-scan
description: Scan the current repo for quantum-vulnerable cryptography (Python/Java/Go). Fully local — code never leaves the machine. No account required.
---

# Qryptive Scan

Detect quantum-vulnerable cryptography locally. **Read-only. No network. No API key.**

## Steps

1. **Docker preflight.** Run `docker info` (quietly). If Docker is not installed or not
   running, tell the user how to install/start it and STOP. Do not print a traceback.

2. **Pull the scanner image if absent:**
   `docker image inspect ghcr.io/qryptive/pqc-scanner:v1 >/dev/null 2>&1 || docker pull --platform linux/amd64 ghcr.io/qryptive/pqc-scanner:v1`
   If the pull fails and the image is not cached (offline), tell the user and STOP.

3. **Scan the repo (local, no network):**
   ```bash
   docker run --rm --platform linux/amd64 --network none \
     -e SCANNER_DUMP_CONTEXT=true \
     -v "$PWD":/work:ro \
     ghcr.io/qryptive/pqc-scanner:v1 scan /work
   ```
   `--platform linux/amd64` is REQUIRED — the image is amd64-only; on Apple-Silicon Macs it
   runs under Docker's emulation. Without the flag, `docker pull` fails with
   `no matching manifest for linux/arm64`. The flag is a no-op on amd64 Linux hosts.
   Capture the JSON: `{ "files_scanned": N, "findings": [...] }`. Each finding carries a
   repo-relative `file` plus `line`.

4. **Resolve ambiguous findings locally (you are the LLM).** For any finding whose
   resolution is `unresolved`, use the dumped 5-ring context already in the JSON to determine
   the algorithm/crypto-object. If you cannot determine it confidently, leave it `unresolved`
   — never guess. Tag each with `resolution_source` ∈ {deterministic, llm, unresolved}.

5. **Report.** Present:
   - Crypto findings vs. asset inventory (split by `finding_type`).
   - Per finding: algorithm, confidence, `file:line`, resolution source.
   - A PQ-readiness summary (crypto findings only).
   - Any `unresolved` findings, listed honestly.

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
