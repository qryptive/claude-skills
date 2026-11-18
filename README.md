# Qryptive PQC skills for Claude Code

Find quantum-vulnerable cryptography in your codebase — **Python, Java, Go, and JavaScript/TypeScript** — without leaving your editor.

The scan runs **fully locally** in a sandboxed container. Your source code never leaves your machine. A **free sign-in with your email** is required the first time you run it — after that, each scan just checks in quietly in the background before it starts.

## Install

```
/plugin marketplace add qryptive/claude-skills
/plugin install qryptive-pqc@qryptive
```

**In VS Code:** restart VS Code after installing. The command then appears as `/qryptive-pqc:qryptive-scan`. If `/plugin` does not run as a command there, ask Claude to run it in the terminal.

## Use

```
/qryptive-scan
```

Claude scans the current repo and reports quantum-vulnerable cryptography split into crypto findings vs. asset inventory, with a post-quantum readiness summary.

## Optional: sync to your dashboard (not needed to scan)

You do **not** need an API key to scan. The free email sign-in (Claude asks for it the first time you run `/qryptive-scan`) is all the scan needs, and your code stays local forever; the sign-in only unlocks running the scanner and never sees your source. The API key below is a separate, optional credential. If you also want to sync results to the Qryptive dashboard (and track your org's quantum posture over time), grab a key at **https://app.qryptive.ai/settings/agent-access**, then:

```
export QRYPTIVE_API_KEY=pqc_org_...
```

and re-run `/qryptive-scan`. The key lives only in your environment; Qryptive never sees your source code on a scan.

**New to this?** Follow the step-by-step walkthrough (with a picture) for generating a key and putting it where Claude Code can actually see it: **[Getting your API key →](skills/qryptive-scan/docs/API_KEY_SETUP.md)**

## Requirements

- **Docker** (the scanner runs as a local, network-isolated container)

## What this is

This repo ships **orchestration only** — how to run the local scanner image and present results. All detection logic lives in the public scanner image; there is no proprietary cryptography knowledge in this repo.

## License

[Apache-2.0](LICENSE)

## Updates & pinning

The scanner image updates **only with your consent**. When you run `/qryptive-scan` and a newer
scanner is available, it tells you and asks before pulling — your current version keeps running if
you decline. Nothing updates silently.

- **Pin a version** (reproducible scans / CI): `export QRYPTIVE_SCANNER_IMAGE=ghcr.io/qryptive/pqc-scanner:v1.0.0`
- **Silence the update check** on the moving channel: `export QRYPTIVE_SKIP_UPDATE_CHECK=1`

Release notes: https://github.com/qryptive/claude-skills/releases
