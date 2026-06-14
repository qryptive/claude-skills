# Qryptive PQC skills for Claude Code

Find quantum-vulnerable cryptography in your codebase — **Python, Java, and Go** — without leaving your editor.

The scan runs **fully locally** in a sandboxed container. Your source code never leaves your machine, and **no account is required**.

## Install

```
/plugin marketplace add qryptive/claude-skills
/plugin install qryptive-pqc@qryptive
```

## Use

```
/qryptive-scan
```

Claude scans the current repo and reports quantum-vulnerable cryptography split into crypto findings vs. asset inventory, with a post-quantum readiness summary.

## Optional: sync to your dashboard

The scan is free and local forever. If you want to sync results to the Qryptive dashboard (and track your org's quantum posture over time), the skill will offer to set you up — or you can grab a key directly at **https://app.qryptive.ai/settings/agent-access**, then:

```
export QRYPTIVE_API_KEY=qk_...
```

and re-run `/qryptive-scan`. The key lives only in your environment; Qryptive never sees your source code on a scan.

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
