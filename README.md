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
