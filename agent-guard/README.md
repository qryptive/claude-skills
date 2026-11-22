# Qryptive agent edit guard

The guard checks the cryptography a coding agent writes. It runs on your machine. At the end of
each agent turn, it scans the files the agent changed and compares them with how they were before
the agent started. If the agent added quantum-vulnerable cryptography, the guard tells the agent,
and the agent fixes it.

The guard is a check, not a fix. It reports new problems. It does not change your code. The agent
(or you) makes the change.

It uses the same local scanner image as `/qryptive-scan`. It needs Docker and the free scanner
sign-in that `/qryptive-scan` asks for once.

The guard is opt-in. Installing the Qryptive plugin does not turn it on. Nothing runs until you
install it in a repository, as shown below.

## Agents

- **Claude Code.** The hook records each file the agent edits. The scan runs once, at the end of
  the turn. Tested end to end with real Claude Code 2.1.289 in headless mode (`claude -p`),
  against an older stand-in scanner image and a test scan pass, not a real sign-in. Not yet
  tested: the interactive Claude Code window, the real `v1` scanner image with a real sign-in,
  and the scan-pass renewal call.
- **Cursor.** Written from Cursor's published hook documentation. It has **not** been run in a
  real Cursor yet ("from docs, not measured").
- **git pre-commit.** The guard checks what you stage, before each commit.

## Install

Run one of these from inside the repository you want to guard. `<plugin folder>` is where the
Qryptive plugin (or this folder's checkout) lives.

```
python3 <plugin folder>/agent-guard/qryptive_guard.py install claude-code   # writes .claude/settings.local.json
python3 <plugin folder>/agent-guard/qryptive_guard.py install cursor        # writes .cursor/hooks.json
python3 <plugin folder>/agent-guard/qryptive_guard.py install git           # writes the pre-commit hook
```

Install it once per repository and per agent. To remove it, run the same command with
`uninstall`.

What install does and does not do:

- It adds its own entries to your existing hook file. It keeps everything else in that file.
- If you run it twice, the second run changes nothing.
- It never replaces or deletes a hook that is not its own. If you already have a git pre-commit
  hook, it stops and prints the one line to add to your hook yourself.
- Its entries name this machine's path to the guard. So it refuses a file that git tracks, and a
  file that leads (through a link) outside the repository, such as your global
  `~/.claude/settings.json`. Each refusal says what to do by hand.
- `install cursor` warns you when `.cursor/hooks.json` is not ignored by git, because it is easy
  to commit by accident.
- If `core.hooksPath` points outside the repository, or into a folder git does not ignore, the git
  install stops and prints the manual line.
- In a repository with several git worktrees, the git hook is shared by all of them. Install and
  uninstall say so.
- The hooks name the plugin folder, and that folder changes when the plugin updates. After a
  plugin update, run install again: it updates its own entries to the new path. Until then, the
  old entries point at a folder that is gone, and the hooks print "did NOT run" and let the agent
  continue.
- Uninstall removes only the guard's own entries. It deletes a file only if the guard created it
  and nothing else is left in it.

## The policy file

You can put a `.qryptive-guard.json` file at the repository root. Every key is optional.

```json
{
  "mode": "feedback",
  "strict_commit": false,
  "checkin": true,
  "ignore_paths": ["vendor/**", "*.gen.py"],
  "allow": [
    {"algorithm": "RSA", "path": "legacy/sso/**", "reason": "Our identity provider needs RSA until 2027"}
  ],
  "scan_on_edit": false
}
```

- `mode`: `feedback` (the default) asks the agent to fix new problems. `warn` only shows them.
  `off` turns the guard off for this repository.
- `strict_commit`: when `true`, the git hook blocks a commit if the check could not run (for
  example, Docker is stopped). When `false` (the default), the commit goes through with a warning.
- `checkin`: when `false`, the guard never renews your scan pass. See "What leaves the machine".
- `ignore_paths`: path patterns the guard does not check. `**` matches any folders. A pattern with
  no `/` matches a file name at any depth.
- `allow`: findings you accept. Each entry names an `algorithm`, a `path` pattern, or both, and
  must have a `reason`. An entry without a reason is dropped, and the guard says so.
- `scan_on_edit`: reserved. It has no effect in this version.

If the file is not valid JSON, the guard uses the defaults and says so. If the file changes
during a session (for example, an agent adds an `allow` entry), the guard says that in its
message, so you can see an agent loosening its own check.

## What leaves the machine

Nothing about your code leaves the machine. No source code, file names, file contents or
findings are sent anywhere. The scan runs in a container with no network.

The only network call is the scan-pass renewal. When your saved scan pass has less than two days
left, or its expiry date cannot be read, the guard tries to renew it, in the same way
`/qryptive-scan` does. It tries at most once a day. That call sends your
scanner key, which client is running (`guard`) and the scanner version. To stop it, set
`"checkin": false`. When the pass then runs out, run `/qryptive-scan` once to renew it.

## What it checks

- Code: Python, Java, Go, JavaScript and TypeScript.
- Configuration and infrastructure: `.tf`, `.yaml`, `.yml` and `.conf` files. This finds, for
  example, an RSA key in Terraform or CloudFormation, and an old TLS policy on a load balancer.
- If the scanner image on your machine is too old to read configuration files, the guard says
  "config file(s) not checked". It never counts those files as checked.

What is NOT checked:

- Dependency manifests: `requirements.txt`, `pom.xml`, `go.mod`, `Gemfile`, `Cargo.toml` and the
  like. The guard does not send them to the scanner at all. A turn that changed only those files
  reads "nothing checked: no file changed this turn is a type the guard reads", so adding a weak
  crypto library to a manifest is not caught.
- JSON and TOML configuration files.
- TLS settings in Istio-style YAML.
- An old `ssl_protocols` list in nginx `.conf` files (a weak curve in the same file is found).

Only NEW problems count. A problem that was already there before the agent's first edit is not
reported as new.

## What its messages mean

- "Qryptive: this turn added quantum-vulnerable cryptography..." means the check ran and found new
  problems. The agent is asked to fix them, or to add an `allow` entry with a reason.
- "Qryptive guard: check did NOT run: ..." means the check could not run (for example, Docker is
  not running, or you are not signed in). This is not a security finding. It never blocks the
  agent. It blocks a commit only with `strict_commit: true`.
- "Qryptive (warning only)..." means there is something to review, but the agent is not asked to
  fix it.
- "Qryptive guard: nothing checked: ..." means files changed, but none is a type the guard reads.
  "Qryptive guard: no changed files ..." means nothing changed. Neither is a clean result: only
  "no new quantum-vulnerable cryptography (N file(s) checked)" says the scan ran and found nothing.

If the agent does not fix the same problem after 3 attempts, the guard stops asking about it and
shows it as a warning. After 6 blocking rounds in one session, the guard stops asking for that
session and lists what is still open. Warnings are shown once per session.

Exit codes for scripts: 0 means clean, 2 means new problems, 3 means the check could not run.
The agent hooks always exit 0 and speak the agent's own hook format instead.

## Things to know

- **If you asked for the vulnerable algorithm.** If you tell the agent to use RSA, the guard still
  reports it. The agent will usually stop and ask you rather than change what you asked for. The
  guard asks up to 3 times for the same problem, then shows it as a warning and lets the agent
  finish. To accept it, add an `allow` entry with a reason to `.qryptive-guard.json`; the guard
  then stops asking at once.
- **Where the "did NOT run" line shows.** Claude Code passes the guard's notice on as its own
  event ("Stop says: ...") when you read its event stream (`--output-format stream-json`). It does
  not appear in plain `claude -p` text output. Whether the interactive window shows it is not yet
  tested.
- **Where the comparison starts.** The comparison starts from the commit that was current at the
  agent's first edit in a session. Changes you made before that edit, and did not commit, are
  judged as if the agent made them. Commit or stash your own work first.
- **Claude Code hides most hook output.** A "check did NOT run" line from the end-of-turn hook
  usually does not reach you. Run `python3 <path>/agent-guard/qryptive_guard.py status` to see
  whether the last check ran, and why not.
- **Files written through the shell.** The edit hook does not see files an agent writes with shell
  commands. The end-of-turn check also looks at every file git sees as changed, so those files are
  still checked.
- **Limits.** One check covers at most 500 files, 1,000,000 characters per file and 50 MB in total.
  Files under 10 characters are skipped, as the scanner skips them. Minified and declaration files
  are skipped too. Anything not checked is listed as "not checked"; nothing is dropped silently.
- **If the guard is missing.** If the guard's files are gone (a removed worktree, an old plugin
  version), the hooks print one "did NOT run" line and let the agent or the commit continue.

## Scanner image

The guard uses the same scanner image as `/qryptive-scan`: the moving
`ghcr.io/qryptive/pqc-scanner:v1` tag. Set `QRYPTIVE_SCANNER_IMAGE` to pin a version, exactly as
for the skill. The guard never pulls an image itself; run `/qryptive-scan` once to pull it. A new
scanner image covers the guard and the skill at the same time.

## Turn it off

- For one repository: set `"mode": "off"` in `.qryptive-guard.json`.
- To remove the hooks: run `qryptive_guard.py uninstall claude-code|cursor|git` from the
  repository. Uninstalling the plugin does not remove them, so run uninstall first.
