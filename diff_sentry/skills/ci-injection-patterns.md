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
