# diff-sentry

**Catch a malicious pull request before you merge it.**

diff-sentry reads a change the way an attacker hopes you won't: it treats the diff as untrusted data, looks for the shapes that real supply-chain attacks use, and reports evidence rather than an opinion.

The fastest way to use it is as a GitHub Action. It needs no API key, no model, and no network access, so it runs on fork pull requests under the read-only token they already get.

```yaml
# .github/workflows/diff-sentry.yml
name: diff-sentry
on: pull_request

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with:
          fetch-depth: 0          # the scan diffs against the PR base
      - uses: qazbnm456/diff-sentry@v0.15.0
```

That is the whole setup. The job fails when an indicator at or above `high` fires. Add `push` to `on:` to also scan commits pushed straight to a branch. A push that bypasses branch protection can also delete this workflow, so `watch` and `release-watch` read the repository and its releases from outside.

## What it catches

| Family | Examples |
|---|---|
| Workflow configuration | `pull_request_target` that checks out the PR head (the pwn-request that broke AsyncAPI) by `ref:`, by a hand-rolled `git fetch`, or by opting back in with `allow-unsafe-pr-checkout: true`; a workflow pointed at a lookalike of your own GitHub owner (the litellm release built from `Berri-AI/litellm`); plus `permissions: write-all` and CODEOWNERS reassignment |
| Obfuscation | base64 that decodes to a shell payload, `_0x…` machine-mangled JavaScript, high-entropy blobs |
| Execution | pipe-to-shell installs, `${IFS}` space-evasion, detached child processes, inline `node -e`, fetch-to-disk droppers, Python startup hooks (`.pth`, `sitecustomize.py`), packed or downloaded code run with `exec` |
| Exfiltration | secrets reaching a network sink, cross-process `/proc/<pid>/mem` reads, OAST callback services, IPFS and permaweb gateways |
| Diff-presentation evasion | payloads shoved past the viewport by a long whitespace run, bidi-override and zero-width characters |
| Provenance | forged `[bot]` identities, bot-mimicking new accounts, accounts created days before the event, profiles that describe an autonomous agent, unsigned or identity-mismatched commits, a fork deleted after the PR |
| Author-controlled channels | a PR branch name carrying shell syntax, slash-command comments that fire `issue_comment` workflows (weighed by what the repository's own workflows answer) |
| Campaign memory (`watch` only) | an account or payload host already flagged in another repository, an edit that removes a flagged payload, a burst of changes from a new account |
| Prompt injection | instructions aimed at an LLM reviewer or triage workflow |

A plain workflow edit, or a `pull_request_target` on its own, is `medium`, below the failure threshold, so a benign workflow PR does not break your build. Deleted lines are not scanned, so removing a payload is not flagged. [How it works](docs/how-it-works.md#severities-are-tuned-against-noise) explains the tuning.

## Inputs

| Input | Default | Purpose |
|---|---|---|
| `fail-on` | `high` | Severity that fails the build (`info`/`low`/`medium`/`high`/`critical`). |
| `report-only-paths` | none | Newline-separated globs scanned but never gated. For files whose job is to carry attack patterns: rule bodies, security fixtures, prompt templates, docs that tabulate payloads. |
| `base-sha` | derived | Override the commit to diff against. |
| `version` | matches the action tag | The diff-sentry release to install from PyPI. `local` installs from the current checkout instead, which is how this repo scans its own PRs with the rules in that PR. |

Outputs: `failed`, `hit-count`, `max-severity`, and `report` (a JSON path).

## Do not reach for `pull_request_target`

Sooner or later you will want the scan to post its results as a PR comment, and a `pull_request` job on a fork PR has a read-only token. The tempting fix is `pull_request_target`, which is the exact misconfiguration that opened the AsyncAPI "Miasma" compromise, and which this action reports as `critical`.

Do it the safe way instead: keep the scan on `pull_request` with no secrets, upload the `report` as an artifact, and post it from a separate `workflow_run` job that runs the base branch's code and never checks out the PR head. diff-sentry's own rules make the same distinction, so the safe shape does not trip them.

## Evidence a model cannot suppress

An LLM reviewer can be argued out of its conclusion by the diff it reads. The Action runs no model at all. In the full pipeline, the rules record their hits before any model takes a turn, and the alert is derived from those hits, so a prompt injection can skew a verdict but cannot remove the evidence ([details](docs/how-it-works.md#evidence-a-model-cannot-suppress)).

## Beyond the Action

https://github.com/user-attachments/assets/d200aee8-263b-483e-ad55-f90ae69f3ab0

_The studio console: paste a real payload, watch the detection stream live, then read the evidence-framed verdict._

If you operate the infrastructure, or maintain a project where a wrong call is expensive, the rest of the system runs locally with a model endpoint you choose:

- **Deep classification**: a reasoning model reads a PR, issue or push in a sandbox and returns a verdict next to the evidence. See [How it works](docs/how-it-works.md).
- **The studio**: a local console that streams a run as it happens. See [`studio/README.md`](studio/README.md).
- **Watch**: monitors a list of repositories, alerts the moment the rules fire, and remembers the accounts and payload hosts it has seen. See [Watching a watchlist](docs/watch.md).
- **Release watch**: compares each new release of the PyPI and npm packages you depend on with the release before it, and alerts when it carries a startup hook, a packed loader or a new install script, or was published without its usual provenance. See [Watching releases](docs/release-watch.md).
- **Trajectories for training**: every run is recorded, and `export` turns the traces into a reward-free dataset for fine-tuning a smaller planner. See [The full pipeline](docs/how-it-works.md#the-full-pipeline).

None of this is needed for the Action, and none of it sends your code anywhere you did not configure yourself.

## Limits

A strong prompt injection can skew a model's verdict, though never the evidence. Some pipe-to-shell shapes, and a secret that reaches a network call across lines, are missed. An external watcher cannot stop an attack that fires the moment a PR opens. [Honest limits](docs/limits.md) lists the known gaps.

## Documentation

- [How it works](docs/how-it-works.md): severity tuning, the evidence union, the full pipeline, running it locally, and the incidents the tests reconstruct.
- [Watching a watchlist](docs/watch.md): the monitor, its alerts, its archive, and what the account dossier holds.
- [Watching releases](docs/release-watch.md): comparing each new PyPI or npm release, and each container image, with what came before.
- [Honest limits](docs/limits.md): what the rules and the pipeline do not see.
- [Development](docs/development.md): the test suites and CI.
- [CHANGELOG](CHANGELOG.md)

## License

MIT. Built on [`rlm-harness`](https://github.com/qazbnm456/rlm-harness).
