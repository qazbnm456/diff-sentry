# Changelog

All notable changes to diff-sentry, a BewAIre-style detector that classifies one GitHub change
(PR, issue or push) for malicious intent on [`rlm-harness`](https://github.com/qazbnm456/rlm-harness).

## Unreleased

### Changed
- **`rlm-harness==1.14.0`, which requires `dspy>=3.4.0,<3.5.0` and `pydantic>=2.11.0`** (from 1.10.1,
  dspy 3.3.1). diff-sentry's own `pydantic` floor rises to match.
- **Each exported action's `state` lists its prior actions in causal order** (interleaved by time)
  instead of write order; labels, rubric facts and the SIEM signal are unchanged.
- **A failed analyst escalation is recorded**: the trace gains a `sub_call` carrying the provider's
  error and `cause: "endpoint"`. The new `analyst_failures` metric counts them (None for a trace
  written before rlm-harness 1.13.0, which could not record them), and `analyst_calls` keeps counting
  only escalations that got a response, so it means the same on traces from either side of the upgrade.
- **The agent guide is `AGENTS.md` (formerly `CLAUDE.md`)**, which Claude Code 2.1.277+ and other coding
  agents read natively. Area-specific invariants moved to path-scoped `.claude/rules/`, and the release
  procedure to `.claude/skills/release`.

### Added
- **The studio's run telemetry flags refused analyst escalations**: the analyst tile turns amber and an
  "N analyst escalations refused" chip appears; a trace too old to record refusals shows neither.

### Fixed
- **The studio feed shows a refused analyst escalation as "Ask analyst failed"** with the provider's
  error, instead of rendering it like one that answered.
- **The studio replays a run in causal order**: a turn's reasoning streams before the tool calls it
  made, and `run_end` always streams last, even when a timestamp is missing, NaN or infinite.
- **CI's consumer-install job fails when the published version cannot be installed**, instead of
  passing green because the negative scan check also exits 1.

### Docs
- **Docs, comments and test docstrings state current facts only**, and claims that had drifted from the
  code are corrected (studio replay order, `RefusalInfo` reasons, where CI resolves rlm-harness).

## 0.4.3

Dependencies only: the `diff_sentry` package itself is unchanged.

### Changed
- **`rlm-harness==1.10.1` and `dspy` 3.3.1** (from 1.0.0 and 3.2.1); the pin stays exact, and a fresh
  install resolves fewer packages because dspy 3.3 drops several exact pins.
- **Traces record more of each run** (the kit version in `run_start`; applied `budgets`, per-attempt
  `usage` and the failed run's `error_chain` in `run_end`; `duration_s` on every tool call and
  `sub_call`), while labels, metrics, rubric facts and the SIEM signal are derived exactly as before.
- **A non-retryable LM error (auth, billing, configuration, unsupported model) fails after one attempt
  and the `status=failed` response names the dspy error class**, so a credential problem reads
  differently from a model that kept producing invalid output (`RLMTaskError`).
- **The studio's "took" label on a tool call shows the recorded `duration_s`**, falling back to the
  event gap only for older traces.

### Fixed
- **An analyst escalation appears in the trace and the exported datasets exactly once.**
- **The analyst intercept handles dspy 3.3's typed `LMResponse`.**
- **A payload containing an unpaired surrogate is recorded** instead of being dropped from the trace.

### Docs
- **`CLAUDE.md` lists all five version sites a release moves**, noting that
  `release.yml` does not gate the README's `uses:` line.

## 0.4.2

### Fixed
- **Paired rules (`pwn-request`, `detached-process-spawn`) only pair signals from the same file**, in both
  the in-loop `scan_indicators` tool and the host-side baseline, so two unrelated files can no longer
  compose a `critical` that neither contains.

### Changed
- **`astral-sh/setup-uv` v10.0.1 and `actions/checkout` v7**, for the Node 24 runtime; the setup-uv bump
  also applies inside `action.yml`, so repos running the action stop seeing the Node 20 deprecation
  warning.

### Added
- **`pwn-request` flags `allow-unsafe-pr-checkout: true` under a privileged trigger** as its third
  checkout form, with its own title; an explicit `false`, a removed opt-in, or a plain `pull_request`
  trigger does not fire.
- **Each hit names the file it came from** instead of the whole diff.
- **A hit id is the same whether the diff was scanned whole or one file at a time**, so the baseline and
  an in-loop re-scan de-duplicate to one piece of evidence.

## 0.4.1

### Changed
- **`pypa/gh-action-pypi-publish` v1.14.2**, whose Twine 7 accepts the core metadata 2.5 that `uv build`
  now emits.

### Fixed
- **`pwn-request` fires only when the PR-head expression reaches a checkout** (an `actions/checkout`
  `ref:` or a `git checkout` / `git fetch` / `gh pr checkout` command), so the safe `workflow_run`
  publisher shape the README recommends stays at the sub-floor `privileged-fork-trigger`.
- **`pwn-request` follows one binding hop**, catching a head SHA bound to a name and then used as
  `ref: ${{ env.HEAD }}`.
- **A hand-rolled fetch of `refs/pull/${{ github.event.number }}/head` is detected.**

## 0.4.0

The first release, led by a GitHub Action anyone can install; the local model pipeline, studio and
trajectory export remain for teams that run that infrastructure.

### Added
- **diff-sentry ships as a GitHub Action** (`action.yml`, with inputs `fail-on`, `report-only-paths`,
  `base-sha`, `version` and outputs `failed`, `hit-count`, `max-severity`, `report`) that runs only the
  deterministic scan, so it needs no credentials, network or Deno and runs safely on fork PRs under the
  read-only token.
- **A `scan` subcommand and a `diff-sentry` console entry point** run the deterministic scan standalone;
  `--fail-on` defaults to the SIEM signal floor, with `--json` and `--include-deletions` options.
- **Ten indicator rules for the Miasma attack families**: `pwn-request`, `privileged-fork-trigger`,
  `diff-viewport-evasion`, `invisible-unicode`, `detached-process-spawn`, `inline-code-exec`,
  `remote-fetch-to-disk`, `obfuscated-identifiers`, and the sub-floor corroborators `dynamic-code-eval`
  and `content-addressed-host`, each with a negative case in the corpus.
- **A `self-scan` CI job** runs this repo's own Action on every PR.
- **`release.yml` publishes to PyPI through OIDC Trusted Publishing** after installing the built wheel
  cleanly and checking that the tag, wheel filename and `__version__` agree.

### Changed
- **`rlm-kit` is replaced by `rlm-harness==1.0.0` from PyPI**; imports move to `rlm_harness`.
- **The rubric uses `rlm_harness.rubric`**, and `schema` still re-exports `Criterion`, `CriterionFact`
  and `RubricCriteria`.
- **The README and package description lead with the Action.**
- **A bare `uv sync` installs the `subscription-sdk` dev group**, keeping the Claude Agent SDK in the dev
  environment.
- **CI pins ruff to `0.16.0`.**

### Fixed
- **`scan` ignores lines a diff deletes by default**, so a commit that removes a payload is not flagged
  for it.

## 0.3.0

### Added
- **An input with no assessable content yields `inconclusive`** (`status="inconclusive"`,
  `reason="insufficient_evidence"`) instead of a confident verdict, enforced by a host-side backstop and
  exported as a reward-free `inconclusive` label; hard indicator evidence still forces a SIEM signal.
- **The studio shows the short fields of an unrecognized tool call** in the drawer, the live feed and the
  trajectory view instead of an empty step, and `deep_classify` keeps a child-rollout link when its
  backend returns one.

## 0.2.1

### Fixed
- **The studio starts on a subscription with the same command as the sibling harnesses**, through a new
  `subscription` extra on `diff-sentry-studio`.
- **`/v1/config` no longer shows a subscription analyst as the classifier**, since no run can use one.

## 0.2.0

### Added
- **The planner and analyst can run on a Claude Pro/Max subscription** by setting `DS_ROOT_LM` /
  `DS_SUB_LM` to `claude-agent-sdk/<model>`; this needs `uv sync --extra subscription`, a logged-in
  Claude Code CLI and no `ANTHROPIC_API_KEY`.
- **The studio has a page-height, three-column layout with a Verdict / Indicators / Change switch**,
  and the Change view reads the normalized content from the run's own trace.

### Changed
- **The classifier must stay on an OpenAI-compatible endpoint**: `config.from_env` rejects a
  `claude-agent-sdk/…` classifier, set directly or inherited from `DS_SUB_LM`, so a subscription-only
  run is not supported.

## 0.1.0

The initial release: classify a change into a judgement-only verdict, union the deterministic indicator
evidence on read (MF3), build the response, emit the SIEM signal host-side, and export reward-free
trajectories, all testable offline. Includes the metadata sandwich (MF1), the GitHub-allowlisted opt-in
enrichment fetch (MF2), the pure-Python indicator suite, the `deep_classify` second-stage seam,
progressive-disclosure attack skills, an offline hackerbot-claw reproduction, and the studio console.
