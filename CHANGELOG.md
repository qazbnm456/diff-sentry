# Changelog

All notable changes to diff-sentry, a BewAIre-style detector that classifies one GitHub change (PR, issue or push) for malicious intent on [`rlm-harness`](https://github.com/qazbnm456/rlm-harness).

## 0.7.1

Upgrade from 0.7.0: `rlm-harness==1.22.0`. The GitHub Action's scan is unchanged; the model pipeline (`pr`, `issue`, `classify`, `watch`) raises fewer false signals on documentation changes and stops calling a misconfigured classifier sooner. Nothing needs configuring.

### Changed
- **A classifier endpoint that answers 400, 401, 403, 404 or 422 is called once**, not retried, and counts toward the circuit breaker, so a wrong model name, key or request stops being called. Timeouts, 429 and 5xx are retried as before. The eval judge does the same for 401, 403 and 404.
- **A planner run that fails on an unparseable reply quotes the reply as the model wrote it**, and says so when the reply carried only reasoning.
- **`rlm-harness==1.22.0`.**
- **The README covers using diff-sentry**; how it works, the watcher, the known limits and development moved to `docs/`.

### Fixed
- **A planner re-scan of a slice of a documentation patch is softened as the scan of that file is**, so a README change that adds a documented installer and removes an indented line no longer signals as `critical`.

## 0.7.0

Upgrade from 0.6.0: `rlm-harness==1.20.0` and `dspy` 3.4.1. The signal now reads only the evidence the planner grounded in the change, and several rules read lower or higher than before, so a SIEM that alerts on severity sees fewer false signals and some new ones (see **Changed**). Nothing needs configuring; the new `DS_*` settings are optional.

### Added
- **Rules for the dev-machine loader shape** (the PolinRider / Contagious Interview family): a font or image file handed to a runtime (`asset-run-as-code`, `critical`), obfuscated code in a developer tool's config (`obfuscated-dev-config`, `critical`), javascript-obfuscator's string array (`obfuscated-string-array`), a text patch under a binary name, a VS Code task that runs on folder open, and an npm script or task that runs a file the change adds (`run-entry-new-file`, `high` when it rides in front of the old command or runs from a lifecycle hook or a folder-open task).
- **`watch --workers N`** (`DS_WATCH_WORKERS`) runs several model runs at once, each in a process of its own.
- **Per-role request parameters**: `DS_ROOT_LM_KWARGS` and `DS_SUB_LM_KWARGS` (or rlm-harness's `RLM_MAIN_LM_KWARGS` / `RLM_SUB_LM_KWARGS`) reach the planner and the analyst, for example a vLLM thinking budget below the token cap. `DS_CLASSIFIER_LM_KWARGS` does the same for the classifier. Keys the settings own, and keys the client does not take, are refused when the configuration loads.
- **The response and the SIEM payload carry `floor_indicator_severity`**, the severity the signal reads.

### Changed
- **The signal reads only grounded evidence.** A planner scan counts toward the floor only when its text is copied from the change (a file rebuilt without its diff markers included) or decoded from it; a scan of text the planner wrote stays in the evidence, marked `grounded: false`. `max_indicator_severity` still covers every hit.
- **A large change gets a verdict instead of `inconclusive`** when it has content and GitHub withheld nothing.
- **`command-substitution` reads the kind of file it is in.** A template literal in source code no shell reads counts only beside a call that starts a program, and a plain code span in prose is formatting. Titles, branch names and shell-read files keep every hit.
- **`inline-code-exec` (`node -e`) is `medium` in an issue body or comment an OWNER, MEMBER or COLLABORATOR wrote**; titles, files and outsiders' text stay `high`.
- **`inline-code-exec` also finds `node` and `-e` split over lines** (a YAML folded scalar, including one whose `-e` line was rewritten), a wrapped `spawn(process.execPath, ['-e', ...])` and escapes in front of `node`; a `node -e` that only a removed line holds no longer counts.
- **`invisible-unicode` is `medium` for direction marks a mail client writes in an Arabic or Hebrew reply** (embeddings and isolates opened after right-to-left text, in a body or comment). Overrides, zero-width and tag characters stay `high`.
- **The bare phrase "system prompt" in an agent instruction file** (`AGENTS.md`, `CLAUDE.md`, `.cursorrules` and the like) is `high` instead of `medium`.
- **A classifier reply cut at `max_tokens` says so**, is not re-sent, counts toward the circuit breaker, and is recorded as `cut: true`.
- **The planner's skills are rewritten by attack surface** (CI, package and build hooks, developer-machine autorun, droppers and exfiltration, text an LLM reads, concealment and provenance); a hidden note is judged by what it asks an agent to do.
- **`rlm-harness==1.20.0` and `dspy` 3.4.1**, with sandbox sub-agents off so one change stays one trajectory.

### Fixed
- **A watcher stopped mid-run neither strands nor double-runs a change.**

## 0.6.0

Upgrade from 0.5.0: the scan now reads the branch name, the author's and outsiders' comments and the account's history, and rates some documentation text lower, so a SIEM that alerts on severity sees both more and fewer signals than before (see **Changed**). Nothing needs configuring; `watch` and its settings are opt-in, and `rlm-harness==1.14.0` is unchanged.

### Added
- **`diff-sentry watch` monitors a watchlist of repositories**: it polls, screens every change deterministically, orders the queue by that screen, and runs one model trajectory per change on a single worker. The SIEM gets an early alert (`stage: "screen"`) once deterministic evidence reaches the signal floor and the model's signal (`stage: "final"`) under the same `run_id`; a change the model never judged is `status="inconclusive"` with `reason="not_escalated"`. `--screen-only` needs no model credentials, and the `DS_WATCH_*` settings in `.env.example` leave the queue and hourly caps off by default.
- **An actor store remembers what each account did before**, and `diff-sentry actor <login>` prints its dossier. It reaches the signal only through five indicators: `actor-known-bad` and `ioc-reuse` (`high`), and `actor-prior-flag`, `actor-burst` and `actor-multi-repo` (`medium`).
- **A snapshot archive keeps the first copy of every change and each edit as a new revision**; `diff-sentry archive verify` re-hashes it and `archive show <sha>` prints a capture. `evidence-scrubbed` (`high`) fires when floor-level evidence from an earlier revision is gone after an edit, and `content-edited` (`low`) records any other edit.
- **The head branch name and the comments of the change's author or an outsider (not maintainers or bots) are scanned**, because the author controls them and no diff holds them. `branch-name-injection` flags shell syntax in a branch name (`high`, `medium` for an owner, member or collaborator), `branch-name-metachar` flags metacharacters (`medium`), and `slash-command-trigger` flags a slash command in a comment (`medium` when the author types it within an hour of opening the change, otherwise `low`). A hit from a comment names the commenter in the new `via` field.
- **Four more provenance indicators, all `medium`**: `brand-new-account` (under 14 days old), `agent-self-description` (an unestablished account whose profile calls it an autonomous or LLM-driven agent), `head-repo-deleted` and `files-not-fully-read` (a PR with more files than GitHub lists).
- **`curl-pipe-shell` is `critical` in more spellings**: `bash <(curl ...)`, `bash -c "$(curl ...)"`, PowerShell's `iwr ... | iex`, a pipe into `sudo bash` or `python3 -`, commands that are quoted, wrapped, joined across lines or written in Markdown or HTML.
- **`invisible-unicode` also covers Unicode tag characters, the variation-selector supplement, the Hangul fillers and the word joiner.**
- **A detector that raises is recorded as a `high` `scanner-error` hit** while the other detectors still run.
- **An opt-in shell oracle** (`DS_ORACLE=1 uv run pytest tests/test_oracle.py`, needs Docker) holds the download rules to what real `bash` and `dash` run in a no-network container.

### Changed
- **A documented installer in prose is `medium` instead of `critical`**: the uv, nvm or rustup one-liner in a README, a PR body or a comment no longer raises a signal. The same text in a code file, from another host, with other flags, or inside a wrapper such as `ssh host '...'` stays `critical`.
- **A bare "system prompt" is `medium` instead of `high`**; an override phrase (`ignore previous instructions`) stays `high`.
- **`pwn-request` shown in a body, a comment or a documentation file is `medium`**; in a workflow file it stays `critical`. `diff-viewport-evasion` is `medium` in a comment and stays `high` in a file.
- **A zero-width space right after `@` no longer fires `invisible-unicode`**, because Dependabot renders `@user` that way.
- **A SIEM payload lists the 100 most severe indicators** and gains `stage` and `indicator_count`; the full list stays in the response file. Hits are capped at 25 per rule, place and title, most severe first, so decoys cannot push out the `critical` behind them.

### Fixed
- **A hit built from text with a lone surrogate (a JSON `\ud800` escape) serializes**, so the change that carried it is no longer lost.

### Docs
- **`.claude/rules/indicators.md` lists the installer softening's accepted over-alerts and known gaps.** The softening is a brake on false positives, not a proof.

## 0.5.0

Upgrade from 0.4.3: dspy 3.4.0 removed the interface rlm-harness 1.10.1 hands its sandbox through, so a fresh 0.4.3 install resolves dspy 3.4.0 and every `pr` / `issue` / `classify` run fails with a `TypeError`. The Action's deterministic `scan` is unaffected. 0.5.0 pins `rlm-harness==1.14.0`, which caps dspy below 3.5.

### Changed
- **`rlm-harness==1.14.0`, which requires `dspy>=3.4.0,<3.5.0` and `pydantic>=2.11.0`** (from 1.10.1, dspy 3.3.1). diff-sentry's own `pydantic` floor rises to match.
- **Each exported action's `state` lists its prior actions in causal order** (interleaved by time) instead of write order; labels, rubric facts and the SIEM signal are unchanged.
- **A failed analyst escalation is recorded**: the trace gains a `sub_call` carrying the provider's error and `cause: "endpoint"`. The new `analyst_failures` metric counts them (None for a trace written before rlm-harness 1.13.0, which could not record them), and `analyst_calls` keeps counting only escalations that got a response, so it means the same on traces from either side of the upgrade.
- **The agent guide is `AGENTS.md` (formerly `CLAUDE.md`)**, which Claude Code 2.1.277+ and other coding agents read natively. Area-specific invariants moved to path-scoped `.claude/rules/`, and the release procedure to `.claude/skills/release`.

### Added
- **The studio's run telemetry flags refused analyst escalations**: the analyst tile turns amber and an "N analyst escalations refused" chip appears; a trace too old to record refusals shows neither.

### Fixed
- **The studio feed shows a refused analyst escalation as "Ask analyst failed"** with the provider's error, instead of rendering it like one that answered.
- **The studio replays a run in causal order**: a turn's reasoning streams before the tool calls it made, and `run_end` always streams last, even when a timestamp is missing, NaN or infinite.
- **CI's consumer-install job fails when the published version cannot be installed**, instead of passing green because the negative scan check also exits 1.

### Docs
- **Docs, comments and test docstrings state current facts only**, and claims that had drifted from the code are corrected (studio replay order, `RefusalInfo` reasons, where CI resolves rlm-harness).

## 0.4.3

Dependencies only: the `diff_sentry` package itself is unchanged.

### Changed
- **`rlm-harness==1.10.1` and `dspy` 3.3.1** (from 1.0.0 and 3.2.1); the pin stays exact, and a fresh install resolves fewer packages because dspy 3.3 drops several exact pins.
- **Traces record more of each run** (the kit version in `run_start`; applied `budgets`, per-attempt `usage` and the failed run's `error_chain` in `run_end`; `duration_s` on every tool call and `sub_call`), while labels, metrics, rubric facts and the SIEM signal are derived exactly as before.
- **A non-retryable LM error (auth, billing, configuration, unsupported model) fails after one attempt and the `status=failed` response names the dspy error class**, so a credential problem reads differently from a model that kept producing invalid output (`RLMTaskError`).
- **The studio's "took" label on a tool call shows the recorded `duration_s`**, falling back to the event gap only for older traces.

### Fixed
- **An analyst escalation appears in the trace and the exported datasets exactly once.**
- **The analyst intercept handles dspy 3.3's typed `LMResponse`.**
- **A payload containing an unpaired surrogate is recorded** instead of being dropped from the trace.

### Docs
- **`CLAUDE.md` lists all five version sites a release moves**, noting that `release.yml` does not gate the README's `uses:` line.

## 0.4.2

### Fixed
- **Paired rules (`pwn-request`, `detached-process-spawn`) only pair signals from the same file**, in both the in-loop `scan_indicators` tool and the host-side baseline, so two unrelated files can no longer compose a `critical` that neither contains.

### Changed
- **`astral-sh/setup-uv` v10.0.1 and `actions/checkout` v7**, for the Node 24 runtime; the setup-uv bump also applies inside `action.yml`, so repos running the action stop seeing the Node 20 deprecation warning.

### Added
- **`pwn-request` flags `allow-unsafe-pr-checkout: true` under a privileged trigger** as its third checkout form, with its own title; an explicit `false`, a removed opt-in, or a plain `pull_request` trigger does not fire.
- **Each hit names the file it came from** instead of the whole diff.
- **A hit id is the same whether the diff was scanned whole or one file at a time**, so the baseline and an in-loop re-scan de-duplicate to one piece of evidence.

## 0.4.1

### Changed
- **`pypa/gh-action-pypi-publish` v1.14.2**, whose Twine 7 accepts the core metadata 2.5 that `uv build` now emits.

### Fixed
- **`pwn-request` fires only when the PR-head expression reaches a checkout** (an `actions/checkout` `ref:` or a `git checkout` / `git fetch` / `gh pr checkout` command), so the safe `workflow_run` publisher shape the README recommends stays at the sub-floor `privileged-fork-trigger`.
- **`pwn-request` follows one binding hop**, catching a head SHA bound to a name and then used as `ref: ${{ env.HEAD }}`.
- **A hand-rolled fetch of `refs/pull/${{ github.event.number }}/head` is detected.**

## 0.4.0

The first release, led by a GitHub Action anyone can install; the local model pipeline, studio and trajectory export remain for teams that run that infrastructure.

### Added
- **diff-sentry ships as a GitHub Action** (`action.yml`, with inputs `fail-on`, `report-only-paths`, `base-sha`, `version` and outputs `failed`, `hit-count`, `max-severity`, `report`) that runs only the deterministic scan, so it needs no credentials, network or Deno and runs safely on fork PRs under the read-only token.
- **A `scan` subcommand and a `diff-sentry` console entry point** run the deterministic scan standalone; `--fail-on` defaults to the SIEM signal floor, with `--json` and `--include-deletions` options.
- **Ten indicator rules for the Miasma attack families**: `pwn-request`, `privileged-fork-trigger`, `diff-viewport-evasion`, `invisible-unicode`, `detached-process-spawn`, `inline-code-exec`, `remote-fetch-to-disk`, `obfuscated-identifiers`, and the sub-floor corroborators `dynamic-code-eval` and `content-addressed-host`, each with a negative case in the corpus.
- **A `self-scan` CI job** runs this repo's own Action on every PR.
- **`release.yml` publishes to PyPI through OIDC Trusted Publishing** after installing the built wheel cleanly and checking that the tag, wheel filename and `__version__` agree.

### Changed
- **`rlm-kit` is replaced by `rlm-harness==1.0.0` from PyPI**; imports move to `rlm_harness`.
- **The rubric uses `rlm_harness.rubric`**, and `schema` still re-exports `Criterion`, `CriterionFact` and `RubricCriteria`.
- **The README and package description lead with the Action.**
- **A bare `uv sync` installs the `subscription-sdk` dev group**, keeping the Claude Agent SDK in the dev environment.
- **CI pins ruff to `0.16.0`.**

### Fixed
- **`scan` ignores lines a diff deletes by default**, so a commit that removes a payload is not flagged for it.

## 0.3.0

### Added
- **An input with no assessable content yields `inconclusive`** (`status="inconclusive"`, `reason="insufficient_evidence"`) instead of a confident verdict, enforced by a host-side backstop and exported as a reward-free `inconclusive` label; hard indicator evidence still forces a SIEM signal.
- **The studio shows the short fields of an unrecognized tool call** in the drawer, the live feed and the trajectory view instead of an empty step, and `deep_classify` keeps a child-rollout link when its backend returns one.

## 0.2.1

### Fixed
- **The studio starts on a subscription with the same command as the sibling harnesses**, through a new `subscription` extra on `diff-sentry-studio`.
- **`/v1/config` no longer shows a subscription analyst as the classifier**, since no run can use one.

## 0.2.0

### Added
- **The planner and analyst can run on a Claude Pro/Max subscription** by setting `DS_ROOT_LM` / `DS_SUB_LM` to `claude-agent-sdk/<model>`; this needs `uv sync --extra subscription`, a logged-in Claude Code CLI and no `ANTHROPIC_API_KEY`.
- **The studio has a page-height, three-column layout with a Verdict / Indicators / Change switch**, and the Change view reads the normalized content from the run's own trace.

### Changed
- **The classifier must stay on an OpenAI-compatible endpoint**: `config.from_env` rejects a `claude-agent-sdk/…` classifier, set directly or inherited from `DS_SUB_LM`, so a subscription-only run is not supported.

## 0.1.0

The initial release: classify a change into a judgement-only verdict, union the deterministic indicator evidence on read (MF3), build the response, emit the SIEM signal host-side, and export reward-free trajectories, all testable offline. Includes the metadata sandwich (MF1), the GitHub-allowlisted opt-in enrichment fetch (MF2), the pure-Python indicator suite, the `deep_classify` second-stage seam, progressive-disclosure attack skills, an offline hackerbot-claw reproduction, and the studio console.
