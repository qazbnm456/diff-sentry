# Changelog

All notable changes to diff-sentry. This project classifies ONE GitHub change (PR/issue/push) for
malicious intent — the diff held as **untrusted data** in a sandboxed REPL, a judgement-only verdict,
and deterministic indicator evidence unioned on read into a SIEM signal — as a traced, improvable RLM
framework on [`rlm-harness`](https://github.com/qazbnm456/rlm-harness) (a BewAIre-style detector).

## Unreleased

### Fixed
- **The scan is scoped per file.** `scan_indicators` reads whatever it is handed as one string, and the
  action hands it the whole `git diff`. Most rules fire on a single match, so that was harmless — but
  two need a PAIR of signals (`pwn-request`: privileged trigger + PR-HEAD checkout;
  `detached-process-spawn`: detached spawn + `child_process`), and a whole-blob read let those pair
  ACROSS FILES. A `workflow_run:` added to one workflow plus a `ref: ${{ ... head.sha }}` sitting in a
  doc example, a test fixture, or the very workflow a change is *deleting*, composed into a `critical`
  that no single file contained. The new `scan_diff` splits a unified diff on its file headers and
  scans each segment on its own; non-diff input (a region the planner pulled out of the REPL, a plain
  file) falls through to the previous whole-text scan. Used by `scan`, by the host-side baseline, and
  by the in-loop `scan_indicators` tool, so all three agree.

### Added
- **Hits name the file they came from.** `location` was the name of the whole diff — `gated.diff` for
  every hit, which meant reading the raw log to find out where a finding actually was. Per-file
  scanning gives each hit its real path.
- **A hit id is now stable between a whole-diff scan and a single-file scan.** The segment the planner
  pulls out is byte-identical to the one the baseline scanned, so the evidence snippets — and therefore
  the ids — match, and the two de-duplicate to one union member on read. Whole-blob scanning could not
  promise that: the snippet window moved with the byte offset.

## 0.4.1

A correctness release for one rule: `pwn-request` was failing the very pattern this
project's README tells people to use.

### Changed
- **`pypa/gh-action-pypi-publish` bumped to v1.14.2** (from v1.14.0). `uv build` now emits core
  metadata 2.5, and the twine bundled in v1.14.0 rejects it — `InvalidDistribution: '2.5' is not a
  valid metadata version` — so the first attempt at this release built cleanly and then failed at
  the upload step. v1.14.2 carries Twine 7, which accepts metadata 2.5.

### Fixed
- **`pwn-request` no longer fires on a workflow that merely READS the PR head.** The rule paired a
  privileged trigger with a PR-HEAD *mention* anywhere in the text and called that a checkout, so the
  validating-publisher shape — `workflow_run`, head SHA in an env var, checkout pinned to the default
  branch — was graded `critical`, identically to the attack. That is the shape README.md tells people to
  use, next to the sentence "diff-sentry's own rules make the same distinction, so the safe shape does
  not trip them"; it did trip them. Escalation now requires the expression to actually reach a checkout:
  an `actions/checkout` `ref:` value, or a `git checkout`/`git fetch`/`gh pr checkout` command. A bare
  mention keeps the sub-floor `medium` `privileged-fork-trigger`, cited at the reference rather than the
  trigger line so a reviewer still lands on the spot worth reading. Found by running the action against
  a real publisher workflow.
- **`pwn-request` now follows one binding hop.** `HEAD: ${{ github.event.pull_request.head.sha }}`
  followed by `ref: ${{ env.HEAD }}` is the same attack split across two lines. Requiring the expression
  to sit on the `ref:` line would have turned the fix above into a free bypass, so a name bound to the
  head expression is tracked and a `ref:` that reads it counts as the checkout.
- **`refs/pull/…` matching tolerates interpolation.** `refs/pull/${{ github.event.number }}/head` — the
  form that actually appears in the wild — was missed, because the character class stopped at the space
  inside the expression. A hand-rolled `git fetch` of the PR head is caught now.

## 0.4.0

The first release, and a repositioning: the front door is now a GitHub Action anyone installs in fifteen
lines, with the trajectory/studio/fine-tuning half kept as the second goal for people who run the
infrastructure themselves.

### Added
- **Ships as a GitHub Action** (`action.yml`, a composite action at the repo root, which is what
  Marketplace requires). Inputs `fail-on` / `report-only-paths` / `base-sha` / `version`; outputs
  `failed` / `hit-count` / `max-severity` / `report`. It runs the DETERMINISTIC scan, never the model
  pipeline, and that is the load-bearing choice: `classify` needs `DS_*` creds, and the only mechanism
  that puts creds into a fork PR's run is `pull_request_target` — the exact misconfiguration that opened
  the AsyncAPI "Miasma" compromise and that this action reports as `critical`. The scan needs no creds,
  no network and no Deno, so it runs under the read-only token a fork PR already gets. `report-only-paths`
  is an input rather than a fixed list because the paths that legitimately carry attack patterns differ
  per repo. The README documents the safe way to comment back on a fork PR (artifact plus a `workflow_run`
  job that never checks out the PR head), because shipping a detector whose own docs recommend the hole it
  detects would distribute that hole at scale.
- **`scan` subcommand** (`cli._cmd_scan`) — the deterministic half standalone, with no model, network,
  creds or Deno. `--fail-on` defaults to `SIGNAL_SEVERITY_FLOOR`, so the CI gate honours the same tuning a
  SIEM signal derives from and a plain workflow edit (`medium`, on purpose) does not fail a build.
  `--json` for machine consumption, `--include-deletions` to audit what a change removed.
- **A `diff-sentry` console entry point** (`[project.scripts]`). There was none, so `uvx diff-sentry` —
  the exact command the Action runs — could not have worked at all.
- **Ten indicator rules covering the Miasma families.** Reconstructing that chain stage by stage found
  seven of its eight stages passing the suite silently, because the rules were shell- and YAML-shaped
  while the attack was Node end to end. Added: `pwn-request` (critical) and `privileged-fork-trigger`
  (medium) for workflow CONFIGURATION as distinct from `workflow-tamper`'s "was a workflow touched";
  `diff-viewport-evasion` and `invisible-unicode` for payloads aimed at the human reading the diff;
  `detached-process-spawn`, `inline-code-exec` and `remote-fetch-to-disk` for Node execution primitives;
  `obfuscated-identifiers` for `_0x…` mangling that base64 detection cannot see; `dynamic-code-eval` and
  `content-addressed-host` (IPFS/permaweb) as sub-floor corroborators. The tuning is the load-bearing
  part: rules that would be noisy alone require two halves to fire, and every rule ships with its negative
  case. Corpus grows by nine entries (six malicious families, three benigns pinning the sub-floor tiers).
- **`self-scan` CI job** — this repo runs the Action it publishes (`uses: ./`, `version: local`), so every
  PR is an integration test of what users install, scanned by the rules in that PR rather than the ones
  already on main. It caught a real defect on its first run.
- **`release.yml`** — PyPI publish over OIDC Trusted Publishing, no API token, with a fork guard on the
  publish job. It verifies the ARTIFACT rather than the checkout: the built wheel is installed into a
  clean environment, the console script must actually flag a known-malicious diff, and the tag, the wheel
  filename and the installed `__version__` must all agree before an irreversible upload.

### Changed
- **`rlm-kit` → `rlm-harness`, pinned to `==1.0.0` from PyPI.** The `[tool.uv.sources]` git pointer is
  gone, so nothing in the dependency closure resolves outside PyPI any more — which is what made
  publishing this package possible at all. Imports move to `rlm_harness`.
- **The rubric adopts the harness's own primitives** (`rlm_harness.rubric`), with `schema` re-exporting
  `Criterion` / `CriterionFact` / `RubricCriteria` for back-compat.
- **README and package description lead with the Action**, and the local pipeline, studio console,
  trajectory export and fine-tuning path are framed as the second goal rather than the premise.
- **`uv sync` default-installs the `subscription-sdk` dev group**, so a bare sync stops pruning the Claude
  Agent SDK out of the shared dev venv.
- **ruff pinned to `0.16.0`** in CI. `uvx ruff` resolves the latest release at run time and ruff's default
  rule set is not a stable contract, so an unpinned lint job goes red overnight with no code change.

### Fixed
- **`scan` no longer flags what a diff deletes.** A unified diff carries removed code as well as added
  code, and the detectors read plain text, so scanning a raw diff flagged a change for the payload it was
  DELETING — the worst failure mode a security gate can have, since it turns every remediation commit red.
  `-` lines are dropped by default; `---` file headers survive and non-diff input is untouched.
- **The CI self-scan no longer fails on its own explanatory comment.** The comment describing "our files
  carry attack patterns as their job" quoted two payload shapes verbatim, and `.github/` is in the gated
  half, so the commit that introduced the gate failed it. Confirmed as a real red CI run, not a
  hypothetical.

## 0.3.0

### Added
- **An ungroundable input yields a principled `inconclusive`, never a confident verdict.** A content-free
  / unfetchable / not-actually-a-change input (an empty `{}` payload normalizes to `(no textual content)`)
  used to still ship a confident `benign, confidence 0.9`. Now `inconclusive` is a SANCTIONED SUBMIT
  outcome — a 4th `verdict` value (`schema.INCONCLUSIVE_VERDICT`, `SUBMIT_VERDICTS`): the classifier
  prompt sanctions it explicitly (only for a change with no assessable content — NOT an escape hatch for a
  hard-but-real change), and the second-stage `deep_classify` enum validator accepts it. `response` maps
  it to `status="inconclusive"` + `RefusalInfo(reason="insufficient_evidence")` (the pre-existing
  inconclusive envelope, previously unreachable). A host-side deterministic BACKSTOP
  (`normalize.has_groundable_content` over the run's normalized `event`) DOWNGRADES even a confident
  verdict to inconclusive when there is no groundable content — defense-in-depth, read-time. It rides the
  reward-free trajectory as an `inconclusive` OUTCOME label (`rl_export.run_labels`, mirroring the
  clean-negative idea) — a FACT, never a score/reward. The DETERMINISTIC SIEM half is untouched:
  `inconclusive` is not in `emit_on`, so a real high/critical indicator still forces a signal on its own.
- **Studio: an unrecognized `tool_call` renders its short scalar fields instead of an empty step, and the
  future harness swap keeps its child-rollout link.** The drawer mapper (`iterations._tool_entry`), the
  SSE mapper (`mapper.to_event` — which previously DROPPED an unknown tool from the live feed, now emits a
  generic `detection.tool` event), and the frontend fallback (`trajectory.js` detail + a generic
  icon/`fam-tool` family) all surface an unknown tool's short scalar payload fields (tool, ok, and any
  short string/number fields; bulky raw/preview/spec/hits dropped) as kv rows — never a bare "no detail
  recorded" when fields exist. And `deep_classify.record_tool_call` now attaches `child_run_id` /
  `child_trace` / `child_meta` when the second-stage result carries them (guarded — a NO-OP for today's
  `self` backend, correct for the documented future `make_harness_tool` swap so the parent→child rollout
  link survives the recording step).

## 0.2.1

### Fixed
- **The studio launches on a subscription with the SAME command as every rlm-harness sibling.** The studio
  member (`diff-sentry-studio`) was missing a forwarding `subscription` extra, so
  `uv run --package diff-sentry-studio --extra live --extra subscription uvicorn …` was rejected — a
  studio-scoped `uv` command resolves extras against the MEMBER, not the root, and the Claude Agent SDK
  extra lived only on the root. Added `subscription = ["diff-sentry[subscription]"]` to
  `studio/pyproject.toml` (mirroring the sibling harnesses) + a "Subscription mode" section to the studio
  README. Closes a cross-downstream drift (same gap fixed in the siblings); the paired-extras convention
  is documented in rlm-harness's "Building a consumer" guide.
- **`/v1/config` never surfaces a subscription analyst as the classifier (a config a run couldn't use).**
  The classifier falls back to the analyst (`DS_CLASSIFIER_LM or DS_SUB_LM`), but the classifier is a
  `make_model_tool` endpoint and `from_env` REJECTS a subscription classifier — so with `DS_CLASSIFIER_LM`
  unset and `DS_SUB_LM` a `claude-agent-sdk/…` sentinel, the panel showed a classifier model no run could
  use. Guard it (`_role_or_none`): fall back to the analyst only when it's a real (non-subscription)
  model, else `None`; the analyst role itself still shows through. Same class swept from the sibling
  studios. Studio test added.

## 0.2.0

### Added
- **Run the planner + analyst on a Claude Pro/Max SUBSCRIPTION** (no API key). Give `DS_ROOT_LM` /
  `DS_SUB_LM` a `claude-agent-sdk/<model>` value and that role runs on your personal Claude login
  through rlm-harness's `rlm_harness.ClaudeAgentLM` (a `dspy.BaseLM` over `claude-agent-sdk`), injected via
  rlm-harness's `configure(main_lm=, sub_lm=)` seam. Each call is a pure completion — no tools, no
  filesystem, no settings leakage — so the sandbox stays the only place code runs. Opt-in extra:
  `uv sync --extra subscription` (installs the Claude Agent SDK the adapter needs); requires the Claude
  Code CLI logged in and `ANTHROPIC_API_KEY` unset (the adapter refuses to start otherwise). The adapter
  ships in the rlm-harness wheel behind its own `[subscription]` extra (promoted out of `examples/` —
  diff-sentry no longer vendors it). Imported lazily via `from rlm_harness import ClaudeAgentLM` (only in
  `detect.setup()`'s sentinel branch) so `import diff_sentry` stays dspy-free and a proxy-only install
  never pulls the extra. A sentinel-configured run in an env that never installed the extra fails LOUD
  with an actionable error naming `uv sync --extra subscription` (`uv lock` records the extra; only sync
  installs it).
- **Studio: a page-height three-view stage.** The middle column is ONE verdict-alloy card filling a
  viewport-height grid — all three columns are independent scroll tracks (feed / card / modules; the
  page itself never scrolls, the family pattern), a sticky head keeps the view switch reachable, and
  long attacker-influenced tokens wrap instead of being clipped by the module frame — with a top-right
  **Verdict / Indicators / Change** switch in triage order — Indicators always reachable, refusal
  included. Run telemetry leads the right column (the sibling-console convention); the header's
  `backend:self` chip is gone (API-only metadata now). The Change view is **trace-backed** for pr/issue
  and replayed runs (their diff never reaches the client): it lazily reads the run's own `run_start`
  event via `GET /v1/runs/{id}/iterations` — the exact normalized untrusted content the planner saw —
  through a pure, unit-tested view-state core (`run-core.js:planChangeView`) that can never wedge on
  loading and never reports a transient fetch error as a gone trace. A `[hidden]`-attribute CSS guard
  (with a static contract test) fixes the mode panes and the Trajectory handle rendering while hidden.
- **The classifier ALWAYS stays on its own OpenAI-compatible endpoint**, never the subscription (mixed
  auth by design). `config.from_env` now REJECTS a `claude-agent-sdk/…` classifier model — set either
  explicitly (`DS_CLASSIFIER_LM`) or inherited from a subscription `DS_SUB_LM` when `DS_CLASSIFIER_LM`
  is unset — with an actionable error: `deep_classify` uses an OpenAI client (not the Agent SDK), the
  tool is ALWAYS registered, and a latent bogus-model-id failure mid-trajectory would burn the one
  hard-budget attempt (`max_retries=1`). A subscription-only end-to-end run is therefore not supported.

## 0.1.0

The initial consumer: classify → judgement-only verdict (`ChangeVerdict`, no hits field) →
deterministic-evidence union on read (`assemble_verdict`, MF3) → response → host-side SIEM signal →
reward-free trajectory export, fully offline-testable (DummyLM / ScriptedInterpreter / injected fakes;
the detection-quality corpus pins the indicator suite's hit/miss behavior). Includes the metadata
sandwich (MF1), the GitHub-allowlisted opt-in enrichment fetch (MF2), the in-loop-safe pure-Python
indicator suite, the `deep_classify` second-stage seam, progressive-disclosure attack skills, the
offline hackerbot-claw incident reproduction, and the in-repo studio console (a uv workspace member).
