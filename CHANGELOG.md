# Changelog

All notable changes to diff-sentry. This project classifies ONE GitHub change (PR/issue/push) for
malicious intent — the diff held as **untrusted data** in a sandboxed REPL, a judgement-only verdict,
and deterministic indicator evidence unioned on read into a SIEM signal — as a traced, improvable RLM
framework on [`rlm-kit`](https://github.com/qazbnm456/rlm-kit) (a BewAIre-style detector).

## 0.2.0

### Added
- **Run the planner + analyst on a Claude Pro/Max SUBSCRIPTION** (no API key). Give `DS_ROOT_LM` /
  `DS_SUB_LM` a `claude-agent-sdk/<model>` value and that role runs on your personal Claude login
  through the vendored `diff_sentry/claude_agent_lm.py` (`ClaudeAgentLM`, a `dspy.BaseLM` over
  `claude-agent-sdk`), injected via rlm-kit's `configure(main_lm=, sub_lm=)` seam. Each call is a pure
  completion — no tools, no filesystem, no settings leakage — so the sandbox stays the only place code
  runs. Opt-in extra: `uv sync --extra subscription`; requires the Claude Code CLI logged in and
  `ANTHROPIC_API_KEY` unset (the adapter refuses to start otherwise). Vendored per the base/wrap split
  (rlm-kit ships the adapter only under `examples/`, not in its wheel; provenance + re-sync in
  `VENDOR.md`). Imported lazily (only in `detect.setup()`'s sentinel branch) so `import diff_sentry`
  stays dspy-free and a proxy-only install never pulls the extra. A sentinel-configured run in an env
  that never installed the extra fails LOUD with an actionable error naming
  `uv sync --extra subscription` (`uv lock` records the extra; only sync installs it).
- **Studio: a page-height three-view stage.** The middle column is ONE verdict-alloy card fixed at page
  height (content scrolls inside; a sticky head keeps the view switch reachable) with a top-right
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
