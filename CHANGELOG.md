# Changelog

All notable changes to diff-sentry. This project classifies ONE GitHub change (PR/issue/push) for
malicious intent — the diff held as **untrusted data** in a sandboxed REPL, a judgement-only verdict,
and deterministic indicator evidence unioned on read into a SIEM signal — as a traced, improvable RLM
framework on [`rlm-kit`](https://github.com/qazbnm456/rlm-kit) (a BewAIre-style detector).

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
- **The studio launches on a subscription with the SAME command as every rlm-kit sibling.** The studio
  member (`diff-sentry-studio`) was missing a forwarding `subscription` extra, so
  `uv run --package diff-sentry-studio --extra live --extra subscription uvicorn …` was rejected — a
  studio-scoped `uv` command resolves extras against the MEMBER, not the root, and the Claude Agent SDK
  extra lived only on the root. Added `subscription = ["diff-sentry[subscription]"]` to
  `studio/pyproject.toml` (mirroring the sibling harnesses) + a "Subscription mode" section to the studio
  README. Closes a cross-downstream drift (same gap fixed in the siblings); the paired-extras convention
  is documented in rlm-kit's "Building a consumer" guide.
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
  through rlm-kit's `rlm_kit.ClaudeAgentLM` (a `dspy.BaseLM` over `claude-agent-sdk`), injected via
  rlm-kit's `configure(main_lm=, sub_lm=)` seam. Each call is a pure completion — no tools, no
  filesystem, no settings leakage — so the sandbox stays the only place code runs. Opt-in extra:
  `uv sync --extra subscription` (installs the Claude Agent SDK the adapter needs); requires the Claude
  Code CLI logged in and `ANTHROPIC_API_KEY` unset (the adapter refuses to start otherwise). The adapter
  ships in the rlm-kit wheel behind its own `[subscription]` extra (promoted out of `examples/` —
  diff-sentry no longer vendors it). Imported lazily via `from rlm_kit import ClaudeAgentLM` (only in
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
