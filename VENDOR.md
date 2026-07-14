# Vendored / external dependencies

diff-sentry deliberately vendors **almost nothing** — it is a downstream *consumer* of rlm-kit (a local
editable path dep), and the deterministic detection logic (indicators, assemble, emit) is its own
pure-Python code. What crosses the boundary to an external source, and why, is listed here.

## Vendored code — the Claude-subscription LM adapter

The one real exception to "almost nothing": `diff_sentry/claude_agent_lm.py`. It is `ClaudeAgentLM`, a
`dspy.BaseLM` that runs the planner and/or analyst on a Claude Pro/Max **subscription** via the official
`claude-agent-sdk` (behind the `[subscription]` extra; see the subscription block in `.env.example`),
injected through rlm-kit's public `configure(main_lm=…, sub_lm=…)` seam. It is copied from rlm-kit's
`examples/claude_agent_lm.py`.

- **Why vendored, not imported.** rlm-kit ships this adapter only under `examples/`, which is **not in
  its installed wheel** — a consumer cannot `import` it. Per rlm-kit's base/wrap split the LM *provider*
  is the consumer's to own, so diff-sentry keeps a copy. It is imported **lazily** (only inside
  `detect.setup()`'s `claude-agent-sdk/` sentinel branch, via `_maybe_subscription_lm`), so
  `import diff_sentry` stays dspy-free and a proxy-only install never needs the extra. The classifier
  never uses it — mixed auth is by design (the classifier always runs on its own OpenAI-compatible
  endpoint; `config.from_env` rejects a sentinel classifier, explicit or inherited).
- **Pinned ref: `48374a1`** (rlm-kit `main` HEAD). The vendored **code body (below the docstring)
  matches that commit verbatim**. Only the docstring/demo differ: the two demo-only imports (`pydantic`,
  `rlm_kit`) and the upstream demo tail (the `Summarize` RLMTask + `main()` runner) are dropped, and the
  module docstring carries a diff-sentry vendored header above the preserved upstream docstring — whose
  Setup step 3 is adjusted to `uv sync --extra subscription` since the runnable demo it referenced is
  gone. Note diff-sentry consumes rlm-kit as an **editable `../rlm-kit` path dep** (no locked git
  commit), so there is no lockfile pin to compare against: the local checkout was at `48374a1` when this
  file was vendored. The adapter is a standalone `dspy.BaseLM` depending only on the long-stable
  `configure(main_lm=, sub_lm=)` seam, so the pin need not track the checkout — but re-check this one
  file whenever `examples/claude_agent_lm.py` changes upstream (and when the dep switches to a
  commit-pinned git source, note the divergence here like the siblings do).
- **How to re-sync (manual — no script).** When `examples/claude_agent_lm.py` changed upstream, re-copy
  the body, re-drop the demo tail + the two demo-only imports, keep the diff-sentry header, and update
  the pinned ref above. It is not covered by any refresh script.

## External services (all opt-in, none bundled)

- **GitHub ingest** (`ingest.py`): shells out to `gh` HOST-SIDE only (transport injectable, never a
  planner tool). The fetched change content is untrusted LM context, never trusted instructions.
- **Enrichment fetch** (`fetch_tool.py`): OFF by default, GitHub-allowlisted (MF2), SSRF-guarded by the
  kit with a resolved-IP re-check on every redirect hop.
- **SIEM webhook** (`emit.py`): host-side POST after the run; the planner never holds SIEM creds.
- **The model endpoints** (planner / analyst / classifier): the user's own, by env. No default vendor.
