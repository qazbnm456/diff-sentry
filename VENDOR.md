# Vendored / external dependencies

diff-sentry vendors nothing. It consumes rlm-harness as an exact PyPI pin, and its deterministic
detection logic (indicators, assemble, emit) is its own pure-Python code. The Claude-subscription
adapter comes from the rlm-harness wheel (`rlm-harness[subscription]` provides
`rlm_harness.ClaudeAgentLM`, injected at `configure(main_lm=…, sub_lm=…)`). The external boundaries
diff-sentry does cross, and why, are listed here.

## External services (all opt-in, none bundled)

- **GitHub ingest** (`ingest.py`): shells out to `gh` HOST-SIDE only (transport injectable, never a
  planner tool). The fetched change content is untrusted LM context, never trusted instructions.
- **Enrichment fetch** (`fetch_tool.py`): OFF by default, GitHub-allowlisted (MF2), SSRF-guarded by the
  kit with a resolved-IP re-check on every redirect hop.
- **SIEM webhook** (`emit.py`): host-side POST after the run; the planner never holds SIEM creds.
- **The model endpoints** (planner / analyst / classifier): the user's own, by env. No default vendor.
