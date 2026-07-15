# Vendored / external dependencies

diff-sentry deliberately vendors **nothing** — it is a downstream *consumer* of rlm-kit (a
commit-pinned git dep), the deterministic detection logic (indicators, assemble, emit) is its own
pure-Python code, and the Claude-subscription adapter it can use now ships in the rlm-kit wheel
(`rlm-kit[subscription]` → `rlm_kit.ClaudeAgentLM`, injected at `configure(main_lm=…, sub_lm=…)`; it
used to be vendored here from rlm-kit's `examples/` and was promoted into the kit). The external
boundaries it does cross, and why, are listed here.

## External services (all opt-in, none bundled)

- **GitHub ingest** (`ingest.py`): shells out to `gh` HOST-SIDE only (transport injectable, never a
  planner tool). The fetched change content is untrusted LM context, never trusted instructions.
- **Enrichment fetch** (`fetch_tool.py`): OFF by default, GitHub-allowlisted (MF2), SSRF-guarded by the
  kit with a resolved-IP re-check on every redirect hop.
- **SIEM webhook** (`emit.py`): host-side POST after the run; the planner never holds SIEM creds.
- **The model endpoints** (planner / analyst / classifier): the user's own, by env. No default vendor.
