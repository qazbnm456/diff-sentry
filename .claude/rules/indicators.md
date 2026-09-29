---
paths:
  - "diff_sentry/indicators.py"
  - "diff_sentry/normalize.py"
  - "tests/corpus/**"
  - "tests/test_indicators.py"
  - "tests/test_detection_quality.py"
  - "tests/test_incident_*.py"
---

# Indicator rules

- **Deterministic, pure Python, no subprocess.** A subprocess spawned inside the live dspy.RLM/asyncio
  process hangs; any heavier scanner belongs host-side, after the run. `mint_id` is a sha1 over
  rule+evidence (no time, no randomness), so a baseline hit and an in-loop re-scan of the same content
  dedupe to ONE union member. Hit evidence is a bounded snippet (`_MAX_EVIDENCE`), never the whole diff.
- **Severities are tuned, not monotone-paranoid.** A plain workflow-file edit is `medium`, below the
  signal floor on purpose: a benign workflow PR must not force a SIEM signal, and a real payload inside
  the workflow fires the high/critical shell/obfuscation rules itself. A CODEOWNERS reassignment is
  `high`. A bare `pull_request_target` (the ordinary label-bot shape) is `medium`; the same trigger
  checking out the PR head is `pwn-request` / `critical` (untrusted code with the base repo's secrets).
  `dev-tunnel-endpoint`, `content-addressed-host` (IPFS) and `dynamic-code-eval` are sub-floor
  corroborators; pairs with no innocent reading (`child_process` + `detached`, network-fetch +
  file-write) are `high`. Requiring both halves is how a common primitive becomes evidence without
  becoming noise.
- **Every rule ships with its negative case**, and `tests/corpus/` pins the suite's hit/miss behavior.
- **`pwn-request` has three checkout forms, each requiring the privileged trigger:** the head expression
  on a `ref:` (directly or one binding hop away), a hand-rolled `git fetch` / `gh pr checkout`, and
  `allow-unsafe-pr-checkout: true` (the actions/checkout v5.1+ opt-in to the fork-PR checkout it blocks
  by default; the line states the intent, so no dataflow is needed). Each form has its own title: calling
  an opt-in "checks out the PR HEAD" sends a reader hunting for a `ref:` that is not there.
- **A paired rule only pairs within one file.** `scan_diff` splits a unified diff on its file headers;
  `scan_content` does the same for an event, whose files `raw_content` would otherwise join into one
  header-less blob. `scan` and the in-loop tool use `scan_diff`, the host-side baseline uses
  `scan_content`, and `normalize.content_segments` is the single definition both `raw_content` and the
  baseline build on. Per-file scoping stops two halves from different files composing into a `critical`
  no file contains, and keeps a hit id byte-stable between a whole-diff and a single-file scan, which is
  what lets the baseline and an in-loop scan dedupe (MF3). Non-diff input falls through to a whole-text
  scan; keep that fallback.
- **The in-loop tool registers as exactly `scan_indicators`.** dspy registers a tool under its
  `__name__` and the prompt calls `scan_indicators(region)`; any other name makes every sandbox call a
  NameError. The inner callable is renamed on purpose (`make_indicator_tool`); keep it.
