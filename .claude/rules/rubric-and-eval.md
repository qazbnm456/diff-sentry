---
paths:
  - "diff_sentry/rubric.py"
  - "diff_sentry/rl_export.py"
  - "diff_sentry/response.py"
  - "diff_sentry/assemble.py"
  - "eval/**"
  - "studio/**"
---

# ATLAS rubric labels and the eval member

## The rubric is a reward-free label surface

- `rl_export.rubric_signal` attaches the ATLAS 4-category (TF/TA/TG/PA) decomposition as LABELS: a fixed,
  no-LLM skeleton in `run_start` meta (`rubric_to_meta(default_rubric())`, one criterion per category,
  since the task is constant; there is no `generate_rubric` path) plus deterministic per-criterion
  `criteria_facts`.
- The facts are a re-lens over `run_labels` / `run_metrics`, not a second derivation: `rubric.trace_facts`
  reuses them, so a criterion's `observed` cannot drift from what a trainer reads. `_CATEGORY_LENS` maps
  TF↔(verdict / signal / hit_iteration_cap), TA↔(scan / deep_classify / analyst / fetch / skill counts +
  circuit-breaks + analyst failures), TG↔(indicator_count / max_indicator_severity / signal /
  cited_unknown), PA↔(verdict / cited_unknown).
- `CriterionFact` has no score/met field; the trainer scores. Never add a reward/score/met field to any
  rubric type.
- `rubric.py` is a dspy-free leaf: it imports only `.schema` at top, and its `rl_export` reuse is a
  function-level import (that path is dspy-free too), so `response.py` can import it at top.
- `response._rubric` surfaces it as `DetectionResponse.rubric` (`RubricReport`); the studio shows it as a
  "labels — not a score" card that adds no judgement. Keep the card legacy-guarded: a response without a
  `rubric` renders nothing.

## The eval member measures; it never rewards

- `eval/` (`diff-sentry-eval`) scores a recorded run's assembled verdict with a fixed external ATLAS
  LLM-as-judge: TF/TA/TG/PA on 0–10, TF primary, per-category means only, no composite, no threshold.
- It is a one-way reader: it reaches diff-sentry only through `verdict_from_events` / `run_labels` /
  `run_metrics` / `AssembledVerdict`, and `diff_sentry` never imports `diff_sentry_eval`
  (`eval/tests/test_boundary.py` enforces it).
- The judge is rubric-free (it never reads `rubric_signal`, which would bias the measure) and holds
  read-never-execute: it assesses the classification statically and treats the change as untrusted.
- A run it cannot score (never finalized, no usable verdict, judge failed) is `unscored`, never a fake 0.
  See `eval/README.md`.
