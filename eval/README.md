# diff-sentry-eval

An offline, reward-free measurement harness for diff-sentry. It scores recorded runs with a 4-category
LLM-as-judge of the assembled malicious-change verdict (TF / TA / TG / PA, each 0-10, TF primary) and
renders a terminal scorecard.

## Why it exists

diff-sentry's own read-time facts are deterministic but shallow: `signal` is a severity-floor derivation,
`verdict` is the planner's own label, and `cited_unknown` only flags a fabricated citation. None of them says
whether the verdict is right. Was a malicious change caught? Was a benign one over-flagged? Does the call rest
on the decoded evidence? An independent LLM judge reads the assembled verdict, the change, and a judge-only
reference, and answers those questions in a scorecard you can reproduce and compare across model versions.

## The boundary

The judge measures and never rewards, and it stays outside the rollout. Data flows one way,
`trace → judge → report`, and the report is terminal: a human, a CI gate, or a leaderboard reads it.

- The report carries per-category means only, never a composite R(τ).
- Nothing is written back into a trace, a dataset, or a diff-sentry export (`rl_export` stays reward-free).
- `diff_sentry` never imports `diff_sentry_eval` (enforced by `eval/tests/test_boundary.py`).
- The judge holds diff-sentry's read-never-execute invariant: it assesses the classification statically and
  treats the change as untrusted data. It never runs or builds the change.

This mirrors the ATLAS paper's split between the training reward and the fixed external judge.

## This eval vs the rollout `rubric_signal`

Both use the ATLAS TF/TA/TG/PA codes and treat TF as primary, but they are decoupled schemes that measure
different objects:

| | rollout `rubric_signal` (`diff_sentry.rubric`) | this eval (`diff_sentry_eval`) |
|---|---|---|
| kind | deterministic FACTS (counts/ids), no LLM | LLM-as-judge 0-10 SCORES |
| what it scores | the run's TRAJECTORY | the assembled VERDICT artifact |
| TF/TA/TG/PA mean | Task / Tool / Tool-grounding / Parameter (trajectory framing) | Classification / Approach / Evidence-grounding / Classification-accuracy (artifact framing) |
| reward | none (a LABEL surface for a trainer) | none (per-category means for a scorecard) |

The eval judge is rubric-free on purpose. It uses a generic prompt (the ATLAS "fixed external judge"
mandate) and never reads `rubric_signal` or `criteria_facts`; wiring the rubric into the judge would breach
the one-way fence. The shared codes give comparability, and the different meanings follow from the different
objects. Keep the two schemes parallel and do not unify them.

## The four categories

diff-sentry's artifact is a verdict plus deterministic evidence, so the four ATLAS categories are recast onto
change classification:

- **TF (Classification Fulfillment)**, primary: does the verdict resolve the change correctly (the right
  benign/suspicious/malicious call and the right read of intent, matching the reference)?
- **TA (Approach Appropriateness)**: did the run decode and inspect the suspicious content, escalate to the
  analyst or the `deep_classify` second stage only when warranted, and gather the intel it needed?
- **TG (Evidence Grounding)**: does the verdict rest on the indicator hits actually recorded (rule hits,
  decoded payloads, the derived signal), and are the cited indicators real?
- **PA (Classification Accuracy)**: is the classification well-formed and coherent: a valid verdict label, a
  sensible confidence, techniques and suspect_files consistent with the evidence, and a recommended action
  that fits the severity?

`score.py` reaches diff-sentry only through its public surface (`verdict_from_events`, `run_labels`,
`run_metrics`, `AssembledVerdict`), the same rule the studio follows. The judge's `change` is the run's
normalized untrusted content from `run_start` meta. The `verdict` and `indicators` blocks come from the
assembled verdict (the deterministic evidence union), never from the planner's raw self-report. The prompt
version is pinned (`atlas-diffsentry-eval-v1`).

## Usage

```sh
# Score EXISTING traces against a taskset (offline with the stub judge; judge creds at most).
# The `--package diff-sentry-eval` is required from the repo root — a plain `uv run` won't install the
# workspace member (it's deliberately not a dependency of the diff-sentry wheel).
uv run --package diff-sentry-eval python -m diff_sentry_eval score "output/traces/*.jsonl" demo
uv run --package diff-sentry-eval python -m diff_sentry_eval score "output/traces/*.jsonl" eval/taskset.example.json --out output/eval

# Run-then-score: drive `diff_sentry.cli.run` per change (run_id = task id), then score the fresh trace.
# Needs the full solve stack (DS_* creds + a Deno sandbox) on top of the judge env. The SIEM emitter is
# disabled for eval runs (no side effects).
uv run --package diff-sentry-eval python -m diff_sentry_eval run demo --out output/eval
```

Runs pair to tasks by the `run_id == task id` convention. The taskset argument is a JSON list of
`{id, change, reference}` objects, or the literal `demo` for the built-in offline set. `change` is the
webhook-style payload the planner sees (the `run` subcommand ingests it). `reference` is the concrete
expected classification that only the judge sees (ATLAS's fuzzy-vs-concrete split). A starter fixture ships
as `eval/taskset.example.json`.

Output goes under `--out` (default `./output/eval/`). Both subcommands write `report.json`; `run` also writes
each run's trace and response there (`traces/`, `responses/`), through `diff_sentry.cli.run`.

## Judge environment (`DSEVAL_*`)

The external judge is configured by role and can be swapped; no model name is hardcoded. With no
`DSEVAL_MODEL` set, or with `--stub`, the deterministic stub judge runs instead. It is fully offline, needs no
creds, and returns fixed mid-scale scores. CI uses it.

```sh
# The eval judge — an o4-mini-class model on any OpenAI-compatible endpoint (needs the `judge` extra).
DSEVAL_MODEL=            # judge model id; empty = use the offline stub judge
DSEVAL_BASE_URL=         # OpenAI-compatible base URL (empty = the openai default)
DSEVAL_API_KEY=          # API key for that endpoint
DSEVAL_TIMEOUT=60        # per-call hard timeout, seconds
```

A live-judge `report.json` pins `judge_model` and `prompt_version`, so its numbers are reproducible and
comparable; a stub report records `judge_model: "stub"`. A run the judge cannot score (never finalized, no
usable verdict, endpoint failure, off-schema output) is reported as `unscored` and excluded from the means. It
never counts as 0.

## Tests

```sh
uv run --package diff-sentry-eval --extra dev python -m pytest eval/tests   # offline: stub, synthetic traces, no creds
```
