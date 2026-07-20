# diff-sentry-eval

An **offline, reward-free measurement harness** for diff-sentry: score recorded runs against a 4-category
LLM-as-judge of the **assembled malicious-change VERDICT** (TF / TA / TG / PA, each 0–10, TF primary) and
render a terminal scorecard.

**Why it exists (the gap it fills):** diff-sentry's own read-time facts are deterministic but *shallow* —
`signal` is a severity-floor derivation, `verdict` is the planner's own label, and `cited_unknown` only
flags a fabricated citation. None of them tells you whether the verdict is actually *right*: did a genuinely
malicious change get caught, did a benign one get over-flagged, does the call rest on the decoded evidence?
An independent LLM judge that reads the assembled verdict + the change + a judge-only reference fills exactly
that hole, and gives a reproducible, comparable scorecard across model versions.

**The boundary:** a reward-free measurement judge, separate from the rollout; it never feeds training. Data
flows one way — `trace → judge → report` — and the report is terminal (read by a human, a CI gate, or a
leaderboard). It carries per-category **means only**, never a composite R(τ); it never writes into a trace,
a dataset, or a diff-sentry export (`rl_export` stays reward-free); and `diff_sentry` never imports
`diff_sentry_eval` (test-enforced, `eval/tests/test_boundary.py`). It also holds diff-sentry's
**read-never-execute** invariant — the judge assesses the classification STATICALLY and treats the change as
untrusted data, it never runs or builds it. This mirrors the paper's own split between the training reward
and the fixed external judge.

**This eval vs the rollout `rubric_signal` — same 4 codes, two DIFFERENT things (by design).** Both use the
ATLAS TF/TA/TG/PA codes and treat TF as primary, but they are DECOUPLED schemes and must not be conflated:

| | rollout `rubric_signal` (`diff_sentry.rubric`) | this eval (`diff_sentry_eval`) |
|---|---|---|
| kind | deterministic FACTS (counts/ids), no LLM | LLM-as-judge 0–10 SCORES |
| what it scores | the run's TRAJECTORY | the assembled VERDICT artifact |
| TF/TA/TG/PA mean | Task / Tool / Tool-grounding / Parameter (trajectory framing) | Classification / Approach / Evidence-grounding / Classification-accuracy (artifact framing) |
| reward | none (a LABEL surface for a trainer) | none (per-category means for a scorecard) |

The eval judge is deliberately **rubric-free** (a GENERIC prompt, the ATLAS "fixed external judge" mandate):
it does NOT read `rubric_signal`/`criteria_facts` — wiring the rubric into the judge would breach the
one-way fence. The shared codes are intentional (comparability), the divergence is intentional (they measure
different objects). Keep them parallel; do not unify.

## Design note — the domain adaptation

diff-sentry's artifact is a **verdict + deterministic evidence**, not a template, so the four ATLAS
categories are re-cast onto the change-classification task:

- **TF (Classification Fulfillment)** — does the verdict correctly resolve the change (right
  benign/suspicious/malicious call, right read of intent, matching the reference)? *Primary.*
- **TA (Approach Appropriateness)** — did the run decode/inspect the suspicious content, escalate to the
  analyst / `deep_classify` second stage only when warranted, and gather the intel it needed?
- **TG (Evidence Grounding)** — does the verdict rest on the deterministic indicator hits actually recorded
  (rule hits, decoded payloads, the derived signal), not invention — and are the cited indicators real (no
  fabricated citations)?
- **PA (Classification Accuracy)** — is the classification well-formed and coherent — a valid verdict label,
  a sensible confidence, techniques/suspect_files consistent with the evidence, a recommended action fitting
  the severity?

The `score.py` reader reaches diff-sentry ONLY through its PUBLIC surface (`verdict_from_events`,
`run_labels`, `run_metrics`, `AssembledVerdict`) — the same rule the studio follows. The judge's `change`
is the run's normalized untrusted content (from `run_start` meta), and the `verdict`/`indicators` blocks are
re-sourced from the ASSEMBLED verdict (the deterministic evidence union), never the planner's raw
self-report. The prompt version is pinned (`atlas-diffsentry-eval-v1`).

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
webhook-style change payload the PLANNER sees (ingested by the `run` subcommand); `reference` is the concrete
expected-classification description the **judge alone** sees (ATLAS's fuzzy-vs-concrete split). A starter
fixture ships as `eval/taskset.example.json`.

Everything is written under `--out` (default `./output/eval/`): `report.json`.

## Judge environment (`DSEVAL_*`)

The external judge is role-based and swappable — no model name is hardcoded. With no `DSEVAL_MODEL` set (or
with `--stub`), the deterministic stub judge runs instead: fully offline, zero creds, fixed mid-scale scores
— the CI path.

```sh
# The eval judge — an o4-mini-class model on any OpenAI-compatible endpoint (needs the `judge` extra).
DSEVAL_MODEL=            # judge model id; empty = use the offline stub judge
DSEVAL_BASE_URL=         # OpenAI-compatible base URL (empty = the openai default)
DSEVAL_API_KEY=          # API key for that endpoint
DSEVAL_TIMEOUT=60        # per-call hard timeout, seconds
```

Every `report.json` pins `judge_model` + `prompt_version`, so a number is reproducible and comparable. Runs
the judge cannot score (never finalized, no usable verdict, endpoint failure, off-schema output) are reported
as `unscored` and excluded from the means — never silently a 0.

## Tests

```sh
uv run --package diff-sentry-eval --extra dev python -m pytest eval/tests   # offline: stub, synthetic traces, no creds
```
