# diff-sentry

A **BewAIre-style malicious-change detector** built on [`rlm-kit`](../rlm-kit) — a downstream consumer of
the RLM scaffold, alongside `cve-reverser`. It reproduces the shape of Datadog's
[BewAIre defense](https://www.datadoghq.com/blog/engineering/stopping-hackerbot-claw-with-bewaire/) (the
`hackerbot-claw` incident): ingest a GitHub change, analyze the diff as **untrusted data**, and emit a
**structured verdict** (benign / suspicious / malicious) into a SIEM.

```
GitHub PR/issue/push  →  normalize (metadata head+tail)  →  RLM classify (diff held in a sandboxed REPL)
                      →  judgement-only verdict  →  UNION deterministic indicators on read  →  SIEM signal
                      →  reward-free trajectory export
```

## Why an RLM fits a classifier

The RLM premise — hold unbounded context as a **variable in a sandboxed Python REPL** and reason over it —
is structurally BewAIre's own hardening advice ("write untrusted input to a file, read it with restricted
tools"). A large multi-file diff lands as a REPL variable the planner explores (decode base64, inspect raw
filenames, `scan_indicators` a decoded value) instead of being pasted into the system prompt. The change
is **data under analysis, never instructions** — which is exactly what a detector of prompt injection must
guarantee about itself.

## The pipeline

| Stage | Module | Note |
|---|---|---|
| Ingest (host-side) | `ingest.py` | `gh api` PR/issue → a change-event dict (transport injectable). |
| Normalize | `normalize.py` | Derived metadata at the **head AND tail** so dspy's ~1000-char input preview shows structure, not attacker free-text (MF1). |
| Classify | `detect.py` | `ClassifyChange(RLMTask)`, a MISSION-framed judgement-only task; interpreter `pyodide` — **reads, never executes** the change. |
| Deterministic detectors | `indicators.py` | Pure-Python, in-loop-safe (no subprocess): `${IFS}`, `curl \| bash`, base64 de-obfuscation, CODEOWNERS/workflow tamper, prompt-injection, exfiltration. |
| Second stage | `deep_classify.py` | A swappable classifier via `rlm_kit.tools.make_model_tool` — the main LM *chooses* to consult it, so the decision is a `tool_call` in the trajectory. |
| Assemble | `assemble.py` | Unions **all** indicator hits from the trace (baseline ∪ tool calls) and derives `signal` — a benign self-report can't suppress hard evidence (MF3). |
| Emit (host-side) | `emit.py` | POST the signal to a SIEM webhook after the run — plumbing, not a planner tool (the planner never holds SIEM creds). |
| Export | `rl_export.py` | Reward-free SFT/RL datasets (`reward=None`) — rollout stage only; scoring lives elsewhere. |

## Prompt-injection stance (honest residual)

diff-sentry is a *detector of* prompt injection, so it must resist one. Its defenses: the untrusted change
is a REPL variable (not spliced into instructions), a MISSION frame that reframes embedded instructions as
a **signal, not a command**, and a normalizer that denies the attacker the preview-window edges. The
**residual** is real and stated plainly: dspy still surfaces a bounded preview of the input into the prompt,
so a strong injection can skew the *verdict* — but never the evidence: the deterministic indicators reach
the SIEM regardless of the model's call (`assemble` unions them and derives `signal` with a high/critical
floor). Verdict-skew is possible; evidence-suppression is structurally prevented.

## Scale / tier (the honest caveat)

BewAIre runs ~10k PRs/week at second-latency. An RLM episode is multi-turn reasoning — seconds-to-minutes
and non-trivial cost per change. So diff-sentry is the **deep-analysis tier**, not the firehose: put a cheap
host-side pre-filter (deterministic indicators + one small single-shot call) in front, and escalate only
flagged/ambiguous changes to the full RLM. That mirrors BewAIre's own cheap-initial → structured-deep shape.

## Usage

```bash
uv sync --group dev
uv run pytest                                  # offline logic tests (DummyLM; no live LLM/Deno/network)

# live (needs DS_* creds + `brew install deno` + `gh`):
uv run python -m diff_sentry pr acme/widgets 7
uv run python -m diff_sentry issue acme/widgets 12
uv run python -m diff_sentry classify event.json           # a payload you already hold (offline ingest)
uv run python -m diff_sentry render output/traces/pr-7.jsonl pr-7    # re-render a response (offline)
uv run python -m diff_sentry export "output/traces/*.jsonl" ds.json  # reward-free export (offline)
```

## Status

**v0.1.0** — the classify → judgement-only verdict → deterministic-evidence union → response → reward-free
export loop, fully offline-testable. Host-side GitHub ingestion and the SIEM emitter ship as real, injectable
seams (unit-tested with fakes); wiring them to a live GitHub/SIEM and adding the cheap pre-filter tier are the
next increments. Built on `rlm-kit` with **zero** changes to the kit — a consumer extends, it doesn't fork.
