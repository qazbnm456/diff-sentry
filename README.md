# diff-sentry

A **BewAIre-style malicious-change detector** built on [`rlm-kit`](https://github.com/qazbnm456/rlm-kit) —
a downstream consumer of the RLM scaffold. It reproduces the shape of Datadog's
[BewAIre defense](https://www.datadoghq.com/blog/engineering/stopping-hackerbot-claw-with-bewaire/) (the
`hackerbot-claw` incident): ingest a GitHub change, analyze the diff as **untrusted data**, and emit a
**structured verdict** (benign / suspicious / malicious) into a SIEM.

https://github.com/user-attachments/assets/d200aee8-263b-483e-ad55-f90ae69f3ab0

_The studio console: paste the hackerbot-claw filename payload, watch the detection stream live, then read
the evidence-framed verdict._

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
| Deterministic detectors | `indicators.py` | Pure-Python, in-loop-safe (no subprocess): `${IFS}`, `curl \| bash`, base64 de-obfuscation, CODEOWNERS/workflow tamper, `permissions: write-all` escalation, CI-skip bypass, secret/`/proc/<pid>/mem` exfiltration, known OAST/exfil callback domains, prompt-injection. |
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

## Grounded in the real incident

The attack shapes above are not hypothetical — they are the payloads `hackerbot-claw` actually used, replayed
offline. Datadog's writeup quotes them verbatim, and the original GitHub artifacts are gone (the attacker
account was deleted: `datadog-iac-scanner` PR #7/#8 and `datadog-agent` issues #47021/#47024 all 404 today;
only the remediation PR #9 survives). So `tests/corpus/hackerbot_claw_incident.json` **reconstructs** the three
events and `tests/test_incident_hackerbot_claw.py` proves the deterministic layer catches each one — no model,
no loop, no network:

- **The `datadog-iac-scanner` PR** — a `${IFS}`/base64 payload hidden in a *filename* under
  `documentation/rules/` (the vulnerable workflow interpolated the changed-file list into bash). It
  de-obfuscates to the published, now-dead `curl … | bash` IOC (**critical**); `raw_content` scans filenames,
  so a filename-borne payload can't hide.
- **The bulk-label issue** (#47021) — a prompt injection telling the triage LLM to label every open issue and
  exfiltrate into Slack. Fires `prompt-injection`.
- **The CODEOWNERS issue** (#47024) — a prompt injection to append a fake owner to `.github/CODEOWNERS`.
  Signals on two independent grounds: `prompt-injection` **and** `codeowners-tamper`.

Each event is asserted under a *neutral benign verdict*, so the signal is evidence-driven (MF3): a false-benign
self-report could not have suppressed any of them. (Shipping the real dead IOC in a defensive corpus is standard
practice — the change is static data the detector reads, never fetches or executes.)

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

# score recorded runs with the reward-free ATLAS LLM-as-judge scorecard (offline with the stub judge):
uv run --package diff-sentry-eval python -m diff_sentry_eval score "output/traces/*.jsonl" demo
```

Each run also carries an **ATLAS TF/TA/TG/PA rubric** — a fixed, reward-free LABEL surface (deterministic
per-criterion facts re-lensed from the run's own labels/metrics, never a score) — in its `run_start` meta,
its `DetectionResponse.rubric`, its `rl_export` bundle (`rubric_signal`), and the studio's rubric card. The
sibling **[`eval/`](eval/README.md)** workspace member (`diff-sentry-eval`) scores the assembled verdict
with an independent LLM judge (per-category means only) — a one-way trace reader that never feeds training.

Prefer a **Claude Pro/Max subscription** over an API key for the planner/analyst? Give either role a
`claude-agent-sdk/<model>` value (e.g. `DS_SUB_LM=claude-agent-sdk/claude-fable-5`) and it runs on your
personal Claude login via the official Claude Agent SDK — `uv sync --extra subscription`, log the Claude
Code CLI in, and `unset ANTHROPIC_API_KEY`. The **classifier** always needs its own OpenAI-compatible
endpoint (set `DS_CLASSIFIER_LM`), so a subscription-only end-to-end run isn't supported. See the
subscription block in [`.env.example`](.env.example).

## Status

**v0.2.0** — the classify → judgement-only verdict → deterministic-evidence union → response → reward-free
export loop, fully offline-testable. The planner/analyst can now run on a **Claude Pro/Max subscription**
(`claude-agent-sdk/<model>`, the opt-in `subscription` extra); the classifier stays on its own
OpenAI-compatible endpoint by design. Host-side GitHub ingestion and the SIEM emitter ship as real, injectable
seams (unit-tested with fakes); wiring them to a live GitHub/SIEM and adding the cheap pre-filter tier are the
next increments. CI gates the offline suite + ruff on every push/PR (`.github/workflows/ci.yml`). A further
tracked increment: a self-review workflow that dogfoods the detector on this repo's own incoming PRs/issues —
structurally safe because the change is ingested as *data* (never checked out, never executed) and a skewed
verdict cannot suppress the evidence union; advisory comment only, never a required merge check. Built on
`rlm-kit` with **zero** changes to the kit — a consumer extends, it doesn't fork.
