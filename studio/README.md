# diff-sentry-studio

The web layer for [`diff-sentry`](..) (ships in-repo as a **uv workspace member**): turn one
malicious-change classification into something a user *watches happen* and then *reads* — a live
**detection log**, the verdict framed by the **evidence** (not the planner's self-report), the
deterministic **indicators** that fired, and the SIEM signal decision — the way the AI-studio
playgrounds feel, not a CLI dump.

Two pieces:

1. **SSE server** — serves a run's structured `DetectionResponse` and **replays the run's trace as
   Server-Sent Events**, so the frontend can render the build-up step by step. It can also drive ONE
   live classification and stream its **action** trajectory.
2. **Web frontend** — a detection console: a change-input box (paste a payload, or ingest a PR/issue),
   a live event feed, a verdict card whose **frame is keyed to the derived state** (signal + evidence
   severity), the **indicators** as the star view, and a Trajectory drawer that replays the RLM run
   turn by turn.

It does **not** re-implement any diff-sentry logic. diff-sentry owns the contract; this serves it. The
one hard rule it honors visually: **the card frame is derived from the deterministic evidence, never
from the planner's `verdict`** — a verdict can be skewed by an in-diff prompt injection; the unioned
indicator evidence and the SIEM signal cannot (MF3). See `DESIGN.md` for the full visual contract.

## The contract it serves

diff-sentry writes two per-run artifacts this server reads (from `<workspace-root>/output` by default —
where the `diff-sentry` CLI writes with its default `--out ./output`; override with `DS_ARTIFACTS_DIR`):

- `responses/{run_id}.json` — the **`DetectionResponse`** (`diff_sentry.schema`): `status`
  (`classified` when a verdict landed / `inconclusive` / `failed`), the planner's judgement-only `verdict`
  (`benign`/`suspicious`/`malicious`) + `confidence`, the **union of every indicator hit**
  (`indicators`, deterministic — id/rule/severity/title/evidence/location), the derived
  `max_indicator_severity`, the **`signal`** boolean (verdict ∈ `emit_on` **OR** severity ≥ the
  high/critical floor — a false-benign verdict cannot suppress it), `techniques`/`suspect_files`, a
  `recommended_action`, and `process` (effort metrics). This is the **final, durable** output.
- `traces/{run_id}.jsonl` — the append-only run trace; its events are replayed as SSE and drive the
  Trajectory drawer.

**`cited_unknown_ids`** (the planner cited an indicator id that has no recorded hit — a fabrication
tell) is **not** in the envelope; the server re-derives it from the trace and augments
`GET /v1/runs/{id}` with it (see `iterations.cited_unknown_ids`). Missing trace → `[]`.

## Endpoints

| Method | Path | Returns |
|---|---|---|
| `GET` | `/` | the detection console (zero-build vanilla page) |
| `POST` | `/v1/classify` | `text/event-stream` — **drive ONE LIVE classification**, ending with `detection.run.completed` carrying the durable `DetectionResponse`. Body `{mode, repo?, number?, payload?, run_id?, overwrite?}`: `mode=classify` runs a pasted `payload`; `mode=pr`/`issue` ingests `repo`+`number` host-side via `gh`. **409** if a finalized run already owns `run_id` and `overwrite` is not `true` (a re-classify resets the trace, so it would clobber the stored run). Needs the `live` extra |
| `GET` | `/v1/fixtures` | the bundled **hackerbot-claw** incident events as one-click demo inputs, with `expected_signal`/`expected_rules` for expected-vs-actual. `{fixtures: []}` when the corpus tree is absent |
| `GET` | `/v1/runs/{run_id}` | the stored `DetectionResponse` JSON, **augmented with `cited_unknown_ids`** (404 if absent) |
| `GET` | `/v1/runs/{run_id}/iterations` | the per-iteration trajectory breakdown (behind the Trajectory drawer) |
| `GET` | `/v1/runs/{run_id}/events?delay=0.0` | `text/event-stream` — a finished run's trace **replayed** as SSE; `delay` (s) paces it |
| `GET` | `/v1/runs` | run ids that have a stored response (the Load picker) |
| `GET` | `/v1/config` | the configured model per role, the classify backend, and the iteration budget the UI seeds from (fault-tolerant: never raises if `DS_*` is unset) |

Best practice (per OpenAI's streaming guidance): the stream carries the **process**; wait for
`detection.run.completed` (it carries the full result on the live endpoint; the UI then re-`GET`s
`/v1/runs/{id}` for the `cited_unknown_ids` augmentation, or GETs it after a replay).

## SSE event vocabulary (trace event → public event)

| trace event | SSE `event` | `data` |
|---|---|---|
| `run_start` | `detection.run.created` | `{models, source, baseline}` (`baseline` = host-side hit count) |
| `main_step` | `detection.plan.step` | `{turn, reasoning, has_code}` |
| `tool_call: scan_indicators` | `detection.scan` | `{n, worst, region}` (hit count + worst severity) |
| `tool_call: deep_classify` | `detection.classify` | `{ok, verdict, confidence, circuit_broken, error, errors}` |
| `tool_call: fetch_url` | `detection.fetch` | `{url, ok, status, bytes, note}` (off by default) |
| `tool_call: read_skill`/`list_skills` | `detection.skill.read` | `{name}` |
| `sub_call` (analyst) | `detection.analyst.escalation` | `{question, answer}` |
| `result` | `detection.result.done` | `{}` — signal; client then GETs the full response |
| `run_end` | `detection.run.completed` | the `DetectionResponse` (live) / `{}` (replay) |

The mapping lives in `diff_sentry_studio/mapper.py` (a pure function, unit-tested) — the single source
of truth for the public event surface.

### Honest caveat — the LIVE feed is actions-only

diff-sentry's `cli.run` exposes exactly one live observer: the `TraceRecorder`'s `on_event`, which
fires for **tool_calls and sub_calls** (the sandbox-invoked actions) as they happen. It has **no**
planner-reasoning callback, so the **live** feed shows the *actions* (scan / deep-classify / ask-analyst
/ fetch / skill) in real time, **not** the planner's reasoning turns. The reasoning is recovered
**post-hoc from the trace** — visible on **replay** (`detection.plan.step`) and in the **Trajectory
drawer**, never in the live feed. This is the deliberate **zero-harness-change** v1: the studio adds no
tool and no callback to the detection path. Surfacing live reasoning is a future **rlm-kit** increment
(a generic planner-step observer on the RLM), **not** a diff-sentry-specific callback bolted on here.

### Ordering caveat (replay)

A stored trace does **not** preserve true `think → act` interleaving: tool_calls are written live
(step_ids 1…N) but the planner's `main_step` reasoning turns flush **post-hoc at finalize** (trailing
step_ids), so a *replay* streams the **action timeline first, then the reasoning turns**. The server
replays in `step_id` order (deterministic); the Trajectory drawer presents turns and their tools
together.

## Run

The studio shares ONE venv with the root `diff-sentry`, so every command runs from the **repo root**
(the workspace root).

**Replay-only** (serve + replay stored runs — no diff-sentry runtime needed). The artifacts dir
defaults to `<repo-root>/output` — exactly where a `diff-sentry` CLI run writes — so no `DS_ARTIFACTS_DIR`
is needed when you run both from the repo root:

```bash
uv sync --package diff-sentry-studio          # fastapi + uvicorn into the shared workspace venv
uv run --package diff-sentry-studio uvicorn diff_sentry_studio.app:app --reload
open http://127.0.0.1:8000/                   # paste/PR/issue → live feed → verdict + indicators
curl http://127.0.0.1:8000/v1/runs
uv run pytest studio/tests                    # the contract tests (no server, no diff-sentry needed)
for t in studio/tests/*.test.js; do node "$t"; done   # the node core-tests (zero-dep, pure JS)
```

**Live** (`POST /v1/classify` drives a REAL classification) needs `diff_sentry` importable AND its env
(`DS_ROOT_LM` planner / `DS_SUB_LM` analyst / `DS_CLASSIFIER_LM` classifier / `DS_BASE_URL` …), a Deno
sandbox (`brew install deno`) for the pyodide REPL, and `gh` for `pr`/`issue` ingest. Without
`diff_sentry` the live worker raises `ModuleNotFoundError` — the stream still completes with a `failed`
card, but nothing runs.

`diff-sentry` consumes **rlm-kit as a commit-pinned git source**, so `uv sync` is self-contained — no
sibling checkout needed. Co-developing rlm-kit locally? Overlay it editable (`uv pip install -e
../rlm-kit`) so your local edits are picked up.

Do the root env setup first (`cp .env.example .env` and fill it in — see the root `README.md`); the
studio reads `os.environ` directly and does **not** auto-load `.env`, so source it into your shell:

```bash
set -a && source .env && set +a               # DS_ROOT_LM / DS_SUB_LM / DS_CLASSIFIER_LM / DS_BASE_URL … (use `source`, not `.`)
uv run --package diff-sentry-studio --extra live \
  uvicorn diff_sentry_studio.app:app --port 8731 --timeout-graceful-shutdown 12
```

**Subscription mode** — if a role runs on a Claude Pro/Max subscription (`.env` has
`DS_ROOT_LM`/`DS_SUB_LM=claude-agent-sdk/<id>`), the live worker also needs the Claude Agent SDK, so add
`--extra subscription` **to every `uv sync`/`uv run`** (it forwards `diff-sentry`'s own `subscription`
extra); it **must** ride with `--extra live` in the **same** command, or a later bare sync prunes the SDK
back out:
```bash
uv run --package diff-sentry-studio --extra live --extra subscription \
  uvicorn diff_sentry_studio.app:app --port 8731 --timeout-graceful-shutdown 12
```
Without it a subscription run raises `ImportError: ClaudeAgentLM requires the optional dependency … No
module named 'claude_agent_sdk'`.

(Artifacts default to `<repo-root>/output`, where the CLI writes them, so the studio's own live runs land
next to CLI runs and are mutually replayable; override with `DS_ARTIFACTS_DIR`. Skip `--reload` for live
runs — editing a `.py` restarts the server mid-stream. SIEM emission is
**off** in the studio: the live worker calls `cli.run(..., emit=False)`, so a classification never
POSTs a signal; the console shows the signal decision + the would-send payload instead.)

**No cooperative cancel (v1).** diff-sentry's `cli.run` takes no `cancel_event`, so the studio has no
Stop button and no graceful-cancel wiring: a live run runs to completion (bounded by the RLM's own
`max_iterations`, typically seconds to a minute). Ctrl+C on the server kills the process; an
in-flight run's worker thread is a daemon and dies with it, which may leave a **partial trace and no
stored response** for that run_id (it is simply not in the Load picker). Adding cooperative cancel is a
future increment and, like live reasoning, belongs in **rlm-kit** (a generic run-cancel seam), not as a
consumer-specific hack here.

The frontend is served from the repo checkout (`static/` resolved next to the package). It is a
**zero-build vanilla** page (no node/npm/bundler): `static/{index.html,app.js,style.css,trajectory.js}`
plus the pure, unit-tested `replay-core.js` / `run-core.js` and a vendored JetBrains Mono. The same
FastAPI app serves it (same-origin, no CORS); `/static/*` are the assets, `/v1/*` the API.

## Web frontend (the detection console)

`GET /` is a single page (see `DESIGN.md`):

- **Change** — paste a change `payload` (or pick a **⚡ hackerbot demo** to load a reconstructed
  attack), or switch to **pr**/**issue** and give `owner/repo` + a number. **Classify** drives a live
  run; the **Load** box replays a stored run id (a `<datalist>` from `GET /v1/runs`). A **light/dark
  toggle** (persisted; honors `prefers-color-scheme`) sits in the header with the role chips.
- **Detection log** — the live SSE feed of *actions* as they happen (scan / deep-classify / ask-analyst
  / fetch / skill). Newest at the bottom. (Planner reasoning is in the Trajectory drawer — see the
  live-feed caveat above.)
- **The result** (two columns) — the middle **stage** is ONE page-height **verdict card** (content
  scrolls inside it) whose alloy is the **derived state, not the verdict**: `alert` (signal **and**
  ≥high evidence), `amber` (signal, softer evidence), `clear` (no signal), `iron` (refusal / no
  verdict). When the planner says `benign` but a hard indicator forced a signal, a **CONTRADICTION**
  banner spells out that the deterministic evidence overrode the self-report. A top-right
  **Verdict / Indicators / Change** switch walks the triage order: the call, then **Indicators** (the
  **star** — every union hit, severity-ranked, with bounded evidence and any base64 decode; always
  reachable, refusal included), then the untrusted diff. The right column opens on **Run telemetry**
  (the run's signature, top-right like the sibling consoles), then **Verdict detail** (rationale,
  techniques, suspect files, and any **fabricated citations**), the **SIEM signal** (the decision +
  the would-send payload, never POSTed), and the **ATLAS rubric** (the run's reward-free TF/TA/TG/PA
  labels — a category badge + each criterion's deterministic observed facts, from `response.rubric`,
  tagged *labels — not a score*; shown on a refusal too, since a failed run still has a trajectory to
  label — same discipline as the sibling consoles).
- Every `status` is explicit — a `failed`/`inconclusive` run shows an **iron refusal card** with the
  reason and any evidence still gathered, never a blank screen.

Both live and replay use one `streamSSE()` (fetch + `ReadableStream`) since native `EventSource` cannot
POST. There is also a **Trajectory** drawer (a bottom-sheet) that replays the run iteration by
iteration — the planner's REPL turns, a tool timeline (segment width ∝ time), and a transport to
step/play through it — built from `GET /v1/runs/{id}/iterations`.

## Not built yet (deferred)

- **Cooperative cancel / graceful shutdown** — no Stop button (see above); a killed live run may leave a
  partial trace and no stored response. The fix is a generic run-cancel seam in **rlm-kit**.
- **Live planner reasoning** — the live feed is actions-only; interleaving reasoning needs a generic
  planner-step observer in **rlm-kit** (the same reason).
- **Wheel-packaged static** — the frontend is served from the repo checkout (the supported run mode);
  bundling `static/` into the wheel for a `pip install`-only deploy is deferred. The `/` route + mount
  are guarded, so a backend-only install without the dir still boots.
- **Per-run isolation under concurrency** — the live endpoint runs one job per request in its own
  thread + queue; heavy concurrent multi-run isolation (they share the process CWD/artifacts dir) is a
  later refinement.
