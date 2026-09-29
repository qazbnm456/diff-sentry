# diff-sentry — agent guide

A BewAIre-style malicious-change detector built on `rlm-harness`. It classifies ONE GitHub change
(PR / issue / push) for malicious intent: the change is UNTRUSTED DATA held in a sandboxed REPL, the
planner SUBMITs a judgement-only verdict, and the deterministic indicator EVIDENCE is unioned on read into
a SIEM signal. `README.md` has the pipeline table and the honest caveats; rlm-harness's "Building a
consumer" is the extension contract this project lives within.

rlm-harness is an exact PyPI pin (`rlm-harness==X.Y.Z` in `pyproject.toml`, locked in `uv.lock`). Overlay
`uv pip install -e ../rlm-harness` only while co-developing the kit, and bump the pin once the fix ships.

## Verify

- `uv run pytest` — the full offline suite (`uv sync --group dev` first). No live LLM, network, or Deno:
  dspy paths use DummyLM / rlm-harness's `ScriptedInterpreter`, transports are injected fakes, and
  `tests/corpus/` pins the indicator suite's hit/miss behavior.
- `uv run --package diff-sentry-eval --extra dev python -m pytest eval/tests` — the eval member's own suite
  (the `--package` is required; a root `uv run` does not install the member). Run it when you touch
  `assemble.py`, `rl_export.py`, `rubric.py`, `schema.py`, or the trace payloads it scores.
- `uvx ruff check .` — lint (line-length 110). CI runs it as its own job, next to both suites and the
  node tests (`.github/workflows/ci.yml`).
- A live run needs role creds (`DS_*`, see `.env.example`), Deno (`brew install deno`), and `gh` for
  `pr`/`issue` ingest. `render`/`export` are offline; `classify` ingests offline but classifies live.

## Running — always through the CLI

- Run via `cli` (`pr` / `issue` / `classify`), never an ad-hoc script. `cli.run(event, …)` is the
  programmatic entry: it records `<out>/traces/{run_id}.jsonl` (dropping a stale one first, since
  TraceRecorder appends), writes `<out>/responses/{run_id}.json`, and emits the SIEM signal host-side
  after the run. It never raises: a crash still writes a `status=failed` response that can signal off the
  evidence floor. Extend `cli.py` rather than driving `detect_from_event` / `build_response` directly.
- Offline: `python -m diff_sentry render <trace> <run_id>` re-renders a response;
  `python -m diff_sentry export "output/traces/*.jsonl" ds.json` exports the reward-free dataset.

## Hard invariants — do not break

- **The change is DATA: read, never execute.** It is a REPL variable under the default `pyodide`
  interpreter; nothing in it is run, built, or fetched-and-run. An embedded instruction is a
  `prompt-injection` signal, never a command. Never route the interpreter to `local`.
- **Judgement-only SUBMIT; evidence is unioned on read (MF3).** `ChangeVerdict` has no hits field; the
  planner may only CITE ids (`indicator_ids`). `assemble.assemble_verdict` unions every hit in the trace
  (run_start `baseline_indicators` ∪ each `scan_indicators` tool_call) and derives
  `signal = verdict ∈ emit_on OR max severity ≥ SIGNAL_SEVERITY_FLOOR`. A false-benign verdict cannot
  suppress evidence; a cited id with no recorded hit lands in `cited_unknown_ids`. The same assembly runs
  on every read path (live, re-render, `rl_export`). Never add a hits/severity/signal field to the SUBMIT
  type or a second signal derivation.
- **An ungroundable input yields `inconclusive`, never a confident verdict.** `inconclusive` is a
  sanctioned 4th SUBMIT value (`schema.INCONCLUSIVE_VERDICT`) mapped to `status="inconclusive"` +
  `RefusalInfo(reason="insufficient_evidence")`. The host-side backstop `normalize.has_groundable_content`
  downgrades even a confident verdict when no groundable content exists. It is a reward-free negative
  outcome, not an escape hatch for a hard-but-real change, and not in `emit_on`, so hard indicator
  evidence still signals on its own.
- **MF1: the metadata sandwich in `normalize_event`.** dspy previews ~1000 chars of head+tail, so an
  identical derived-metadata header and footer deny the attacker those edges, and attacker-authored
  metadata fields are capped (`_MAX_META_*`). The title/author ride in `raw_content` so the host-side
  baseline catches a title-borne injection that skews the planner. Don't flatten the sandwich or lift
  the caps.
- **MF2: enrichment fetch is GitHub-allowlisted and off by default** (`enable_fetch=False`). An injected
  instruction could steer a fetcher to `https://attacker.tld/?leak=…`: the kit's SSRF guard blocks
  internal targets, and the `github_hosts` allowlist blocks external ones, re-checked on every redirect
  hop. Never add a general-purpose fetch or fetch a URL the change names. `fetch_allow_cidrs` only
  relaxes the resolved-IP layer (fake-IP proxy / split DNS); the syntactic guard still refuses
  localhost/metadata.
- **Indicators are deterministic, pure Python, and in-loop safe.** Rule-level invariants (severity
  tuning, per-file pairing, `pwn-request`, the tool name) live in `.claude/rules/indicators.md`.
- **Models are ROLES configured by env**: `DS_ROOT_LM` planner, `DS_SUB_LM` analyst, `DS_CLASSIFIER_LM`
  classifier (defaults to the analyst). Refer to them by role; no hardcoded model name.
- **The budget is hard: `max_retries=1`, no whole-RLM retry.** One change = one trajectory, so the trace
  stays valid training data. A failed run is infra before it is a schema bug; see
  `.claude/rules/detect-setup.md` for how the failure names itself.
- **A second model-judgement is a TOOL, never the sub-LM.** `deep_classify` (on rlm-harness's
  `make_model_tool`) is the swappable second-stage seam the planner chooses to call, so the decision is a
  `tool_call` in the trajectory. The analyst intercept (`intercept_sub_lm`) is tracing-only, zero
  transforms. Swapping the backend touches only `classify_backend` / `_selfclassify_chat`. The planner
  passes distilled findings, never the whole diff.
- **GitHub ingest and SIEM emission are host-side plumbing, never planner tools.** `ingest.py` shells out
  to `gh` host-side (transport injectable); `emit.emit_signal` POSTs after the run, stays out of the
  trajectory, and never raises. Only choices the policy makes are tools; delivering a finished result is
  plumbing.
- **This is a ROLLOUT source: trajectories, not reward.** `rl_export` passes `reward=None`; labels read
  the assembled verdict and metrics are objective effort counters. `deep_classify` tool_calls train the
  classifier; every other action is the planner's. A metric keeps ONE meaning across rlm-harness
  versions (the corpus mixes them; `run_start.payload.rlm_harness` names the writer): a quantity a newer
  kit makes observable gets a NEW key that is None where the trace cannot say (e.g. `analyst_failures`).
  The ATLAS rubric and the eval member stay reward-free too; see `.claude/rules/rubric-and-eval.md`.
- **Attack knowledge lives in `diff_sentry/skills/`, not the prompt.** The skill catalog is injected
  (`load_skills_as_tools(discovery="inject")`) and `read_skill(name)` pulls a body on demand. Fix a wrong
  convention by editing or adding a skill; `detect.INSTRUCTIONS` holds only identity, the MISSION frame,
  the tool cost model, the triage loop, and output-gating rules. Skills ship via
  `packages = ["diff_sentry"]`; a force-include duplicates them and breaks the build.
- **Keep the dspy-free modules dspy-free.** `config`, `schema`, `normalize`, `indicators`, `assemble`,
  `response`, `emit`, `ingest`, `rl_export`, and `rubric` must not import dspy at module top, and
  `import diff_sentry` must not import dspy (`ClassifyChange` / `setup` / `run` / `detect_from_event` are
  lazy PEP 562 re-exports).
- **The trace self-describes the run.** `run_start` meta carries the normalized event, instructions,
  source echo, `baseline_indicators`, `emit_on`, role→model names, budgets, and the rubric skeleton, so
  an offline re-render/export re-derives the same `signal` (reading `emit_on` from meta, never current
  config). Any new per-run config that affects read-time derivation must ride in meta.

## Topic guides

Claude Code loads each rule automatically when you touch a matching file; other agents should read the
file before working in that area.

| Area | File |
|---|---|
| Indicator rules, severities, corpus | `.claude/rules/indicators.md` |
| Model roles, subscription auth, run failures | `.claude/rules/detect-setup.md` |
| ATLAS rubric labels, eval member, studio rubric card | `.claude/rules/rubric-and-eval.md` |
| Cutting a release (five version sites) | `.claude/skills/release/SKILL.md` |
| What to keep across context compaction | `.claude/rules/handoff.md` |

## Layout

- rlm-harness owns the generic cores: `make_model_tool` (chat → retry → validate → circuit-break) under
  `deep_classify`, and the SSRF primitives (`is_safe_url`, `resolved_host_is_safe`, `parse_cidrs`) under
  `fetch_tool`, which adds the GitHub allowlist, the httpx provider, and tracing.
- When this consumer needs a workaround, fix the reusable gap in rlm-harness generically; never
  special-case diff-sentry there. Consumer values (`DS_*` roles, the verdict schema, indicator rules, the
  SIEM payload shape) stay here.
- Next increments: a cheap pre-filter tier (deterministic indicators + one small single-shot call) as
  host-side plumbing in front of `cli.run`, not extra RLM turns; and live GitHub/SIEM wiring.
- Two workspace members, never in the `diff_sentry` wheel: `studio/` (`diff-sentry-studio`, the detection
  console, behind its `live` extra) and `eval/` (`diff-sentry-eval`, the reward-free scorecard). Both read
  the trace / `DetectionResponse` contract through the public surface only. Keep the root wheel at
  `packages = ["diff_sentry"]` so `uv build` never sweeps them in.
