# diff-sentry-studio: visual & UX spec

The web frontend's design contract. Implementation (`static/{index.html,app.js,style.css,trajectory.js}`)
follows this file. Architecture lives in the README (zero-build vanilla, a vendored font, served
same-origin by the FastAPI app); this doc owns the look and feel.

## 1. Theme

**A detection console.** A dark security console where an AI agent classifies ONE GitHub change for
malicious intent. The change (a PR diff, an issue body) is UNTRUSTED DATA under analysis. The console's
job is to show, unmistakably, **the call** (benign / suspicious / malicious) and, above all, **the
deterministic evidence** the call is checked against. Cyan signal-light on deep slate, sharp 2px geometry,
metal accents.

Energy: focused, instrumented, neither playful nor corporate. The mono-forward type, the verdict-alloy
frame, and the indicator evidence must be unmistakable on the first screen.

Utility mode, no marketing hero. The page reads in four steps: orient (header), input (change), status
(live feed), result (verdict, evidence, change).

## 2. The signature: evidence ≠ verdict (MF3, made visual)

diff-sentry's load-bearing invariant is that the planner submits a JUDGEMENT only; the deterministic
indicator EVIDENCE is unioned on read, and a high/critical hit forces a SIEM signal **regardless of the
verdict**. A prompt injection can skew the verdict but not the evidence, so the frame alloy is keyed to the
**derived state, NOT the planner's verdict**:

| derived state | frame alloy | headline | when |
|---|---|---|---|
| **alert** | red-metal | ALERT | `signal == true` AND `max_indicator_severity ≥ high` (hard evidence fired) |
| **flagged** | amber | FLAGGED | `signal == true` on sub-floor evidence (the verdict ∈ `emit_on` carried it) |
| **noted** | amber | NOTED | `signal == false` but verdict ≠ benign (e.g. a narrowed `DS_EMIT_ON` leaves a `suspicious` verdict sub-threshold). No signal badge, and never green, since green would contradict the verdict chip |
| **clear** | green | CLEAR | `signal == false` AND verdict == benign |
| **refusal** | iron | REFUSAL (`failed`) / INCONCLUSIVE (otherwise) | no verdict landed |

The planner's `verdict` is a chip inside the card, not the frame. When a `benign` verdict comes with a
fired signal (the hackerbot false-benign), the card carries a prominent **CONTRADICTION** marker
(`⚠ planner verdict benign · deterministic evidence overrides — SIEM signal fired regardless`). That is
diff-sentry's money shot: the model was skewed and the evidence still reached the SIEM.
`cited_unknown_ids` (the planner cited a hit that does not exist) shows as a **fabricated citation** badge.

## 3. Palette

Dark by default, with a **light theme** toggled from the header: `:root[data-theme="light"]` overrides the
tokens; the choice is persisted and seeded from `prefers-color-scheme`. The live tokens in
`style.css` (`:root` and `[data-theme="light"]`) are the source of truth; the dark set is:

```
--bg:#0a0e13  --surface-1:#121a24  --surface-2:#1a2431  --surface-3:#232f3e
--border:#313e4d  --border-strong:#45566a
--text:#e8eef4  --text-dim:#a2b4c4  --text-faint:#6a7c8d
--signal:#22d3c2  --signal-dim:#3fb3a8  --signal-glow:rgba(34,211,194,0.24)   /* THE brand accent */
/* severity (indicator wells + severity badge) */
--sev-critical:#f85149  --sev-high:#ff8c42  --sev-medium:#d29922  --sev-low:#3fb950  --sev-info:#6a7c8d
/* verdict-alloy (the frame signature — keyed to DERIVED state, §2) */
--alert-1:#ff6b5e; --alert-2:#a3231b; --alert-glow:rgba(248,81,73,0.30)      /* red-metal: hard evidence */
--amber-1:#ffd56b; --amber-2:#b8860b; --amber-glow:rgba(255,204,85,0.28)     /* flagged / noted */
--clear-1:#56d364; --clear-2:#2ea043; --clear-glow:rgba(63,185,80,0.22)      /* clear (benign, no signal) */
--iron-1:#5a6672;  --iron-2:#2e3742;  --iron-glow:rgba(70,80,92,0.20)        /* refusal / failed */
--analyst:#a371f7   /* the expensive sub-LM escalation (violet = rare/costly) */
--ok:#3fb950  --bad:#f85149  --warn:#d29922   /* feed/timeline outcome tints */
```

Rules: `--signal` is for interactive and "live" things (links, the Classify button, the active stream
pulse). Verdict-alloy metals belong on the card frame and its headline. Severity colors belong on the
indicator wells and the severity badge. Do not cross-use them. Nested surfaces step (bg → surface-1 →
surface-2 → surface-3), each with a 1px `--border`; two same-tone panels never touch.

## 4. Typography

Mono-forward, because a security console reads as a terminal. `JetBrains Mono` (vendored woff2 400/700)
for the wordmark, all labels, ids, stats, badges, the diff, and the indicator wells. System sans
(`ui-sans-serif,-apple-system,…`) ONLY for human prose: `summary`, `rationale`, indicator `title`,
refusal `detail`. The mono-frame / sans-prose contrast is the hierarchy.

## 5. Components

### 5.1 Header
`▣ diff-sentry studio` wordmark (`▣` in `--signal`). Right: three role chips
`planner / analyst / classifier`, each a mono pill showing the configured model name from `GET /v1/config`
on page load (a steady `--signal` dot when configured, no pulse; the name truncates with an ellipsis when
the header runs out of width and hides below 760px). Then a theme toggle (`☾`/`☀`). There is no backend
chip, matching the sibling consoles; the classify backend stays API-only metadata on `GET /v1/config`.

### 5.2 Change input (left rail, top)
`▾ CHANGE` panel with a **mode switch** (`paste | pr | issue`):
- **paste** (classify): a mono `<textarea>` for a change-event JSON `{repo,kind,number,author,title,body,
  files}`. A **⚡ load a hackerbot demo** picker (from `GET /v1/fixtures`) drops a real reconstructed
  incident payload in and shows its `incident_ref`, `expected_signal`, and `expected_rules`, so the result
  can be read against the ground truth.
- **pr / issue**: `owner/repo` + number.
- **Classify ▶** (primary, `--signal`), disabled until the input is valid and while a run streams. A note
  under it says SIEM emission is off in the studio: the console shows the signal decision and the
  would-send payload, and never POSTs.
- A divider `or load a past run`, then a run-id input bound to a `<datalist>` from `GET /v1/runs` + Load.

### 5.3 Live feed (left rail, fills remaining height)
`▾ DETECTION LOG`. A scroll container, newest row at the bottom, appending one row per SSE event and
auto-scrolling only when already at the bottom. Each row: an inline-SVG icon chip tinted by family, a mono
primary line, a right-meta. Families:
- `detection.scan`: radar, tinted by the worst severity (label **Scan** · meta `N hits · worst`)
- `detection.classify`: `--ok` when validated, `--warn` when not; `--bad` with label
  **Deep classify · circuit broke** or **Deep classify · error** (meta `verdict conf`, or the error)
- `detection.analyst.escalation`: `--analyst` (label **Ask analyst**, the question as detail)
- `detection.fetch`: download, `--signal` (label **Fetch** · meta `200 · 4.5 KB`); failure → **Fetch
  failed** in `--bad` with the note
- `detection.skill.read`: book, `#7d8fb3` (label **Read skill** · meta the skill name)
- `detection.tool` (any other tool): a wrench, `--text-faint` (label the tool name · meta `ok`/`failed`),
  so an unrecognized tool still gets a row
- `detection.run.created` / `completed`: flag, `--signal` (**Classification started** / **Finalized**);
  a client-side stream failure renders **Stream error** in `--bad`

Planner reasoning (`detection.plan.step`) is not in this feed, live or replay: diff-sentry flushes
`main_step` after the run (see the README). It lives in the Trajectory drawer. For a detector the action
stream is the core story: which indicators fired, and whether the run escalated.

### 5.4 The result: middle stage + right modules
Page-level **3 columns**: process rail | stage | modules. The modules column is absent (`.no-meta`) until
a result lands. Below 1280px the modules drop to a full-width row and the page scrolls; below 760px
everything stacks in one column.

**Middle stage:** ONE **verdict-alloy card** (frame per §2). On a wide screen it is fixed at page height
and its content scrolls INSIDE the card. A top-right **Verdict / Indicators / Change** switch orders the
views by triage:
1. **Verdict view** (the landing view): the derived-state headline (§2), the `verdict` chip +
   `confidence`, the `max_indicator_severity` badge, a **SIGNAL** badge (`● SIEM signal` when
   `signal==true`), a fabricated-citation badge when `cited_unknown_ids` is non-empty, the CONTRADICTION
   marker (§2), then the `summary` (sans) and `recommended_action` (allow / flag-for-review /
   block-merge). A refusal shows the refusal body instead (§5.5).
2. **Indicators view** (the star, ALWAYS present, refusal included, because the evidence outlives the
   self-report): the UNION of every hit, each in a well colored by severity: `[SEV] rule` (mono) + `title`
   (sans) + a bounded `evidence` snippet (+ `decoded` when the rule de-obfuscated one) + `location`. The
   union is rendered FLAT. A baseline hit and a planner re-scan of the same content dedupe to one member
   (`mint_id` is deterministic), so baseline-vs-re-scan provenance is not recoverable from the union and
   is not drawn here; it lives in the Trajectory drawer's per-turn `scan` calls and the `run_start`
   `baseline` count. Empty → "no indicators fired".
3. **Change view** (when the run carries a source; never on a refusal): the source line
   (`repo · kind · #number · author`), then the change. A pasted payload's files render as a diff colored
   by role (additions green, deletions red, hunk headers signal, file headers faint); an issue shows its
   body. A pr/issue or replayed run, whose diff never reaches the client, falls back to the run's OWN
   `run_start` event, fetched lazily from `GET /v1/runs/{id}/iterations`: the exact normalized untrusted
   content the planner saw, mono and uncolored (capped at 16k chars with a truncation marker). A missing
   trace gets a "nothing to show" note; a transient fetch error gets its own retry note, never a false
   "gone" claim.

**Right modules** (`.module`: thin top accent, uppercase label head, `--surface-1` body), in order:
1. `RUN TELEMETRY`, top-right as the run's signature (the convention across the sibling consoles), from
   `process`: an `elapsed_s` headline, then a grid of steps (the run's OWN count, unclamped), scans,
   deep-classify (amber if a circuit broke), and analyst (violet if >0). Fetch is off by default, so it
   has no fixed tile; a fetch shows in the Trajectory drawer. `hit_iteration_cap` shows as an amber flag
   chip, read from `process` and never inferred from a step-vs-cap comparison.
2. `VERDICT DETAIL`: `rationale` (sans), `techniques[]` chips, `suspect_files[]`, and each
   `cited_unknown_ids` entry as a red fabrication chip.
3. `SIEM SIGNAL`: whether a signal fired, plus the would-send payload, which mirrors
   `emit.signal_payload` field for field (run id, source, verdict, confidence, recommended action,
   max severity, techniques, suspect files, summary, and the indicator list). A note says the studio does
   not POST.
4. `SUMMARY`: the one-line recap, when the response has one.
5. `ATLAS RUBRIC`, tagged as labels and not a score: each criterion with a TF/TA/TG/PA category badge, its
   name and description, and its deterministic `observed` facts. It never shows a score. A response
   without a `rubric` renders nothing here.

### 5.5 States (every state explicit)
| status | frame | body |
|---|---|---|
| `classified` (signal, evidence ≥ high) | red-metal | ALERT headline, SIGNAL badge, full evidence |
| `classified` (signal on sub-floor evidence) | amber | FLAGGED headline |
| `classified` (non-benign, no signal) | amber | NOTED headline, no signal badge (the verdict chip still shows) |
| `classified` (benign, no signal) | green | CLEAR headline |
| `inconclusive` | iron | INCONCLUSIVE refusal card (ran, no usable verdict) + any indicators gathered |
| `failed` | iron | REFUSAL card with the reason and detail. **The evidence floor still shows**: a run that crashed after a critical hit still displays the SIGNAL badge |

### 5.6 Empty / running / error
- Empty: a dim shield placeholder: "Classify a change: paste a payload, load a PR/issue, or try a
  hackerbot demo." No modules column (`.no-meta`).
- Running: a skeleton card (iron frame) with "Classifying…" in the stage and no modules column. The live
  activity is the Detection log, which streams actions as they happen; telemetry and indicators render
  once the result lands.
- Stream error mid-run: the backend completes the stream with a `failed` response, which renders the
  refusal card. Without the `live` extra the worker still does this, so the stream never hangs. A
  client-side stream failure renders a `stream_error` refusal. Never blank.

### 5.7 Trajectory drawer (bottom sheet)
Replays a finished run turn by turn from `GET /v1/runs/{id}/iterations`, opened by a `▤ Trajectory`
handle once a run is on screen. It reads rlm-harness's `trace/v1` contract, which is additive-only within
v1, so missing fields degrade instead of breaking. Parts: a tool timeline (segment width ∝ `duration_s`,
colored by family scan/classify/analyst/fetch/skill, plus a generic family for other tools), a left nav
of turns with a search box, a detail pane (Init → the change + instructions + model roles + budgets; a
turn → reasoning + REPL; a tool → its structured content: scan hits, classify verdict, analyst Q→A, fetch
head), and a replay transport `⏮ ▶/⏸ ⏭ N×` (1× to 64×; the pure decisions live in `replay-core.js`,
unit-tested). Timing is honest about its two clocks: when the trace has live per-turn stamps
(`per_turn_timing`) the drawer shows per-turn durations; otherwise it says so in an info note and
replays each turn at a nominal pace.

## 6. Depth / motion
2px geometry (radius 2px for chips, buttons, and panels; 3px for the card). Depth comes from surface steps
and 1px hairlines; the card gets one soft lift plus its alloy frame. No glassmorphism, no purple/blue
gradients (the only gradient is the verdict-alloy frame and its one-time sweep on mount). All motion
respects `prefers-reduced-motion`. Alloy sweep 600ms on card mount; feed-row enter 180ms; running dot
pulse.

## 7. Do / Don't
Do: mono for structure, sans for prose; key the frame to the DERIVED state (§2), never the raw verdict;
make the Indicators view the star; render every state explicitly (a refusal is first-class); show the
CONTRADICTION marker when the verdict undersells the evidence.

Don't: use Inter, a centered hero, three identical cards, or a purple/blue gradient; invent response
fields a run lacks (hide, don't fake); block the UI on the font (it degrades); key the frame on the
planner's verdict, which is the MF3 violation this design exists to prevent.

## 8. Acceptance (in a browser)
1. The first screen is unmistakably this product: a shield placeholder, the mono wordmark, and the
   model-name chips.
2. A hackerbot PR demo classifies to a **red-metal** ALERT card with an `obfuscated-payload`/`critical`
   indicator well (its base64 decodes to a curl-pipe-shell) and a `● SIEM signal` badge. If the planner said benign, the CONTRADICTION marker shows
   and the frame stays red (evidence overrides).
3. A benign refactor is a **green** CLEAR card with no signal and an empty Indicators view.
4. The Indicators view is the visual star, rendering the flat union of hits; per-turn scan provenance
   (baseline vs re-scan) lives in the Trajectory drawer.
5. `failed`/`inconclusive` show the iron refusal card; a failed run that fired a critical hit still shows
   the SIGNAL badge.
6. The live feed streams the action families (scan/classify/analyst/fetch/skill), newest at the bottom.
7. The `▤ Trajectory` handle opens the drawer with a working timeline and replay transport.
8. No overflow at 375px; the verdict-alloy frame survives mobile.
