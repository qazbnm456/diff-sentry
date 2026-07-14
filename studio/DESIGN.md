# diff-sentry-studio: visual & UX spec

The web frontend's design contract. Implementation (`static/{index.html,app.js,style.css,trajectory.js}`)
follows this file. Architecture is locked in the README (zero-build vanilla, a vendored font, served
same-origin by the FastAPI app). This doc owns the *look and feel* only.

## 1. Theme

**A detection console.** A dark security console where an AI agent classifies ONE GitHub change for
malicious intent. The change (a PR diff, an issue body) is UNTRUSTED DATA under analysis; the console's
job is to show, unmistakably, **the call** (benign / suspicious / malicious) and — the part that matters
most — **the deterministic evidence** the call is checked against. Cyan signal-light on deep slate, sharp
2px geometry, metal accents.

Energy: focused, instrumented. Not playful, not corporate. The mono-forward type, the verdict-alloy
frame, and the indicator evidence are the things that must be unmistakable on first screen.

Utility mode (no marketing hero): orient (header) , input (change) , status (live feed) , result
(verdict + change + evidence).

## 2. The signature: evidence ≠ verdict (MF3, made visual)

diff-sentry's load-bearing invariant is that the planner submits a JUDGEMENT only; the deterministic
indicator EVIDENCE is unioned on read and a high/critical hit forces a SIEM signal **regardless of the
verdict**. The console must make this legible, so the frame alloy is keyed to the **derived state, NOT
the planner's verdict** (a verdict can be skewed by a prompt injection; the evidence cannot):

| derived state | frame alloy | when |
|---|---|---|
| **alert** | red-metal | `signal == true` AND `max_indicator_severity ≥ high` (hard evidence fired) |
| **flagged** | amber | `signal == true` by verdict alone (verdict ∈ emit_on, sub-floor evidence) |
| **noted** | amber | `signal == false` but verdict ≠ benign (e.g. a narrowed `DS_EMIT_ON` leaves a `suspicious` verdict sub-threshold) — amber, no signal badge, never green |
| **clear** | green | `signal == false` AND verdict == benign |
| **refusal / failed** | iron | no verdict landed |

The planner's `verdict` is a chip inside the card, not the frame. When the verdict UNDERSELLS the
evidence — a `benign` verdict over an `alert`-state run (the hackerbot false-benign) — the card carries a
prominent **CONTRADICTION** marker (`⚠ verdict benign · evidence overrides`). That is diff-sentry's money
shot: the model was skewed, the evidence still reached the SIEM. `cited_unknown_ids` (planner cited a hit
that does not exist) shows as a **fabrication** chip.

## 3. Palette

Dark default, with a **light theme** toggled from the header (`[data-theme="light"]` overrides the
tokens; persisted, seeded from `prefers-color-scheme`). Live tokens are `style.css :root` +
`[data-theme=light]` (source of truth).

```
--bg:#0a0e13  --surface-1:#121a24  --surface-2:#1a2431  --surface-3:#232f3e
--border:#313e4d  --border-strong:#45566a
--text:#e8eef4  --text-dim:#a2b4c4  --text-faint:#6a7c8d
--signal:#22d3c2  --signal-dim:#3fb3a8  --signal-glow:rgba(34,211,194,0.24)   /* THE brand accent */
/* severity (indicator wells + severity badge) */
--sev-critical:#f85149  --sev-high:#ff8c42  --sev-medium:#d29922  --sev-low:#3fb950  --sev-info:#6a7c8d
/* verdict-alloy (the frame signature — keyed to DERIVED state, §2) */
--alert-1:#ff6b5e; --alert-2:#a3231b; --alert-glow:rgba(248,81,73,0.30)      /* red-metal: hard evidence */
--amber-1:#ffd56b; --amber-2:#b8860b; --amber-glow:rgba(255,204,85,0.28)     /* flagged by verdict */
--clear-1:#56d364; --clear-2:#2ea043; --clear-glow:rgba(63,185,80,0.22)      /* clear (benign, no signal) */
--iron-1:#5a6672;  --iron-2:#2e3742;  --iron-glow:rgba(70,80,92,0.20)        /* refusal / failed */
--analyst:#a371f7   /* the expensive sub-LM escalation (violet = rare/costly) */
```

Rules: `--signal` is for interactive + "live" things (links, the Classify button, the active stream
pulse). Verdict-alloy metals are ONLY on the card frame. Severity colors are on the indicator wells + the
severity badge. Do not cross-use. Nested surfaces step (bg → surface-1 → surface-2 → surface-3) each with
a 1px `--border`; never two same-tone panels touching.

## 4. Typography

Mono-forward (a security console reads as a terminal). `JetBrains Mono` (vendored woff2 400/700) for the
wordmark, all labels, ids, stats, badges, the diff, the indicator wells. System sans
(`ui-sans-serif,-apple-system,…`) ONLY for human prose: `summary`, `rationale`, indicator `title`,
refusal `detail`. The mono-frame / sans-prose contrast is the hierarchy.

## 5. Components

### 5.1 Header
`▣ diff-sentry studio` wordmark (`▣` in `--signal`). Right: three role chips
`planner / analyst / classifier`, each a mono pill showing the configured model name from `GET /v1/config`
on page load (steady `--signal` dot, NO pulse; truncates with ellipsis only when the header runs out of
width). A `backend:self` chip (from `classify_backend`). Then a theme toggle (`☾`/`☀`).

### 5.2 Change input (left rail, top) — no feed
`▾ CHANGE` panel with a **mode switch** (`paste | pr | issue`):
- **paste** (classify): a mono `<textarea>` for a change-event JSON `{repo,kind,number,author,title,body,
  files}`. A **⚡ Load a hackerbot demo** control (from `GET /v1/fixtures`) drops a real reconstructed
  incident payload in, showing its `expected_signal`/`expected_rules` so the result can be read against
  the ground truth.
- **pr / issue**: `owner/repo` + number.
- **Classify ▶** (primary, `--signal`), disabled until the input is valid / while a run streams
  ("Classifying…"). SIEM emission is OFF in the studio (a note says so; the console shows the signal
  decision + the would-send payload, it does not POST).
- A divider `or load a past run` then a run-id input bound to a `<datalist>` from `GET /v1/runs` + Load.

### 5.3 Live feed (left rail, fills remaining height)
`▾ DETECTION LOG`. A scroll container, newest row at the bottom, live (each SSE event appends),
auto-scroll only when already at the bottom. Each row: an inline-SVG icon chip tinted by family, a mono
primary line, a right-meta. Families:
- `detection.scan` , radar , severity-of-worst (label **Scan** · meta `N hits · worst`)
- `detection.classify` , brain , `--signal`/`--warn` (label **Deep classify** · meta `verdict conf`;
  circuit-break → alert icon + **circuit broke**; endpoint error → **classify error**)
- `detection.analyst.escalation` , life-buoy , `--analyst` (label **Ask analyst**)
- `detection.fetch` , download , `--signal` (label **Fetch** · meta `200 · 4.5 KB`; failure → `--bad`)
- `detection.skill.read` , book , `#7d8fb3` (label **Read skill**)
- `detection.run.created` / `completed` , flag , `--signal` (**Classification started** / **Finalized**)

Live plan.step reasoning is NOT in this feed (diff-sentry's `main_step` flushes post-hoc — see the
README); it lives in the Trajectory drawer. The live feed is the ACTION stream, which for a detector is
the core story (which indicators fired, did it escalate).

### 5.4 The result: middle stage + right modules
Page-level **3 columns**: process rail | stage | modules.

**Middle stage:** a **verdict-alloy card** (frame per §2) with a top-right **Verdict / Change** switch.
- **Verdict view:** the derived-state headline (ALERT / FLAGGED / CLEAR / REFUSAL), the `verdict` chip +
  `confidence`, the `max_indicator_severity` badge, a **SIGNAL** badge (`● SIEM signal` when
  `signal==true`), the CONTRADICTION marker when the verdict undersells the evidence (§2), then the
  `summary` (sans) and `recommended_action` (allow / flag-for-review / block-merge).
- **Change view:** the change under review — the source line (`repo · kind · #number · author`), then the
  diff/body colored by role (additions green, deletions red, hunk headers signal, file headers faint).
  For an issue, the body. Absent → a note.

**Right modules** (`.module`: thin top accent, uppercase label head, `--surface-1` body), in order:
1. `INDICATORS` (the star — pinned first): the deterministic evidence, the UNION of every hit. Each a well
   colored by severity: `[SEV] rule` (mono) + `title` (sans) + a bounded `evidence` snippet (+ `decoded`
   when the rule de-obfuscated one) + `location`. The union is rendered FLAT — a baseline hit and a planner
   re-scan of the same content dedupe to one member (`mint_id` is deterministic), so "baseline vs re-scan"
   is not cleanly recoverable from the union and is not drawn here; that provenance lives in the Trajectory
   drawer's per-turn `scan` calls (and the `run_start` `baseline` count). Empty → "no indicators fired".
2. `RUN TELEMETRY` (`process`): `elapsed_s` headline, then a grid — steps (the run's OWN count, unclamped) ·
   scans · deep-classify (amber if circuit-broke) · analyst (violet if >0). Fetch is off by default, so it
   is not a fixed tile; a fetch shows in the Trajectory drawer when one occurs. `hit_iteration_cap` as an
   amber flag chip (authoritative from `process`, never inferred from a step-vs-cap comparison).
3. `VERDICT DETAIL`: `rationale` (sans), `techniques[]` chips, `suspect_files[]`, `cited_unknown_ids` as a
   red fabrication chip.
4. `SIEM SIGNAL`: whether a signal fired + the compact would-send payload (the `signal_payload` subset:
   verdict, severity, techniques, suspect_files, the indicator list). A note: the studio does not POST.
5. `SUMMARY`: the one-line recap, a closing module.

### 5.5 States (every state explicit)
| status | frame | body |
|---|---|---|
| `classified` (evidence ≥ high) | red-metal | verdict + change, ALERT headline, SIGNAL badge, full evidence |
| `classified` (signal by verdict) | amber | FLAGGED headline |
| `classified` (non-benign, no signal) | amber | NOTED headline, no signal badge (verdict chip still shows) |
| `classified` (benign, no signal) | green | CLEAR headline |
| `inconclusive` | iron | refusal card (ran, no usable verdict) + any indicators gathered |
| `failed` | iron | refusal card ("run did not finalize") + detail; **the evidence floor still shows** — a run that crashed after a critical hit must STILL display the SIGNAL badge |

### 5.6 Empty / running / error
- Empty: a dim shield/scanner placeholder: "Classify a change: paste a payload, load a PR/issue, or try a
  hackerbot demo." The right column collapses (`.no-meta`).
- Running: a skeleton card (iron frame) + "Classifying…" in the stage; the right column is empty
  (`.no-meta`). The live activity IS the Detection log (left rail), which streams actions as they happen —
  the run's telemetry/indicators render in the right column once the result lands.
- Stream error mid-run: the backend emits a `failed` response → render the refusal card. Never blank.
  (Even without the `live` extra, the worker completes the SSE with a `failed` refusal — the stream never
  hangs.)

### 5.7 Trajectory drawer (bottom sheet)
Replays a finished run turn by turn — `GET /v1/runs/{id}/iterations`. Opened by a `▤ Trajectory` handle
once a run is on screen. Built on rlm-kit's `trace/v1` contract (additive-only within v1, so it degrades
gracefully on older traces). Tool timeline (segment width ∝ `duration_s`, colored by family
scan/classify/analyst/fetch/skill), left nav of turns, a detail pane (Init → the change + instructions +
model roles + budgets; a turn → reasoning + REPL; a tool → its structured content — scan hits, classify
verdict, analyst Q→A, fetch head), and a replay transport `⏮ ▶/⏸ ⏭ N×` (pure decisions in
`replay-core.js`, unit-tested). Degrades gracefully; two-clocks honesty (`per_turn_timing`).

## 6. Depth / motion
2px geometry (radius 2px chips/buttons/panels, 3px card). Depth via surface steps + 1px hairlines;
the card gets one soft lift + its alloy frame. No glassmorphism, no purple/blue gradients (the only
gradient is the verdict-alloy frame + its one-time sweep on mount). All motion respects
`prefers-reduced-motion`. Alloy sweep 600ms on card mount; feed-row enter 180ms; running dot pulse.

## 7. Do / Don't
Do: mono for structure, sans for prose; frame keyed to DERIVED state (§2), never the raw verdict; make
the INDICATORS module the star; render every state explicitly (refusal is first-class); show the
CONTRADICTION marker when verdict undersells evidence. Don't: no Inter, no centered-hero, no
three-identical-cards, no purple/blue gradient; don't invent response fields a run lacks (hide, don't
fake); don't block the UI on the font (it degrades); don't key the frame on the planner's
verdict (that is the MF3 violation this design exists to prevent).

## 8. Acceptance (in a browser)
1. First screen is unmistakably this product: a shield placeholder + mono wordmark + model-name chips.
2. A hackerbot PR demo classifies to a **red-metal** ALERT card with a `curl-pipe-shell`/`critical`
   indicator well and a `● SIEM signal` badge — even if the planner said benign, the CONTRADICTION marker
   shows and the frame stays red (evidence overrides).
3. A benign refactor is a **green** CLEAR card, no signal, empty INDICATORS.
4. The INDICATORS module is the visual star, rendering the flat union of hits; per-turn scan provenance
   (baseline vs re-scan) lives in the Trajectory drawer, not the module.
5. `failed`/`inconclusive` show the iron refusal card; a failed run that fired a critical hit STILL shows
   the SIGNAL badge.
6. The live feed streams the action families (scan/classify/analyst/fetch/skill); newest at bottom.
7. The `▤ Trajectory` handle opens the drawer with a working timeline + replay transport.
8. No overflow at 375px; the verdict-alloy frame survives mobile.
