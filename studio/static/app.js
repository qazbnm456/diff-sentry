/* diff-sentry-studio frontend — the detection console. Zero-build vanilla JS. Reads window.ReplayCore,
   window.RunCore, window.Trajectory (loaded before this). See DESIGN.md for the visual contract. The
   load-bearing rule (§2): the card frame is keyed to the DERIVED state (signal + evidence severity), NOT
   the planner's verdict — a verdict can be skewed by an injection; the evidence cannot. */
(function () {
  "use strict";
  const $ = (s) => document.querySelector(s);
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const SEV = ["info", "low", "medium", "high", "critical"];
  const sevRank = (s) => { const i = SEV.indexOf(String(s || "").toLowerCase()); return i < 0 ? -1 : i; };
  const fmtBytes = (n) => n == null ? "" : n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`;
  const formatElapsed = (s) => { if (s == null) return ""; s = Math.round(s); const m = Math.floor(s / 60), r = s % 60; return m ? `${m}m ${String(r).padStart(2, "0")}s` : `${r}s`; };
  const tint = (s) => esc(s);   // diff-sentry REPL code is Python/JSON — escape only (no YAML highlighter)
  const _linkify = (s) => /^https?:\/\//.test(s) ? `<a href="${esc(s)}" target="_blank" rel="noopener">${esc(s)} ↗</a>` : esc(s);

  const ICONS = {
    scan: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/><path d="M12 3v3M12 18v3M3 12h3M18 12h3"/></svg>',
    classify: '<svg viewBox="0 0 24 24"><rect x="5" y="5" width="14" height="14" rx="2"/><path d="M9 9h6M9 12h6M9 15h3"/></svg>',
    analyst: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="3.5"/><path d="M12 3v5M12 16v5M3 12h5M16 12h5"/></svg>',
    fetch: '<svg viewBox="0 0 24 24"><path d="M12 3v12M7 11l5 5 5-5M4 21h16"/></svg>',
    skill: '<svg viewBox="0 0 24 24"><path d="M5 4h9a2 2 0 012 2v14H7a2 2 0 01-2-2z"/><path d="M9 4v12"/></svg>',
    flag: '<svg viewBox="0 0 24 24"><path d="M5 21V4M5 4h11l-2 4 2 4H5"/></svg>',
    shield: '<svg viewBox="0 0 24 24"><path d="M12 3l7 3v5c0 5-3 8-7 10-4-2-7-5-7-10V6z"/></svg>',
  };

  const feedEl = $("#feed"), stageEl = $("#stage-col"), metaEl = $("#meta-col"), layoutEl = $(".layout");
  let CONFIG = { models: {}, max_iterations: 25, emit_on: [] };
  let currentRunId = null, busy = false;
  const getRunId = () => currentRunId, isBusy = () => busy;

  const traj = window.Trajectory({ $, esc, feedError, ICONS, fmtBytes, tint, formatElapsed, _linkify, getRunId, isBusy });

  function setBusy(b) { busy = b; $("#classify").disabled = b || !validInput(); traj.refreshTransport(); }
  function feedError(e) { addFeedRow("detection.run.completed", { _error: String(e && e.message || e) }); }

  // ── SSE ───────────────────────────────────────────────────────────────
  async function streamSSE(method, url, body, onEvent) {
    const resp = await fetch(url, { method, headers: body ? { "Content-Type": "application/json" } : {}, body: body ? JSON.stringify(body) : undefined });
    if (!resp.ok) { const err = new Error(`HTTP ${resp.status}`); err.status = resp.status; try { err.detail = (await resp.json()).detail; } catch (_) {} throw err; }
    const reader = resp.body.getReader(), dec = new TextDecoder(); let buf = "";
    for (;;) {
      const { done, value } = await reader.read(); if (done) break;
      buf += dec.decode(value, { stream: true });
      let i;
      while ((i = buf.indexOf("\n\n")) >= 0) {
        const chunk = buf.slice(0, i); buf = buf.slice(i + 2);
        const em = /^event: (.*)$/m.exec(chunk), dm = /^data: (.*)$/m.exec(chunk);
        if (em) { let data = {}; try { data = dm ? JSON.parse(dm[1]) : {}; } catch (_) {} onEvent(em[1].trim(), data); }
      }
    }
  }

  // ── live feed rows ──────────────────────────────────────────────────────
  // The feed shows ACTIONS only, in BOTH live and replay. `detection.plan.step` (planner reasoning) and
  // `detection.result.done` are deliberately absent — reasoning lives in the Trajectory drawer, and an
  // unmapped event falls through `FEED[event] || (() => null)` to no row (never a stuck skeleton).
  const FEED = {
    "detection.scan": (d) => ({ icon: "scan", fam: `sev-${d.worst || "info"}`, label: "Scan", meta: `${d.n || 0} hit${d.n === 1 ? "" : "s"}${d.worst ? " · " + d.worst : ""}` }),
    "detection.classify": (d) => ({ icon: "classify", fam: d.circuit_broken || d.error ? "fam-bad" : (d.ok ? "fam-ok" : "fam-warn"),
      label: d.circuit_broken ? "Deep classify · circuit broke" : d.error ? "Deep classify · error" : "Deep classify",
      meta: d.verdict ? `${d.verdict}${d.confidence != null ? " " + d.confidence : ""}` : (d.error || "") }),
    "detection.analyst.escalation": (d) => ({ icon: "analyst", fam: "fam-analyst", label: "Ask analyst", detail: d.question, reason: true }),
    "detection.fetch": (d) => ({ icon: "fetch", fam: d.ok ? "fam-signal" : "fam-bad", label: d.ok ? "Fetch" : "Fetch failed",
      meta: d.status != null ? `${d.status}${d.bytes != null ? " · " + fmtBytes(d.bytes) : ""}` : "", detail: d.ok ? d.url : d.note }),
    "detection.skill.read": (d) => ({ icon: "skill", fam: "fam-skill", label: "Read skill", meta: d.name }),
    "detection.run.created": () => ({ icon: "flag", fam: "fam-signal", label: "Classification started" }),
    "detection.run.completed": (d) => ({ icon: "flag", fam: d._error ? "fam-bad" : "fam-signal", label: d._error ? "Stream error" : "Finalized", detail: d._error }),
  };
  function addFeedRow(event, data) {
    const spec = (FEED[event] || (() => null))(data); if (!spec) return;
    const atBottom = feedEl.scrollHeight - feedEl.scrollTop - feedEl.clientHeight < 40;
    const row = document.createElement("div"); row.className = "feed-row enter";
    row.innerHTML = `<div class="fr-ic ${spec.fam}">${ICONS[spec.icon] || ""}</div><div class="fr-body">` +
      `<div class="fr-line"><span class="fr-primary">${esc(spec.label)}</span>${spec.meta ? `<span class="fr-meta">${esc(spec.meta)}</span>` : ""}</div>` +
      `${spec.detail ? `<div class="fr-detail${spec.reason ? " reason" : ""}">${esc(spec.detail)}</div>` : ""}</div>`;
    feedEl.appendChild(row);
    if (atBottom) feedEl.scrollTop = feedEl.scrollHeight;
  }

  // ── derived state (§2 — the frame alloy is keyed to EVIDENCE, not the verdict) ──
  function deriveState(r) {
    const status = r.status || "";
    if (status === "failed" || status === "inconclusive" || !r.verdict) return { key: "iron", head: status === "failed" ? "REFUSAL" : "INCONCLUSIVE" };
    const hardEvidence = sevRank(r.max_indicator_severity) >= sevRank("high");
    if (r.signal && hardEvidence) return { key: "alert", head: "ALERT" };
    if (r.signal) return { key: "amber", head: "FLAGGED" };
    // No signal, but the planner did NOT clear it (e.g. a narrowed DS_EMIT_ON leaves a `suspicious`
    // verdict sub-threshold). Green CLEAR would contradict the verdict chip — amber "NOTED", no signal.
    if (r.verdict !== "benign") return { key: "amber", head: "NOTED" };
    return { key: "clear", head: "CLEAR" };   // §2: clear only when !signal AND verdict benign
  }

  // ── render the result ───────────────────────────────────────────────────
  let CURRENT = null, stageView = "verdict";
  function renderResult(r) {
    CURRENT = r; stageView = "verdict";
    currentRunId = r.id || currentRunId;
    renderStage(r); renderModules(r);
    layoutEl.classList.remove("no-meta");
    traj.showHandle();
  }

  function renderStage(r) {
    const st = deriveState(r);
    const isRefusal = st.key === "iron";
    const hasChange = !!(r.source && (r.source.repo || r.source.number)) || (CURRENT._change);
    // ONE page-height alloy card (frame = derived state, MF3), three views behind the top-right
    // switch, in triage order: VERDICT → INDICATORS (always reachable, even on a refusal — the
    // evidence outlives the self-report) → CHANGE (when the run carries one; never on a refusal).
    const views = [["verdict", "Verdict"], ["indicators", "Indicators"]];
    if (!isRefusal && hasChange) views.push(["change", "Change"]);
    if (!views.some(([v]) => v === stageView)) stageView = "verdict";
    const switchHtml = `<div class="stage-switch">` + views.map(([v, label]) =>
      `<button data-view="${v}" class="${stageView === v ? "on" : ""}">${label}</button>`).join("") + `</div>`;
    let body;
    if (stageView === "indicators") body = indicatorsHtml(r);
    else if (stageView === "change") body = changeView(r);
    else body = isRefusal ? refusalView(r) : verdictView(r, st);
    stageEl.innerHTML = `<div class="card ${st.key} sweep"><div class="card-inner">` +
      `<div class="card-head"><span class="state-head ${st.key}">${esc(st.head)}</span>${switchHtml}</div>` +
      body + `</div></div>`;
    stageEl.querySelectorAll(".stage-switch button").forEach((b) => b.addEventListener("click", () => { stageView = b.dataset.view; renderStage(r); }));
  }

  function verdictView(r, st) {
    const contradiction = r.signal && r.verdict === "benign"
      ? `<span class="contradiction">⚠ planner verdict <b>benign</b> · deterministic evidence overrides — SIEM signal fired regardless</span>` : "";
    const badges = [
      r.verdict ? `<span class="badge verdict-${esc(r.verdict)}">${esc(r.verdict)}${r.confidence != null ? " " + r.confidence : ""}</span>` : "",
      `<span class="badge sev-${esc(r.max_indicator_severity || "info")}">sev ${esc(r.max_indicator_severity || "info")}</span>`,
      r.signal ? `<span class="badge signal">● SIEM signal</span>` : "",
      (r.cited_unknown_ids || []).length ? `<span class="badge" style="color:var(--bad);border-color:var(--bad)">fabricated citation</span>` : "",
    ].join("");
    return `<div class="card-head">${badges}</div>${contradiction}` +
      (r.summary ? `<p class="card-summary">${esc(r.summary)}</p>` : "") +
      (r.recommended_action ? `<div class="rec-action">recommended · <b>${esc(r.recommended_action)}</b></div>` : "");
  }

  function refusalView(r) {
    const rf = r.refusal || {};
    return `<div class="card-head">${r.signal ? `<span class="badge signal">● SIEM signal</span>` : ""}` +
      `<span class="badge sev-${esc(r.max_indicator_severity || "info")}">sev ${esc(r.max_indicator_severity || "info")}</span></div>` +
      `<div class="refusal"><div class="rf-reason">${esc(rf.reason || r.status || "no verdict")}</div>` +
      `<p>${esc(rf.detail || "The run did not produce a usable verdict.")}</p></div>`;
  }

  function changeView(r) {
    const s = r.source || {};
    const num = s.number != null ? `#${esc(s.number)} · ` : "";
    const srcLine = `${esc(s.repo || "")} · ${esc(s.kind || "")} · ${num}${esc(s.author || "")}`;
    const change = CURRENT._change;   // set when we ingested a payload locally (paste mode only)
    const plan = RunCore.planChangeView(change, CURRENT._traceChange);
    let diff = "";
    if (plan.kind === "files") {
      diff = change.files.map((f) => `<div class="file-head">${esc(f.filename || "")} [${esc(f.status || "")} +${f.additions || 0} -${f.deletions || 0}]</div>` +
        `<div class="diff-well">${diffLines(f.patch || "")}</div>`).join("");
    } else if (plan.kind === "body") {
      diff = `<div class="diff-well"><span class="diff-line ctx">${esc(change.body)}</span></div>`;
    } else if (plan.kind === "trace") {
      // A pr/issue (or replayed) run — the diff never reaches the client. This is the run's OWN
      // `run_start` event from /iterations: the exact normalized untrusted content the planner saw.
      diff = `<div class="diff-well"><span class="diff-line ctx">${esc(CURRENT._traceChange)}</span></div>`;
    } else if (plan.kind === "loading") {
      if (plan.fetch) fetchTraceChange(CURRENT);
      diff = `<div class="prose">loading the change from the run's trace…</div>`;
    } else if (plan.kind === "error") {
      diff = `<div class="prose">Couldn't read the run's trace (a transient fetch error) — load the run again to retry.</div>`;
    } else {
      diff = `<div class="prose">The change body is not held client-side and this run's trace carries no readable event — nothing to show.</div>`;
    }
    return `<div class="change-src">${srcLine}</div>${diff}`;
  }
  async function fetchTraceChange(r) {
    r._traceChange = null;   // in flight — planChangeView won't refire while pending
    try {
      const resp = await fetch(`/v1/runs/${encodeURIComponent(r.id || currentRunId)}/iterations`);
      if (resp.ok) {
        const init = ((await resp.json()) || {}).initial;
        r._traceChange = (init && typeof init.change === "string" && init.change) ? init.change : false;
      } else {
        // 404 = the trace is genuinely gone (terminal "gone"); anything else is transient → "error".
        r._traceChange = resp.status === 404 ? false : { error: true };
      }
    } catch (_) { r._traceChange = { error: true }; }
    if (CURRENT === r && stageView === "change") renderStage(r);
  }
  function diffLines(patch) {
    return String(patch).split("\n").map((ln) => {
      let cls = "ctx";
      if (/^\+\+\+|^---|^diff |^index /.test(ln)) cls = "file";
      else if (/^@@/.test(ln)) cls = "hunk";
      else if (/^\+/.test(ln)) cls = "add";
      else if (/^-/.test(ln)) cls = "del";
      return `<span class="diff-line ${cls}">${esc(ln) || " "}</span>`;
    }).join("");
  }

  function indicatorsHtml(r) {
    const inds = r.indicators || [];
    return inds.length
      ? inds.map((h) => `<div class="ind sev-${esc(h.severity || "info")}"><div class="ind-top"><span class="ind-sev">${esc(h.severity || "")}</span>` +
        `<span class="ind-rule">${esc(h.rule || "")}</span></div><div class="ind-title">${esc(h.title || "")}</div>` +
        (h.evidence ? `<code class="ind-ev">${esc(h.evidence)}</code>` : "") +
        (h.decoded ? `<code class="ind-ev ind-decoded">decoded → ${esc(h.decoded)}</code>` : "") +
        (h.location ? `<div class="ind-loc">${esc(h.location)}</div>` : "") + `</div>`).join("")
      : `<div class="ind-empty">no indicators fired — the deterministic layer found nothing</div>`;
  }

  function renderModules(r) {
    const p = r.process || {};

    // Show the run's OWN step count unclamped — clamping to CONFIG.max_iterations (today's env) would
    // falsify a replayed run recorded under a different cap. Cap-hit is authoritative from `process`.
    const steps = p.steps != null ? String(p.steps) : "—";
    const stats = [
      ["steps", steps, p.hit_iteration_cap ? "warn" : ""],
      ["scans", p.scan_calls != null ? p.scan_calls : "—", ""],
      ["deep-classify", p.deep_classify_calls != null ? p.deep_classify_calls : "—", p.deep_classify_circuit_breaks ? "warn" : ""],
      ["analyst", p.analyst_calls != null ? p.analyst_calls : "—", p.analyst_calls ? "analyst" : ""],
    ].map(([l, v, c]) => `<div class="stat ${c}"><div class="sv">${esc(v)}</div><div class="sl">${l}</div></div>`).join("");

    const techs = (r.techniques || []).map((t) => `<span class="tchip">${esc(t)}</span>`).join("");
    const suspects = (r.suspect_files || []).map((f) => `<span class="tchip">${esc(f)}</span>`).join("");
    const fabs = (r.cited_unknown_ids || []).map((c) => `<span class="tchip fab">${esc(c)} (no hit)</span>`).join("");

    const siem = r.signal
      ? `<div class="siem-on">● a SIEM signal would be emitted</div><pre class="siem-payload">${esc(JSON.stringify(siemPayload(r), null, 2))}</pre>` +
        `<div class="emit-note">The studio does not POST — this is the payload the host-side emitter would send.</div>`
      : `<div class="siem-off">no signal — below the emit threshold and the evidence floor</div>`;

    // Telemetry first — the run's signature sits top-right, the family convention across the consoles.
    metaEl.innerHTML =
      module("Run telemetry", `<div class="headline">${esc(formatElapsed(p.elapsed_s) || "—")}</div><div class="stat-grid">${stats}</div>` +
        (p.hit_iteration_cap ? `<span class="flag-chip">hit iteration cap</span>` : "")) +
      module("Verdict detail", (r.rationale ? `<div class="prose">${esc(r.rationale)}</div>` : "") +
        (techs ? `<div class="chips">${techs}</div>` : "") + (suspects ? `<div class="ind-group-label">suspect files</div><div class="chips">${suspects}</div>` : "") +
        (fabs ? `<div class="ind-group-label">fabricated citations</div><div class="chips">${fabs}</div>` : "")) +
      module("SIEM signal", siem) +
      (r.summary ? module("Summary", `<div class="prose">${esc(r.summary)}</div>`) : "") +
      rubricModule(r.rubric);
  }
  function module(label, body) {
    return `<div class="module"><div class="module-cap"></div><div class="module-head">${esc(label)}</div><div class="module-body">${body}</div></div>`;
  }

  // The ATLAS rubric module — the run's reward-free TF/TA/TG/PA LABELS. Each criterion shows the
  // deterministic FACTS re-lensed from the trace (never a score/verdict; the trainer scores dᵢ). Guarded:
  // a legacy response with no `rubric` field renders nothing.
  function fmtFact(v) {
    if (Array.isArray(v)) return v.length ? v.join(", ") : "—";
    if (v === null || v === undefined) return "—";
    if (typeof v === "object") return JSON.stringify(v);
    return String(v);
  }
  function rubricModule(rubric) {
    if (!rubric || !rubric.criteria || !rubric.criteria.length) return "";
    const crit = (c) => {
      const cat = String(c.category || "").toLowerCase();
      const catCls = ["tf", "ta", "tg", "pa"].includes(cat) ? cat : "x";
      const facts = Object.entries(c.observed || {});
      const factsHtml = facts.length
        ? `<div class="rub-facts">${facts.map(([k, v]) =>
            `<span class="rub-fact"><span class="rk">${esc(k)}</span><span class="rv">${esc(fmtFact(v))}</span></span>`).join("")}</div>`
        : `<div class="rub-facts empty">no facts observed</div>`;
      // the category class sits on `.rub-crit` so its `--rc` accent inherits to BOTH the left rule
      // (`.rub-crit` border) and the badge child — CSS custom props inherit downward only.
      return `<div class="rub-crit cat-${catCls}"><div class="rub-crit-head">` +
        `<span class="cat-badge">${esc(c.category)}</span>` +
        `<span class="rub-name">${esc(c.criterion)}</span></div>` +
        (c.description ? `<p class="rub-desc">${esc(c.description)}</p>` : "") +
        factsHtml + `</div>`;
    };
    return `<div class="module rubric"><div class="module-cap"></div>` +
      `<div class="module-head">ATLAS rubric <span class="rub-tag">labels — not a score</span></div>` +
      `<div class="module-body"><div class="rub-list">${rubric.criteria.map(crit).join("")}</div></div></div>`;
  }
  function siemPayload(r) {
    // Mirror emit.signal_payload field-for-field — the console claims this is what the host-side emitter
    // would POST, so it must not drop fields the real payload carries.
    return {
      run_id: r.id, source: r.source || {}, verdict: r.verdict, confidence: r.confidence,
      recommended_action: r.recommended_action, max_indicator_severity: r.max_indicator_severity,
      techniques: r.techniques, suspect_files: r.suspect_files, summary: r.summary,
      indicators: (r.indicators || []).map((h) => ({ id: h.id, rule: h.rule, severity: h.severity, title: h.title, location: h.location })),
    };
  }

  // ── skeleton / empty ────────────────────────────────────────────────────
  function showEmpty() {
    layoutEl.classList.add("no-meta");
    stageEl.innerHTML = `<div class="empty-stage"><span class="es-glyph">${ICONS.shield}</span>` +
      `Classify a change: paste a payload, load a PR/issue, or try a hackerbot demo.</div>`;
    metaEl.innerHTML = "";
  }
  function showSkeleton() {
    stageEl.innerHTML = `<div class="skeleton-card iron"><span class="sk-pulse"></span><div style="margin-top:14px">Classifying…</div></div>`;
    metaEl.innerHTML = ""; layoutEl.classList.add("no-meta");
  }

  // ── classify (live) ─────────────────────────────────────────────────────
  function currentRequest() {
    const mode = document.querySelector(".mode-btn.on").dataset.mode;
    if (mode === "pr") return { mode, repo: $("#pr-repo").value.trim(), number: Number($("#pr-number").value) };
    if (mode === "issue") return { mode, repo: $("#issue-repo").value.trim(), number: Number($("#issue-number").value) };
    let payload = {}; try { payload = JSON.parse($("#payload").value); } catch (_) { payload = null; }
    return { mode: "classify", payload };
  }
  function validInput() {
    const mode = document.querySelector(".mode-btn.on").dataset.mode;
    if (mode === "pr") return !!$("#pr-repo").value.trim() && Number($("#pr-number").value) > 0;
    if (mode === "issue") return !!$("#issue-repo").value.trim() && Number($("#issue-number").value) > 0;
    try { return !!JSON.parse($("#payload").value); } catch (_) { return false; }
  }
  function refreshClassifyBtn() { $("#classify").disabled = busy || !validInput(); }

  async function classify(overwrite) {
    const req = currentRequest();
    if (!req) return;
    // Reset FIRST: only a pasted payload is held client-side for the Change view. Without this reset a
    // pr/issue run (whose files live server-side) would render the PREVIOUS paste's diff under its source.
    CURRENT_CHANGE = null;
    if (req.mode === "classify" && req.payload) CURRENT_CHANGE = req.payload;
    feedEl.innerHTML = ""; showSkeleton(); traj.reset(); setBusy(true);
    let finalResp = null, finalStatus = null, err = null;
    try {
      await streamSSE("POST", "/v1/classify", { ...req, overwrite: !!overwrite }, (event, data) => {
        if (event === "detection.run.created") { currentRunId = data.run_id || currentRunId; addFeedRow(event, data); }
        else if (event === "detection.run.completed") { finalResp = data; finalStatus = data.status; addFeedRow(event, data); }
        else addFeedRow(event, data);
      });
    } catch (e) { err = e; }
    setBusy(false);
    const plan = RunCore.planTerminal(err, finalStatus);
    if (plan.stage === "existing") {   // 409 — a finalized run owns this id
      if (confirm(`A finalized run already exists for this change. Replace it?`)) return classify(true);
      showEmpty(); return;
    }
    if (plan.stage === "failed") { feedError(err); renderResult({ status: "failed", refusal: { reason: "stream_error", detail: err && (err.detail || err.message) } }); return; }
    // clean end: the completed event carried the raw response; re-GET for the trace-derived
    // cited_unknown_ids augmentation (the fabrication tell the envelope omits — see /v1/runs/{id}).
    if (finalResp) {
      let full = finalResp;
      try { const g = await fetch(`/v1/runs/${encodeURIComponent(currentRunId)}`); if (g.ok) full = await g.json(); } catch (_) {}
      full._change = CURRENT_CHANGE; renderResult(full); refreshRuns();
    }
  }
  let CURRENT_CHANGE = null;

  // ── load a past run (replay) ────────────────────────────────────────────
  async function loadRun(id) {
    if (!id) return;
    currentRunId = id; feedEl.innerHTML = ""; showSkeleton(); traj.reset(); CURRENT_CHANGE = null;
    let resp = null;
    try {
      const r = await fetch(`/v1/runs/${encodeURIComponent(id)}`);
      if (!r.ok) throw new Error(`no run ${id}`);
      resp = await r.json();
    } catch (e) { feedError(e); renderResult({ status: "failed", refusal: { reason: "not_found", detail: String(e.message) } }); return; }
    // replay the trace into the feed (paced), then render the stored response
    try {
      await streamSSE("GET", `/v1/runs/${encodeURIComponent(id)}/events`, null, (event, data) => addFeedRow(event, data));
    } catch (_) {}
    resp._change = null; CURRENT = resp; renderResult(resp);
  }

  // ── config / fixtures / runs ────────────────────────────────────────────
  async function loadConfig() {
    try { CONFIG = await (await fetch("/v1/config")).json(); } catch (_) {}
    const m = CONFIG.models || {};
    [["planner", m.planner], ["analyst", m.analyst], ["classifier", m.classifier]].forEach(([role, name]) => {
      const chip = $(`#role-${role}`); if (!chip) return;
      chip.querySelector(".role-model").textContent = name || "";
      chip.title = name || role; chip.classList.toggle("ready", !!name);
    });
  }
  async function loadFixtures() {
    let fx = [];
    try { fx = (await (await fetch("/v1/fixtures")).json()).fixtures || []; } catch (_) {}
    const sel = $("#fixture-pick");
    fx.forEach((f, i) => { const o = document.createElement("option"); o.value = String(i); o.textContent = `⚡ ${f.name}`; sel.appendChild(o); });
    sel._fixtures = fx;
  }
  async function refreshRuns() {
    try {
      const runs = (await (await fetch("/v1/runs")).json()).runs || [];
      $("#runs").innerHTML = runs.map((r) => `<option value="${esc(r)}"></option>`).join("");
      $("#runs-hint").textContent = runs.length ? `${runs.length} loadable run${runs.length === 1 ? "" : "s"}` : "no stored runs yet";
    } catch (_) {}
  }

  // ── theme ───────────────────────────────────────────────────────────────
  function initTheme() {
    const saved = localStorage.getItem("ds-theme");
    const dark = saved ? saved === "dark" : !matchMedia("(prefers-color-scheme: light)").matches;
    document.documentElement.setAttribute("data-theme", dark ? "dark" : "light");
    $("#theme-toggle").textContent = dark ? "☾" : "☀";
  }
  $("#theme-toggle").addEventListener("click", () => {
    const dark = document.documentElement.getAttribute("data-theme") !== "dark";
    document.documentElement.setAttribute("data-theme", dark ? "dark" : "light");
    localStorage.setItem("ds-theme", dark ? "dark" : "light");
    $("#theme-toggle").textContent = dark ? "☾" : "☀";
  });

  // ── wiring ──────────────────────────────────────────────────────────────
  document.querySelectorAll(".mode-btn").forEach((b) => b.addEventListener("click", () => {
    document.querySelectorAll(".mode-btn").forEach((x) => x.classList.toggle("on", x === b));
    ["classify", "pr", "issue"].forEach((m) => { $(`#pane-${m}`).hidden = m !== b.dataset.mode; });
    refreshClassifyBtn();
  }));
  ["#payload", "#pr-repo", "#pr-number", "#issue-repo", "#issue-number"].forEach((s) => $(s).addEventListener("input", refreshClassifyBtn));
  $("#classify").addEventListener("click", () => classify(false));
  $("#load").addEventListener("click", () => loadRun($("#load-id").value.trim()));
  $("#load-id").addEventListener("keydown", (e) => { if (e.key === "Enter") loadRun($("#load-id").value.trim()); });
  $("#fixture-pick").addEventListener("change", (e) => {
    const fx = e.target._fixtures || []; const f = fx[Number(e.target.value)];
    if (!f) { $("#fixture-note").hidden = true; return; }
    $("#payload").value = JSON.stringify(f.event, null, 2);
    $("#fixture-note").hidden = false;
    $("#fixture-note").innerHTML = `<b>${esc(f.name)}</b> — ${esc(f.incident_ref || "")}<br>expected: signal <b>${f.expected_signal}</b> · rules ${esc((f.expected_rules || []).join(", "))}`;
    refreshClassifyBtn();
  });

  initTheme(); loadConfig(); loadFixtures(); refreshRuns(); showEmpty();
})();
