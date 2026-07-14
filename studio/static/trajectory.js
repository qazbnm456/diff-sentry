/* The RLM-run replay drawer (a bottom-sheet): a live tool timeline + iteration nav + a resumable,
   speed-aware replay. Handed shared helpers + getters for the live currentRunId / busy state (READ only);
   the pure replay-walk + timing math stays in ReplayCore (replay-core.js, unit-tested). Loaded as a plain
   <script> before app.js, exposing a window.Trajectory factory. Tool families are diff-sentry's:
   scan / classify / analyst / fetch / skill. */
(function () {
  "use strict";
  window.Trajectory = function createTrajectory(deps) {
    const { $, esc, feedError, ICONS, fmtBytes, tint, formatElapsed, _linkify, getRunId, isBusy } = deps;

  const trajEl = {
    handle: $("#traj-handle"), drawer: $("#traj-drawer"), backdrop: $("#traj-backdrop"),
    run: $("#traj-run"), stat: $("#traj-stat"), note: $("#traj-note"),
    timeline: $("#traj-timeline"), axisEnd: $("#traj-axis-end"),
    steps: $("#traj-steps"), detail: $("#traj-detail"),
    search: $("#traj-search"), searchCount: $("#traj-search-count"),
    prev: $("#traj-prev"), play: $("#traj-play"), next: $("#traj-next"), speed: $("#traj-speed"),
    progress: $("#traj-progress"), progressLabel: $("#traj-progress-label"), progressFill: $("#traj-progress-fill"),
    expand: $("#traj-expand"), close: $("#traj-close"),
  };
  let trajMatches = [], trajMatchCur = -1;
  let traj = null, trajSel = null, trajPlay = null;
  const REPLAY_SPEEDS = [1, 2, 4, 8, 16, 32, 64];
  let replaySpeed = 2;
  let rpStop = null, rpRealMs = 0, rpElapsed = 0, rpStartedAt = 0, rpTick = null;

  const TOOL_ICON = { scan: "scan", classify: "classify", analyst: "analyst", fetch: "fetch", skill: "skill" };
  function toolFam(t) {
    if (t.label === "scan") return "fam-scan";
    if (t.label === "classify") return t.circuit_broken || t.error ? "fam-bad" : (t.ok === false ? "fam-warn" : "fam-ok");
    if (t.ok === false || t.error) return "fam-bad";   // a failed analyst carries `error` but no `ok` key
    return { fetch: "fam-signal", skill: "fam-skill", analyst: "fam-analyst" }[t.label] || "fam-signal";
  }
  const secs = (s) => s == null ? "" : s < 1 ? `${Math.round(s * 1000)}ms` : s < 60 ? `${s.toFixed(1)}s` : formatElapsed(s);

  function showTrajHandle() { if (trajEl.handle && getRunId()) trajEl.handle.hidden = false; }
  function resetTrajectory() {
    traj = null; trajSel = null; stopReplay();
    if (trajEl.handle) trajEl.handle.hidden = true;
    if (trajEl.drawer && !trajEl.drawer.hidden) closeTrajectory();
  }
  let closeTimer = null;
  async function openTrajectory() {
    if (!getRunId()) return;
    try {
      const r = await fetch(`/v1/runs/${encodeURIComponent(getRunId())}/iterations`);
      if (!r.ok) { feedError(new Error(`no trajectory for ${getRunId()}`)); return; }
      traj = await r.json();
    } catch (e) { feedError(e); return; }
    renderTrajectory();
    clearTimeout(closeTimer);   // a re-open inside the close window must not be re-hidden by the stale timer
    trajEl.backdrop.hidden = false; trajEl.drawer.hidden = false;
    trajEl.handle.setAttribute("aria-expanded", "true");
    // Flush the unhide before animating: rAF alone fires BEFORE the next style recalc, so coming from
    // display:none the .open/.show transitions would have no start frame and jump straight to the end.
    void trajEl.drawer.offsetHeight;
    trajEl.steps.scrollTop = 0; trajEl.timeline.scrollLeft = 0;   // render-time scrollIntoView no-ops while hidden
    trajEl.backdrop.classList.add("show"); trajEl.drawer.classList.add("open");
  }
  function closeTrajectory() {
    stopReplay(); setFull(false);
    trajEl.drawer.classList.remove("open"); trajEl.backdrop.classList.remove("show");
    trajEl.handle.setAttribute("aria-expanded", "false");
    closeTimer = setTimeout(() => { trajEl.drawer.hidden = true; trajEl.backdrop.hidden = true; }, 260);
  }
  function setFull(full) {
    trajEl.drawer.classList.toggle("full", full);
    if (trajEl.expand) { trajEl.expand.textContent = full ? "⤡" : "⤢"; trajEl.expand.title = full ? "restore" : "expand"; }
  }

  function renderTrajectory() {
    if (!traj) return;
    trajEl.run.textContent = getRunId() || "";
    const its = traj.iterations || [], tl = traj.timeline || [];
    trajEl.stat.textContent =
      `${its.length} turn${its.length === 1 ? "" : "s"} · ${tl.length} tool call${tl.length === 1 ? "" : "s"}` +
      (traj.total_s != null ? ` · ${formatElapsed(traj.total_s)}` : "");
    trajEl.note.className = "traj-note " + (traj.per_turn_timing ? "live" : "info");
    trajEl.note.hidden = !traj.timing_note;
    trajEl.note.innerHTML = traj.timing_note
      ? `<span class="note-tag">${traj.per_turn_timing ? "● per-turn timing" : "ⓘ timing"}</span>` +
        `<span class="note-body">${esc(traj.timing_note)}</span>` : "";
    trajEl.axisEnd.textContent = traj.total_s != null ? formatElapsed(traj.total_s) : "";
    renderTimeline(tl); renderSteps(its);
    if (trajEl.search) trajEl.search.value = "";
    runSearch(""); refreshTransport(); selectStop("init", 0);
  }

  function refreshTransport() {
    const off = isBusy() || stopList().length <= 1;
    [trajEl.prev, trajEl.play, trajEl.next].forEach((b) => { if (b) b.disabled = off; });
    if (off && trajPlay) stopReplay();
  }

  function stopMatches(kind, index, q) {
    if (kind === "init") {
      const i = traj.initial || {};
      return `${i.change || ""} ${i.instructions || ""}`.toLowerCase().includes(q);
    }
    const it = (traj.iterations || [])[index] || {};
    return `${it.reasoning || ""}\n${it.code || ""}\n${it.output || ""}`.toLowerCase().includes(q);
  }
  function runSearch(raw) {
    const q = (raw || "").trim().toLowerCase();
    const steps = [...trajEl.steps.querySelectorAll(".tstep")];
    trajMatches = []; trajMatchCur = -1;
    if (!q) { steps.forEach((b) => b.classList.remove("match", "dim")); if (trajEl.searchCount) trajEl.searchCount.textContent = ""; return; }
    steps.forEach((b) => {
      const hit = stopMatches(b.dataset.kind, Number(b.dataset.idx), q);
      b.classList.toggle("match", hit); b.classList.toggle("dim", !hit);
      if (hit) trajMatches.push({ kind: b.dataset.kind, index: Number(b.dataset.idx) });
    });
    if (trajEl.searchCount) trajEl.searchCount.textContent = `${trajMatches.length} match${trajMatches.length === 1 ? "" : "es"}`;
  }
  function jumpToNextMatch() {
    if (!trajMatches.length) return;
    trajMatchCur = (trajMatchCur + 1) % trajMatches.length; gotoStop(trajMatches[trajMatchCur]);
  }

  function renderTimeline(tl) {
    if (!tl.length) { trajEl.timeline.innerHTML = `<div class="traj-empty">no tool calls recorded</div>`; return; }
    const total = tl.reduce((a, t) => a + (t.duration_s || 0), 0) || 1;
    const parts = []; let prevTurn = null;
    tl.forEach((t) => {
      const ti = t.turn_index;
      if (ti != null && ti !== prevTurn) {
        const turnNo = (((traj && traj.iterations) || [])[ti] || {}).turn;
        parts.push(`<button class="turn-mark" data-turn-index="${ti}" title="Turn ${turnNo} starts here">` +
          `<span class="tm-lab">T${esc(turnNo != null ? turnNo : ti)}</span><span class="tm-arrow">▸</span></button>`);
        prevTurn = ti;
      }
      const dur = Math.max(t.duration_s || 0, 0);
      const w = Math.max(108, Math.round((dur / total) * 720));
      const title = `${t.label} · +${secs(t.rel_s)} · took ${secs(t.duration_s)}`;
      parts.push(`<button class="seg ${toolFam(t)}" role="listitem" data-tool="${t.seq}" ` +
        `data-turn-index="${ti != null ? ti : ""}" style="flex:${Math.max(dur, 0.01).toFixed(3)} 0 ${w}px" title="${esc(title)}">` +
        `<span class="seg-ic">${ICONS[TOOL_ICON[t.label]] || ""}</span>` +
        `<span class="seg-lab">${esc(t.label)}</span><span class="seg-dur">${esc(secs(t.duration_s))}</span></button>`);
    });
    trajEl.timeline.innerHTML = parts.join("");
  }

  function renderSteps(its) {
    const maxDur = its.reduce((m, it) => it.duration_s != null ? Math.max(m, it.duration_s) : m, 0);
    const item = (kind, idx, label, sub, it) => {
      let dur = "";
      if (it && it.duration_s != null) {
        const pct = maxDur > 0 ? Math.max(4, Math.round((it.duration_s / maxDur) * 100)) : 0;
        dur = `<span class="ts-dur">${esc(secs(it.duration_s))}</span><span class="ts-bar"><span style="width:${pct}%"></span></span>`;
      }
      return `<button class="tstep" data-kind="${kind}" data-idx="${idx}"><span class="ts-lab">${esc(label)}</span>` +
        `${sub ? `<span class="ts-sub">${esc(sub)}</span>` : ""}${dur}</button>`;
    };
    trajEl.steps.innerHTML = item("init", 0, "Init", "change + env", null) +
      its.map((it) => item("turn", it.index, `Turn ${it.turn != null ? it.turn : it.index}`, firstLine(it.reasoning), it)).join("");
  }
  function firstLine(s) {
    if (!s) return "";
    const ln = String(s).split("\n").find((x) => x.trim()) || "";
    return ln.length > 52 ? ln.slice(0, 52) + "…" : ln;
  }

  function scrollTimelineIntoView(seg) {
    const c = trajEl.timeline; if (!c || !seg) return;
    const cr = c.getBoundingClientRect(), sr = seg.getBoundingClientRect();
    c.scrollTo({ left: Math.max(0, c.scrollLeft + (sr.left - cr.left) - (c.clientWidth - sr.width) / 2), behavior: "smooth" });
  }

  function selectStop(kind, index) {
    trajSel = { kind, index };
    let relTurn = null;
    if (kind === "turn") relTurn = index;
    else if (kind === "tool") { const ti = ((traj.timeline || [])[index] || {}).turn_index; relTurn = ti != null ? ti : null; }
    let selStep = null, relStep = null;
    trajEl.steps.querySelectorAll(".tstep").forEach((b) => {
      const bi = Number(b.dataset.idx), turnStep = b.dataset.kind === "turn";
      const on = kind !== "tool" && b.dataset.kind === kind && bi === index;
      b.classList.toggle("on", on); if (on) selStep = b;
      const rel = kind === "tool" && turnStep && relTurn != null && bi === relTurn;
      b.classList.toggle("related", rel); if (rel) relStep = b;
    });
    let firstRelSeg = null;
    trajEl.timeline.querySelectorAll(".seg").forEach((b) => {
      b.classList.toggle("on", kind === "tool" && Number(b.dataset.tool) === index);
      const rel = kind === "turn" && relTurn != null && b.dataset.turnIndex !== "" && Number(b.dataset.turnIndex) === relTurn;
      b.classList.toggle("related", rel); if (rel && !firstRelSeg) firstRelSeg = b;
    });
    if (firstRelSeg) scrollTimelineIntoView(firstRelSeg);
    const navTarget = selStep || relStep;
    if (navTarget) navTarget.scrollIntoView({ block: "nearest", behavior: "smooth" });
    if (kind === "init") trajEl.detail.innerHTML = detailInit(traj.initial || {});
    else if (kind === "turn") trajEl.detail.innerHTML = detailTurn((traj.iterations || [])[index] || {});
    else trajEl.detail.innerHTML = detailTool((traj.timeline || [])[index] || {});
    trajEl.detail.scrollTop = 0;
  }

  function detailInit(ini) {
    const m = ini.models || {};
    const chips = ["planner", "analyst", "classifier"].map((r) =>
      m[r] ? `<span class="ini-chip"><b>${esc(r)}</b> ${esc(m[r])}</span>` : "").join("");
    const budget = [];
    if (ini.max_iterations != null) budget.push(`${ini.max_iterations} iterations`);
    if (ini.max_llm_calls != null) budget.push(`${ini.max_llm_calls} analyst calls`);
    const src = ini.source || {};
    const srcNum = src.number != null ? `#${esc(src.number)} · ` : "";
    const srcLine = src.repo ? `${esc(src.repo)} · ${esc(src.kind || "")} · ${srcNum}${esc(src.author || "")}` : "";
    return `<div class="det-head"><h3>Initial state</h3><span class="det-sub">the change under review + the environment</span></div>` +
      (srcLine ? `<div class="ini-budget">${srcLine}</div>` : "") +
      (chips ? `<div class="ini-chips">${chips}</div>` : "") +
      (budget.length ? `<div class="ini-budget">budget · ${esc(budget.join(" · "))}</div>` : "") +
      (ini.instructions ? srcBlock("Instructions (system)", ini.instructions, true) : "") +
      srcBlock(`Change${ini.change_chars != null ? ` · ${ini.change_chars} chars (UNTRUSTED)` : ""}`, ini.change || "", false);
  }

  function detailTurn(it) {
    const hasRepl = it.code || it.output;
    const sub = (it.duration_s != null || it.rel_s != null) ? `+${secs(it.rel_s)} · took ${secs(it.duration_s)}` : "planner reasoning, then the REPL code it ran";
    return `<div class="det-head"><h3>Turn ${esc(it.turn != null ? it.turn : it.index)}</h3><span class="det-sub">${esc(sub)}</span></div>` +
      (it.reasoning ? `<div class="det-reason">${esc(it.reasoning)}</div>` : `<div class="det-muted">no reasoning recorded</div>`) +
      (hasRepl ? `<details class="repl" open><summary>REPL · code + output</summary>` +
        (it.code ? `<div class="block"><div class="block-head">code</div><pre class="code-well">${tint(it.code)}</pre></div>` : "") +
        (it.output ? `<div class="block"><div class="block-head">output</div><pre class="out-well">${esc(it.output)}</pre></div>` : "") +
        `</details>` : "");
  }

  function detailTool(t) {
    const failed = t.ok === false;
    const head = `<div class="det-head"><h3><span class="th-fam ${toolFam(t)}">${esc(t.label)}</span></h3>` +
      `<span class="det-sub">+${esc(secs(t.rel_s))} · took ${esc(secs(t.duration_s))}${failed ? " · failed" : ""}</span></div>`;
    const kv = (k, v) => `<div class="kv"><span>${esc(k)}</span><code>${v}</code></div>`;
    if (t.label === "scan") {
      const hits = (t.hits || []).map((h) =>
        `<div class="ind sev-${esc(h.severity || "info")}"><div class="ind-top"><span class="ind-sev">${esc(h.severity || "")}</span>` +
        `<span class="ind-rule">${esc(h.rule || "")}</span></div><div class="ind-title">${esc(h.title || "")}</div>` +
        (h.evidence ? `<code class="ind-ev">${esc(h.evidence)}</code>` : "") +
        (h.decoded ? `<code class="ind-ev ind-decoded">decoded → ${esc(h.decoded)}</code>` : "") +
        (h.location ? `<div class="ind-loc">${esc(h.location)}</div>` : "") + `</div>`).join("");
      return head + kv("region", esc((t.target || "").slice(0, 200))) +
        `<div class="block-head">${esc(t.n || 0)} indicator${t.n === 1 ? "" : "s"}</div>` +
        (hits || `<div class="det-muted">no indicators fired on this region</div>`);
    }
    if (t.label === "classify") {
      return head + (t.verdict ? kv("verdict", esc(t.verdict)) : "") +
        (t.confidence != null ? kv("confidence", esc(t.confidence)) : "") +
        (t.circuit_broken ? `<div class="det-muted">circuit broke — too many unusable replies</div>` : "") +
        (t.error ? `<div class="det-bad">endpoint error · ${esc(t.error)}</div>` : "") +
        ((t.errors || []).length ? `<ul class="errors">${t.errors.map((e) => `<li>${esc(e)}</li>`).join("")}</ul>` : "") +
        (t.findings ? srcBlock("Findings (input)", t.findings, true) : "") +
        (t.output ? `<div class="block"><div class="block-head">raw output</div><pre class="src-well">${esc(t.output)}</pre></div>` : "");
    }
    if (t.label === "analyst") {
      return head + (t.model ? kv("model", esc(t.model)) : "") +
        (t.error ? `<div class="det-muted">error · ${esc(t.error)}</div>` : "") +
        srcBlock("Question", t.input || "", false) + srcBlock("Answer", t.output || "", false);
    }
    if (t.label === "skill") {
      const isCatalog = t.target === "(catalog)";
      return head + kv(isCatalog ? "list" : "skill", esc(t.target)) +
        (t.result_len != null ? kv("length", `${esc(t.result_len)} chars`) : "") +
        (t.content ? `<div class="block"><div class="block-head">${isCatalog ? "catalog" : "content (head)"}</div><pre class="src-well">${esc(t.content)}</pre></div>` : "");
    }
    if (t.label === "fetch") {
      return head + kv("url", _linkify(String(t.target || ""))) +
        (t.status != null ? kv("status", esc(t.status)) : "") +
        (t.bytes != null ? kv("size", esc(fmtBytes(t.bytes))) : "") +
        (failed && t.note ? `<div class="det-bad">${esc(t.note)}</div>` : "") +
        (t.content ? `<div class="block"><div class="block-head">${failed ? "response" : "fetched (head)"}</div><pre class="src-well">${esc(t.content)}</pre></div>` : "");
    }
    const rows = [];
    if (t.target) rows.push(kv("target", _linkify(String(t.target))));
    if (t.note) rows.push(kv("note", esc(t.note)));
    return head + (rows.join("") || `<div class="det-muted">no detail recorded</div>`);
  }

  function srcBlock(title, body, collapsed) {
    return `<details class="block"${collapsed ? "" : " open"}><summary>${esc(title)}</summary><pre class="src-well">${esc(body)}</pre></details>`;
  }

  function stopList() { return ReplayCore.buildStops((traj && traj.iterations) || []); }
  function curStopIdx(list) { return ReplayCore.stopIndex(list, trajSel); }
  function gotoStop(s) { selectStop(s.kind, s.index); }
  function stepBy(dir) {
    const list = stopList();
    const target = ReplayCore.stepTarget(list, curStopIdx(list), dir);
    if (trajPlay) beginStop(target);
    else { gotoStop(target); if (rpStop) seekPaused(target); }
  }
  function seekPaused(stop) {
    rpStop = stop; rpRealMs = realMsFor(stop); rpElapsed = 0; freezeProgress();
    if (trajEl.progressLabel) trajEl.progressLabel.textContent = `⏸ ${stopLabel(stop)} · ${(rpRealMs / replaySpeed / 1000).toFixed(1)}s`;
  }
  function realMsFor(stop) { return ReplayCore.realMsFor(stop, (traj && traj.iterations) || [], !!(traj && traj.per_turn_timing)); }
  function stopLabel(stop) { return stop && stop.kind === "turn" ? `Turn ${(((traj && traj.iterations) || [])[stop.index] || {}).turn}` : "Init"; }
  function rpAccrue() { if (trajPlay && rpStartedAt) { rpElapsed = ReplayCore.accrue(rpElapsed, performance.now() - rpStartedAt, replaySpeed); rpStartedAt = performance.now(); } }
  function cycleSpeed() {
    rpAccrue();
    replaySpeed = REPLAY_SPEEDS[(REPLAY_SPEEDS.indexOf(replaySpeed) + 1) % REPLAY_SPEEDS.length];
    if (trajEl.speed) trajEl.speed.textContent = `${replaySpeed}×`;
    if (trajPlay) armDwell();
    else if (rpStop && trajEl.progressLabel) trajEl.progressLabel.textContent = `⏸ ${stopLabel(rpStop)} · ${(Math.max(0, (rpRealMs - rpElapsed) / replaySpeed) / 1000).toFixed(1)}s`;
  }
  function toggleReplay() {
    if (trajPlay) return pauseReplay();
    if (rpStop && rpElapsed < rpRealMs) return resumePlay();
    startReplay();
  }
  function startReplay() { if (!traj) return; setPlayBtn(true); beginStop(ReplayCore.resolveStart(trajSel, (traj && traj.timeline) || [])); }
  function resumePlay() { setPlayBtn(true); armDwell(); }
  function beginStop(stop) { gotoStop(stop); rpStop = stop; rpRealMs = realMsFor(stop); rpElapsed = 0; armDwell(); }
  function armDwell() {
    clearTimeout(trajPlay); clearInterval(rpTick);
    const dwell = ReplayCore.dwellMs(rpRealMs, rpElapsed, replaySpeed);
    rpStartedAt = performance.now(); paintProgress(rpElapsed / Math.max(1, rpRealMs), dwell); startCountdown(dwell);
    trajPlay = setTimeout(() => {
      const next = ReplayCore.nextStop(stopList(), curStopIdx(stopList()));
      if (!next) { stopReplay(); return; }
      beginStop(next);
    }, dwell);
  }
  function pauseReplay() {
    rpAccrue(); clearTimeout(trajPlay); clearInterval(rpTick); trajPlay = null; setPlayBtn(false); freezeProgress();
    if (trajEl.progressLabel) trajEl.progressLabel.textContent = `⏸ ${stopLabel(rpStop)} · ${(Math.max(0, (rpRealMs - rpElapsed) / replaySpeed) / 1000).toFixed(1)}s`;
  }
  function stopReplay() {
    clearTimeout(trajPlay); clearInterval(rpTick); trajPlay = null; rpStop = null; rpElapsed = 0; setPlayBtn(false);
    if (trajEl.progress) trajEl.progress.hidden = true;
    const f = trajEl.progressFill; if (f) { f.style.transition = "none"; f.style.width = "0%"; }
  }
  function setPlayBtn(on) { if (!trajEl.play) return; trajEl.play.textContent = on ? "⏸" : "▶"; trajEl.play.classList.toggle("on", on); }
  function startCountdown(dwell) {
    clearInterval(rpTick);
    const endAt = performance.now() + dwell;
    const tick = () => {
      const left = Math.max(0, endAt - performance.now());
      if (trajEl.progressLabel) trajEl.progressLabel.textContent = `▶ ${stopLabel(rpStop)} · ${(left / 1000).toFixed(1)}s`;
      if (left <= 0) clearInterval(rpTick);
    };
    tick(); rpTick = setInterval(tick, 100);
  }
  function paintProgress(fromFrac, dwell) {
    if (trajEl.progress) trajEl.progress.hidden = false;
    const f = trajEl.progressFill; if (!f) return;
    f.style.transition = "none"; f.style.width = `${(Math.min(1, fromFrac) * 100).toFixed(2)}%`;
    void f.offsetWidth; f.style.transition = `width ${dwell}ms linear`; f.style.width = "100%";
  }
  function freezeProgress() {
    const f = trajEl.progressFill; if (!f) return;
    f.style.transition = "none"; f.style.width = `${(Math.min(1, rpElapsed / Math.max(1, rpRealMs)) * 100).toFixed(2)}%`;
  }

  if (trajEl.handle) {
    trajEl.handle.addEventListener("click", openTrajectory);
    trajEl.close.addEventListener("click", closeTrajectory);
    trajEl.backdrop.addEventListener("click", closeTrajectory);
    trajEl.play.addEventListener("click", toggleReplay);
    if (trajEl.prev) trajEl.prev.addEventListener("click", () => stepBy(-1));
    if (trajEl.next) trajEl.next.addEventListener("click", () => stepBy(1));
    if (trajEl.speed) trajEl.speed.addEventListener("click", cycleSpeed);
    if (trajEl.search) {
      trajEl.search.addEventListener("input", () => runSearch(trajEl.search.value));
      trajEl.search.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); jumpToNextMatch(); } });
    }
    if (trajEl.expand) trajEl.expand.addEventListener("click", () => setFull(!trajEl.drawer.classList.contains("full")));
    trajEl.timeline.addEventListener("click", (e) => {
      const mark = e.target.closest(".turn-mark");
      if (mark) { stopReplay(); selectStop("turn", Number(mark.dataset.turnIndex)); return; }
      const seg = e.target.closest(".seg"); if (!seg) return;
      stopReplay(); selectStop("tool", Number(seg.dataset.tool));
    });
    trajEl.steps.addEventListener("click", (e) => {
      const st = e.target.closest(".tstep"); if (!st) return;
      stopReplay(); selectStop(st.dataset.kind, Number(st.dataset.idx));
    });
    document.addEventListener("keydown", (e) => {
      if (trajEl.drawer.hidden) return;
      if (e.key === "Escape") return closeTrajectory();
      if (e.target === trajEl.search) return;
      if (isBusy()) return;
      if (e.key === "ArrowRight" || e.key === "ArrowLeft") { e.preventDefault(); stepBy(e.key === "ArrowRight" ? 1 : -1); }
    });
  }

  return { open: openTrajectory, reset: resetTrajectory, showHandle: showTrajHandle, refreshTransport: refreshTransport };
  };
})();
