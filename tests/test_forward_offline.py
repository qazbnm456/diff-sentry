"""L2 — offline INTEGRATION through the REAL dspy.RLM.aforward loop (no live model, no Deno, no network).

Uses rlm-harness's `rlm_harness.testing` seam: a scripted DummyLM drives the planner, a `ScriptedInterpreter`
runs each turn's step (dispatching the REAL injected tools, so their tracing runs) and SUBMITs. This is
the layer the unit tests can't reach — it exercises `planner → scan_indicators → (deep_classify) →
verdict → assemble → response → emit` on a trace the real loop produced. It also pins the
`scan_indicators` registered name end-to-end (a wrong name would KeyError in the `call(...)` step).
"""

from __future__ import annotations

import asyncio

from rlm_harness import RLMConfig, TraceRecorder, configure
from rlm_harness.testing import ScriptedInterpreter, call, scripted_lm, submit
from rlm_harness.trace import load_events

from diff_sentry.assemble import verdict_from_events
from diff_sentry.config import DetectConfig
from diff_sentry.detect import ClassifyChange
from diff_sentry.emit import emit_signal
from diff_sentry.indicators import scan_indicators
from diff_sentry.normalize import event_metadata, normalize_event, raw_content
from diff_sentry.response import build_response
from tests.conftest import BENIGN_SELF_REPORT, MALICIOUS_EVENT, MALICIOUS_VERDICT


def _run_scripted(tmp_path, event, steps, planner_turns, *, chat_fn=None, run_id="pr-7",
                  emit_on=("suspicious", "malicious"), hand_over=False, max_iterations=10):
    """Drive one full scripted classification and return (planner_verdict, trace_events)."""
    configure(RLMConfig(main_model="x", sub_model="x", interpreter="mock", observe=False,
                        max_iterations=max_iterations),
              main_lm=scripted_lm(planner_turns), sub_lm=scripted_lm([{"reasoning": "r", "verdict": "{}"}]))
    cfg = DetectConfig(main_model="x", sub_model="x", interpreter="mock", classifier_model="x",
                       emit_on=tuple(emit_on), siem_webhook_url="https://siem.example/hook")
    task = ClassifyChange(config=cfg, chat_fn=chat_fn, interpreter=ScriptedInterpreter(steps),
                          event=event if hand_over else None)
    event_str = normalize_event(event)
    ms = event_metadata(event)
    baseline = [h.model_dump() for h in scan_indicators(raw_content(event))]
    path = str(tmp_path / f"{run_id}.jsonl")
    meta = {
        "event": event_str, "instructions": task.instructions,
        "source": {k: ms.get(k) for k in ("repo", "kind", "number", "content_sha256")},
        "baseline_indicators": baseline, "emit_on": list(emit_on),
        "planner": "p", "analyst": "a", "classifier": "c", "max_iterations": 25,
    }

    async def _go():
        with TraceRecorder(path, run_id=run_id, meta=meta):
            return await task.arun(event=event_str)

    return asyncio.run(_go()), load_events(path, run_id)


def test_malicious_change_full_flow_offline(tmp_path):
    """The whole chain through the real loop: the planner scans, SUBMITs malicious, the assembled signal
    fires, and the host-side emitter POSTs — the wiring holds end-to-end."""
    region = raw_content(MALICIOUS_EVENT)
    verdict, events = _run_scripted(
        tmp_path, MALICIOUS_EVENT,
        steps=[call("scan_indicators", region=region), submit({"verdict": MALICIOUS_VERDICT})],
        planner_turns=[{"reasoning": "scan the diff", "code": "print(scan_indicators(event))"},
                       {"reasoning": "submit", "code": "SUBMIT(verdict=...)"}])

    assert verdict.verdict == "malicious"                       # SUBMIT coerced into ChangeVerdict
    # the REAL scan_indicators tool ran inside the loop (registered under the name the prompt uses)
    assert any(e["type"] == "tool_call" and e["payload"].get("tool") == "scan_indicators" for e in events)
    assembled = verdict_from_events(events)
    assert assembled.signal is True and assembled.max_indicator_severity == "critical"
    resp = build_response(assembled, events, "pr-7")
    assert resp.status == "classified"
    sent = {}

    def poster(url, headers, payload):
        sent["verdict"] = payload["verdict"]
        return 202

    emit = emit_signal(resp, DetectConfig(main_model="x", sub_model="x", classifier_model="x",
                                          siem_webhook_url="https://siem.example/hook"), poster=poster)
    assert emit.emitted and emit.status_code == 202 and sent["verdict"] == "malicious"


def test_scan_indicators_tool_is_callable_in_the_loop(tmp_path):
    """The step calls the tool by the name the prompt uses; a mismatched registered name would KeyError
    here."""
    _verdict, events = _run_scripted(
        tmp_path, MALICIOUS_EVENT,
        steps=[call("scan_indicators", region=raw_content(MALICIOUS_EVENT)),
               submit({"verdict": MALICIOUS_VERDICT})],
        planner_turns=[{"reasoning": "scan", "code": "scan_indicators(event)"},
                       {"reasoning": "submit", "code": "SUBMIT(...)"}])
    scan_calls = [e for e in events if e["type"] == "tool_call" and e["payload"].get("tool") == "scan_indicators"]
    assert scan_calls and scan_calls[0]["payload"].get("n", 0) >= 1


def test_mf3_backstop_through_the_real_loop(tmp_path):
    """A (wrong) benign SUBMIT over a malicious change, driven by the real loop: the deterministic
    evidence still forces a signal — MF3 holds on a trace the loop actually wrote, not a hand-built one."""
    verdict, events = _run_scripted(
        tmp_path, MALICIOUS_EVENT,
        steps=[call("scan_indicators", region=raw_content(MALICIOUS_EVENT)),
               submit({"verdict": BENIGN_SELF_REPORT})],
        planner_turns=[{"reasoning": "scan", "code": "scan_indicators(event)"},
                       {"reasoning": "submit benign", "code": "SUBMIT(...)"}])
    assert verdict.verdict == "benign"
    assembled = verdict_from_events(events)
    assert assembled.signal is True                              # evidence union overrides the self-report
    assert "ind-does-not-exist-00000000" in assembled.cited_unknown_ids


def test_deep_classify_escalation_is_recorded(tmp_path):
    """The planner consults the second-stage classifier through the loop; the tool_call lands in the
    trace with the classifier's structured verdict (injected chat_fn — no network)."""
    def fake_chat(findings):
        return '{"verdict": "malicious", "confidence": 0.9, "rationale": "curl|bash", "techniques": ["x"]}'

    _verdict, events = _run_scripted(
        tmp_path, MALICIOUS_EVENT, chat_fn=fake_chat,
        steps=[call("deep_classify", findings="ci filename decodes to curl|bash"),
               submit({"verdict": MALICIOUS_VERDICT})],
        planner_turns=[{"reasoning": "escalate", "code": "deep_classify('...')"},
                       {"reasoning": "submit", "code": "SUBMIT(...)"}])
    dc = [e for e in events if e["type"] == "tool_call" and e["payload"].get("tool") == "deep_classify"]
    assert dc and dc[0]["payload"].get("verdict") == "malicious"


_INCONCLUSIVE = {**BENIGN_SELF_REPORT, "verdict": "inconclusive", "indicator_ids": []}


def _main_outputs(events):
    return [e["payload"].get("output", "") for e in events if e["type"] == "main_step"]


def test_an_inconclusive_submit_on_a_real_change_is_refused_in_the_trajectory(tmp_path):
    """An `inconclusive` SUBMIT on a change with content to read is refused: the loop hands the refusal back as the
    step's output and the planner decides in the same trajectory."""
    verdict, events = _run_scripted(
        tmp_path, MALICIOUS_EVENT, hand_over=True,
        steps=[submit({"verdict": _INCONCLUSIVE}), submit({"verdict": MALICIOUS_VERDICT})],
        planner_turns=[{"reasoning": "unsure", "code": "SUBMIT(...)"}, {"reasoning": "decide", "code": "SUBMIT(...)"}])
    assert verdict.verdict == "malicious"
    refusal = _main_outputs(events)[0]
    assert "refused" in refusal and "2 files, " in refusal and "characters in `event`" in refusal


def test_an_inconclusive_submit_stands_after_two_refusals(tmp_path):
    verdict, events = _run_scripted(
        tmp_path, MALICIOUS_EVENT, hand_over=True,
        steps=[submit({"verdict": _INCONCLUSIVE})] * 3,
        planner_turns=[{"reasoning": "unsure", "code": "SUBMIT(...)"}] * 3)
    assert verdict.verdict == "inconclusive"
    assert sum("refused" in out for out in _main_outputs(events)) == 2


def test_an_inconclusive_submit_on_an_empty_change_stands(tmp_path):
    verdict, _events = _run_scripted(
        tmp_path, {"repo": "acme/app", "kind": "push", "number": 0}, hand_over=True,
        steps=[submit({"verdict": _INCONCLUSIVE})], planner_turns=[{"reasoning": "nothing", "code": "SUBMIT(...)"}])
    assert verdict.verdict == "inconclusive"


def test_an_inconclusive_at_the_iteration_cap_stands(tmp_path):
    """dspy's extract fallback writes the verdict once the cap is reached; no planner turn is left to answer a
    refusal, and refusing there would fail the run."""
    import json

    verdict, _events = _run_scripted(
        tmp_path, MALICIOUS_EVENT, hand_over=True, max_iterations=1,
        steps=[call("scan_indicators", region=raw_content(MALICIOUS_EVENT))],
        planner_turns=[{"reasoning": "scan", "code": "scan_indicators(event)"},
                       {"reasoning": "out of turns", "verdict": json.dumps(_INCONCLUSIVE)}])
    assert verdict.verdict == "inconclusive"


def test_an_inconclusive_stands_when_github_withheld_part_of_the_change(tmp_path):
    withheld = {**MALICIOUS_EVENT, "files": [*MALICIOUS_EVENT["files"], {
        "filename": "src/big.js", "status": "added", "additions": 90000, "deletions": 0, "patch": ""}]}
    verdict, _events = _run_scripted(
        tmp_path, withheld, hand_over=True,
        steps=[submit({"verdict": _INCONCLUSIVE})], planner_turns=[{"reasoning": "unseen", "code": "SUBMIT(...)"}])
    assert verdict.verdict == "inconclusive"
