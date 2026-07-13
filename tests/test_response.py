"""The response envelope: status mapping, source echo, and the failed/crash path carrying evidence."""

from __future__ import annotations

from rlm_kit.trace import load_events

from diff_sentry.assemble import verdict_from_events
from diff_sentry.response import build_failed_response, build_response


def test_build_response_classified(make_trace):
    events = load_events(make_trace())
    a = verdict_from_events(events)
    resp = build_response(a, events, "pr-7")
    assert resp.status == "classified"
    assert resp.verdict == "malicious"
    assert resp.signal is True
    assert resp.source and resp.source.get("repo") == "acme/widgets"
    assert resp.model.get("planner") == "planner-x"
    assert resp.process.scan_calls >= 1
    assert resp.max_indicator_severity == "critical"


def test_failed_response_still_carries_evidence_and_signal(make_trace):
    # a run that never finalized (no result) still surfaces the deterministic indicators + a signal
    events = load_events(make_trace(with_result=False))
    resp = build_failed_response("pr-7", events, "boom")
    assert resp.status == "failed"
    assert resp.refusal and resp.refusal.reason == "run_failed"
    assert resp.indicators                      # baseline hits survived
    assert resp.signal is True                  # a critical indicator forces a signal even on crash


def test_inconclusive_when_no_result(make_trace):
    events = load_events(make_trace(with_result=False))
    a = verdict_from_events(events)
    assert a is None
