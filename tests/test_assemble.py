"""Assemble-on-read is the MF3 backstop: union ALL indicator hits from the trace, and derive `signal`
so a benign self-report cannot suppress hard deterministic evidence."""

from __future__ import annotations

from rlm_kit.trace import load_events

from diff_sentry.assemble import _emit_on_from_meta, verdict_from_events
from tests.conftest import BENIGN_EVENT, BENIGN_SELF_REPORT, MALICIOUS_EVENT, MALICIOUS_VERDICT


def test_unions_indicators_from_baseline_and_tool_calls(make_trace):
    events = load_events(make_trace(event=MALICIOUS_EVENT, verdict=MALICIOUS_VERDICT))
    a = verdict_from_events(events)
    assert a is not None
    rules = {h.rule for h in a.indicators}
    # baseline scan + the in-loop scan_indicators tool call both contributed; de-duped by id
    assert "ci-shell-injection" in rules
    assert "codeowners-tamper" in rules
    assert a.max_indicator_severity == "critical"     # the decoded curl|bash payload
    assert a.signal is True


def test_benign_self_report_cannot_suppress_hard_evidence(make_trace):
    """A (wrong) benign verdict over a malicious change: the deterministic high/critical indicator must
    STILL force a signal — evidence is a fact, the verdict is only a judgement."""
    events = load_events(make_trace(event=MALICIOUS_EVENT, verdict=BENIGN_SELF_REPORT))
    a = verdict_from_events(events)
    assert a is not None
    assert a.verdict == "benign"          # the planner's judgement carries through untouched
    assert a.signal is True               # ...but the signal fires anyway (MF3 backstop)
    assert a.max_indicator_severity == "critical"


def test_fabricated_citation_is_flagged(make_trace):
    events = load_events(make_trace(event=MALICIOUS_EVENT, verdict=BENIGN_SELF_REPORT))
    a = verdict_from_events(events)
    assert "ind-does-not-exist-00000000" in a.cited_unknown_ids


def test_no_result_event_returns_none(make_trace):
    events = load_events(make_trace(with_result=False))
    assert verdict_from_events(events) is None


def test_emit_on_is_read_from_meta():
    assert _emit_on_from_meta([{"type": "run_start", "payload": {"meta": {"emit_on": ["malicious"]}}}]) \
        == ("malicious",)
    assert _emit_on_from_meta([]) == ("suspicious", "malicious")   # default for an old/absent trace


def test_offline_signal_matches_the_runs_emit_on(make_trace):
    """A 'suspicious' verdict on a change with no high indicators: the default threshold signals, a
    'malicious'-only threshold recorded in meta does not — and offline re-derivation honors it (finding 5)."""
    susp = {**BENIGN_SELF_REPORT, "verdict": "suspicious", "indicator_ids": []}
    default = verdict_from_events(load_events(make_trace(event=BENIGN_EVENT, verdict=susp, run_id="b1")))
    strict = verdict_from_events(load_events(
        make_trace(event=BENIGN_EVENT, verdict=susp, run_id="b2", emit_on=["malicious"])))
    assert default.signal is True and default.max_indicator_severity == "info"
    assert strict.signal is False
