"""The response envelope: status mapping, source echo, and the failed/crash path carrying evidence."""

from __future__ import annotations

import json

from rlm_kit.trace import load_events

from diff_sentry.assemble import verdict_from_events
from diff_sentry.ingest import event_from_payload
from diff_sentry.response import build_failed_response, build_response
from diff_sentry.schema import CRITERION_CATEGORIES
from tests.conftest import BENIGN_EVENT, MALICIOUS_EVENT, MALICIOUS_VERDICT


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


# ---- inconclusive: an ungroundable input must not ship a CONFIDENT verdict ----

def test_empty_payload_yields_inconclusive_not_a_confident_verdict(make_trace):
    """The core gap: a content-free change (empty payload → '(no textual content)') must NOT ship a
    confident verdict. Even a confident benign SUBMIT is DOWNGRADED to status=inconclusive (the
    defense-in-depth backstop) — never a 'benign, confidence 0.9'."""
    empty = event_from_payload({})
    confident_benign = {**MALICIOUS_VERDICT, "verdict": "benign", "confidence": 0.9,
                        "techniques": [], "suspect_files": [], "indicator_ids": []}
    events = load_events(make_trace(event=empty, verdict=confident_benign, run_id="empty-1"))
    resp = build_response(verdict_from_events(events), events, "empty-1")
    assert resp.status == "inconclusive"
    assert resp.verdict is None                                     # NOT a confident benign
    assert resp.refusal and resp.refusal.reason == "insufficient_evidence"
    assert resp.signal is False                                     # no groundable content → no indicators


def test_inconclusive_verdict_maps_to_refusal(make_trace):
    """The sanctioned `inconclusive` SUBMIT over a GROUNDABLE change maps to status=inconclusive +
    RefusalInfo(reason='insufficient_evidence')."""
    inc = {**MALICIOUS_VERDICT, "verdict": "inconclusive", "techniques": [], "suspect_files": [],
           "indicator_ids": []}
    events = load_events(make_trace(event=BENIGN_EVENT, verdict=inc, run_id="inc-1"))
    resp = build_response(verdict_from_events(events), events, "inc-1")
    assert resp.status == "inconclusive"
    assert resp.refusal and resp.refusal.reason == "insufficient_evidence"
    assert resp.verdict is None


def test_inconclusive_verdict_cannot_suppress_hard_evidence(make_trace):
    """The load-bearing property: an `inconclusive` verdict over a change with a REAL high/critical
    indicator must STILL force the deterministic signal — the status downgrade never touches the SIEM
    half (`inconclusive` is not in `emit_on`; hard evidence signals on its own, the MF3 backstop)."""
    inc = {**MALICIOUS_VERDICT, "verdict": "inconclusive", "techniques": [], "suspect_files": [],
           "indicator_ids": []}
    events = load_events(make_trace(event=MALICIOUS_EVENT, verdict=inc, run_id="inc-2"))
    resp = build_response(verdict_from_events(events), events, "inc-2")
    assert resp.status == "inconclusive"
    assert resp.refusal and resp.refusal.reason == "insufficient_evidence"
    assert resp.signal is True                          # the critical indicator forces the signal anyway
    assert resp.max_indicator_severity == "critical"
    assert resp.refusal.indicators                      # the evidence rides the refusal envelope too


def test_groundable_benign_stays_classified(make_trace):
    """Regression: a real, groundable benign change is UNCHANGED — status classified, verdict carried."""
    benign = {**MALICIOUS_VERDICT, "verdict": "benign", "confidence": 0.8, "techniques": [],
              "suspect_files": [], "indicator_ids": []}
    events = load_events(make_trace(event=BENIGN_EVENT, verdict=benign, run_id="ben-1"))
    resp = build_response(verdict_from_events(events), events, "ben-1")
    assert resp.status == "classified" and resp.verdict == "benign"


# ---- ATLAS rubric (a reward-free LABEL surface, surfaced in the response) ----

def test_response_carries_the_atlas_rubric_labels(make_trace):
    events = load_events(make_trace())
    r = build_response(verdict_from_events(events), events, "pr-7")
    assert r.rubric is not None
    assert r.rubric.categories == list(CRITERION_CATEGORIES)
    assert len(r.rubric.criteria) == 4                       # one criterion per category (fixed skeleton)
    assert {c.category for c in r.rubric.criteria} == set(CRITERION_CATEGORIES)
    tf = next(c for c in r.rubric.criteria if c.category == "TF")
    assert tf.description and tf.observed.get("verdict") == "malicious"   # facts re-lensed from the trace


def test_response_rubric_is_reward_free(make_trace):
    events = load_events(make_trace())
    blob = build_response(verdict_from_events(events), events, "pr-7").model_dump_json()
    d = json.loads(blob)["rubric"]
    for crit in d["criteria"]:
        assert "score" not in crit and "met" not in crit    # labels only — no score/verdict on a criterion
        assert "score" not in crit["observed"] and "reward" not in crit["observed"]


def test_failed_response_still_carries_the_rubric(make_trace):
    events = load_events(make_trace(with_result=False))
    rf = build_failed_response("pr-7", events, "boom")
    assert rf.status == "failed" and rf.rubric is not None and len(rf.rubric.criteria) == 4
