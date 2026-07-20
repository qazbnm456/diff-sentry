"""Tests for the ATLAS rubric surface (`rubric.py`) — deterministic, reward-free, dspy-free.

Fixtures are SYNTHETIC in-code event lists (the export-test pattern), never the gitignored `output/traces/`
artifacts, so the suite runs on a fresh clone / in CI. The facts are driven through the ASSEMBLED verdict
(indicator UNION from the trace + the derived signal), exactly as `run_labels`/`run_metrics` read them.
"""

from __future__ import annotations

from diff_sentry.rl_export import run_labels, run_metrics, rubric_signal
from diff_sentry.rubric import (
    CATEGORY_MEANING,
    criteria_facts,
    default_rubric,
    rubric_from_meta,
    rubric_to_meta,
    validate_rubric,
)
from diff_sentry.schema import CRITERION_CATEGORIES, Criterion, RubricCriteria


def _hit(severity: str, rule: str, i: int) -> dict:
    return {"id": f"ind-{rule}-{i:08x}", "rule": rule, "severity": severity,
            "title": f"{rule} fired", "evidence": "…", "location": ".github/workflows/ci.yml"}


def _run(*, verdict="malicious", indicators=(("critical", "ci-shell-injection"),), cited_unknown=(),
         scan=1, deep_classify=1, deep_cb=0, analyst=1, fetches=0, skills=1, steps=3, max_iterations=25,
         emit_on=("suspicious", "malicious"), with_rubric=False):
    """A synthetic diff-sentry trace reproducing the facts the rubric lens reads."""
    hits = [_hit(sev, rule, i) for i, (sev, rule) in enumerate(indicators)]
    meta = {"source": {"repo": "acme/x", "kind": "pull_request", "number": 7},
            "baseline_indicators": hits, "emit_on": list(emit_on), "max_iterations": max_iterations}
    if with_rubric:
        meta["rubric"] = rubric_to_meta(default_rubric())
    ev = [{"type": "run_start", "step_id": 0, "ts": 1000.0, "payload": {"meta": meta}}]
    sid = 1
    for _ in range(steps):
        ev.append({"type": "main_step", "step_id": sid, "payload": {"reasoning": "r", "code": "c"}})
        sid += 1
    for _ in range(scan):
        ev.append({"type": "tool_call", "step_id": sid, "payload": {
            "tool": "scan_indicators", "args": {"region": "diff"}, "ok": True, "hits": hits, "n": len(hits)}})
        sid += 1
    for _ in range(deep_classify):
        ev.append({"type": "tool_call", "step_id": sid, "payload": {
            "tool": "deep_classify", "ok": True, "verdict": verdict, "confidence": 0.9, "errors": []}})
        sid += 1
    for _ in range(deep_cb):
        ev.append({"type": "tool_call", "step_id": sid, "payload": {
            "tool": "deep_classify", "ok": False, "circuit_broken": True, "errors": ["x", "x"]}})
        sid += 1
    for _ in range(analyst):
        ev.append({"type": "sub_call", "step_id": sid, "ts": 1004.0,
                   "payload": {"model": "test/analyst", "input": "ask", "processed": "ans"}})
        sid += 1
    for _ in range(fetches):
        ev.append({"type": "tool_call", "step_id": sid, "payload": {
            "tool": "fetch_url", "args": {"url": "https://api.github.com/x"}, "ok": True}})
        sid += 1
    for _ in range(skills):
        ev.append({"type": "tool_call", "step_id": sid, "payload": {
            "tool": "read_skill", "args": {"name": "triage-a-change"}}})
        sid += 1
    ev.append({"type": "result", "step_id": sid, "payload": {"output": {
        "summary": "s", "verdict": verdict, "confidence": 0.9, "rationale": "why",
        "techniques": [], "suspect_files": [], "indicator_ids": list(cited_unknown),
        "recommended_action": "allow"}}})
    return ev


def _by_cat(events):
    return {f.category: f.observed for f in criteria_facts(events)}


# ---- the fixed skeleton --------------------------------------------------

def test_default_rubric_is_the_fixed_four_category_skeleton():
    r = default_rubric()
    assert [c.category for c in r.criteria] == list(CRITERION_CATEGORIES)
    assert all(c.weight == 1.0 and c.name and c.description for c in r.criteria)
    assert len({c.name for c in r.criteria}) == 4          # unique names


def test_default_rubric_ignores_task_and_is_constant():
    assert rubric_to_meta(default_rubric("anything")) == rubric_to_meta(default_rubric())


def test_category_meaning_covers_every_category():
    assert set(CATEGORY_MEANING) == set(CRITERION_CATEGORIES)


# ---- validate_rubric (self-check + structural lint) ----------------------

def test_validate_rubric_passes_the_default_skeleton():
    assert validate_rubric(default_rubric()) == []


def test_validate_rubric_flags_structural_issues():
    assert validate_rubric(RubricCriteria(criteria=[])) == ["rubric has no criteria"]
    dupe = RubricCriteria(criteria=[
        Criterion(name="a", description="a decisive verdict", category="TF", weight=1.0),
        Criterion(name="a", description="a scan tool call", category="TA", weight=1.0),
    ])
    issues = validate_rubric(dupe)
    assert any("categories not represented" in i for i in issues)   # TG/PA missing
    assert any("duplicate criterion names" in i for i in issues)
    vague = RubricCriteria(criteria=[
        Criterion(name="x", description="quality is good", category="TF", weight=1.0)])
    assert any("may not be trace-observable" in i for i in validate_rubric(vague))
    blank = RubricCriteria(criteria=[
        Criterion(name="y", description="   ", category="TA", weight=1.0)])
    assert any("empty descriptions" in i for i in validate_rubric(blank))


# ---- carry / recover the rubric in run_start meta ------------------------

def test_rubric_meta_round_trip():
    ev = _run(with_rubric=True)
    recovered = rubric_from_meta(ev)
    assert [c.name for c in recovered.criteria] == [c.name for c in default_rubric().criteria]


def test_rubric_from_meta_empty_without_rubric_key():
    assert rubric_from_meta(_run()).criteria == []
    assert rubric_from_meta([]).criteria == []


# ---- the merge-safety invariant the lens depends on ----------------------

def test_run_labels_and_run_metrics_keys_are_disjoint():
    # trace_facts = {**run_labels, **run_metrics}; an overlapping key would silently shadow a fact.
    ev = _run()
    assert set(run_labels(ev)) & set(run_metrics(ev)) == set()


# ---- criteria_facts: shape, purity, fallback -----------------------------

def test_criteria_facts_one_per_category_and_never_a_verdict_score():
    facts = criteria_facts(_run())
    assert [f.category for f in facts] == list(CRITERION_CATEGORIES)
    for f in facts:
        assert "score" not in f.observed and "met" not in f.observed   # facts only, never a verdict-score


def test_criteria_facts_falls_back_to_default_for_a_meta_less_trace():
    facts = criteria_facts(_run())                         # _run() writes no rubric into meta
    assert {f.category for f in facts} == set(CRITERION_CATEGORIES)


def test_criteria_facts_uses_the_recorded_rubric_when_present():
    facts = criteria_facts(_run(with_rubric=True))
    assert {f.criterion for f in facts} == {c.name for c in default_rubric().criteria}


# ---- the four categories DIFFERENTIATE contrasting runs ------------------

def test_lens_differentiates_malicious_benign_and_thrash_runs():
    strong = _by_cat(_run(verdict="malicious", indicators=(("critical", "ci-shell-injection"),),
                          cited_unknown=(), deep_cb=0, analyst=1))
    benign = _by_cat(_run(verdict="benign", indicators=(), cited_unknown=(), deep_classify=0, analyst=0))
    thrash = _by_cat(_run(verdict="suspicious", indicators=(("medium", "workflow-tamper"),),
                          cited_unknown=("ind-fake-00000000",), deep_classify=0, deep_cb=3, analyst=0,
                          steps=30, max_iterations=30))

    # TF: a decisive verdict; the capped thrash run is flagged, the strong run is not
    assert strong["TF"]["verdict"] == "malicious" and strong["TF"]["signal"] is True
    assert strong["TF"]["hit_iteration_cap"] is False
    assert thrash["TF"]["hit_iteration_cap"] is True
    assert benign["TF"]["verdict"] == "benign" and benign["TF"]["signal"] is False

    # TA: the circuit-break thrash tell + the analyst-escalation difference surface HERE
    assert strong["TA"]["deep_classify_circuit_breaks"] == 0 < thrash["TA"]["deep_classify_circuit_breaks"]
    assert strong["TA"]["analyst_calls"] == 1 and thrash["TA"]["analyst_calls"] == 0

    # TG: the evidence + the fabrication tell (cited_unknown) live HERE, not in TF
    assert strong["TG"]["max_indicator_severity"] == "critical" and strong["TG"]["indicator_count"] == 1
    assert benign["TG"]["max_indicator_severity"] == "info" and benign["TG"]["indicator_count"] == 0
    assert strong["TG"]["cited_unknown"] == 0 and thrash["TG"]["cited_unknown"] == 1

    # PA: well-formedness — the fabricated citation separates the thrash run from the clean ones
    assert strong["PA"]["cited_unknown"] == 0 and thrash["PA"]["cited_unknown"] == 1


# ---- rubric_signal is internally consistent ------------------------------

def test_rubric_signal_reports_the_effective_rubric_for_a_legacy_trace():
    sig = rubric_signal(_run())                            # meta carries no rubric
    reported = {c["name"] for c in sig["rubric"]}
    facted = {f["criterion"] for f in sig["criteria_facts"]}
    assert reported == facted == {c.name for c in default_rubric().criteria}   # no orphan facts
