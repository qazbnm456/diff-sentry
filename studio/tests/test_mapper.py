"""The trace-event → SSE mapping (the public event surface), verified per event type. Pure — no server."""

from diff_sentry_studio.mapper import _worst_severity, to_event


def test_run_start_carries_models_source_and_baseline_count():
    ev = to_event({"type": "run_start", "payload": {"meta": {
        "planner": "P", "analyst": "A", "classifier": "C",
        "source": {"repo": "acme/x", "kind": "pull_request", "number": 7},
        "baseline_indicators": [{"id": "a"}, {"id": "b"}]}}})
    assert ev["event"] == "detection.run.created"
    assert ev["data"]["models"] == {"planner": "P", "analyst": "A", "classifier": "C"}
    assert ev["data"]["source"]["repo"] == "acme/x" and ev["data"]["baseline"] == 2


def test_run_start_surfaces_the_atlas_rubric_hint():
    # the run_start meta carries the ATLAS rubric skeleton; the created event surfaces a cheap hint
    # (the full per-criterion facts arrive via the GET response, never streamed).
    created = to_event({"type": "run_start", "payload": {"meta": {"rubric": [
        {"name": "verdict_resolves_change", "category": "TF", "weight": 1.0, "description": "d"},
        {"name": "tools_used_appropriately", "category": "TA", "weight": 1.0, "description": "d"},
        {"name": "verdict_grounded_in_indicators", "category": "TG", "weight": 1.0, "description": "d"},
        {"name": "classification_wellformed", "category": "PA", "weight": 1.0, "description": "d"}]}}})
    assert created["data"]["rubric"] == {"categories": ["PA", "TA", "TF", "TG"], "criteria": 4}


def test_run_start_rubric_hint_empty_when_absent():
    # a legacy trace with no rubric in meta must not crash — empty hint
    created = to_event({"type": "run_start", "payload": {"meta": {}}})
    assert created["data"]["rubric"] == {"categories": [], "criteria": 0}


def test_main_step_is_a_plan_step():
    ev = to_event({"type": "main_step", "payload": {"turn": 2, "reasoning": "r", "code": "c"}})
    assert ev == {"event": "detection.plan.step", "data": {"turn": 2, "reasoning": "r", "has_code": True}}


def test_sub_call_is_an_analyst_escalation_with_input_processed_keys():
    # rlm-kit's sub-LM records input / processed / raw — NOT question/answer.
    ev = to_event({"type": "sub_call", "payload": {"input": "does this reach a sink?", "processed": "yes"}})
    assert ev["event"] == "detection.analyst.escalation"
    assert ev["data"] == {"question": "does this reach a sink?", "answer": "yes"}


def test_scan_indicators_reports_count_and_worst_severity():
    ev = to_event({"type": "tool_call", "payload": {
        "tool": "scan_indicators", "args": {"region": "curl x | bash"}, "ok": True, "n": 2,
        "hits": [{"severity": "medium"}, {"severity": "critical"}]}})
    assert ev["event"] == "detection.scan"
    assert ev["data"]["n"] == 2 and ev["data"]["worst"] == "critical"


def test_deep_classify_validated_variant():
    ev = to_event({"type": "tool_call", "payload": {
        "tool": "deep_classify", "ok": True, "verdict": "malicious", "confidence": 0.9, "errors": []}})
    assert ev["event"] == "detection.classify"
    assert ev["data"]["ok"] is True and ev["data"]["verdict"] == "malicious" and ev["data"]["confidence"] == 0.9


def test_deep_classify_circuit_break_variant():
    ev = to_event({"type": "tool_call", "payload": {
        "tool": "deep_classify", "ok": False, "circuit_broken": True, "errors": ["bad", "bad"]}})
    assert ev["data"]["ok"] is False and ev["data"]["circuit_broken"] is True


def test_deep_classify_endpoint_error_variant_has_no_ok_key():
    # the endpoint-error shape records ONLY `error` — no `ok` key. `ok` must default to False, and the
    # error must surface (regression guard on the mapper's payload tolerance).
    ev = to_event({"type": "tool_call", "payload": {
        "tool": "deep_classify", "args": {"findings": "…"}, "error": "ConnectTimeout"}})
    assert ev["data"]["ok"] is False and ev["data"]["error"] == "ConnectTimeout"


def test_fetch_url_carries_status_bytes_note():
    ev = to_event({"type": "tool_call", "payload": {
        "tool": "fetch_url", "args": {"url": "https://api.github.com/x"}, "ok": True,
        "status": 200, "bytes": 4096, "note": "ok"}})
    assert ev["event"] == "detection.fetch"
    assert ev["data"]["url"] == "https://api.github.com/x" and ev["data"]["status"] == 200


def test_skill_reads():
    assert to_event({"type": "tool_call", "payload": {"tool": "read_skill", "args": {"name": "triage"}}}) == {
        "event": "detection.skill.read", "data": {"name": "triage"}}
    assert to_event({"type": "tool_call", "payload": {"tool": "list_skills", "args": {}}})["data"]["name"] == "(catalog)"


def test_result_and_run_end_and_final():
    assert to_event({"type": "result", "payload": {}}) == {"event": "detection.result.done", "data": {}}
    assert to_event({"type": "run_end", "payload": {}})["event"] == "detection.run.completed"
    # `final` is SKIPPED: a real trace holds both `final` and `run_end`, so mapping both would emit the
    # terminal event twice (and the `final` copy before `result`). `run_end` is the sole terminal.
    assert to_event({"type": "final", "payload": {}}) is None


def test_unknown_event_type_is_skipped():
    assert to_event({"type": "something_else", "payload": {}}) is None


def test_unrecognized_tool_is_surfaced_with_its_scalar_fields():
    # a rare/future tool must NOT be dropped from the feed — it surfaces as a generic `detection.tool`
    # event carrying its short scalar fields (bulky raw/preview/spec/hits dropped).
    ev = to_event({"type": "tool_call", "payload": {
        "tool": "mystery_tool", "ok": True, "count": 3, "note": "did a thing",
        "raw": "x" * 5000, "hits": [{"id": "a"}], "args": {"region": "r"}}})
    assert ev["event"] == "detection.tool"
    assert ev["data"]["tool"] == "mystery_tool" and ev["data"]["ok"] is True
    assert ev["data"]["fields"] == {"count": 3, "note": "did a thing"}   # scalars only; raw/hits/args dropped


def test_worst_severity_ranks_and_tolerates_junk():
    assert _worst_severity([{"severity": "low"}, {"severity": "high"}, {"severity": "info"}]) == "high"
    assert _worst_severity([{"severity": "nonsense"}, {"no_sev": 1}, "notadict"]) is None
    assert _worst_severity([]) is None
