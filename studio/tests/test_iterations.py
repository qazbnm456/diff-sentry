"""The trajectory breakdown + the re-derived fabrication tell — pure over the trace, no server."""

from diff_sentry_studio.iterations import build_iterations, cited_unknown_ids


def _trace():
    return [
        {"type": "run_start", "step_id": 0, "ts": 1.0, "payload": {"meta": {
            "event": "the normalized change text", "planner": "P", "analyst": "A", "classifier": "C",
            "source": {"repo": "acme/x", "kind": "pull_request", "number": 7},
            "baseline_indicators": [{"id": "ind-a"}], "emit_on": ["suspicious", "malicious"],
            "max_iterations": 25}}},
        {"type": "main_step", "step_id": 1, "ts": 1.0,
         "payload": {"turn": 0, "reasoning": "triage", "code": "scan_indicators(x)", "output": "1 hit"}},
        {"type": "tool_call", "step_id": 2, "ts": 3.0, "payload": {
            "tool": "scan_indicators", "args": {"region": "curl|bash"}, "ok": True, "n": 1,
            "hits": [{"id": "ind-b", "rule": "curl-pipe-shell", "severity": "critical", "title": "t"}]}},
        {"type": "result", "step_id": 3, "ts": 4.5, "payload": {"output": {
            "verdict": "malicious", "indicator_ids": ["ind-a", "ind-b", "ind-ghost"]}}},
        {"type": "run_end", "step_id": 4, "ts": 5.0, "payload": {}},
    ]


def test_build_iterations_surfaces_change_and_timeline():
    d = build_iterations(_trace())
    assert d["initial"]["change"] == "the normalized change text"
    assert d["initial"]["source"]["repo"] == "acme/x"
    assert d["initial"]["models"] == {"planner": "P", "analyst": "A", "classifier": "C"}
    assert d["total_s"] == 4.0
    assert len(d["iterations"]) == 1 and d["iterations"][0]["reasoning"] == "triage"
    scan = d["timeline"][0]
    assert scan["label"] == "scan" and scan["rel_s"] == 2.0 and scan["hits"][0]["rule"] == "curl-pipe-shell"


def test_scan_hits_carry_evidence_and_decoded_for_the_indicators_view():
    trace = [{"type": "run_start", "step_id": 0, "ts": 1.0, "payload": {"meta": {}}},
             {"type": "tool_call", "step_id": 1, "ts": 2.0, "payload": {
                 "tool": "scan_indicators", "args": {"region": "r"}, "hits": [
                     {"id": "i", "rule": "obfuscated-payload", "severity": "critical", "title": "t",
                      "evidence": "Y3Vyb…", "location": "f.md", "decoded": "curl x | bash"}]}}]
    hit = build_iterations(trace)["timeline"][0]["hits"][0]
    assert hit["decoded"] == "curl x | bash" and hit["evidence"] == "Y3Vyb…" and hit["location"] == "f.md"


def test_cited_unknown_ids_flags_only_uncorroborated_citations():
    # the planner cited ind-a (baseline), ind-b (a scan hit), and ind-ghost (no recorded hit). Only the
    # ghost is a fabrication tell — re-derived from the trace because DetectionResponse omits it.
    assert cited_unknown_ids(_trace()) == ["ind-ghost"]


def test_cited_unknown_ids_empty_when_no_result():
    trace = [{"type": "run_start", "step_id": 0, "payload": {"meta": {"baseline_indicators": [{"id": "x"}]}}}]
    assert cited_unknown_ids(trace) == []


def test_unrecognized_tool_surfaces_its_scalar_fields():
    # an unknown tool_call must render its SHORT scalar fields (never an empty step / a bare str(args)).
    trace = [{"type": "run_start", "step_id": 0, "ts": 1.0, "payload": {"meta": {}}},
             {"type": "tool_call", "step_id": 1, "ts": 2.0, "payload": {
                 "tool": "mystery_tool", "ok": True, "count": 2, "label_hint": "did work",
                 "raw": "x" * 5000, "args": {"region": "r"}, "hits": [{"id": "a"}]}}]
    entry = build_iterations(trace)["timeline"][0]
    assert entry["label"] == "mystery_tool" and entry["tool"] == "mystery_tool" and entry["ok"] is True
    assert entry["fields"] == {"count": 2, "label_hint": "did work"}   # scalars only; raw/args/hits dropped


def test_per_turn_timing_off_when_main_steps_cluster():
    # older-style trace: main_steps flushed at finalize (ts cluster) → no per-turn timing, no fake durations
    trace = [{"type": "run_start", "step_id": 0, "ts": 1.0, "payload": {"meta": {}}},
             {"type": "main_step", "step_id": 1, "ts": 9.0, "payload": {"turn": 0, "reasoning": "a"}},
             {"type": "main_step", "step_id": 2, "ts": 9.0, "payload": {"turn": 1, "reasoning": "b"}}]
    d = build_iterations(trace)
    assert d["per_turn_timing"] is False
    assert "duration_s" not in d["iterations"][0]
