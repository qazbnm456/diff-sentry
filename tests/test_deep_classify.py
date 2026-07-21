"""The second-stage classifier seam: JSON validation + the tool with an injected chat_fn (no network)."""

from __future__ import annotations

from diff_sentry.config import DetectConfig
from diff_sentry.deep_classify import _parse_classifier_json, make_deep_classify_tool


def _cfg():
    return DetectConfig(main_model="x", sub_model="x", classifier_model="x")


def test_parse_valid_json():
    v = _parse_classifier_json('{"verdict": "malicious", "confidence": 0.8, "techniques": ["x"]}')
    assert v.ok and v.verdict == "malicious" and v.confidence == 0.8


def test_parse_strips_code_fence():
    v = _parse_classifier_json('```json\n{"verdict": "benign", "confidence": 0.2}\n```')
    assert v.ok and v.verdict == "benign"


def test_parse_rejects_unknown_verdict():
    v = _parse_classifier_json('{"verdict": "evil"}')
    assert not v.ok


def test_inconclusive_is_enum_valid_at_the_second_stage():
    # a deep escalation on a content-free / ungroundable change can also decline to the sanctioned outcome
    v = _parse_classifier_json('{"verdict": "inconclusive", "confidence": 0.2, "rationale": "no content"}')
    assert v.ok and v.verdict == "inconclusive"


def test_parse_rejects_non_json():
    v = _parse_classifier_json("I think this is malicious.")
    assert not v.ok


def test_tool_returns_second_stage_verdict():
    tool = make_deep_classify_tool(_cfg(), chat_fn=lambda findings: '{"verdict": "malicious", '
                                   '"confidence": 0.9, "rationale": "curl|bash", "techniques": ["x"]}')
    out = tool("ci filename decodes to curl|bash")
    assert "second-stage verdict: malicious" in out


def test_tool_handles_unusable_reply():
    tool = make_deep_classify_tool(_cfg(), chat_fn=lambda findings: "no json here")
    out = tool("ambiguous change")
    assert "unusable" in out.lower()


def test_tool_surfaces_endpoint_error():
    def boom(findings):
        raise RuntimeError("endpoint down")

    tool = make_deep_classify_tool(_cfg(), chat_fn=boom)
    out = tool("x")
    assert "ENDPOINT ERROR" in out


def test_deep_classify_record_has_no_child_fields_today(tmp_path):
    """The child_* harness-link fields are GUARDED — a no-op for today's `self` backend (its
    ModelToolResult carries none), so the recorded tool_call must NOT carry child_run_id/child_trace/
    child_meta. Correct for the future make_harness_tool swap; inert now."""
    from rlm_kit import TraceRecorder
    from rlm_kit.trace import load_events

    tool = make_deep_classify_tool(_cfg(), chat_fn=lambda f: '{"verdict": "benign", "confidence": 0.3}')
    path = str(tmp_path / "dc.jsonl")
    with TraceRecorder(path, run_id="dc"):
        tool("some findings")
    tc = [e for e in load_events(path, "dc")
          if e["type"] == "tool_call" and e["payload"].get("tool") == "deep_classify"]
    assert tc, "deep_classify tool_call should be recorded"
    for key in ("child_run_id", "child_trace", "child_meta"):
        assert key not in tc[0]["payload"]
