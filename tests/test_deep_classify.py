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
