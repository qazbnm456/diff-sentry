"""The second-stage classifier seam: JSON validation + the tool with an injected chat_fn (no network)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from diff_sentry.config import DetectConfig
from diff_sentry.deep_classify import _parse_classifier_json, _selfclassify_chat, make_deep_classify_tool


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
    """The child_* harness-link fields are GUARDED: the `self` backend's ModelToolResult carries none, so
    the recorded tool_call must NOT carry child_run_id/child_trace/child_meta. The guard exists for a
    make_harness_tool backend, which would populate them."""
    from rlm_harness import TraceRecorder
    from rlm_harness.trace import load_events

    tool = make_deep_classify_tool(_cfg(), chat_fn=lambda f: '{"verdict": "benign", "confidence": 0.3}')
    path = str(tmp_path / "dc.jsonl")
    with TraceRecorder(path, run_id="dc"):
        tool("some findings")
    tc = [e for e in load_events(path, "dc")
          if e["type"] == "tool_call" and e["payload"].get("tool") == "deep_classify"]
    assert tc, "deep_classify tool_call should be recorded"
    for key in ("child_run_id", "child_trace", "child_meta"):
        assert key not in tc[0]["payload"]


class _FakeOpenAI:
    """`openai.OpenAI` with one canned reply, keeping the request it was sent."""

    sent: dict = {}
    reply: tuple[str | None, str] = ("", "stop")

    def __init__(self, **_kw):
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kw):
        _FakeOpenAI.sent = kw
        content, finish = _FakeOpenAI.reply
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=content), finish_reason=finish)])


def _chat(monkeypatch, reply, **cfg):
    import openai

    monkeypatch.setattr(openai, "OpenAI", _FakeOpenAI)
    _FakeOpenAI.reply = reply
    return _selfclassify_chat(DetectConfig(main_model="x", sub_model="x", classifier_model="c", classifier_max_tokens=2048, **cfg))


def test_classifier_lm_kwargs_reach_the_request_under_the_settings_it_may_not_override(monkeypatch):
    chat = _chat(monkeypatch, ('{"verdict": "benign"}', "stop"),
                 classifier_lm_kwargs={"temperature": 1, "extra_body": {"thinking_token_budget": 512}})
    chat("findings")
    sent = _FakeOpenAI.sent
    assert sent["temperature"] == 1 and sent["extra_body"] == {"thinking_token_budget": 512}
    assert sent["model"] == "c" and sent["max_tokens"] == 2048 and sent["messages"][1]["content"] == "findings"


def test_the_default_request_keeps_its_temperature(monkeypatch):
    _chat(monkeypatch, ('{"verdict": "benign"}', "stop"))("f")
    assert _FakeOpenAI.sent["temperature"] == 0.1


@pytest.mark.parametrize("content", ["", None, '{"verdict": "mal'])
def test_a_reply_cut_at_max_tokens_says_so_once_and_counts_toward_the_breaker(monkeypatch, content):
    calls = []
    chat = _chat(monkeypatch, (content, "length"))
    tool = make_deep_classify_tool(DetectConfig(main_model="x", sub_model="x", classifier_model="c", classifier_circuit_break=2),
                                   chat_fn=lambda f: calls.append(f) or chat(f))
    out = tool("findings")
    assert len(calls) == 1                                    # not re-sent: the same request is cut the same way
    assert "max_tokens=2048" in out and "DS_CLASSIFIER_MAX_TOKENS" in out and "ENDPOINT" not in out
    tool("findings")
    assert "CIRCUIT BREAKER" in tool("findings") and len(calls) == 2


def test_a_cut_reply_is_marked_in_the_trace(monkeypatch, tmp_path):
    from rlm_harness import TraceRecorder
    from rlm_harness.trace import load_events

    tool = make_deep_classify_tool(_cfg(), chat_fn=_chat(monkeypatch, ("", "length")))
    path = str(tmp_path / "cut.jsonl")
    with TraceRecorder(path, run_id="cut"):
        tool("findings")
    payload = next(e["payload"] for e in load_events(path, "cut") if e["type"] == "tool_call")
    assert payload["cut"] is True and payload["ok"] is False and payload["raw"] == ""


def test_a_reply_cut_after_its_answer_still_counts(monkeypatch):
    chat = _chat(monkeypatch, ('{"verdict": "suspicious", "confidence": 0.6}', "length"))
    out = make_deep_classify_tool(_cfg(), chat_fn=chat)("findings")
    assert "second-stage verdict: suspicious" in out


def test_an_ordinary_unusable_reply_does_not_blame_the_budget(monkeypatch):
    out = make_deep_classify_tool(_cfg(), chat_fn=_chat(monkeypatch, ("no json here", "stop")))("findings")
    assert "unusable" in out.lower() and "max_tokens" not in out
