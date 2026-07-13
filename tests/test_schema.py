"""The judgement-only output model + its healing coercion."""

from __future__ import annotations

from diff_sentry.schema import ChangeVerdict, max_severity, severity_rank
from tests.conftest import MALICIOUS_VERDICT


def test_change_verdict_roundtrip():
    v = ChangeVerdict.from_payload(MALICIOUS_VERDICT)
    assert v.verdict == "malicious"
    assert v.confidence == 0.95
    assert "codeowners-tamper" in v.techniques


def test_from_payload_ignores_legacy_keys():
    # a stray planner that tried to author indicators must not break coercion — the extra key is dropped
    payload = {**MALICIOUS_VERDICT, "indicators": [{"id": "x"}], "signal": True}
    v = ChangeVerdict.from_payload(payload)
    assert v.verdict == "malicious"
    assert not hasattr(v, "indicators")


def test_confidence_is_bounded():
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        ChangeVerdict(summary="s", verdict="benign", confidence=1.5, rationale="r")


def test_severity_ordering():
    assert severity_rank("critical") > severity_rank("high") > severity_rank("info")
    assert max_severity(["low", "critical", "medium"]) == "critical"
    assert max_severity([]) == "info"
    assert max_severity(["bogus"]) == "info"
