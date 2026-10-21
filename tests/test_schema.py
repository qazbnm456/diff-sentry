"""The judgement-only output model + its healing coercion."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from diff_sentry.schema import ChangeVerdict, decisive_verdict_model, max_severity, severity_rank
from tests.conftest import MALICIOUS_VERDICT


def test_change_verdict_roundtrip():
    v = ChangeVerdict.from_payload(MALICIOUS_VERDICT)
    assert v.verdict == "malicious"
    assert v.confidence == 0.95
    assert "codeowners-tamper" in v.techniques


def test_from_payload_ignores_legacy_keys():
    # a stray planner that tried to author indicators must not break coercion; the extra key is dropped
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


def test_the_decisive_model_is_the_submit_type_with_inconclusive_refused_twice():
    model = decisive_verdict_model("3 files")
    assert model.__name__ == "ChangeVerdict" and issubclass(model, ChangeVerdict)
    assert model.model_json_schema() == ChangeVerdict.model_json_schema()     # the prompt the planner sees is unchanged
    for _ in range(2):
        with pytest.raises(ValidationError, match=r"refused: this change has content to classify \(3 files\)"):
            model(**{**MALICIOUS_VERDICT, "verdict": " Inconclusive"})
    assert model(**{**MALICIOUS_VERDICT, "verdict": "inconclusive"}).verdict == "inconclusive"
    assert model(**MALICIOUS_VERDICT).verdict == "malicious"
    assert decisive_verdict_model("x") is not model                          # each run counts its own refusals
