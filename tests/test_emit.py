"""The host-side SIEM emitter: emits only on signal + a configured webhook, and never raises."""

from __future__ import annotations

from diff_sentry.config import DetectConfig
from diff_sentry.emit import emit_signal, signal_payload
from diff_sentry.schema import DetectionResponse, IndicatorHit


def _resp(signal: bool) -> DetectionResponse:
    return DetectionResponse(
        id="pr-7", status="classified", verdict="malicious", confidence=0.9, signal=signal,
        summary="s", rationale="r", techniques=["ci-shell-injection"],
        indicators=[IndicatorHit(id="ind-x", rule="ci-shell-injection", severity="high", title="t")],
        max_indicator_severity="high",
    )


def _cfg(webhook: str = "https://siem.example/hook") -> DetectConfig:
    return DetectConfig(main_model="x", sub_model="x", classifier_model="x", siem_webhook_url=webhook,
                        siem_token="secret")


def test_emits_on_signal_with_webhook():
    sent = {}

    def poster(url, headers, payload):
        sent["url"], sent["headers"], sent["payload"] = url, headers, payload
        return 202

    r = emit_signal(_resp(signal=True), _cfg(), poster=poster)
    assert r.emitted and r.status_code == 202
    assert sent["url"] == "https://siem.example/hook"
    assert sent["headers"]["Authorization"] == "Bearer secret"
    assert sent["payload"]["verdict"] == "malicious"
    assert sent["payload"]["indicators"][0]["rule"] == "ci-shell-injection"


def test_no_signal_is_skipped():
    r = emit_signal(_resp(signal=False), _cfg(), poster=lambda *a: 200)
    assert not r.emitted and r.skipped_reason == "no_signal"


def test_no_webhook_is_skipped():
    r = emit_signal(_resp(signal=True), _cfg(webhook=""), poster=lambda *a: 200)
    assert not r.emitted and r.skipped_reason == "no_webhook"


def test_transport_error_never_raises():
    def boom(*a):
        raise RuntimeError("siem down")

    r = emit_signal(_resp(signal=True), _cfg(), poster=boom)
    assert not r.emitted and "siem down" in r.error


def test_signal_payload_is_compact():
    p = signal_payload(_resp(signal=True))
    assert set(p) >= {"run_id", "verdict", "indicators", "max_indicator_severity"}
