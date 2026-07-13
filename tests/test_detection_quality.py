"""L4a — offline DETECTION-QUALITY corpus over the deterministic layer (scan_indicators + assemble).

No model, no loop: just the pattern detectors + the read-time evidence floor. Each corpus event is
assembled under a NEUTRAL benign verdict, so `signal` is driven PURELY by the deterministic evidence
(the MF3 floor), never by a self-report. The harness pins three things:

  * recall == 1.0 on the malicious families (every malicious event fires its family's key rule and
    reaches the signal floor — the detector cannot miss a family we claim to cover),
  * false-positive rate == 0 on the CLEAN benigns (measured on `signal`, not on "no rule fired": a
    benign workflow edit legitimately fires `workflow-tamper`/medium, which is BELOW the signal floor),
  * the known-fp bucket stays TRACKED — a security doc whose prose quotes injection phrasing fires
    `prompt-injection` today; we count it, we don't pretend it's clean, so a future rule change that
    fixes OR worsens it is visible in the diff.

A per-event golden rule-set guards against a regex tweak silently changing what fires.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from diff_sentry.assemble import assemble_verdict
from diff_sentry.indicators import scan_indicators
from diff_sentry.normalize import raw_content
from diff_sentry.schema import SIGNAL_SEVERITY_FLOOR, ChangeVerdict, severity_rank

_CORPUS = json.loads((Path(__file__).parent / "corpus" / "change_corpus.json").read_text())
_ENTRIES = _CORPUS["entries"]
_EMIT_ON = ("suspicious", "malicious")


def _assemble(event, *, verdict_label="benign"):
    """Assemble the event under a chosen verdict, with only the host-side baseline in the trace — so the
    signal derives from the deterministic evidence floor, exactly as the crash path and MF3 backstop do."""
    baseline = [h.model_dump() for h in scan_indicators(raw_content(event))]
    events = [{"type": "run_start",
               "payload": {"meta": {"baseline_indicators": baseline, "emit_on": list(_EMIT_ON)}}}]
    verdict = ChangeVerdict(summary="s", verdict=verdict_label, confidence=0.5, rationale="r")
    return assemble_verdict(verdict, events, emit_on=_EMIT_ON)


def _fired_rules(event) -> list[str]:
    return sorted({h.rule for h in scan_indicators(raw_content(event))})


def _ids(kind):
    return [e["name"] for e in _ENTRIES if e["kind"] == kind]


# ── golden per-event rule-set (regex-drift guard) ─────────────────────────────────────────────────

@pytest.mark.parametrize("entry", _ENTRIES, ids=[e["name"] for e in _ENTRIES])
def test_golden_rule_set_matches(entry):
    """The exact set of rules that fires on each event is pinned; a silent behavioral change fails here."""
    assert _fired_rules(entry["event"]) == sorted(entry["expected_rules"]), entry["name"]


@pytest.mark.parametrize("entry", _ENTRIES, ids=[e["name"] for e in _ENTRIES])
def test_signal_matches_label(entry):
    """Every event's derived signal (under a neutral benign verdict) matches its checked-in expectation."""
    assert _assemble(entry["event"]).signal is entry["expected_signal"], entry["name"]


# ── the aggregate quality gates ───────────────────────────────────────────────────────────────────

def test_recall_on_malicious_is_perfect():
    """Every malicious family signals AND fires its declared key rule — even under a benign verdict, so
    a false-benign self-report could not have suppressed it. Recall must be exactly 1.0."""
    mal = [e for e in _ENTRIES if e["kind"] == "malicious"]
    assert mal, "corpus must carry malicious families"
    missed = []
    for e in mal:
        rules = _fired_rules(e["event"])
        assembled = _assemble(e["event"])
        floor_ok = severity_rank(assembled.max_indicator_severity) >= severity_rank(SIGNAL_SEVERITY_FLOOR)
        if not (assembled.signal and floor_ok and e["key_rule"] in rules):
            missed.append(e["name"])
    recall = (len(mal) - len(missed)) / len(mal)
    assert recall == 1.0, f"missed malicious families: {missed}"


def test_false_positive_rate_on_clean_benigns_is_zero():
    """No CLEAN benign may reach the signal floor. Measured on `signal`, NOT on 'no rule fired' — a legit
    workflow edit fires `workflow-tamper`/medium (sub-floor), which correctly does not signal."""
    benign = [e for e in _ENTRIES if e["kind"] == "benign"]
    assert benign, "corpus must carry clean benigns"
    false_positives = [e["name"] for e in benign if _assemble(e["event"]).signal]
    fpr = len(false_positives) / len(benign)
    assert fpr == 0.0, f"clean benigns that wrongly signalled: {false_positives}"


def test_known_false_positives_are_tracked_not_hidden():
    """The known-fp bucket is a documented, COUNTED false positive (prose quoting injection phrasing).
    We assert it still signals today AND that the count is exactly what we checked in — so a rule change
    that removes OR adds a known FP is a visible test diff, never a silent surprise."""
    known_fp = [e for e in _ENTRIES if e["kind"] == "known-fp"]
    assert len(known_fp) == 1, "update this count deliberately when the known-fp corpus changes"
    for e in known_fp:
        assembled = _assemble(e["event"])
        assert assembled.signal is True, f"known-fp {e['name']} no longer signals — good? update the corpus"
        assert e["key_rule"] in _fired_rules(e["event"])
