"""L4b — offline REPRODUCTION of the real hackerbot-claw incident (late Feb-early Mar 2026).

Datadog's public writeup ("Stopping hackerbot-claw with BewAIre") documents an AI agent that opened
malicious PRs and prompt-injection issues against their public repos. The original artifacts are gone
(the attacker account was deleted — datadog-iac-scanner PR #7/#8 and datadog-agent issues #47021/#47024
all 404 today; only the remediation PR #9 survives), so we CANNOT live-ingest them. Instead we
reconstruct the three payloads the article quotes verbatim into change events and prove the DETERMINISTIC
layer (scan_indicators + assemble) catches all three OFFLINE — no model, no loop, no network.

Each event is assembled under a NEUTRAL benign verdict, so `signal` is driven purely by the MF3 evidence
floor: a false-benign self-report from the planner could not have suppressed any of these. This is the
same harness shape as `test_detection_quality.py`, scoped to the real incident with provenance.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from diff_sentry.assemble import assemble_verdict
from diff_sentry.indicators import scan_indicators
from diff_sentry.normalize import raw_content
from diff_sentry.schema import SIGNAL_SEVERITY_FLOOR, ChangeVerdict, severity_rank

_CORPUS = json.loads((Path(__file__).parent / "corpus" / "hackerbot_claw_incident.json").read_text())
_ENTRIES = _CORPUS["entries"]
_EMIT_ON = ("suspicious", "malicious")


def _hits(event):
    return scan_indicators(raw_content(event))


def _assemble(event, *, verdict_label="benign"):
    """Assemble under a chosen verdict with only the host-side baseline in the trace, so the signal
    derives from the deterministic evidence floor — exactly the MF3 backstop the crash path relies on."""
    baseline = [h.model_dump() for h in _hits(event)]
    events = [{"type": "run_start",
               "payload": {"meta": {"baseline_indicators": baseline, "emit_on": list(_EMIT_ON)}}}]
    verdict = ChangeVerdict(summary="s", verdict=verdict_label, confidence=0.5, rationale="r")
    return assemble_verdict(verdict, events, emit_on=_EMIT_ON)


def _fired_rules(event):
    return sorted({h.rule for h in _hits(event)})


def test_all_three_incident_payloads_reconstructed():
    """The reproduction covers exactly the three distinct hackerbot-claw payloads from the writeup."""
    assert len(_ENTRIES) == 3
    assert all(e["kind"] == "malicious" for e in _ENTRIES)


@pytest.mark.parametrize("entry", _ENTRIES, ids=[e["name"] for e in _ENTRIES])
def test_golden_rule_set_matches(entry):
    """The exact set of rules that fires on each reconstructed event is pinned (regex-drift guard)."""
    assert _fired_rules(entry["event"]) == sorted(entry["expected_rules"]), entry["name"]


@pytest.mark.parametrize("entry", _ENTRIES, ids=[e["name"] for e in _ENTRIES])
def test_incident_signals_even_under_a_benign_verdict(entry):
    """Every incident payload reaches the signal floor AND fires its declared key rule under a NEUTRAL
    benign verdict — so a false-benign self-report could not have suppressed the evidence (MF3)."""
    assembled = _assemble(entry["event"])
    assert assembled.signal is entry["expected_signal"] is True, entry["name"]
    floor_ok = severity_rank(assembled.max_indicator_severity) >= severity_rank(SIGNAL_SEVERITY_FLOOR)
    assert floor_ok, f"{entry['name']} did not reach the {SIGNAL_SEVERITY_FLOOR} floor"
    assert entry["key_rule"] in _fired_rules(entry["event"]), entry["name"]


def test_ci_pr_payload_deobfuscates_to_the_published_ioc():
    """The datadog-iac-scanner PR fixture: the ${IFS}/base64 filename must DECODE to the published
    `curl … | bash` IOC. This is the deobfuscation the detector performs statically — it reads the
    payload, it never fetches or runs it."""
    entry = next(e for e in _ENTRIES if e["name"] == "iac_scanner_pr_ifs_b64_curl_bash_filename")
    obf = [h for h in _hits(entry["event"]) if h.rule == "obfuscated-payload"]
    assert obf, "the base64 filename payload must be deobfuscated"
    assert obf[0].decoded == entry["expected_deobfuscated"]
    assert obf[0].severity == "critical"  # inner curl|bash lifts the obfuscated hit to critical


def test_codeowners_issue_signals_on_two_independent_grounds():
    """The datadog-agent CODEOWNERS injection fires BOTH prompt-injection (the `system prompt` phrase)
    and codeowners-tamper (it names .github/CODEOWNERS) — belt-and-suspenders, exactly the hackerbot-claw
    governance-takeover move."""
    entry = next(e for e in _ENTRIES if e["name"] == "datadog_agent_issue_codeowners_injection")
    rules = _fired_rules(entry["event"])
    assert "prompt-injection" in rules
    assert "codeowners-tamper" in rules
