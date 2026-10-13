"""Replay of the hackerbot-claw CAMPAIGN through the same pipeline the watcher runs, in event order.

`test_incident_hackerbot_claw.py` pins what the text rules catch in the quoted payloads. This pins what the
watcher adds around them, against `tests/corpus/hackerbot_claw_campaign.json`:

* the account is measured as it was on the day (7 days old on Feb 27), not as it is today;
* the self-described agent profile and the branch-name / comment channels are read;
* a change whose own content is unremarkable is raised by what the account did before;
* the dossier answers when, where and how quickly it moved.

Every event is assembled under a NEUTRAL benign verdict, so the signal is driven by the evidence floor alone
(MF3); the model's verdict on the earlier targets is simulated as `malicious`."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from diff_sentry.actors import ActorStore
from diff_sentry.assemble import assemble_verdict
from diff_sentry.cli import _baseline_indicators
from diff_sentry.indicators import scan_change
from diff_sentry.ingest import event_from_payload
from diff_sentry.schema import ChangeVerdict, IndicatorHit

_CORPUS = json.loads((Path(__file__).parent / "corpus" / "hackerbot_claw_campaign.json").read_text())
_ACCOUNT = _CORPUS["account"]
_ENTRIES = _CORPUS["entries"]
_EMIT_ON = ("suspicious", "malicious")


def _payload(entry, *, with_time=True):
    ev = dict(entry["event"])
    if with_time:
        ev["created_at"] = entry["at"]
    ev["provenance"] = {"author_login": _ACCOUNT["login"], "author_type": "User", "author_association": "NONE",
                        "author_account_created_at": _ACCOUNT["created"],
                        "author_profile": {"bio": _ACCOUNT["bio"]}}
    return event_from_payload(ev)


def _signal(baseline):
    events = [{"type": "run_start", "payload": {"meta": {"baseline_indicators": baseline,
                                                          "emit_on": list(_EMIT_ON)}}}]
    verdict = ChangeVerdict(summary="s", verdict="benign", confidence=0.5, rationale="r")
    return assemble_verdict(verdict, events, emit_on=_EMIT_ON).signal


def _replay(store):
    """Run every entry, oldest first, the way `Watcher._examine` does: correlate, baseline, record, then the
    model's verdict lands on the sighting. Returns {name: (rule set, signal)}."""
    out = {}
    for entry in sorted(_ENTRIES, key=lambda e: e["at"]):
        event = _payload(entry)
        content = scan_change(event)
        facts, prior = store.correlate(event, content)
        event["provenance"].update(facts)
        if prior:
            event["prior_indicators"] = prior
        baseline = _baseline_indicators(event)
        hits = [IndicatorHit(**h) for h in baseline]
        run_id = entry["name"]
        store.record(event, run_id=run_id, hits=hits, content_hits=content)
        signal = _signal(baseline)
        if signal:
            store.finalize(run_id, verdict="malicious", signal=True,
                           max_severity=max(h["severity"] for h in baseline))
        out[entry["name"]] = ({h["rule"] for h in baseline}, signal)
    return out


@pytest.fixture
def store(tmp_path):
    s = ActorStore(str(tmp_path / "actors.db"), clock=lambda: datetime(2026, 9, 29, tzinfo=UTC))
    yield s
    s.close()


@pytest.mark.parametrize("entry", _ENTRIES, ids=[e["name"] for e in _ENTRIES])
def test_each_event_fires_its_declared_rules_in_campaign_order(entry, store):
    rules, signal = _replay(store)[entry["name"]]
    missing = set(entry["must_fire"]) - rules
    assert not missing, f"{entry['name']} did not fire {sorted(missing)}; fired {sorted(rules)}"
    assert signal is True                                   # every target ends up flagged


@pytest.mark.parametrize("entry", _ENTRIES, ids=[e["name"] for e in _ENTRIES])
def test_which_events_signal_on_their_own_content_alone(entry):
    event = _payload(entry)
    assert _signal(_baseline_indicators(event)) is entry["signals_alone"], entry["name"]


def test_the_clean_looking_change_is_raised_only_by_the_campaign_memory(store):
    rules, _ = _replay(store)["synthetic_comment_trigger_on_a_clean_looking_change"]
    alone = {h["rule"] for h in _baseline_indicators(_payload(next(
        e for e in _ENTRIES if e["name"].startswith("synthetic_comment"))))}
    assert "actor-known-bad" in rules and "actor-known-bad" not in alone
    assert "curl-pipe-shell" not in rules and "branch-name-injection" not in rules   # its content is clean


def test_the_payload_host_links_the_second_target_to_the_first(store):
    _replay(store)
    d = store.dossier(_ACCOUNT["login"])
    assert {i["ioc"] for i in d["iocs"]} == {"hackmoltrepeat.com"}
    assert len(next(i for i in d["iocs"])["repos"]) >= 3       # the same host across the campaign's repos


def test_age_is_measured_on_the_day_not_today():
    micro = _payload(next(e for e in _ENTRIES if e["name"].startswith("microsoft")))
    rustpy = _payload(next(e for e in _ENTRIES if e["name"].startswith("rustpython")))
    assert micro["provenance"]["author_account_age_days"] == 7
    assert rustpy["provenance"]["author_account_age_days"] == 10
    # the same payload read WITHOUT its own timestamp falls back to the wall clock, and the account looks old:
    # exactly the error a replay of a historical incident must not make
    naive = _payload(next(e for e in _ENTRIES if e["name"].startswith("microsoft")), with_time=False)
    assert naive["provenance"]["author_account_age_days"] > 100
    assert "brand-new-account" not in {h["rule"] for h in _baseline_indicators(naive)}


def test_the_dossier_reconstructs_the_campaign(store):
    _replay(store)
    d = store.dossier(_ACCOUNT["login"])
    assert d["account_created_at"].startswith("2026-02-20")
    assert d["account_age_at_first_seen_days"] == 7           # created Feb 20, first seen Feb 27
    assert d["first_seen"].startswith("2026-02-27T05:14") and d["last_seen"].startswith("2026-03-02T05:57")
    assert len(d["repos"]) == 5
    assert [e["repo"] for e in d["timeline"]][:2] == ["microsoft/ai-discovery-agent", "DataDog/datadog-iac-scanner"]
    assert d["hour_utc"][5] == 4 and d["hour_utc"][18] == 1   # four of five acts at 05:xx UTC
    assert d["profile"]["author_profile"]["bio"] == _ACCOUNT["bio"]
    assert d["timeline"][0]["head_ref"].startswith("dev$(")   # the branch name is on the record


def test_a_benign_verdict_on_an_earlier_target_clears_the_account_flag_but_not_the_payload_link(store):
    # The model calls the FIRST target benign. That clears the account-level inference (one false positive
    # must not taint an account for good), but the payload host is evidence, so the link to the next target
    # survives whatever the model said.
    first = min(_ENTRIES, key=lambda e: e["at"])
    event = _payload(first)
    content = scan_change(event)
    hits = [IndicatorHit(**h) for h in _baseline_indicators(event)]
    store.record(event, run_id="first", hits=hits, content_hits=content)
    store.finalize("first", verdict="benign", signal=True, max_severity="critical")
    second = _payload(next(e for e in _ENTRIES if e["name"].startswith("datadog")))
    facts, _ = store.correlate(second, scan_change(second))
    assert "actor_known_bad_repos" not in facts and "actor_prior_flag_repos" not in facts
    assert facts["ioc_reuse"] == [{"ioc": "hackmoltrepeat.com", "repos": ["microsoft/ai-discovery-agent"]}]
    assert _signal(_baseline_indicators(second)) is True
