"""Account history from GH Archive (via ClickHouse's public playground): off by default, parameterised, best-effort, and read as of the event. No network: the post is faked."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from urllib.parse import parse_qs, urlsplit

import pytest

from diff_sentry.history import account_history, enabled
from diff_sentry.indicators import scan_provenance


def _post(row: dict | None = None, status: int = 200, calls: list | None = None):
    def post(url: str, body: bytes, limit: int):
        if calls is not None:
            calls.append((url, body))
        return status, (json.dumps(row) + "\n").encode() if row is not None else b""
    return post


_ROW = {"events": 900, "first_event": "2014-01-21 10:19:35", "events_before": 880,
        "last_before": "2026-09-01 00:00:00", "repos_before": 41}


def test_the_login_and_times_are_parameters_never_part_of_the_sql():
    calls: list = []
    facts = account_history("mallory", datetime(2026, 10, 22, tzinfo=UTC), post=_post(_ROW, calls=calls))
    assert facts == {"events_before": 880, "repos_before": 41, "first_event": "2014-01-21 10:19:35", "last_before_days": 51}
    url, body = calls[0]
    params = parse_qs(urlsplit(url).query)
    assert urlsplit(url).netloc == "play.clickhouse.com" and params["param_login"] == ["mallory"]
    assert params["param_as_of"] == ["2026-10-22 00:00:00"] and params["param_cut"] == ["2026-09-22 00:00:00"]
    assert b"mallory" not in body and b"{login:String}" in body


@pytest.mark.parametrize("login", ["", "a/b", "x' OR 1=1 --", "-lead", "a" * 40])
def test_a_login_that_is_not_a_github_login_is_never_sent(login):
    calls: list = []
    assert account_history(login, post=_post(_ROW, calls=calls)) == {} and not calls


def test_a_failed_lookup_is_no_facts_and_no_events_is_a_fact():
    assert account_history("mallory", post=_post(status=503)) == {}
    assert account_history("mallory", post=_post(None)) == {}
    assert account_history("mallory", post=_post({"events": 0})) == {"events_before": 0, "repos_before": 0}


def test_it_is_off_unless_turned_on(monkeypatch):
    monkeypatch.delenv("DS_ACCOUNT_HISTORY", raising=False)
    assert enabled() is None
    monkeypatch.setenv("DS_ACCOUNT_HISTORY", "yes")          # only the named source turns it on
    assert enabled() is None
    monkeypatch.setenv("DS_ACCOUNT_HISTORY", "clickhouse")
    assert callable(enabled())
    monkeypatch.delenv("DS_ACCOUNT_HISTORY")
    assert callable(enabled(True))


def test_ingest_records_the_history_only_when_given_a_lookup():
    from diff_sentry.ingest import issue_event

    issue = {"title": "t", "body": "b", "user": {"login": "mallory", "type": "User", "id": 7},
             "author_association": "NONE", "created_at": "2026-10-22T00:00:00Z", "comments": 0}

    def api(path):
        return issue if path.startswith("repos/") else {"created_at": "2015-01-01T00:00:00Z"}

    asked = []
    with_history = issue_event("o/r", 1, api=api, history=lambda login, as_of: asked.append((login, as_of)) or {"last_before_days": 900})
    assert with_history["provenance"]["author_history_last_before_days"] == 900
    assert asked == [("mallory", datetime(2026, 10, 22, tzinfo=UTC))]
    assert not any(k.startswith("author_history_") for k in issue_event("o/r", 1, api=api)["provenance"])


def _rules(prov: dict) -> dict[str, str]:
    return {h.rule: h.severity for h in scan_provenance({"author_login": "mallory", "author_type": "User", **prov})}


def test_a_dormant_account_active_again_is_a_corroborator():
    assert _rules({"author_history_last_before_days": 800})["dormant-account-reactivated"] == "medium"
    assert "dormant-account-reactivated" not in _rules({"author_history_last_before_days": 364})
    bot = scan_provenance({"author_login": "x", "author_type": "Bot", "author_history_last_before_days": 800})
    assert "dormant-account-reactivated" not in {h.rule for h in bot}


def test_an_old_account_with_no_public_history_is_a_corroborator():
    assert _rules({"author_history_events_before": 0, "author_account_age_days": 400})["no-public-history"] == "low"
    assert "no-public-history" not in _rules({"author_history_events_before": 0, "author_account_age_days": 20})
    assert "no-public-history" not in _rules({"author_history_events_before": 3, "author_account_age_days": 400})


def test_an_answer_it_cannot_read_is_no_facts():
    assert account_history("mallory", post=_post({"events": "many"})) == {}
    assert account_history("mallory", post=_post({"events": 3, "events_before": 2, "last_before": "yesterday"})) == {}


def test_history_from_before_the_account_existed_is_another_accounts():
    from diff_sentry.ingest import issue_event

    issue = {"title": "t", "body": "b", "user": {"login": "mallory", "type": "User", "id": 7},
             "author_association": "NONE", "created_at": "2026-10-22T00:00:00Z", "comments": 0}

    def api(path):
        return issue if path.startswith("repos/") else {"created_at": "2024-06-01T00:00:00Z"}

    prov = issue_event("o/r", 1, api=api, history=lambda login, as_of: {
        "events_before": 50, "first_event": "2015-03-01 00:00:00", "last_before_days": 2000})["provenance"]
    assert prov["author_history_other_account"] is True
    assert not any(k.startswith("author_history_") and k != "author_history_other_account" for k in prov)
