"""The forensic archive: immutable, content-addressed, append-only. What matters is that a later capture can add history but never replace an earlier one, and that tampering with the archive is detectable."""

from __future__ import annotations

import gzip
import os
import threading
from datetime import UTC, datetime

import pytest

from diff_sentry.ingest import GhApiError
from diff_sentry.snapshot import RecordingApi, SnapshotStore, scrub_emails

_EV = {"repo": "a/b", "kind": "pull_request", "number": 7, "title": "t", "body": "original body"}


def _put(store, event=_EV, **kw):
    return store.put(repo="a/b", kind="pull_request", number=7, event=event, raw={"pulls/7": {"x": 1}}, **kw)


def test_a_capture_round_trips(tmp_path):
    store = SnapshotStore(str(tmp_path))
    cap = _put(store)
    assert cap.is_new and os.path.exists(cap.path)
    doc = store.get(cap.sha256)
    assert doc["event"] == _EV and doc["raw"] == {"pulls/7": {"x": 1}} and doc["schema"].startswith("diff-sentry/")


def test_identical_content_deduplicates_but_is_still_indexed(tmp_path):
    store = SnapshotStore(str(tmp_path))
    first, second = _put(store, reason="first_seen"), _put(store, reason="recheck")
    assert first.sha256 == second.sha256 and first.is_new and not second.is_new
    assert [r["reason"] for r in store.history("a/b", "pull_request", 7)] == ["first_seen", "recheck"]


def test_an_edit_adds_a_new_object_and_keeps_the_original(tmp_path):
    # the point of the archive: after the attacker edits the body, the ORIGINAL is still there
    store = SnapshotStore(str(tmp_path))
    before = _put(store)
    after = _put(store, {**_EV, "body": "cleaned up"}, reason="changed")
    assert before.sha256 != after.sha256
    assert store.get(before.sha256)["event"]["body"] == "original body"
    assert store.get(after.sha256)["event"]["body"] == "cleaned up"
    assert [r["sha256"] for r in store.history("a/b", "pull_request", 7)] == [before.sha256, after.sha256]


def test_key_order_does_not_change_the_address(tmp_path):
    store = SnapshotStore(str(tmp_path))
    a = store.put(repo="a/b", kind="issue", number=1, event={"x": 1, "y": 2})
    b = store.put(repo="a/b", kind="issue", number=1, event={"y": 2, "x": 1})
    assert a.sha256 == b.sha256


def test_an_existing_object_is_never_rewritten(tmp_path):
    store = SnapshotStore(str(tmp_path))
    cap = _put(store)
    before = os.stat(cap.path)
    _put(store)
    after = os.stat(cap.path)
    assert (before.st_mtime_ns, before.st_size) == (after.st_mtime_ns, after.st_size)


@pytest.mark.parametrize("bad", ["../../etc/passwd", "abc", "", "G" * 64, "a" * 63, "a" * 65])
def test_only_a_sha256_addresses_an_object(tmp_path, bad):
    store = SnapshotStore(str(tmp_path))
    with pytest.raises(ValueError):
        store.get(bad)


def test_email_addresses_never_reach_the_archive_but_the_domain_does(tmp_path):
    payload = "tree abc\nauthor Mallory <mallory@evil.example> 1790000000 +0800\ncommitter M <m@evil.example> 1 +0800"
    raw = {"users/1": {"login": "m", "email": "mallory@evil.example", "bio": "write to mallory@evil.example"},
           "repos/a/b/pulls/7/commits": [{"commit": {
               "author": {"name": "M", "email": "m@evil.example"}, "committer": {"email": "c@evil.example"},
               "verification": {"verified": True, "payload": payload, "signature": "-----BEGIN-----"},
               "message": "fix\n\nMentions x@evil.example in prose.\n\nCo-authored-by: X <x@evil.example>\n"
                          "Signed-off-by: Y <y@evil.example>"}}]}
    store = SnapshotStore(str(tmp_path))
    cap = store.put(repo="a/b", kind="pull_request", number=7, event={"provenance": {"email": "e@evil.example"}}, raw=raw)
    doc = store.get(cap.sha256)
    assert doc["raw"]["users/1"]["email"] == "***@evil.example"
    commit = doc["raw"]["repos/a/b/pulls/7/commits"][0]["commit"]
    assert commit["author"]["email"] == "***@evil.example" and commit["committer"]["email"] == "***@evil.example"
    assert doc["event"]["provenance"]["email"] == "***@evil.example"
    # the signed payload and the trailers carry addresses too
    assert "mallory@evil.example" not in commit["verification"]["payload"]
    assert "author Mallory <***@evil.example> 1790000000 +0800" in commit["verification"]["payload"]
    assert "x@evil.example" not in commit["message"].split("Co-authored-by")[1]
    assert "y@evil.example" not in commit["message"] and "<***@evil.example>" in commit["message"]
    # free text is evidence: prose and the bio stay as captured, and the input object is not modified
    assert "Mentions x@evil.example in prose." in commit["message"]
    assert doc["raw"]["users/1"]["bio"].endswith("mallory@evil.example")
    assert raw["users/1"]["email"] == "mallory@evil.example"


def test_history_is_per_change(tmp_path):
    store = SnapshotStore(str(tmp_path))
    _put(store)
    store.put(repo="a/b", kind="issue", number=7, event={"other": 1})
    assert len(store.history("a/b", "pull_request", 7)) == 1
    assert store.history("a/b", "pull_request", 99) == []


def test_the_capture_time_is_recorded_in_utc(tmp_path):
    store = SnapshotStore(str(tmp_path))
    _put(store, captured_at=datetime(2026, 2, 27, 5, 14, tzinfo=UTC))
    assert store.history("a/b", "pull_request", 7)[0]["ts"] == "2026-02-27T05:14:00+00:00"


def test_an_intact_store_verifies(tmp_path):
    store = SnapshotStore(str(tmp_path))
    _put(store)
    _put(store, {**_EV, "body": "x"}, reason="changed")
    assert store.verify() == []


def test_a_tampered_object_is_detected(tmp_path):
    store = SnapshotStore(str(tmp_path))
    cap = _put(store)
    with gzip.open(cap.path, "wb") as fh:
        fh.write(b'{"forged": true}')
    problems = store.verify()
    assert len(problems) == 1 and cap.sha256 in problems[0] and "hashes to" in problems[0]


def test_a_missing_object_is_detected(tmp_path):
    store = SnapshotStore(str(tmp_path))
    cap = _put(store)
    os.remove(cap.path)
    assert any("is missing" in p for p in store.verify())


def test_a_corrupt_index_line_is_reported_and_skipped(tmp_path):
    store = SnapshotStore(str(tmp_path))
    _put(store)
    with open(tmp_path / "index.jsonl", "a") as fh:
        fh.write("not json\n")
    assert any("not JSON" in p for p in store.verify())
    assert len(store.history("a/b", "pull_request", 7)) == 1


def test_concurrent_captures_keep_the_index_whole(tmp_path):
    store = SnapshotStore(str(tmp_path))

    def work(n):
        for i in range(20):
            store.put(repo="a/b", kind="issue", number=n, event={"n": n, "i": i})

    threads = [threading.Thread(target=work, args=(n,)) for n in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert store.verify() == []
    assert sum(len(store.history("a/b", "issue", n)) for n in range(4)) == 80


def test_recording_api_captures_bodies_and_lets_errors_through():
    def inner(path):
        if path == "bad":
            raise GhApiError("nope", status=404)
        return {"path": path}

    rec = RecordingApi(inner)
    assert rec("repos/a/b/pulls/1") == {"path": "repos/a/b/pulls/1"}
    with pytest.raises(GhApiError):
        rec("bad")
    assert rec.records == {"repos/a/b/pulls/1": {"path": "repos/a/b/pulls/1"}}


def test_trailers_are_masked_whatever_the_line_ending():
    for sep in ("\n", "\r\n", "\r"):
        message = f"fix{sep}Signed-off-by: A <a@b.example>{sep}Co-authored-by: C <c@d.example>"
        masked = scrub_emails({"message": message})
        assert "a@b.example" not in masked["message"] and "c@d.example" not in masked["message"], repr(sep)
        assert "<***@b.example>" in masked["message"] and "<***@d.example>" in masked["message"], repr(sep)
