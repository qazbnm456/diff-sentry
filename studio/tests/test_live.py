"""The live-run driver — verified with `cli.run` / ingest STUBBED, so it needs no LLM, dspy, gh, or
diff_sentry. The action stream comes from the recorder's `on_event` (no dspy callback — diff-sentry's
cli.run has none), so these tests exercise the sink mapping, the ingest dispatch, and the finalize path."""

import json
import types
from pathlib import Path

import pytest

from diff_sentry_studio.live import (
    _build_event,
    _describe_exc,
    _failed_dict,
    run_live,
    trace_event_sink,
)


# ---- trace_event_sink: the sandbox-invoked tools + analyst, from the recorder's on_event ----

def test_trace_event_sink_maps_tools_and_sub_calls_and_skips_the_rest():
    sunk = []
    on_event = trace_event_sink(sunk.append)
    on_event({"type": "tool_call", "payload": {"tool": "scan_indicators", "hits": [{"severity": "high"}], "n": 1}})
    on_event({"type": "tool_call", "payload": {"tool": "deep_classify", "ok": True, "verdict": "malicious"}})
    on_event({"type": "sub_call", "payload": {"input": "q", "processed": "a"}})
    on_event({"type": "main_step", "payload": {"reasoning": "r", "code": "c"}})   # SKIP — post-hoc burst
    on_event({"type": "run_start", "payload": {}})                               # SKIP — endpoint owns created
    assert [e["event"] for e in sunk] == [
        "detection.scan", "detection.classify", "detection.analyst.escalation"]
    assert sunk[0]["data"]["worst"] == "high" and sunk[1]["data"]["verdict"] == "malicious"


# ---- _build_event: dispatch classify / pr / issue over an injectable ingest ----

def _fake_ingest():
    return types.SimpleNamespace(
        event_from_payload=lambda p: {"via": "payload", "repo": p.get("repo")},
        pr_event=lambda repo, n: {"via": "pr", "repo": repo, "number": n},
        issue_event=lambda repo, n: {"via": "issue", "repo": repo, "number": n})


def test_build_event_classify_uses_event_from_payload():
    ev = _build_event({"mode": "classify", "payload": {"repo": "acme/x"}}, ingest=_fake_ingest())
    assert ev == {"via": "payload", "repo": "acme/x"}


def test_build_event_pr_and_issue_use_gh_ingest():
    assert _build_event({"mode": "pr", "repo": "acme/x", "number": 7}, ingest=_fake_ingest())["via"] == "pr"
    assert _build_event({"mode": "issue", "repo": "acme/x", "number": 12}, ingest=_fake_ingest())["via"] == "issue"


# ---- run_live: drive cli.run, stream the action events, prefer the durable response ----

def test_run_live_streams_actions_then_prefers_the_response_file(tmp_path):
    sunk, final = [], {}
    (tmp_path / "responses").mkdir()
    (tmp_path / "responses" / "r1.json").write_text(json.dumps({"status": "classified", "id": "r1"}))

    def cli_run(event, *, run_id="change", outdir="./output", config=None, on_event=None,
                extra_tools=(), emit=True, poster=None):
        # the tools stream via on_event exactly as the recorder would; emit MUST be False (viewer)
        assert emit is False
        on_event({"type": "tool_call", "payload": {"tool": "scan_indicators", "hits": [{"severity": "critical"}], "n": 1}})
        on_event({"type": "sub_call", "payload": {"input": "q", "processed": "a"}})
        return types.SimpleNamespace(response_path=str(Path(outdir) / "responses" / f"{run_id}.json"))

    run_live({"mode": "classify", "payload": {"repo": "acme/x"}}, "r1", sunk.append, final.update,
             artifacts_dir=tmp_path, cli_run=cli_run, ingest=_fake_ingest())
    assert [e["event"] for e in sunk] == ["detection.scan", "detection.analyst.escalation"]
    assert final == {"status": "classified", "id": "r1"}     # the on-disk artifact wins


def test_run_live_calls_cli_run_with_the_real_run_signature(tmp_path):
    # REGRESSION guard for the zero-harness-change promise: this fake MIRRORS diff-sentry's real
    # `run(event, *, run_id, outdir, config, on_event, extra_tools, emit, poster)` EXACTLY. If run_live
    # ever passed an unexpected kwarg (callbacks=, cancel_event=), the call would TypeError → a failed
    # response, and this test would fail.
    final = {}

    def cli_run(event, *, run_id="change", outdir="./output", config=None, on_event=None,
                extra_tools=(), emit=True, poster=None):
        (Path(outdir) / "responses").mkdir(parents=True, exist_ok=True)
        (Path(outdir) / "responses" / f"{run_id}.json").write_text(json.dumps({"status": "classified", "id": run_id}))
        return types.SimpleNamespace(response_path=str(Path(outdir) / "responses" / f"{run_id}.json"))

    run_live({"mode": "classify", "payload": {}}, "r2", lambda e: None, final.update,
             artifacts_dir=tmp_path, cli_run=cli_run, ingest=_fake_ingest())
    assert final == {"status": "classified", "id": "r2"}     # no TypeError → the call shape is valid


def test_run_live_failure_becomes_an_informative_failed_response(tmp_path):
    final = {}

    def cli_run(event, **kw):
        raise RuntimeError("boom in the run")

    run_live({"mode": "classify", "payload": {}}, "r", lambda e: None, final.update,
             artifacts_dir=tmp_path, cli_run=cli_run, ingest=_fake_ingest(),
             build_failed_response=lambda run_id, events, detail: types.SimpleNamespace(
                 model_dump=lambda: {"status": "failed", "detail": detail}))
    assert final["status"] == "failed" and "boom in the run" in final["detail"]


def test_run_live_missing_live_extra_completes_as_failed_not_hang():
    # server started WITHOUT the `live` extra → `from diff_sentry import ingest` (or cli) raises in the
    # worker. on_done MUST still fire (else the SSE hangs forever). ingest/cli_run default to None → the
    # real imports, absent in a replay-only env.
    import importlib.util
    if importlib.util.find_spec("diff_sentry") is not None:
        pytest.skip("diff-sentry present (live extra) — this repro requires it ABSENT")
    final = {}
    run_live({"mode": "classify", "payload": {}}, "r", lambda e: None, final.update)
    assert final["status"] == "failed" and "diff_sentry" in final["refusal"]["detail"]


def test_describe_exc_surfaces_the_underlying_cause():
    try:
        try:
            raise RuntimeError("BadGatewayError: all channels failed")
        except RuntimeError as cause:
            raise ValueError("Failed to produce a valid 'result' after 1 attempts") from cause
    except ValueError as exc:
        d = _describe_exc(exc)
    assert "Failed to produce a valid 'result'" in d and "caused by RuntimeError" in d and "BadGateway" in d


def test_describe_exc_without_a_cause_is_just_the_error():
    assert _describe_exc(ValueError("boom")) == "ValueError: boom"


def test_failed_dict_is_self_contained_when_diff_sentry_absent():
    # build_failed_response=None forces importing diff_sentry.response; when it is absent (replay-only) the
    # minimal literal is returned — status=failed / object=change.detection / detail preserved, so the SSE
    # can always complete. (Uses a fake bfr here to stay import-light.)
    d = _failed_dict("r", "detail here", lambda run_id, events, detail: types.SimpleNamespace(
        model_dump=lambda: {"status": "failed", "detail": detail}))
    assert d == {"status": "failed", "detail": "detail here"}


def test_failed_dict_minimal_literal_shape():
    # force the except branch by handing a bfr that raises (simulating diff_sentry absent)
    def boom(*a, **k):
        raise ModuleNotFoundError("No module named 'diff_sentry'")
    d = _failed_dict("r", "the detail", boom)
    assert d["status"] == "failed" and d["object"] == "change.detection"
    assert d["signal"] is False and d["refusal"]["detail"] == "the detail"


def test_run_live_disables_litellm_aiohttp_transport(tmp_path):
    litellm = pytest.importorskip("litellm")
    litellm.disable_aiohttp_transport = False
    run_live({"mode": "classify", "payload": {}}, "r", lambda e: None, lambda f: None,
             artifacts_dir=tmp_path, cli_run=lambda event, **k: types.SimpleNamespace(response_path=None),
             ingest=_fake_ingest(),
             build_failed_response=lambda *a, **k: types.SimpleNamespace(model_dump=lambda: {"status": "failed"}))
    assert litellm.disable_aiohttp_transport is True
