"""cli.run orchestration — the 283-line entry point, driven OFFLINE by stubbing the RLM.

`run()`'s job is orchestration, not classification: reset the stale trace → detect → load the trace →
assemble → build the response → write it → emit host-side. We stub `detect_from_event` (`cli.run`
resolves it as a module global at call time, so `monkeypatch.setattr(cli, ...)` with
an `async def` fake is the right seam — no production-signature pollution). The fake WRITES a realistic
trace (baseline in run_start meta + a scan_indicators tool_call + a result) so run()'s REAL assemble →
response → emit path runs on genuine JSONL. The crash test's fake writes the trace and THEN raises, so
the failed-path emitter has evidence to fire on.
"""

from __future__ import annotations

from types import SimpleNamespace

from rlm_kit import TraceRecorder, record_tool_call

from diff_sentry import cli
from diff_sentry.config import DetectConfig
from diff_sentry.indicators import scan_indicators
from diff_sentry.normalize import event_metadata, normalize_event, raw_content
from diff_sentry.schema import ChangeVerdict
from tests.conftest import BENIGN_EVENT, MALICIOUS_EVENT, MALICIOUS_VERDICT


def _cfg(**kw) -> DetectConfig:
    return DetectConfig(main_model="x", sub_model="x", classifier_model="x", interpreter="mock",
                        siem_webhook_url="https://siem.example/hook", **kw)


def _write_trace(trace_path, run_id, event, *, verdict=None, with_result=True):
    """Lay down a realistic trace the way detect_from_event would, so run()'s read path is genuine.

    Mirrors conftest.make_trace, but writes to the exact `trace_path` run() passes (the fixture owns its
    own tmp path), so this must build the meta inline."""
    baseline = [h.model_dump() for h in scan_indicators(raw_content(event))]
    ms = event_metadata(event)
    meta = {
        "event": normalize_event(event), "instructions": "…",
        "source": {k: ms.get(k) for k in ("repo", "kind", "number", "author", "title",
                                           "file_count", "content_sha256")},
        "baseline_indicators": baseline, "emit_on": ["suspicious", "malicious"],
        "planner": "p", "analyst": "a", "classifier": "c", "max_iterations": 25, "max_llm_calls": 8,
    }
    with TraceRecorder(trace_path, run_id=run_id, meta=meta) as rec:
        region_hits = scan_indicators(raw_content(event))
        record_tool_call("scan_indicators", args={"region": "diff"}, ok=True,
                         hits=[h.model_dump() for h in region_hits], n=len(region_hits))
        rec.record_main_trajectory(SimpleNamespace(trajectory=[], final_reasoning="done"))
        if with_result:
            rec.record_result(verdict if verdict is not None else MALICIOUS_VERDICT)


def _classify_fake(event_arg, verdict=None):
    async def _fake(event, config, *, trace_path=None, run_id="change", on_event=None, extra_tools=()):
        _write_trace(trace_path, run_id, event_arg, verdict=verdict, with_result=True)
        return ChangeVerdict.from_payload(verdict or MALICIOUS_VERDICT)

    return _fake


def _crash_fake(event_arg):
    async def _fake(event, config, *, trace_path=None, run_id="change", on_event=None, extra_tools=()):
        # Write the trace (baseline evidence lands) and THEN crash — the failed-path emitter needs the
        # baseline in the trace to fire, exactly as a real run that dies AFTER the host-side scan would.
        _write_trace(trace_path, run_id, event_arg, with_result=False)
        raise RuntimeError("planner exploded mid-run")

    return _fake


def test_run_writes_response_and_emits(tmp_path, monkeypatch):
    """Happy path: response written, status classified, the host-side emitter POSTs the signal, and a
    stale trace from a prior run is dropped first (_reset_trace)."""
    outdir = tmp_path / "output"
    stale = outdir / "traces" / "pr-7.jsonl"
    stale.parent.mkdir(parents=True)
    # A stale event for THIS run_id — load_events would keep it (it filters on run_id), so it only
    # disappears if _reset_trace actually removes the file. This makes the assertion below able to fail.
    stale.write_text('{"schema": "rlm-kit/trace/v1", "run_id": "pr-7", "step_id": 0, "ts": 0, '
                     '"type": "stale", "payload": {"stale": "garbage from a previous run"}}\n')
    monkeypatch.setattr(cli, "detect_from_event", _classify_fake(MALICIOUS_EVENT))
    sent = {}

    def poster(url, headers, payload):
        sent["verdict"] = payload["verdict"]
        return 202

    arts = cli.run(MALICIOUS_EVENT, run_id="pr-7", outdir=str(outdir), config=_cfg(), poster=poster)

    assert arts.status == "classified"
    assert (outdir / "responses" / "pr-7.json").exists()
    assert arts.assembled.verdict == "malicious" and arts.assembled.signal is True
    assert arts.emit is not None and arts.emit.emitted and arts.emit.status_code == 202
    assert sent["verdict"] == "malicious"
    # the stale trace was reset — only the fake's events remain
    assert all("stale" not in e.get("payload", {}) for e in arts.events)


def test_failed_run_still_writes_and_emits_on_evidence(tmp_path, monkeypatch):
    """A crash AFTER the host-side baseline scan still writes an informative response and STILL emits,
    because a high/critical baseline indicator forces the signal on the failed path (MF3 on the crash path)."""
    outdir = tmp_path / "output"
    monkeypatch.setattr(cli, "detect_from_event", _crash_fake(MALICIOUS_EVENT))
    sent = {}

    def poster(url, headers, payload):
        sent["payload"] = payload
        return 202

    arts = cli.run(MALICIOUS_EVENT, run_id="pr-7", outdir=str(outdir), config=_cfg(), poster=poster)

    assert arts.status == "failed" and arts.assembled is None
    assert (outdir / "responses" / "pr-7.json").exists()
    assert arts.emit is not None and arts.emit.emitted, "a high/critical baseline must emit on the crash path"
    # a failed run carries no verdict, but the deterministic evidence still reaches the SIEM
    assert sent["payload"]["verdict"] is None
    assert sent["payload"]["max_indicator_severity"] == "critical"
    assert sent["payload"]["indicators"], "the baseline indicators must ride the crash-path signal"


def test_failed_run_on_benign_evidence_does_not_emit(tmp_path, monkeypatch):
    """A crash with only sub-floor evidence (a benign change) must NOT emit — the floor gates the signal."""
    outdir = tmp_path / "output"
    monkeypatch.setattr(cli, "detect_from_event", _crash_fake(BENIGN_EVENT))
    arts = cli.run(BENIGN_EVENT, run_id="pr-8", outdir=str(outdir), config=_cfg(), poster=lambda *a: 202)
    assert arts.status == "failed"
    assert arts.emit is not None and not arts.emit.emitted and arts.emit.skipped_reason == "no_signal"


def test_no_emit_flag_skips_emitter(tmp_path, monkeypatch):
    """emit=False never touches the poster and leaves RunArtifacts.emit as None."""
    outdir = tmp_path / "output"
    monkeypatch.setattr(cli, "detect_from_event", _classify_fake(MALICIOUS_EVENT))
    called = {"n": 0}

    def poster(*a):
        called["n"] += 1
        return 202

    arts = cli.run(MALICIOUS_EVENT, run_id="pr-7", outdir=str(outdir), config=_cfg(),
                   emit=False, poster=poster)
    assert arts.status == "classified" and arts.emit is None and called["n"] == 0


def test_cmd_render_and_export_offline(tmp_path, make_trace, capsys):
    """The offline subcommands via build_parser: `render` re-derives a response from a trace, `export`
    emits a reward-free bundle. Both run with no model/network."""
    trace = make_trace(run_id="pr-7")

    rc = cli._cmd_render(SimpleNamespace(trace=trace, run_id="pr-7", out=None))
    assert rc == 0
    assert '"verdict": "malicious"' in capsys.readouterr().out

    out_json = tmp_path / "ds.json"
    args = cli.build_parser().parse_args(["export", trace, str(out_json)])
    rc = args.func(args)
    assert rc == 0 and out_json.exists()
    import json
    bundle = json.loads(out_json.read_text())
    assert all(a.get("reward") is None for a in bundle["actions"])
    assert bundle["labels"]["pr-7"]["signal"] is True
