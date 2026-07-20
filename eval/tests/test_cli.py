"""The CLI: `score` over a tmp trace with the stub judge; the exit-code contract; `run`'s lazy-diff_sentry
wiring, all offline. Traces are written through the REAL TraceRecorder (conftest.record_run)."""

from __future__ import annotations

import json
from types import SimpleNamespace

from conftest import MALICIOUS_CHANGE, record_run

from diff_sentry_eval.cli import main


def test_score_writes_report_over_tmp_trace(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("DSEVAL_MODEL", raising=False)      # no live judge configured -> the stub
    record_run(tmp_path, run_id="demo-malicious-ci")
    out = tmp_path / "eval"
    code = main(["score", str(tmp_path / "*.jsonl"), "demo", "--out", str(out)])
    assert code == 0
    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert report["n"] == 1 and report["n_unscored"] == 0
    assert report["judge_model"] == "stub" and report["primary"] == "TF"
    assert report["means"] == {"TF": 5.0, "TA": 5.0, "TG": 5.0, "PA": 5.0}
    assert report["rows"][0]["task_id"] == "demo-malicious-ci"
    assert report["rows"][0]["verdict"] == "malicious" and report["rows"][0]["signal"] is True
    assert "reward" not in json.dumps(report).lower()
    printed = capsys.readouterr().out
    assert "demo-malicious-ci" in printed and "MEAN" in printed    # the terminal scorecard rendered


def test_score_skips_runs_with_no_matching_task(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("DSEVAL_MODEL", raising=False)
    record_run(tmp_path, run_id="not-in-taskset")
    code = main(["score", str(tmp_path / "*.jsonl"), "demo", "--out", str(tmp_path / "eval")])
    assert code == 1                                       # nothing scored
    assert "skipped 1 run(s)" in capsys.readouterr().out


def test_score_handles_no_trace_files(tmp_path, monkeypatch):
    monkeypatch.delenv("DSEVAL_MODEL", raising=False)
    code = main(["score", str(tmp_path / "nothing-*.jsonl"), "demo", "--out", str(tmp_path / "eval")])
    assert code == 1


def test_score_exits_nonzero_when_the_only_run_is_unscored(tmp_path, monkeypatch):
    # a finalized run with no usable verdict pairs to a task but can't be scored → n_unscored == n → exit 1
    from conftest import _EMPTY_VERDICT
    monkeypatch.delenv("DSEVAL_MODEL", raising=False)
    record_run(tmp_path, run_id="demo-benign-docs", verdict=_EMPTY_VERDICT)
    out = tmp_path / "eval"
    code = main(["score", str(tmp_path / "*.jsonl"), "demo", "--out", str(out)])
    assert code == 1
    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert report["n"] == 1 and report["n_unscored"] == 1 and report["means"] == {}


def test_stub_flag_forces_offline_judge_even_with_env(tmp_path, monkeypatch):
    monkeypatch.setenv("DSEVAL_MODEL", "some-live-judge")
    record_run(tmp_path, run_id="demo-malicious-ci")
    out = tmp_path / "eval"
    code = main(["score", str(tmp_path / "*.jsonl"), "demo", "--out", str(out), "--stub"])
    assert code == 0
    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert report["judge_model"] == "stub"                 # the env judge was never touched


def test_run_drives_diff_sentry_lazily_then_scores(tmp_path, monkeypatch):
    """`run` wiring, offline: `diff_sentry.cli.run` is monkeypatched (the in-function lazy import resolves
    the patched attribute at call time) to replay a recorded trace per task — run_id = task id, one run per
    demo task."""
    monkeypatch.delenv("DSEVAL_MODEL", raising=False)
    import diff_sentry.cli as ds_cli

    driven: list = []

    def fake_run(event, *, run_id, outdir, emit=True, **kwargs):
        driven.append((run_id, outdir, emit))
        events = record_run(tmp_path, run_id=run_id, change=MALICIOUS_CHANGE)
        return SimpleNamespace(events=events)

    monkeypatch.setattr(ds_cli, "run", fake_run)
    out = tmp_path / "eval"
    code = main(["run", "demo", "--out", str(out)])
    assert code == 0
    assert len(driven) == 2                                # demo has 2 tasks; one solve per task
    assert all(outdir == str(out) and emit is False for _, outdir, emit in driven)  # eval never emits
    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert report["n"] == 2 and report["n_unscored"] == 0
