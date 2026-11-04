"""The trace a `classify` run writes rebuilds the exact planner requests (rlm-harness 1.25.0).

Drives `python -m diff_sentry classify <payload>` OFFLINE through the real `cli.run` → `detect_from_event` → `setup` → `dspy.RLM` loop: only the two LMs (scripted, via `_maybe_subscription_lm`, the seam `setup` already injects through) and the interpreter (`ScriptedInterpreter`) are stand-ins. A downstream SFT builder converts these traces with `export_sft_turns(render="adapter", strict=True)`, so that call must succeed, with no `custom_types`, on a normal SUBMIT run and on one that ends in dspy's extract fallback.
"""

from __future__ import annotations

import importlib
import json

import pytest
from rlm_harness.dataset import export_sft_turns
from rlm_harness.testing import ScriptedInterpreter, call, scripted_lm, submit
from rlm_harness.trace import group_by_run, load_events

from diff_sentry import cli, detect
from diff_sentry.config import DetectConfig
from diff_sentry.normalize import raw_content
from tests.conftest import MALICIOUS_EVENT, MALICIOUS_VERDICT


def _classify(tmp_path, monkeypatch, *, steps, turns, argv=(), max_iterations=10, run_tag=None):
    """Run `classify` on MALICIOUS_EVENT written as a payload file; return the trace's events."""
    cfg = DetectConfig(main_model="planner", sub_model="analyst", classifier_model="x", interpreter="mock",
                       max_iterations=max_iterations, run_tag=run_tag)
    monkeypatch.setattr(DetectConfig, "from_env", classmethod(lambda cls: cfg))
    lms = {"planner": scripted_lm(turns), "analyst": scripted_lm([{"reasoning": "r", "verdict": "{}"}])}
    monkeypatch.setattr(detect, "_maybe_subscription_lm", lambda model: lms[model])
    # dspy lets only the thread + async task that first called `dspy.configure` call it again, and each `cli.run` is its own `asyncio.run`: rlm-harness reuses the first global config on a later task, which would keep an earlier test's scripted planner. Forget the owner so this run's `setup` configures its own.
    dspy_settings = importlib.import_module("dspy.dsp.utils.settings")
    monkeypatch.setattr(dspy_settings, "config_owner_thread_id", None)
    monkeypatch.setattr(dspy_settings, "config_owner_async_task", None)

    class _Scripted(detect.ClassifyChange):
        def __init__(self, *a, **kw):
            super().__init__(*a, interpreter=ScriptedInterpreter(steps), **kw)

    monkeypatch.setattr(detect, "ClassifyChange", _Scripted)
    # The payload carries a GitHub file's `changes` count too, which ingest ignores.
    payload = {**MALICIOUS_EVENT, "files": [{**f, "changes": f["additions"] + f["deletions"]}
                                            for f in MALICIOUS_EVENT["files"]]}
    path = tmp_path / "event.json"
    path.write_text(json.dumps(payload))
    out = tmp_path / "output"
    assert cli.main(["classify", str(path), "--run-id", "t-1", "--out", str(out), "--no-emit", *argv]) == 0
    return load_events(str(out / "traces" / "t-1.jsonl"), "t-1")


def _types(events):
    return [e["type"] for e in events]


def test_a_submit_run_exports_verified_adapter_turns(tmp_path, monkeypatch):
    events = _classify(
        tmp_path, monkeypatch,
        steps=[call("scan_indicators", region=raw_content(MALICIOUS_EVENT)), submit({"verdict": MALICIOUS_VERDICT})],
        turns=[{"reasoning": "scan", "code": "print(scan_indicators(event))"},
               {"reasoning": "submit", "code": "SUBMIT(verdict=...)"}])
    assert _types(events).count("rlm_setup") == 1 and "extract" not in _types(events)
    setup = next(e["payload"] for e in events if e["type"] == "rlm_setup")
    assert set(setup["inputs_sha256"]) == {"event"} and "run_tag" not in setup
    records = export_sft_turns(group_by_run(events), render="adapter", strict=True)
    assert [r["kind"] for r in records] == ["action", "action"]
    assert all(r["verified"] is True and r["assistant_source"] == "completion" for r in records)


def test_an_extract_fallback_run_exports_its_extract_call(tmp_path, monkeypatch):
    events = _classify(
        tmp_path, monkeypatch, max_iterations=1,
        steps=[call("scan_indicators", region=raw_content(MALICIOUS_EVENT))],
        turns=[{"reasoning": "scan", "code": "print(scan_indicators(event))"},
               {"reasoning": "out of turns", "verdict": json.dumps(MALICIOUS_VERDICT)}])
    assert "extract" in _types(events)
    records = export_sft_turns(group_by_run(events), render="adapter", strict=True)
    assert [r["kind"] for r in records] == ["action", "extract"]
    assert all(r["verified"] is True for r in records)


@pytest.mark.parametrize("argv, env, expected", [
    (["--run-tag", "teacher-b25-t0.7"], None, "teacher-b25-t0.7"),
    ([], "from-env", "from-env"),
    (["--run-tag", "flag-wins"], "from-env", "flag-wins"),
])
def test_the_run_tag_is_stamped_on_every_planner_call(tmp_path, monkeypatch, argv, env, expected):
    events = _classify(
        tmp_path, monkeypatch, argv=argv, run_tag=env,
        steps=[submit({"verdict": MALICIOUS_VERDICT})], turns=[{"reasoning": "submit", "code": "SUBMIT(...)"}])
    assert next(e["payload"] for e in events if e["type"] == "rlm_setup")["run_tag"] == expected
    records = export_sft_turns(group_by_run(events), render="adapter", strict=True)
    assert records and all(r["run_tag"] == expected for r in records)


def test_ds_run_tag_is_read_from_the_environment(monkeypatch):
    monkeypatch.setenv("DS_ROOT_LM", "p")
    monkeypatch.setenv("DS_SUB_LM", "a")
    monkeypatch.setenv("DS_RUN_TAG", "  teacher-1 ")
    assert DetectConfig.from_env().run_tag == "teacher-1"
    monkeypatch.setenv("DS_RUN_TAG", " ")
    assert DetectConfig.from_env().run_tag is None
