"""Taskset loading — the change payload vs judge-only reference split, and dup-id rejection."""

from __future__ import annotations

import json

import pytest

from diff_sentry_eval.taskset import demo_taskset, load_taskset


def test_demo_taskset_is_well_formed():
    tasks = demo_taskset()
    assert len(tasks) >= 2
    assert len({t.id for t in tasks}) == len(tasks)             # unique ids
    for t in tasks:
        assert t.id and t.change and t.reference                # both the planner-visible change + the reference
    # the demo covers both poles — a malicious and a benign change
    assert any("malicious" in t.reference.lower() for t in tasks)
    assert any("benign" in t.reference.lower() for t in tasks)


def test_load_taskset_reads_id_change_reference(tmp_path):
    p = tmp_path / "ts.json"
    p.write_text(json.dumps([
        {"id": "chg-1", "change": {"repo": "a/b", "files": []}, "reference": "expected verdict"},
        {"id": "chg-2", "change": {"repo": "a/c"}},             # reference optional
    ]), encoding="utf-8")
    tasks = load_taskset(str(p))
    assert [t.id for t in tasks] == ["chg-1", "chg-2"]
    assert tasks[1].reference == ""


def test_load_taskset_rejects_missing_id_bad_change_and_dup_ids(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps([{"change": {"repo": "x"}}]), encoding="utf-8")  # no id
    with pytest.raises(ValueError):
        load_taskset(str(bad))
    badchange = tmp_path / "badchange.json"
    badchange.write_text(json.dumps([{"id": "x", "change": "not-an-object"}]), encoding="utf-8")
    with pytest.raises(ValueError, match="change"):
        load_taskset(str(badchange))
    dup = tmp_path / "dup.json"
    dup.write_text(json.dumps([
        {"id": "x", "change": {}}, {"id": "x", "change": {}}]), encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        load_taskset(str(dup))


def test_example_taskset_file_is_loadable():
    # the shipped starter fixture must parse (a real change payload + a judge-only reference)
    import pathlib
    example = pathlib.Path(__file__).resolve().parents[1] / "taskset.example.json"
    tasks = load_taskset(str(example))
    assert tasks and tasks[0].change.get("files") and tasks[0].reference
