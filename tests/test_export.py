"""Reward-free dataset export over a real trace — labels read the ASSEMBLED (deterministic) facts."""

from __future__ import annotations

from diff_sentry.rl_export import export_dataset, load_runs


def test_export_is_reward_free_and_reads_assembled_labels(make_trace, tmp_path):
    path = make_trace(run_id="pr-7")
    runs = load_runs(path)
    bundle = export_dataset(runs)

    # every exported action carries reward=None (the stage boundary — scoring is a separate project)
    assert all(a.get("reward") is None for a in bundle["actions"])

    labels = bundle["labels"]["pr-7"]
    assert labels["verdict"] == "malicious"
    assert labels["signal"] is True
    assert labels["indicator_count"] >= 2
    assert labels["max_indicator_severity"] == "critical"

    # the second-stage classifier records split out as their own single-turn stream
    assert bundle["classifier"], "deep_classify call should appear in the classifier split"

    metrics = bundle["metrics"]["pr-7"]
    assert metrics["scan_calls"] >= 1
    assert metrics["deep_classify_calls"] >= 1


def test_labels_none_when_no_result(make_trace):
    runs = load_runs(make_trace(run_id="pr-9", with_result=False))
    labels = export_dataset(runs)["labels"]["pr-9"]
    assert labels["verdict"] == "none" and labels["signal"] is False
