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


def test_export_carries_the_reward_free_rubric_signal(make_trace):
    """The ATLAS rubric surface rides beside the trajectory as LABELS — the fixed 4-category skeleton +
    deterministic per-criterion facts, never a score."""
    bundle = export_dataset(load_runs(make_trace(run_id="pr-7")))
    sig = bundle["rubric_signal"]["pr-7"]
    assert {c["category"] for c in sig["rubric"]} == {"TF", "TA", "TG", "PA"}
    assert {f["criterion"] for f in sig["criteria_facts"]} == {c["name"] for c in sig["rubric"]}
    for f in sig["criteria_facts"]:
        assert "score" not in f and "met" not in f and "reward" not in f   # facts only, never a reward


def test_run_metrics_carries_effort_fields(make_trace):
    """The reward-free effort metrics a trainer shapes into a reward — the fields must be present and the
    deterministic ones correct (a 2-step trace is far below the 25-iteration cap, no circuit breaks)."""
    runs = load_runs(make_trace(run_id="pr-11"))
    metrics = export_dataset(runs)["metrics"]["pr-11"]
    for key in ("steps", "scan_calls", "deep_classify_calls", "deep_classify_circuit_breaks",
                "analyst_calls", "fetches", "skill_reads", "elapsed_s", "hit_iteration_cap"):
        assert key in metrics, key
    assert metrics["hit_iteration_cap"] is False
    assert metrics["deep_classify_circuit_breaks"] == 0
    assert metrics["scan_calls"] >= 1
    assert metrics["skill_reads"] >= 1
