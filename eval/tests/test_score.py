"""Scoring a run: reconstruct judge inputs from the trace, and the three unscored paths (never-finalized,
no-usable-verdict, judge-failed) — each a reason, never a fake 0."""

from __future__ import annotations

from diff_sentry_eval.judge import make_eval_judge, stub_judge
from diff_sentry_eval.schema import EvalRow, EvalScore
from diff_sentry_eval.score import aggregate, build_judge_inputs, score_run


def test_build_judge_inputs_reconstructs_from_the_trace(scored_events, demo_task):
    inputs = build_judge_inputs(scored_events, demo_task)
    assert inputs is not None
    assert inputs["reference"] == demo_task.reference          # judge-only
    assert "ci.yml" in inputs["change"]                        # the untrusted change the planner saw (from meta)
    assert "malicious" in inputs["verdict"]                    # the assembled classification to judge
    assert "indicator" in inputs["indicators"].lower() or "-" in inputs["indicators"]
    assert "derived SIEM signal" in inputs["execution_summary"]


def test_score_run_scores_a_finalized_run(scored_events, demo_task):
    row = score_run(scored_events, demo_task, stub_judge)
    assert not row.unscored and row.score is not None
    assert row.verdict == "malicious" and row.signal is True   # deterministic facts ride alongside
    assert row.metrics["scan_calls"] == 1 and row.metrics["analyst_calls"] == 1


def test_score_run_unscored_when_never_finalized(no_result_events, demo_task):
    row = score_run(no_result_events, demo_task, stub_judge)
    assert row.unscored and row.score is None
    assert "never finalized" in row.unscored_reason


def test_score_run_unscored_when_no_usable_verdict(inconclusive_events, demo_task):
    row = score_run(inconclusive_events, demo_task, stub_judge)
    assert row.unscored and row.score is None
    assert "inconclusive" in row.unscored_reason or "no usable verdict" in row.unscored_reason
    assert build_judge_inputs(inconclusive_events, demo_task) is None   # nothing to judge


def test_score_run_unscored_when_the_judge_fails(scored_events, demo_task):
    dead = make_eval_judge(chat_fn=lambda p: "never json")
    row = score_run(scored_events, demo_task, dead)
    assert row.unscored and row.score is None                  # a failed judge is unscored, not a fake 0
    assert row.verdict == "malicious"                          # the deterministic fact still rides along


def test_aggregate_means_over_scored_only_tf_primary():
    rows = [
        EvalRow(task_id="a", run_id="a", score=EvalScore(TF=8, TA=6, TG=6, PA=8)),
        EvalRow(task_id="b", run_id="b", score=EvalScore(TF=6, TA=4, TG=4, PA=6)),
        EvalRow(task_id="c", run_id="c", unscored=True, unscored_reason="never finalized"),
    ]
    report = aggregate(rows, taskset="demo", judge_model="stub")
    assert report.n == 3 and report.n_unscored == 1              # unscored counted but excluded from means
    assert report.means["TF"] == 7.0                            # mean of 8 and 6, not diluted by the unscored
    assert report.primary == "TF"
