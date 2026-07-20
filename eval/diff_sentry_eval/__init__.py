"""diff-sentry-eval — an OFFLINE, reward-free MEASUREMENT harness for diff-sentry runs.

The boundary this package exists to keep: **it measures; it never rewards.** It is a one-way reader of
diff-sentry's trace + assembled-verdict contract — the data flows trace → judge → report (a terminal
scorecard), and the scores are read by a human, a CI gate, or a leaderboard render. They are NEVER

- composed into a single weighted reward R(tau) (the report carries per-category means only),
- written back into a trace, a dataset, or a diff-sentry export (`rl_export` stays reward-free), or
- imported BY diff-sentry (`diff_sentry` never imports `diff_sentry_eval`; test-enforced one-way dep).

This mirrors the ATLAS paper's own split: training rewards and the fixed external evaluation judge are
different judges on purpose — folding the eval score into the rollout core would bias the very measure it
provides. It also holds diff-sentry's read-never-execute invariant: the judge assesses the classification
STATICALLY, it never runs/builds the change. If you find yourself importing `diff_sentry_eval` from the
rollout core, stop: that is the violation.
"""

from __future__ import annotations

from .judge import EvalJudgeConfig, JudgeVerdict, make_eval_judge, stub_judge
from .schema import CATEGORIES, EvalReport, EvalRow, EvalScore
from .score import aggregate, build_judge_inputs, score_run
from .taskset import EvalTask, demo_taskset, load_taskset

__version__ = "0.1.0"

__all__ = [
    "CATEGORIES",
    "EvalJudgeConfig",
    "EvalReport",
    "EvalRow",
    "EvalScore",
    "EvalTask",
    "JudgeVerdict",
    "aggregate",
    "build_judge_inputs",
    "demo_taskset",
    "load_taskset",
    "make_eval_judge",
    "score_run",
    "stub_judge",
]
