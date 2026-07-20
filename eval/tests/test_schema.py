"""The report shapes carry measurements, never a reward — no composite/total field anywhere."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from diff_sentry_eval.schema import CATEGORIES, EvalReport, EvalRow, EvalScore


def test_categories_are_the_four_atlas_codes():
    assert CATEGORIES == ("TF", "TA", "TG", "PA")


def test_eval_score_has_no_composite_field_and_clamps_range():
    assert EvalScore(TF=8.0, TA=5.0, TG=6.0, PA=7.0).TF == 8.0   # constructs from four category scores
    fields = set(EvalScore.model_fields)
    assert fields == {"TF", "TA", "TG", "PA", "notes"}       # no total / composite / reward
    with pytest.raises(ValidationError):
        EvalScore(TF=11.0, TA=5, TG=5, PA=5)                  # > 10 rejected
    with pytest.raises(ValidationError):
        EvalScore(TF=-1.0, TA=5, TG=5, PA=5)                  # < 0 rejected


def test_eval_report_carries_means_not_a_composite():
    rep = EvalReport(taskset="demo", n=2, n_unscored=1, means={"TF": 7.0, "TA": 6.0, "TG": 5.0, "PA": 8.0})
    assert rep.primary == "TF"
    assert set(rep.means) == set(CATEGORIES)
    assert "total" not in EvalReport.model_fields and "reward" not in EvalReport.model_fields
    assert "score" not in EvalReport.model_fields               # only per-category means, no aggregate score


def test_eval_row_defaults_to_unscored_clean():
    row = EvalRow(task_id="t", run_id="t")
    assert row.score is None and row.unscored is False
    assert row.verdict == "" and row.signal is False and row.cited_unknown == 0
