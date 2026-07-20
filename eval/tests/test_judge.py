"""The judge validator + the offline stub — strict 0-10 parsing, deterministic stub, no creds."""

from __future__ import annotations

from diff_sentry_eval.judge import (
    EVAL_TEMPLATE,
    PROMPT_VERSION,
    EvalJudgeConfig,
    make_eval_judge,
    parse_eval_json,
    stub_judge,
)


def test_parse_eval_json_accepts_all_four_and_clamps():
    v = parse_eval_json('{"scores": {"TF": 8, "TA": 5.5, "TG": 12, "PA": -3}, "notes": "ok"}')
    assert v.ok
    assert v.scores == {"TF": 8.0, "TA": 5.5, "TG": 10.0, "PA": 0.0}   # clamped to [0,10]
    assert v.notes == "ok"


def test_parse_eval_json_rejects_off_schema():
    assert not parse_eval_json("not json").ok
    assert not parse_eval_json('{"scores": {"TF": 5}}').ok             # missing TA/TG/PA
    assert not parse_eval_json('{"scores": {"TF": true, "TA": 5, "TG": 5, "PA": 5}}').ok  # bool ≠ number
    assert not parse_eval_json('{"notes": "no scores object"}').ok


def test_parse_eval_json_tolerates_a_code_fence():
    v = parse_eval_json('```json\n{"scores": {"TF": 4, "TA": 4, "TG": 4, "PA": 4}}\n```')
    assert v.ok and v.scores["TF"] == 4.0


def test_stub_judge_is_deterministic_and_marks_itself():
    verdict = stub_judge({"anything": 1})
    assert verdict.ok and verdict.score is not None
    assert (verdict.score.TF, verdict.score.TA, verdict.score.TG, verdict.score.PA) == (5.0, 5.0, 5.0, 5.0)
    assert "not a model verdict" in verdict.score.notes


def test_make_eval_judge_with_an_injected_chat_fn_scores_and_survives_garbage():
    inputs = {"change": "c", "reference": "r", "verdict": "malicious", "indicators": "i",
              "execution_summary": "e", "total_rounds": 3}
    good = make_eval_judge(chat_fn=lambda p: '{"scores": {"TF": 7, "TA": 6, "TG": 6, "PA": 8}}')
    v = good(inputs)
    assert v.ok and v.score.TF == 7.0
    # a judge that never returns valid JSON → unscored, never a fake score
    bad = make_eval_judge(chat_fn=lambda p: "I refuse to answer in JSON")
    assert not bad(inputs).ok


def test_config_reads_dseval_env(monkeypatch):
    monkeypatch.setenv("DSEVAL_MODEL", "some/judge-model")
    monkeypatch.setenv("DSEVAL_BASE_URL", "https://judge.example")
    cfg = EvalJudgeConfig.from_env()
    assert cfg.model == "some/judge-model" and cfg.base_url == "https://judge.example"
    assert PROMPT_VERSION == "atlas-diffsentry-eval-v1"
    assert "{verdict}" in EVAL_TEMPLATE and "DO NOT run" in EVAL_TEMPLATE  # never-execute in the prompt
