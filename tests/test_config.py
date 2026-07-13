"""DetectConfig — env parsing (from_env), the classify_backend guard, and the can_emit property.

The developer's shell may carry ambient `DS_*` vars; every test scrubs the full set first so a real
environment can't flip a default under the test.
"""

from __future__ import annotations

import pytest

from diff_sentry.config import DetectConfig

# Every DS_* var from_env reads — cleared before each test so ambient env can't leak in.
_DS_ENV = (
    "DS_ROOT_LM", "DS_SUB_LM", "DS_BASE_URL", "DS_API_KEY", "DS_CLASSIFIER_LM", "DS_PLANNER_MAX_TOKENS",
    "DS_CLASSIFY_BACKEND", "DS_CLASSIFIER_BASE_URL", "DS_CLASSIFIER_API_KEY", "DS_CLASSIFIER_SYSTEM_PROMPT",
    "DS_CLASSIFIER_TIMEOUT", "DS_CLASSIFIER_MAX_TOKENS", "DS_CLASSIFIER_TRANSIENT_RETRIES",
    "DS_CLASSIFIER_CIRCUIT_BREAK", "DS_INTERPRETER", "DS_OBSERVE", "DS_ADAPTER", "DS_MAX_ITERATIONS",
    "DS_MAX_LLM_CALLS", "DS_MAX_OUTPUT_CHARS", "DS_ENABLE_FETCH", "DS_FETCH_TIMEOUT", "DS_FETCH_MAX_BYTES",
    "DS_FETCH_ALLOW_CIDRS", "DS_ENABLE_SKILLS", "DS_SIEM_WEBHOOK_URL", "DS_SIEM_TOKEN", "DS_EMIT_ON",
)


@pytest.fixture
def clean_env(monkeypatch):
    for name in _DS_ENV:
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


def test_from_env_requires_planner_and_analyst(clean_env):
    with pytest.raises(ValueError, match="DS_ROOT_LM"):
        DetectConfig.from_env()
    clean_env.setenv("DS_ROOT_LM", "planner-x")            # analyst still missing
    with pytest.raises(ValueError):
        DetectConfig.from_env()


def test_from_env_defaults(clean_env):
    clean_env.setenv("DS_ROOT_LM", "planner-x")
    clean_env.setenv("DS_SUB_LM", "analyst-x")
    cfg = DetectConfig.from_env()
    assert cfg.main_model == "planner-x" and cfg.sub_model == "analyst-x"
    assert cfg.classifier_model == "analyst-x"             # classifier defaults to the analyst
    assert cfg.classify_backend == "self"
    assert cfg.interpreter == "pyodide"                    # read-not-execute default
    assert cfg.enable_fetch is False                       # fetch off by default (exfil surface)
    assert cfg.emit_on == ("suspicious", "malicious")
    assert cfg.fetch_allow_cidrs == ()
    assert cfg.enable_skills is True


def test_from_env_parses_knobs(clean_env):
    clean_env.setenv("DS_ROOT_LM", "p")
    clean_env.setenv("DS_SUB_LM", "a")
    clean_env.setenv("DS_CLASSIFIER_LM", "dedicated-classifier")
    clean_env.setenv("DS_EMIT_ON", "malicious")
    clean_env.setenv("DS_ENABLE_FETCH", "true")
    clean_env.setenv("DS_FETCH_ALLOW_CIDRS", "10.0.0.0/8, 192.168.0.0/16")
    clean_env.setenv("DS_MAX_ITERATIONS", "40")
    clean_env.setenv("DS_ENABLE_SKILLS", "no")
    cfg = DetectConfig.from_env()
    assert cfg.classifier_model == "dedicated-classifier"  # explicit override wins over the analyst
    assert cfg.emit_on == ("malicious",)
    assert cfg.enable_fetch is True
    assert cfg.fetch_allow_cidrs == ("10.0.0.0/8", "192.168.0.0/16")
    assert cfg.max_iterations == 40
    assert cfg.enable_skills is False


def test_post_init_rejects_unwired_backend():
    with pytest.raises(ValueError, match="classify_backend"):
        DetectConfig(main_model="x", sub_model="x", classify_backend="anthropic")


def test_can_emit_reflects_webhook():
    assert DetectConfig(main_model="x", sub_model="x").can_emit is False
    assert DetectConfig(main_model="x", sub_model="x",
                        siem_webhook_url="https://siem.example/hook").can_emit is True
