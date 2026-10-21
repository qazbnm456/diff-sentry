"""DetectConfig: env parsing (from_env), the classify_backend guard, and the can_emit property.

The developer's shell may carry ambient `DS_*` vars; every test scrubs the full set first so a real
environment can't flip a default under the test.
"""

from __future__ import annotations

import pytest

from diff_sentry.config import DetectConfig

# Every DS_* var from_env reads, cleared before each test so ambient env can't leak in.
_DS_ENV = (
    "DS_ROOT_LM", "DS_SUB_LM", "DS_BASE_URL", "DS_API_KEY", "DS_CLASSIFIER_LM", "DS_PLANNER_MAX_TOKENS",
    "DS_ROOT_LM_KWARGS", "DS_SUB_LM_KWARGS", "RLM_MAIN_LM_KWARGS", "RLM_SUB_LM_KWARGS",
    "DS_CLASSIFY_BACKEND", "DS_CLASSIFIER_BASE_URL", "DS_CLASSIFIER_API_KEY", "DS_CLASSIFIER_SYSTEM_PROMPT",
    "DS_CLASSIFIER_TIMEOUT", "DS_CLASSIFIER_MAX_TOKENS", "DS_CLASSIFIER_TRANSIENT_RETRIES",
    "DS_CLASSIFIER_CIRCUIT_BREAK", "DS_CLASSIFIER_LM_KWARGS", "DS_INTERPRETER", "DS_OBSERVE", "DS_ADAPTER", "DS_MAX_ITERATIONS",
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


def test_role_lm_kwargs_default_unset(clean_env):
    clean_env.setenv("DS_ROOT_LM", "p")
    clean_env.setenv("DS_SUB_LM", "a")
    clean_env.setenv("DS_SUB_LM_KWARGS", "  ")                 # blank reads as unset
    cfg = DetectConfig.from_env()
    assert cfg.planner_lm_kwargs is None and cfg.analyst_lm_kwargs is None


def test_role_lm_kwargs_parse_per_role(clean_env):
    clean_env.setenv("DS_ROOT_LM", "p")
    clean_env.setenv("DS_SUB_LM", "a")
    clean_env.setenv("DS_ROOT_LM_KWARGS", '{"extra_body": {"thinking_token_budget": 8192}}')
    cfg = DetectConfig.from_env()
    assert cfg.planner_lm_kwargs == {"extra_body": {"thinking_token_budget": 8192}}
    assert cfg.analyst_lm_kwargs is None                     # one role's parameters never reach the other


@pytest.mark.parametrize("raw", ["{not json", "[1, 2]", '"budget"'])
def test_role_lm_kwargs_malformed_names_the_variable(clean_env, raw):
    clean_env.setenv("DS_ROOT_LM", "p")
    clean_env.setenv("DS_SUB_LM", "a")
    clean_env.setenv("DS_SUB_LM_KWARGS", raw)
    with pytest.raises(ValueError, match="DS_SUB_LM_KWARGS"):
        DetectConfig.from_env()


@pytest.mark.parametrize("var", ["DS_ROOT_LM_KWARGS", "DS_SUB_LM_KWARGS"])
def test_role_lm_kwargs_kit_owned_key_fails_at_parse(clean_env, var):
    # Caught at setup() instead, every run would fail and a watcher would bury its whole queue.
    clean_env.setenv("DS_ROOT_LM", "p")
    clean_env.setenv("DS_SUB_LM", "a")
    clean_env.setenv(var, '{"timeout": 600}')
    with pytest.raises(ValueError, match=var):
        DetectConfig.from_env()


@pytest.mark.parametrize(("kit_var", "field"), [("RLM_MAIN_LM_KWARGS", "planner_lm_kwargs"),
                                                ("RLM_SUB_LM_KWARGS", "analyst_lm_kwargs")])
def test_role_lm_kwargs_read_the_kit_variable(clean_env, kit_var, field):
    # setup() builds the kit's config itself, so without this the kit's documented variable is ignored.
    clean_env.setenv("DS_ROOT_LM", "p")
    clean_env.setenv("DS_SUB_LM", "a")
    clean_env.setenv(kit_var, '{"extra_body": {"thinking_token_budget": 4096}}')
    assert getattr(DetectConfig.from_env(), field) == {"extra_body": {"thinking_token_budget": 4096}}


def test_role_lm_kwargs_alias_and_kit_variable_agree_or_refuse(clean_env):
    clean_env.setenv("DS_ROOT_LM", "p")
    clean_env.setenv("DS_SUB_LM", "a")
    clean_env.setenv("DS_ROOT_LM_KWARGS", '{"extra_body": {"thinking_token_budget": 8192}}')
    clean_env.setenv("RLM_MAIN_LM_KWARGS", '{"extra_body":{"thinking_token_budget":8192}}')  # same value
    assert DetectConfig.from_env().planner_lm_kwargs == {"extra_body": {"thinking_token_budget": 8192}}
    clean_env.setenv("RLM_MAIN_LM_KWARGS", '{"extra_body": {"thinking_token_budget": 1024}}')
    with pytest.raises(ValueError, match="DS_ROOT_LM_KWARGS and RLM_MAIN_LM_KWARGS"):
        DetectConfig.from_env()


def test_role_lm_kwargs_kit_variable_error_names_it(clean_env):
    clean_env.setenv("DS_ROOT_LM", "p")
    clean_env.setenv("DS_SUB_LM", "a")
    clean_env.setenv("RLM_SUB_LM_KWARGS", '{"model": "elsewhere"}')
    with pytest.raises(ValueError, match="RLM_SUB_LM_KWARGS"):
        DetectConfig.from_env()


def test_post_init_rejects_unwired_backend():
    with pytest.raises(ValueError, match="classify_backend"):
        DetectConfig(main_model="x", sub_model="x", classify_backend="anthropic")


def test_can_emit_reflects_webhook():
    assert DetectConfig(main_model="x", sub_model="x").can_emit is False
    assert DetectConfig(main_model="x", sub_model="x",
                        siem_webhook_url="https://siem.example/hook").can_emit is True


def test_classifier_lm_kwargs_parse_on_their_own(clean_env):
    clean_env.setenv("DS_ROOT_LM", "p")
    clean_env.setenv("DS_SUB_LM", "a")
    clean_env.setenv("DS_SUB_LM_KWARGS", '{"temperature": 0.7}')
    clean_env.setenv("DS_CLASSIFIER_LM_KWARGS", '{"temperature": 1, "extra_body": {"thinking_token_budget": 1024}}')
    cfg = DetectConfig.from_env()
    assert cfg.classifier_lm_kwargs == {"temperature": 1, "extra_body": {"thinking_token_budget": 1024}}
    assert cfg.analyst_lm_kwargs == {"temperature": 0.7}      # the analyst's parameters never reach the classifier


@pytest.mark.parametrize("key", ["model", "messages", "stream", "n", "timeout", "max_tokens", "max_completion_tokens"])
def test_classifier_lm_kwargs_refuse_what_the_classifier_settings_own(clean_env, key):
    clean_env.setenv("DS_ROOT_LM", "p")
    clean_env.setenv("DS_SUB_LM", "a")
    clean_env.setenv("DS_CLASSIFIER_LM_KWARGS", f'{{"{key}": 1}}')
    with pytest.raises(ValueError, match=f"DS_CLASSIFIER_LM_KWARGS may not set {key}"):
        DetectConfig.from_env()


def test_classifier_lm_kwargs_malformed_names_the_variable(clean_env):
    clean_env.setenv("DS_ROOT_LM", "p")
    clean_env.setenv("DS_SUB_LM", "a")
    clean_env.setenv("DS_CLASSIFIER_LM_KWARGS", "[1]")
    with pytest.raises(ValueError, match="DS_CLASSIFIER_LM_KWARGS"):
        DetectConfig.from_env()


def test_classifier_lm_kwargs_refuse_a_key_the_client_does_not_take(clean_env):
    # sent as is, it would fail every call as an endpoint error that the circuit breaker never counts
    clean_env.setenv("DS_ROOT_LM", "p")
    clean_env.setenv("DS_SUB_LM", "a")
    clean_env.setenv("DS_CLASSIFIER_LM_KWARGS", '{"temprature": 1}')
    with pytest.raises(ValueError, match="takes no temprature"):
        DetectConfig.from_env()


@pytest.mark.parametrize("raw", ['{"self": 1}', '{"extra_body": "x"}', '{"extra_body": {"max_tokens": 99999}}', '{"extra_body": {"stream": true}}'])
def test_classifier_lm_kwargs_refuse_a_way_around_the_guard(clean_env, raw):
    clean_env.setenv("DS_ROOT_LM", "p")
    clean_env.setenv("DS_SUB_LM", "a")
    clean_env.setenv("DS_CLASSIFIER_LM_KWARGS", raw)
    with pytest.raises(ValueError, match="DS_CLASSIFIER_LM_KWARGS"):
        DetectConfig.from_env()
