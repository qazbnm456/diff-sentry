"""Subscription-path wiring: the classifier-hazard guard (config) + the sentinel router (detect).

Runs WITHOUT the `[subscription]` extra: the hazard tests touch only dspy-free config.from_env; the
router test exercises only the NON-sentinel branch (which never imports the vendored adapter). The
sentinel branch, which imports claude-agent-sdk, is left to a live run / an env that has the extra.
"""

from __future__ import annotations

import pytest

from diff_sentry import DetectConfig
from tests.test_config import _DS_ENV  # the FULL scrub list — ambient DS_* env must not flip a test

_SUBSCRIPTION_BASE = {
    "DS_ROOT_LM": "claude-agent-sdk/claude-sonnet-5",
    "DS_SUB_LM": "claude-agent-sdk/claude-fable-5",
}


def _clearenv(monkeypatch):
    for k in _DS_ENV:
        monkeypatch.delenv(k, raising=False)


def test_from_env_classifier_hazard_inherited(monkeypatch):
    """Subscription analyst + unset DS_CLASSIFIER_LM → the classifier would inherit the sentinel → raise."""
    _clearenv(monkeypatch)
    for k, v in _SUBSCRIPTION_BASE.items():
        monkeypatch.setenv(k, v)
    with pytest.raises(ValueError) as exc:
        DetectConfig.from_env()
    assert "DS_CLASSIFIER_LM" in str(exc.value)
    assert "subscription" in str(exc.value).lower()


def test_from_env_classifier_hazard_explicit(monkeypatch):
    """Explicit DS_CLASSIFIER_LM set to a sentinel is also rejected (the classifier is never the subscription)."""
    _clearenv(monkeypatch)
    for k, v in _SUBSCRIPTION_BASE.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("DS_CLASSIFIER_LM", "claude-agent-sdk/claude-opus-4-8")
    with pytest.raises(ValueError):
        DetectConfig.from_env()


def test_from_env_subscription_ok_with_real_classifier(monkeypatch):
    """Subscription planner/analyst + a REAL classifier id → valid; sentinel survives on the two roles."""
    _clearenv(monkeypatch)
    for k, v in _SUBSCRIPTION_BASE.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("DS_CLASSIFIER_LM", "qwen/qwen3-next-80b")
    cfg = DetectConfig.from_env()
    assert cfg.main_model == "claude-agent-sdk/claude-sonnet-5"
    assert cfg.sub_model == "claude-agent-sdk/claude-fable-5"
    assert cfg.classifier_model == "qwen/qwen3-next-80b"


def test_from_env_planner_only_subscription_ok(monkeypatch):
    """Sentinel planner + REAL analyst, DS_CLASSIFIER_LM unset → valid: the classifier inherits a real id."""
    _clearenv(monkeypatch)
    monkeypatch.setenv("DS_ROOT_LM", "claude-agent-sdk/claude-sonnet-5")
    monkeypatch.setenv("DS_SUB_LM", "qwen/qwen3-next-80b")
    cfg = DetectConfig.from_env()
    assert cfg.main_model == "claude-agent-sdk/claude-sonnet-5"
    assert cfg.classifier_model == "qwen/qwen3-next-80b"


def test_from_env_proxy_path_unchanged(monkeypatch):
    """No sentinel anywhere → the classifier still defaults to the analyst (byte-identical to before)."""
    _clearenv(monkeypatch)
    monkeypatch.setenv("DS_ROOT_LM", "openai/gpt-4o")
    monkeypatch.setenv("DS_SUB_LM", "openai/gpt-4o")
    cfg = DetectConfig.from_env()
    assert cfg.classifier_model == "openai/gpt-4o"


def test_maybe_subscription_lm_missing_extra_is_actionable(monkeypatch):
    """Sentinel + missing claude-agent-sdk → an error that NAMES the fix, not a bare import crash.

    (The real-world path: `uv lock` records the extra but only `uv sync --extra subscription`
    installs it — a sentinel-configured run in a never-synced env must say so.)
    """
    pytest.importorskip("dspy")  # importing detect pulls dspy+rlm_kit, present in the dev env
    import sys

    from diff_sentry.detect import _maybe_subscription_lm

    monkeypatch.delitem(sys.modules, "diff_sentry.claude_agent_lm", raising=False)
    monkeypatch.setitem(sys.modules, "claude_agent_sdk", None)  # import → ModuleNotFoundError
    with pytest.raises(ModuleNotFoundError) as exc:
        _maybe_subscription_lm("claude-agent-sdk/claude-sonnet-5")
    assert "uv sync --extra subscription" in str(exc.value)


def test_maybe_subscription_lm_non_sentinel_returns_none():
    """The router returns None for a non-sentinel model WITHOUT importing the vendored adapter/SDK."""
    pytest.importorskip("dspy")  # importing detect pulls dspy+rlm_kit, present in the dev env
    import sys

    from diff_sentry.detect import _maybe_subscription_lm

    assert _maybe_subscription_lm("openai/gpt-4o") is None
    assert "diff_sentry.claude_agent_lm" not in sys.modules
