"""The RLM task declaration — MISSION frame, skills wiring, tools, and a real dspy.RLM build.

Uses configure_dummy (DummyLM + mock interpreter): builds through the real dspy.RLM constructor with no
network/Deno. No forward() call (that needs a live model + classifier endpoint)."""

from __future__ import annotations

from diff_sentry.config import DetectConfig
from diff_sentry.detect import INSTRUCTIONS, ClassifyChange
from diff_sentry.schema import ChangeVerdict


def _cfg():
    return DetectConfig(main_model="x", sub_model="x", interpreter="mock", classifier_model="x")


def test_declaration_fields():
    assert ClassifyChange.signature == "event: str -> verdict: ChangeVerdict"
    assert ClassifyChange.output_field == "verdict"
    assert ClassifyChange.output_model is ChangeVerdict


def test_instructions_carry_mission_and_contract():
    assert "DETECTOR" in INSTRUCTIONS
    assert "UNTRUSTED" in INSTRUCTIONS
    assert "PROMPT-INJECTION ATTACK" in INSTRUCTIONS
    assert "You NEVER execute" in INSTRUCTIONS
    assert "cannot add, hide, or invent" in INSTRUCTIONS
    assert "JUDGEMENT only" in INSTRUCTIONS


def test_instructions_inject_skill_manifest(configure_dummy):
    task = ClassifyChange(config=_cfg())
    assert "<available_skills>" in task.instructions
    assert "triage-a-change" in task.instructions
    assert "prompt-injection-catalog" in task.instructions


def test_tools_wired(configure_dummy):
    task = ClassifyChange(config=_cfg())
    names = {getattr(t, "__name__", getattr(t, "name", "")) for t in task.tools}
    assert "scan_indicators" in names             # the deterministic detector tool (registered name)
    assert "deep_classify" in names               # the second-stage seam
    assert "read_skill" in names
    # fetch is OFF by default (exfil surface) — no fetch_url unless enable_fetch
    assert "fetch_url" not in names


def test_prompt_tool_names_match_registered_tools(configure_dummy):
    """Every consumer tool the prompt tells the planner to call must be REGISTERED under that exact name.
    A mismatch is a NameError in the sandbox that only the live forward path would otherwise surface
    (regresses the scan_indicators/scan_indicators_tool drift)."""
    task = ClassifyChange(config=_cfg())
    names = {getattr(t, "__name__", getattr(t, "name", "")) for t in task.tools}
    for name in ("scan_indicators", "deep_classify", "read_skill"):
        assert name in names, f"{name!r} is not a registered tool name"
        assert f"`{name}(" in INSTRUCTIONS or f"`{name}`" in INSTRUCTIONS, \
            f"{name!r} is registered but the prompt never tells the planner to call it"


def test_fetch_tool_wired_when_enabled(configure_dummy):
    cfg = DetectConfig(main_model="x", sub_model="x", interpreter="mock", classifier_model="x",
                       enable_fetch=True)
    task = ClassifyChange(config=cfg)
    names = {getattr(t, "__name__", getattr(t, "name", "")) for t in task.tools}
    assert "fetch_url" in names


def test_build_rlm_resolves_custom_output_type(configure_dummy):
    """ChangeVerdict must resolve via dspy custom_types, not call-stack walking (rlm-kit invariant)."""
    import dspy

    task = ClassifyChange(config=_cfg())
    rlm = task._build_rlm()
    assert isinstance(rlm, dspy.RLM)
    assert "verdict" in rlm.signature.output_fields
    task._teardown_interpreter()


def test_extra_tools_are_wired(configure_dummy):
    def my_tool(x):
        return "ok"

    task = ClassifyChange(config=_cfg(), extra_tools=[my_tool])
    names = {getattr(t, "__name__", getattr(t, "name", "")) for t in task.tools}
    assert "my_tool" in names


def test_setup_passes_max_output_chars_through():
    from rlm_kit import get_config

    from diff_sentry.detect import setup

    setup(DetectConfig(main_model="x", sub_model="x", interpreter="mock", classifier_model="x",
                       max_output_chars=25_000))
    assert get_config().max_output_chars == 25_000


def test_from_env_reads_roles_and_knobs(monkeypatch):
    monkeypatch.setenv("DS_ROOT_LM", "planner-x")
    monkeypatch.setenv("DS_SUB_LM", "analyst-x")
    monkeypatch.setenv("DS_MAX_OUTPUT_CHARS", "42000")
    cfg = DetectConfig.from_env()
    assert cfg.main_model == "planner-x" and cfg.sub_model == "analyst-x"
    assert cfg.max_output_chars == 42_000
    assert cfg.classifier_model == "analyst-x"   # defaults to the analyst when unset
