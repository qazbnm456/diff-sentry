"""Host-side ingestion — turn a GitHub PR/issue into the normalized change event diff-sentry classifies.

This is PLUMBING that runs OUTSIDE the RLM (the planner never talks to GitHub). It shapes a webhook-style
payload dict — `{repo, kind, number, author, title, body, files:[{filename,status,additions,deletions,
patch}]}` — that `normalize.normalize_event` renders into the untrusted `event: str`. The GitHub transport
is injectable (`api`) so this is testable offline; the default shells out to the `gh` CLI host-side.

Pure stdlib; no dspy. `event_from_payload` is the offline path (a payload you already have).
"""

from __future__ import annotations

import json
from typing import Any, Callable, Optional

# An `api` maps a `gh api <path>` argument to parsed JSON. Injectable for tests; default uses `gh`.
GhApi = Callable[[str], Any]


def _gh_cli_api(timeout: float = 30.0) -> GhApi:
    def call(path: str) -> Any:
        import subprocess  # host-side only; NEVER reached from inside the RLM

        out = subprocess.run(["gh", "api", path], capture_output=True, text=True, timeout=timeout, check=True)
        return json.loads(out.stdout)

    return call


def event_from_payload(payload: dict) -> dict:
    """Normalize a webhook-style payload we already hold into the canonical change-event dict. Tolerant of
    missing keys — every field defaults to empty so a partial payload still classifies."""
    files = []
    for f in payload.get("files") or []:
        files.append({
            "filename": f.get("filename", ""),
            "status": f.get("status", ""),
            "additions": f.get("additions", 0),
            "deletions": f.get("deletions", 0),
            "patch": f.get("patch", ""),
        })
    return {
        "repo": payload.get("repo", ""),
        "kind": payload.get("kind", "pull_request"),
        "number": payload.get("number"),
        "author": payload.get("author", ""),
        "title": payload.get("title", ""),
        "body": payload.get("body", ""),
        "files": files,
    }


def pr_event(repo: str, number: int, *, api: Optional[GhApi] = None) -> dict:
    """Fetch a PR + its files from GitHub (host-side) into a change-event dict. `api` is injectable."""
    call = api or _gh_cli_api()
    pr = call(f"repos/{repo}/pulls/{number}")
    files = call(f"repos/{repo}/pulls/{number}/files")
    return {
        "repo": repo,
        "kind": "pull_request",
        "number": number,
        "author": (pr.get("user") or {}).get("login", ""),
        "title": pr.get("title", ""),
        "body": pr.get("body", "") or "",
        "files": [
            {"filename": f.get("filename", ""), "status": f.get("status", ""),
             "additions": f.get("additions", 0), "deletions": f.get("deletions", 0),
             "patch": f.get("patch", "") or ""}
            for f in (files or [])
        ],
    }


def issue_event(repo: str, number: int, *, api: Optional[GhApi] = None) -> dict:
    """Fetch an issue from GitHub (host-side) into a change-event dict — the issue body is the untrusted
    content (the hackerbot-claw prompt-injection issues came in this shape)."""
    call = api or _gh_cli_api()
    issue = call(f"repos/{repo}/issues/{number}")
    return {
        "repo": repo,
        "kind": "issue",
        "number": number,
        "author": (issue.get("user") or {}).get("login", ""),
        "title": issue.get("title", ""),
        "body": issue.get("body", "") or "",
        "files": [],
    }
