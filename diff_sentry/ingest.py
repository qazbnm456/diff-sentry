"""Host-side ingestion — turn a GitHub PR/issue into the normalized change event diff-sentry classifies.

This is PLUMBING that runs OUTSIDE the RLM (the planner never talks to GitHub). It shapes a webhook-style
payload dict — `{repo, kind, number, author, title, body, files:[{filename,status,additions,deletions,
patch}], provenance:{…}}` — that `normalize.normalize_event` renders into the untrusted `event: str`. The
GitHub transport is injectable (`api`) so this is testable offline; the default shells out to `gh`.

`provenance` is host-side source/identity ENRICHMENT (author type/association, account age, commit
signatures — the "source" signals from the malicious-PR research), fetched via extra best-effort `gh api`
calls. It is DERIVED FACT, not untrusted text: `indicators.scan_provenance` turns it into deterministic
baseline hits (bot-impersonation / unsigned-commits / unknown-contributor), joining the evidence union.

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


def _age_days(created_at: str) -> Optional[int]:
    """Account age in whole days from an ISO-8601 `created_at`. Host-side only (uses the wall clock — never
    reached from the RLM/replay path, so it does not break trace determinism)."""
    try:
        from datetime import datetime, timezone

        created = datetime.fromisoformat(str(created_at).replace("Z", "+00:00"))
        return max(0, (datetime.now(timezone.utc) - created).days)
    except (ValueError, TypeError):
        return None


def _provenance(repo: str, number: Optional[int], user: Optional[dict], association: Any,
                call: GhApi, *, fetch_commits: bool) -> dict:
    """Best-effort HOST-SIDE source/provenance facts for a change — author identity/association, account
    age, and (PRs) commit signature counts, from `gh api`. Every enrichment call is guarded: a `gh` hiccup
    or a missing field just OMITS that key, never sinks the ingest. The `indicators.scan_provenance`
    detectors turn these into deterministic hits at baseline."""
    user = user if isinstance(user, dict) else {}
    login = str(user.get("login", "") or "")
    prov: dict = {"author_login": login, "author_type": str(user.get("type", "") or "")}
    if association:
        prov["author_association"] = str(association)
    if login:
        try:
            created = (call(f"users/{login}") or {}).get("created_at")
            age = _age_days(created) if created else None
            if age is not None:
                prov["author_account_age_days"] = age
        except Exception:  # noqa: BLE001 — enrichment is best-effort; a failed lookup just omits age
            pass
    if fetch_commits and number is not None:
        try:
            commits = call(f"repos/{repo}/pulls/{number}/commits?per_page=100")
        except Exception:  # noqa: BLE001 — best-effort; a failed lookup just omits the commit-signature facts
            commits = None
        if isinstance(commits, list):
            # Count BOTH before assigning, so a malformed element can't leave a half-populated pair.
            unverified = sum(1 for c in commits if isinstance(c, dict)
                             and not (((c.get("commit") or {}).get("verification") or {}).get("verified")))
            prov["commits_total"] = len(commits)
            prov["commits_unverified"] = unverified
    return prov


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
    out = {
        "repo": payload.get("repo", ""),
        "kind": payload.get("kind", "pull_request"),
        "number": payload.get("number"),
        "author": payload.get("author", ""),
        "title": payload.get("title", ""),
        "body": payload.get("body", ""),
        "files": files,
    }
    if isinstance(payload.get("provenance"), dict):
        out["provenance"] = payload["provenance"]   # pass through host-supplied provenance facts, if any
    return out


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
        "provenance": _provenance(repo, number, pr.get("user"), pr.get("author_association"),
                                  call, fetch_commits=True),
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
        "provenance": _provenance(repo, number, issue.get("user"), issue.get("author_association"),
                                  call, fetch_commits=False),
    }
