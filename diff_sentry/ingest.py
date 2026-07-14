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

# GitHub commit `verification.reason` values where a signature WAS attached but does not bind to the
# committer's GitHub identity (spoofing-shaped) — distinct from a plain unsigned commit.
_SIG_MISMATCH_REASONS = frozenset({"bad_email", "unknown_key", "no_user", "unverified_email"})


class GhApiError(Exception):
    """A `gh api` call failed. `status` is the HTTP status when the failure was an HTTP error the CLI
    reported (a POSITIVELY-confirmed 404 vs a transient/network error, which leaves `status=None`) — so an
    enrichment caller can turn a real 404 into a fact while still omitting on any transient failure."""

    def __init__(self, message: str, *, status: Optional[int] = None):
        super().__init__(message)
        self.status = status


def _gh_cli_api(timeout: float = 30.0) -> GhApi:
    def call(path: str) -> Any:
        import subprocess  # host-side only; NEVER reached from inside the RLM

        out = subprocess.run(["gh", "api", path], capture_output=True, text=True, timeout=timeout)
        if out.returncode != 0:
            # gh prints the HTTP error BODY (JSON, with a `"status"`) to stdout on an HTTP failure; stdout is
            # empty on a network/transport failure. So a confirmed 404 is distinguishable from a transient.
            status = None
            body = out.stdout.strip()
            if body:
                try:
                    parsed = json.loads(body)
                    raw = parsed.get("status") if isinstance(parsed, dict) else None
                    status = int(raw) if raw is not None and str(raw).isdigit() else None
                except (ValueError, TypeError):
                    status = None
            # gh puts the human-readable error ("gh: Not Found (HTTP 404)", auth hints) on stderr — carry a
            # bounded slice so a host-side status=failed response is diagnosable, not just "exit 1".
            detail = (out.stderr or "").strip()[:200]
            msg = f"gh api {path} failed (exit {out.returncode})" + (f": {detail}" if detail else "")
            raise GhApiError(msg, status=status)
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
    uid = user.get("id")
    # `ghost` is GitHub's reserved deleted-user attribution — no lookup needed (scan_provenance flags the
    # login). Otherwise prefer the immutable numeric id (rename-proof) over the login.
    if login and login.strip().lower() != "ghost":
        try:
            acct = call(f"user/{uid}" if uid else f"users/{login}") or {}
            age = _age_days(acct.get("created_at")) if acct.get("created_at") else None
            if age is not None:
                prov["author_account_age_days"] = age
            if acct.get("name"):
                prov["author_display_name"] = str(acct["name"])[:120]   # attacker-authored — kept OUT of MF1
        except GhApiError as e:
            if e.status == 404:
                prov["author_not_found"] = True                         # POSITIVE 404 → a fact
        except Exception:  # noqa: BLE001 — transient failure: omit, never sink the ingest
            pass
    if fetch_commits and number is not None:
        try:
            commits = call(f"repos/{repo}/pulls/{number}/commits?per_page=100")
        except Exception:  # noqa: BLE001 — best-effort; a failed lookup just omits the commit-signature facts
            commits = None
        if isinstance(commits, list):
            # Tally everything BEFORE assigning, so a malformed element can't leave a half-populated dict.
            # Every nested field is isinstance-guarded (not just `or {}`): a TRUTHY non-dict — `{"commit":
            # "x"}` from a schema-broken 200 or a proxying transport — would otherwise raise on `.get` and
            # sink the whole ingest, breaking the best-effort contract this function documents above.
            unverified = mismatch = 0
            spoofed_authors: list[str] = []
            for c in commits:
                if not isinstance(c, dict):
                    continue
                commit = c.get("commit")
                commit = commit if isinstance(commit, dict) else {}
                verification = commit.get("verification")
                verification = verification if isinstance(verification, dict) else {}
                if verification.get("verified"):
                    continue
                unverified += 1
                if str(verification.get("reason") or "") in _SIG_MISMATCH_REASONS:
                    mismatch += 1
                author = commit.get("author")
                author_name = str((author if isinstance(author, dict) else {}).get("name") or "")
                if author_name:
                    spoofed_authors.append(author_name[:80])
            prov["commits_total"] = len(commits)
            prov["commits_unverified"] = unverified
            if mismatch:
                prov["commits_sig_identity_mismatch"] = mismatch
            if spoofed_authors:
                # DEDUPE (order-preserving) before the bound so an attacker can't flood the list with copies
                # of a plain name to push a bot-named commit past the cap. scan_provenance judges the names.
                prov["unverified_commit_authors"] = list(dict.fromkeys(spoofed_authors))[:20]
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
