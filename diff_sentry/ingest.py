"""Host-side ingestion: turn a GitHub PR/issue into the normalized change event diff-sentry classifies.

This is PLUMBING that runs OUTSIDE the RLM (the planner never talks to GitHub). It shapes a webhook-style payload dict (`{repo, kind, number, author, title, body, files:[{filename,status,additions,deletions, patch}], provenance:{…}}`) that `normalize.normalize_event` renders into the untrusted `event: str`. The GitHub transport is injectable (`api`) so this is testable offline; the default shells out to `gh`.

`provenance` is host-side source/identity ENRICHMENT, fetched via extra best-effort `gh api` calls: author type/association, the account's absolute `created_at` and its age AS OF the event (so a replay of an old incident sees the account as it was, not as it is today), profile facts, the event's own timestamps, the head repo/fork, commit signatures, and the commit dates/timezone offsets. `indicators.scan_provenance` turns it into deterministic baseline hits, joining the evidence union. The event also carries the attacker- controlled channels beyond the body: the PR head branch name (`head_ref`, the branch-name injection vector) and the bounded comment thread (`comments`, the slash-command trigger vector); both are UNTRUSTED text.

Pure stdlib; no dspy. `event_from_payload` is the offline path (a payload you already have).
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any

# An `api` maps a `gh api <path>` argument to parsed JSON. Injectable for tests; default uses `gh`.
GhApi = Callable[[str], Any]
# A `raw` maps (path, Accept media type) to the response TEXT, for the one surface that is not JSON: the `.patch` mbox, whose `Date:` headers keep the author's UTC offset (REST and GraphQL normalize it away).
GhRaw = Callable[[str, str], str]

_PATCH_ACCEPT = "application/vnd.github.patch"
# Bounds on attacker-authored text carried in the event/provenance.
_MAX_COMMENTS = 40
_MAX_COMMENT_PAGES = 5            # 500 comments per thread and kind; the newest _MAX_COMMENTS are kept
_MAX_FILE_PAGES = 30              # GitHub lists at most 3000 files of a PR
_MAX_COMMENT_CHARS = 2000
_MAX_PROFILE_FIELD = 200
_MAX_PATCH_TEXT = 2_000_000

# GitHub commit `verification.reason` values where a signature WAS attached but does not bind to the committer's GitHub identity (spoofing-shaped), distinct from a plain unsigned commit.
_SIG_MISMATCH_REASONS = frozenset({"bad_email", "unknown_key", "no_user", "unverified_email"})


class GhApiError(Exception):
    """A `gh api` call failed. `status` is the HTTP status when the failure was an HTTP error the CLI reported (a POSITIVELY-confirmed 404 vs a transient/network error, which leaves `status=None`), so an enrichment caller can turn a real 404 into a fact while still omitting on any transient failure."""

    def __init__(self, message: str, *, status: int | None = None):
        super().__init__(message)
        self.status = status


def _gh_cli_api(timeout: float = 30.0) -> GhApi:
    def call(path: str) -> Any:
        import subprocess  # host-side only; NEVER reached from inside the RLM

        # check=False is the INTENT, stated rather than defaulted: the returncode is inspected below because `gh` prints the HTTP error body on failure, and raising would discard it.
        out = subprocess.run(["gh", "api", path], capture_output=True, text=True,
                             timeout=timeout, check=False)
        if out.returncode != 0:
            # gh prints the HTTP error BODY (JSON, with a `"status"`) to stdout on an HTTP failure; stdout is empty on a network/transport failure. So a confirmed 404 is distinguishable from a transient.
            status = None
            body = out.stdout.strip()
            if body:
                try:
                    parsed = json.loads(body)
                    raw = parsed.get("status") if isinstance(parsed, dict) else None
                    status = int(raw) if raw is not None and str(raw).isdigit() else None
                except (ValueError, TypeError):
                    status = None
            # gh puts the human-readable error ("gh: Not Found (HTTP 404)", auth hints) on stderr; carry a bounded slice so a host-side status=failed response is diagnosable, not just "exit 1".
            detail = (out.stderr or "").strip()[:200]
            msg = f"gh api {path} failed (exit {out.returncode})" + (f": {detail}" if detail else "")
            raise GhApiError(msg, status=status)
        return json.loads(out.stdout)

    return call


def _gh_cli_raw(timeout: float = 30.0) -> GhRaw:
    def call(path: str, accept: str) -> str:
        import subprocess  # host-side only; NEVER reached from inside the RLM

        out = subprocess.run(["gh", "api", "-H", f"Accept: {accept}", path], capture_output=True,
                             text=True, timeout=timeout, check=False)
        if out.returncode != 0:
            raise GhApiError(f"gh api {path} failed (exit {out.returncode})", status=None)
        return out.stdout[:_MAX_PATCH_TEXT]

    return call


def _parse_ts(value: Any) -> datetime | None:
    """An aware datetime from an ISO-8601 string, else None. A naive value is read as UTC."""
    if isinstance(value, datetime):
        dt = value
    else:
        try:
            # `fromisoformat` parses a trailing "Z" on 3.11+ (the `requires-python` floor).
            dt = datetime.fromisoformat(str(value))
        except (ValueError, TypeError):
            return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _iso(value: Any) -> str:
    """The ISO-8601 string when `value` parses, else "": a malformed timestamp is dropped, not carried."""
    return str(value) if _parse_ts(value) is not None else ""


def _age_days(created_at: Any, as_of: Any = None) -> int | None:
    """Account age in whole days from an ISO-8601 `created_at`, measured AS OF `as_of` (the event's own creation time). Without `as_of` it falls back to the wall clock, which is right for a live event and wrong for a replay, hence the event time is passed whenever it is known. Host-side only."""
    created = _parse_ts(created_at)
    if created is None:
        return None
    ref = _parse_ts(as_of) if as_of else None
    return max(0, ((ref or datetime.now(UTC)) - created).days)


def _clip(value: Any, n: int) -> str:
    return str(value or "")[:n]


def _domain(email: Any) -> str:
    """The domain of an address, the only part of an email the store keeps (data minimization)."""
    text = str(email or "")
    return text.rsplit("@", 1)[1].strip().lower()[:100] if "@" in text else ""


def _profile_facts(acct: dict) -> dict:
    """Numeric account facts + the attacker-authored profile strings, from a `users/{id}` body. The strings are bounded and stay OUT of the MF1 metadata sandwich (only `scan_provenance` reads them)."""
    facts: dict = {}
    for src, dst in (("followers", "author_followers"), ("following", "author_following"),
                     ("public_repos", "author_public_repos"), ("public_gists", "author_public_gists")):
        v = acct.get(src)
        if isinstance(v, int) and not isinstance(v, bool):
            facts[dst] = v
    if acct.get("created_at") and _iso(acct.get("created_at")):
        facts["author_account_created_at"] = str(acct["created_at"])
    if _iso(acct.get("updated_at")):
        facts["author_profile_updated_at"] = str(acct["updated_at"])
    profile = {k: _clip(acct.get(k), _MAX_PROFILE_FIELD)
               for k in ("bio", "company", "location", "blog", "twitter_username") if acct.get(k)}
    if _domain(acct.get("email")):
        profile["email_domain"] = _domain(acct.get("email"))
    if profile:
        facts["author_profile"] = profile
    return facts


def _mbox_offsets(text: str, limit: int = 100) -> dict[str, int]:
    """UTC offsets (`+0800`) of the commit author dates in a `.patch` mbox, counted per offset.

    Only the header block of each message is read (from the `From <sha> …` separator to the first blank line), so a `Date:` line inside a diff is never mistaken for a header."""
    offsets: dict[str, int] = {}
    seen = 0
    in_header = False
    for line in (text or "").splitlines():
        if re.match(r"^From [0-9a-f]{40} ", line):
            in_header, seen = True, seen + 1
            if seen > limit:
                break
            continue
        if in_header:
            if not line.strip():
                in_header = False
            elif line.startswith("Date:"):
                try:
                    off = parsedate_to_datetime(line[5:].strip()).utcoffset()
                except (TypeError, ValueError):
                    continue
                if off is not None:
                    mins = int(off.total_seconds() // 60)
                    key = f"{'+' if mins >= 0 else '-'}{abs(mins) // 60:02d}{abs(mins) % 60:02d}"
                    offsets[key] = offsets.get(key, 0) + 1
    return offsets


def _provenance(repo: str, number: int | None, user: dict | None, association: Any,
                call: GhApi, *, fetch_commits: bool, as_of: Any = None,
                raw: GhRaw | None = None) -> dict:
    """Best-effort HOST-SIDE source/provenance facts for a change: author identity/association, the account's absolute `created_at` and its age as of the event, profile facts, and (PRs) commit signature counts, commit dates and UTC offsets, from `gh api`. Every enrichment call is guarded: a `gh` hiccup or a missing field just OMITS that key, never sinks the ingest. The `indicators.scan_provenance` detectors turn these into deterministic hits at baseline."""
    user = user if isinstance(user, dict) else {}
    login = str(user.get("login", "") or "")
    prov: dict = {"author_login": login, "author_type": str(user.get("type", "") or "")}
    if association:
        prov["author_association"] = str(association)
    uid = user.get("id")
    if isinstance(uid, int) and not isinstance(uid, bool):
        prov["author_id"] = uid
    if _iso(as_of):
        prov["event_created_at"] = str(as_of)
    # `ghost` is GitHub's reserved deleted-user attribution; no lookup needed (scan_provenance flags the login). Otherwise prefer the immutable numeric id (rename-proof) over the login.
    if login and login.strip().lower() != "ghost":
        try:
            acct = call(f"user/{uid}" if uid else f"users/{login}") or {}
            age = _age_days(acct.get("created_at"), as_of) if acct.get("created_at") else None
            if age is not None:
                prov["author_account_age_days"] = age
            if acct.get("name"):
                prov["author_display_name"] = str(acct["name"])[:120]   # attacker-authored, kept OUT of MF1
            prov.update(_profile_facts(acct))
        except GhApiError as e:
            if e.status == 404:
                prov["author_not_found"] = True                         # POSITIVE 404 → a fact
        except Exception:  # noqa: BLE001,S110 (transient failure: omit, never sink the ingest)
            pass
    if fetch_commits and number is not None:
        try:
            commits = call(f"repos/{repo}/pulls/{number}/commits?per_page=100")
        except Exception:  # noqa: BLE001 (best-effort; a failed lookup just omits the commit-signature facts)
            commits = None
        if isinstance(commits, list):
            # Tally everything BEFORE assigning, so a malformed element can't leave a half-populated dict. Every nested field is isinstance-guarded (not just `or {}`): a TRUTHY non-dict such as `{"commit": "x"}` (a schema-broken 200) would otherwise raise on `.get` and sink the ingest.
            unverified = mismatch = 0
            spoofed_authors: list[str] = []
            author_dates: list[str] = []
            email_domains: list[str] = []
            for c in commits:
                if not isinstance(c, dict):
                    continue
                commit = c.get("commit")
                commit = commit if isinstance(commit, dict) else {}
                author = commit.get("author")
                author = author if isinstance(author, dict) else {}
                if _iso(author.get("date")):
                    author_dates.append(str(author["date"]))
                if _domain(author.get("email")):
                    email_domains.append(_domain(author.get("email")))
                verification = commit.get("verification")
                verification = verification if isinstance(verification, dict) else {}
                if verification.get("verified"):
                    continue
                unverified += 1
                if str(verification.get("reason") or "") in _SIG_MISMATCH_REASONS:
                    mismatch += 1
                author_name = str(author.get("name") or "")
                if author_name:
                    spoofed_authors.append(author_name[:80])
            prov["commits_total"] = len(commits)
            prov["commits_unverified"] = unverified
            if mismatch:
                prov["commits_sig_identity_mismatch"] = mismatch
            if spoofed_authors:
                # DEDUPE (order-preserving) before the bound so an attacker can't flood the list with copies of a plain name to push a bot-named commit past the cap. scan_provenance judges the names.
                prov["unverified_commit_authors"] = list(dict.fromkeys(spoofed_authors))[:20]
            if author_dates:
                prov["commit_author_dates"] = sorted(author_dates)[:20]
            if email_domains:
                prov["commit_email_domains"] = list(dict.fromkeys(email_domains))[:10]
        if raw is not None:
            # REST and GraphQL return commit dates in UTC; only the `.patch` mbox keeps the author's own offset. It is the author's CLAIM (a committer can set any date), so it is soft evidence.
            try:
                offsets = _mbox_offsets(raw(f"repos/{repo}/pulls/{number}", _PATCH_ACCEPT))
            except Exception:  # noqa: BLE001 (best-effort; the offsets are simply omitted)
                offsets = {}
            if offsets:
                prov["commit_tz_offsets"] = offsets
    return prov


def _head_facts(pr: dict) -> dict:
    """Where the PR's code comes from: the head repo/fork, its creation time, and the head sha. A `null` head repo means the fork was deleted after the PR was opened: an author cleanup tell."""
    head = pr.get("head") if isinstance(pr.get("head"), dict) else {}
    facts: dict = {}
    if head.get("sha"):
        facts["head_sha"] = _clip(head["sha"], 40)
    base = pr.get("base") if isinstance(pr.get("base"), dict) else {}
    if base.get("ref"):
        facts["base_ref"] = _clip(base["ref"], 120)
    repo_obj = head.get("repo")
    if isinstance(repo_obj, dict):
        facts["head_repo"] = _clip(repo_obj.get("full_name"), 200)
        facts["head_repo_fork"] = bool(repo_obj.get("fork"))
        if _iso(repo_obj.get("created_at")):
            facts["head_repo_created_at"] = str(repo_obj["created_at"])
    elif "repo" in head:
        facts["head_repo_deleted"] = True
    return facts


def _timeline(obj: dict) -> dict:
    """The event's own timestamps (UTC), assigned by GitHub: an author cannot edit them afterwards."""
    out = {}
    for src, dst in (("created_at", "event_created_at"), ("updated_at", "event_updated_at"),
                     ("closed_at", "event_closed_at"), ("merged_at", "event_merged_at")):
        if _iso(obj.get(src)):
            out[dst] = str(obj[src])
    return out


def _pages(call: GhApi, base: str, max_pages: int, *, start: int = 1) -> list:
    """Items of a paginated list endpoint, 100 per page, from page `start` for up to `max_pages` pages. A failed page raises. A server that ignores `page=` (the same first item twice) stops the loop instead of returning duplicates for every page."""
    out: list = []
    previous_first = None
    for page in range(start, start + max_pages):
        body = call(f"{base}?per_page=100&page={page}")
        if not isinstance(body, list) or not body:
            break
        if body[0] == previous_first:
            break
        previous_first = body[0]
        out += body
        if len(body) < 100:
            break
    return out


def _comments(call: GhApi, repo: str, number: int, *, review: bool, total: Any = None
              ) -> tuple[list[dict] | None, bool]:
    """One thread of comments: the channel hackerbot used to fire `/format`-style workflow triggers. Comment bodies are UNTRUSTED. Returns `(comments, truncated)`; `comments` is None when the lookup failed, so the caller can tell "no comments" from "could not read them": the two must not both read as an empty thread, or a transient error looks like an edit. When the thread is longer than `_MAX_COMMENT_PAGES` pages and the object told us how long (`total`), the NEWEST pages are read, because a slash command fires on the latest comment; `truncated` says older ones were not."""
    base = (f"repos/{repo}/pulls/{number}/comments" if review else f"repos/{repo}/issues/{number}/comments")
    last = -(-total // 100) if isinstance(total, int) and not isinstance(total, bool) and total > 0 else None
    start = max(1, last - _MAX_COMMENT_PAGES + 1) if last else 1
    try:
        items = _pages(call, base, _MAX_COMMENT_PAGES, start=start)
    except Exception:  # noqa: BLE001 (best-effort; reported as incomplete, never a failed ingest)
        return None, False
    truncated = start > 1 or (last is None and len(items) >= _MAX_COMMENT_PAGES * 100)
    out: list[dict] = []
    for c in items:
        if not isinstance(c, dict):
            continue
        u = c.get("user") if isinstance(c.get("user"), dict) else {}
        entry = {
            "author": _clip(u.get("login"), 80),
            "author_type": _clip(u.get("type"), 20),
            "association": _clip(c.get("author_association"), 40),
            "created_at": _iso(c.get("created_at")),
            "kind": "review" if review else "conversation",
            "body": _clip(c.get("body"), _MAX_COMMENT_CHARS),
        }
        if isinstance(u.get("id"), int) and not isinstance(u.get("id"), bool):
            entry["author_id"] = u["id"]
        out.append(entry)
    return out, truncated


def _all_comments(call: GhApi, repo: str, number: int, *, pull: bool, conv_total: Any = None,
                  review_total: Any = None) -> tuple[list[dict], bool, bool]:
    """The newest `_MAX_COMMENTS` comments of a change, whether every lookup succeeded, and whether older comments were left unread. The newest are kept because a slash command fires on the latest comment."""
    parts = [_comments(call, repo, number, review=False, total=conv_total)]
    if pull:
        parts.append(_comments(call, repo, number, review=True, total=review_total))
    merged = [c for part, _ in parts for c in (part or [])]
    merged.sort(key=lambda c: c["created_at"])
    return (merged[-_MAX_COMMENTS:], all(part is not None for part, _ in parts),
            any(trunc for _, trunc in parts) or len(merged) > _MAX_COMMENTS)


def clean_comments(raw: Any) -> list[dict]:
    """A defensive copy of a host-supplied `comments` list (offline payloads): dict entries only, every field bounded, so a pasted event obeys the same limits a fetched one does."""
    out: list[dict] = []
    for c in raw if isinstance(raw, list) else []:
        if not isinstance(c, dict):
            continue
        entry = {
            "author": _clip(c.get("author"), 80), "author_type": _clip(c.get("author_type"), 20),
            "association": _clip(c.get("association"), 40), "created_at": _iso(c.get("created_at")),
            "kind": "review" if c.get("kind") == "review" else "conversation",
            "body": _clip(c.get("body"), _MAX_COMMENT_CHARS),
        }
        if isinstance(c.get("author_id"), int) and not isinstance(c.get("author_id"), bool):
            entry["author_id"] = c["author_id"]
        out.append(entry)
    return out[-_MAX_COMMENTS:]


def _fill_age(prov: dict, event_created_at: str) -> dict:
    """An offline payload that carries the account's `created_at` but no age gets the age AS OF the event."""
    out = dict(prov)
    if out.get("author_account_age_days") is None and out.get("author_account_created_at"):
        age = _age_days(out["author_account_created_at"], out.get("event_created_at") or event_created_at)
        if age is not None:
            out["author_account_age_days"] = age
    return out


def event_from_payload(payload: dict) -> dict:
    """Normalize a webhook-style payload we already hold into the canonical change-event dict. Tolerant of missing keys: every field defaults to empty so a partial payload still classifies."""
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
    created = _iso(payload.get("created_at"))
    if created:
        out["created_at"] = created
    if payload.get("head_ref"):
        out["head_ref"] = _clip(payload["head_ref"], 250)
    comments = clean_comments(payload.get("comments"))
    if comments:
        out["comments"] = comments
    if isinstance(payload.get("provenance"), dict):
        # pass through host-supplied provenance facts, if any
        out["provenance"] = _fill_age(payload["provenance"], created)
    for key in ("actor_history", "prior_indicators"):
        if payload.get(key):
            out[key] = payload[key]
    return out


def pr_event(repo: str, number: int, *, api: GhApi | None = None, raw: GhRaw | None = None) -> dict:
    """Fetch a PR + its files, comments and provenance from GitHub (host-side) into a change-event dict.

    `api` is injectable. The `.patch` fetch (commit UTC offsets) runs only on the real `gh` transport or an explicitly injected `raw`, so a test that fakes `api` never reaches the network."""
    call = api or _gh_cli_api()
    raw_call = raw if raw is not None else (_gh_cli_raw() if api is None else None)
    pr = call(f"repos/{repo}/pulls/{number}")
    files = _pages(call, f"repos/{repo}/pulls/{number}/files", _MAX_FILE_PAGES)
    timeline = _timeline(pr)
    prov = _provenance(repo, number, pr.get("user"), pr.get("author_association"),
                       call, fetch_commits=True, as_of=timeline.get("event_created_at"), raw=raw_call)
    prov.update(timeline)
    prov.update(_head_facts(pr))
    changed = pr.get("changed_files")
    if isinstance(changed, int) and not isinstance(changed, bool):
        prov["changed_files"] = changed
        if changed > len(files):
            prov["files_truncated"] = True      # GitHub lists at most 3000; the rest were never read
    event = {
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
        "provenance": prov,
    }
    if timeline.get("event_created_at"):
        event["created_at"] = timeline["event_created_at"]
    head = pr.get("head") if isinstance(pr.get("head"), dict) else {}
    if head.get("ref"):
        event["head_ref"] = _clip(head["ref"], 250)
    comments, complete, truncated = _all_comments(call, repo, number, pull=True, conv_total=pr.get("comments"),
                                                  review_total=pr.get("review_comments"))
    if comments:
        event["comments"] = comments
    if not complete:
        prov["comments_incomplete"] = True
    if truncated:
        prov["comments_truncated"] = True
    return event


def issue_event(repo: str, number: int, *, api: GhApi | None = None) -> dict:
    """Fetch an issue from GitHub (host-side) into a change-event dict; the issue body is the untrusted content (the hackerbot-claw prompt-injection issues came in this shape)."""
    call = api or _gh_cli_api()
    issue = call(f"repos/{repo}/issues/{number}")
    timeline = _timeline(issue)
    prov = _provenance(repo, number, issue.get("user"), issue.get("author_association"),
                       call, fetch_commits=False, as_of=timeline.get("event_created_at"))
    prov.update(timeline)
    event = {
        "repo": repo,
        "kind": "issue",
        "number": number,
        "author": (issue.get("user") or {}).get("login", ""),
        "title": issue.get("title", ""),
        "body": issue.get("body", "") or "",
        "files": [],
        "provenance": prov,
    }
    if timeline.get("event_created_at"):
        event["created_at"] = timeline["event_created_at"]
    comments, complete, truncated = _all_comments(call, repo, number, pull=False,
                                                  conv_total=issue.get("comments"))
    if comments:
        event["comments"] = comments
    if not complete:
        prov["comments_incomplete"] = True
    if truncated:
        prov["comments_truncated"] = True
    return event


def public_activity(login: str, *, api: GhApi | None = None, pages: int = 3) -> dict:
    """A bounded summary of an account's recent PUBLIC activity (GitHub keeps the last 30 days / 300 events): distinct repos, event types, and the UTC hour-of-day histogram. GitHub assigns the timestamps, so the histogram is the timezone evidence to lean on, though the author still chooses when to act (commit-date offsets are only a claim). Best-effort: an empty dict on any failure."""
    if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})", login or ""):
        return {}      # a GitHub login, nothing that could alter the request path
    call = api or _gh_cli_api()
    events: list[dict] = []
    for page in range(1, max(1, pages) + 1):
        try:
            batch = call(f"users/{login}/events/public?per_page=100&page={page}")
        except Exception:  # noqa: BLE001 (best-effort)
            break
        if not isinstance(batch, list) or not batch:
            break
        events += [e for e in batch if isinstance(e, dict)]
        if len(batch) < 100:
            break
    if not events:
        return {}
    hours = [0] * 24
    types: dict[str, int] = {}
    repos: dict[str, int] = {}
    stamps: list[str] = []
    for e in events:
        ts = _parse_ts(e.get("created_at"))
        if ts is not None:
            hours[ts.astimezone(UTC).hour] += 1
            stamps.append(ts.astimezone(UTC).isoformat())
        t = _clip(e.get("type"), 40)
        types[t] = types.get(t, 0) + 1
        name = _clip((e.get("repo") or {}).get("name") if isinstance(e.get("repo"), dict) else "", 200)
        if name:
            repos[name] = repos.get(name, 0) + 1
    stamps.sort()
    return {"events": len(events), "hour_utc": hours, "types": types,
            "repos": dict(sorted(repos.items(), key=lambda kv: -kv[1])[:50]),
            "first": stamps[0] if stamps else "", "last": stamps[-1] if stamps else ""}
