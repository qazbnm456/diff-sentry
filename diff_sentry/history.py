"""An account's public history before the GitHub Events API's 30 days, from GH Archive as ClickHouse serves it publicly.

GitHub's Events API keeps an account's last 30 days, so it cannot tell an account that has been active for years from one that slept for years and woke up last week, the shape a taken-over account has. GH Archive holds every public event since 2011, and ClickHouse serves it as the `github_events` table on its public playground (`play.clickhouse.com`, user `play`, no key), queried by `actor_login`. Only a login and a time go out: the account is public, and so is what we watch.

Off by default: it sends a login to a third party, so an operator turns it on (`DS_ACCOUNT_HISTORY=clickhouse`, or `--account-history` on `watch`, `pr`, `issue` and `actor`), and `scan` and the GitHub Action never reach it. Host-side plumbing like `ingest`: never a planner tool, best-effort (an empty dict on any failure), the query parameterised (`{login:String}`, never formatted into the SQL), the response bounded. Pure stdlib + httpx; no dspy.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode

log = logging.getLogger(__name__)

_ENDPOINT = "https://play.clickhouse.com/"
_LOGIN_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})")
_WINDOW_DAYS = 30                 # what the Events API already shows; history is what came before it
_MAX_RESPONSE_BYTES = 1 << 20
_QUERY = """
SELECT count() AS events,
       min(created_at) AS first_event,
       countIf(created_at < {cut:DateTime}) AS events_before,
       maxIf(created_at, created_at < {cut:DateTime}) AS last_before,
       uniqExactIf(repo_name, created_at < {cut:DateTime}) AS repos_before
FROM github_events
WHERE actor_login = {login:String} AND created_at <= {as_of:DateTime}
FORMAT JSONEachRow
"""

# A post maps (url, body, byte limit) to (status, body). Injectable, so tests need no network.
Post = Callable[[str, bytes, int], tuple[int, bytes]]


def _httpx_post(timeout: float = 10.0) -> Post:
    def post(url: str, body: bytes, limit: int) -> tuple[int, bytes]:
        import httpx

        if not url.startswith(_ENDPOINT):
            raise ValueError("only ClickHouse's public playground is queried")
        with httpx.stream("POST", url, content=body, timeout=timeout, follow_redirects=False) as resp:
            data = bytearray()
            for chunk in resp.iter_bytes():
                data += chunk
                if len(data) > limit:
                    raise ValueError("the response is larger than its bound")
            return resp.status_code, bytes(data)

    return post


def _stamp(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S")


def account_history(login: str, as_of: datetime | None = None, *, post: Post | None = None) -> dict:
    """The account's public events up to `as_of` (the event's own time, so a replay sees what was true then): how many there were before the last `_WINDOW_DAYS`, in how many repositories, the first, and how many days before `as_of` the last of them was. `{}` when the login is not a GitHub login or the query fails; no event at all is zero events, not `{}`."""
    if not _LOGIN_RE.fullmatch(login or ""):
        return {}
    as_of = (as_of or datetime.now(UTC)).astimezone(UTC)
    params = {"user": "play", "param_login": login, "param_as_of": _stamp(as_of),
              "param_cut": _stamp(as_of - timedelta(days=_WINDOW_DAYS))}
    try:
        status, body = (post or _httpx_post())(f"{_ENDPOINT}?{urlencode(params)}", _QUERY.encode(), _MAX_RESPONSE_BYTES)
        if status != 200:
            raise ValueError(f"HTTP {status}")
        row = json.loads(body.decode("utf-8").splitlines()[0])
        if not int(row.get("events") or 0):     # none at all, as far as GH Archive has indexed: a fact, not a failure
            return {"events_before": 0, "repos_before": 0}
        out = {"events_before": int(row.get("events_before") or 0), "repos_before": int(row.get("repos_before") or 0),
               "first_event": str(row.get("first_event") or "")}
        if out["events_before"]:
            last = datetime.fromisoformat(str(row["last_before"])).replace(tzinfo=UTC)
            out["last_before_days"] = (as_of - last).days
        return out
    except Exception as exc:  # noqa: BLE001 (best-effort: a failed lookup or an answer it cannot read omits the facts)
        log.warning("account history %s: %s", login, str(exc)[:200])
        return {}


_MAX_CACHED = 4096


def enabled(flag: bool = False) -> Callable[[str, datetime | None], dict] | None:
    """The account-history lookup when the operator turned it on (`flag`, or `DS_ACCOUNT_HISTORY=clickhouse`), else None. The lookup remembers each account's answer for the day it was asked about, so a watch that sees one author many times asks once."""
    import os

    if not flag and os.getenv("DS_ACCOUNT_HISTORY", "").strip().lower() != "clickhouse":
        return None
    seen: dict[tuple[str, str], dict] = {}

    def lookup(login: str, as_of: datetime | None = None) -> dict:
        key = (login.lower(), (as_of or datetime.now(UTC)).date().isoformat())
        if key not in seen:
            if len(seen) >= _MAX_CACHED:
                seen.clear()
            seen[key] = account_history(login, as_of)
        return seen[key]

    return lookup
