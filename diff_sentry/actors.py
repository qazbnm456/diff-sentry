"""Host-side actor store — who is behind a change, and what else they did.

A per-change classifier sees one PR. The campaigns worth catching span many: hackerbot-claw hit seven
repositories in ten days from one account, with one payload host. The defender of each repository saw one
attempt; a watcher that remembers sees a pattern from the second. This store is that memory, and the source
of the post-incident dossier (account age, profile, when and where the account acted, in what timezone
evidence, what it left behind).

It is HOST-SIDE plumbing like `ingest` and `emit`: the planner never queries it. Three things leave it:

* `correlate` → plain provenance facts (`actor_repos_24h`, `ioc_reuse`, …) that `indicators.scan_provenance`
  turns into baseline hits, so cross-event evidence joins the same union as every other hit (MF3) and there
  is no second signal derivation;
* `history` → a bounded, host-derived summary the normalizer shows the planner as data (repositories,
  outcomes, rule names, hours active, and which profile FIELDS changed, never the profile text);
* `dossier` → the full record, for a human.

Attribution is by who wrote the text. A hit that came from someone else's comment on a change is recorded
against the commenter (`channel='comment'`), never against the change's author: otherwise a drive-by comment
would frame a maintainer. The commenter's dossier is also where the slash-command vector shows up.

Storage is one SQLite file (stdlib). Only public GitHub facts are kept; emails are reduced to a domain before
they reach an event. Pure stdlib; no dspy.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
from collections.abc import Callable, Iterable
from datetime import UTC, datetime, timedelta
from itertools import pairwise
from typing import Any

from .dbutil import open_versioned
from .hosts import fetch_targets, ioc_of
from .normalize import event_metadata
from .schema import IndicatorHit, at_signal_floor, max_severity, severity_rank

_SCHEMA = """
CREATE TABLE IF NOT EXISTS actors (
    key TEXT PRIMARY KEY, login TEXT NOT NULL, gh_id INTEGER, created_at TEXT,
    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT NOT NULL, seen_at TEXT NOT NULL, sha TEXT NOT NULL,
    data TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS profiles_key ON profiles (key, id);
CREATE TABLE IF NOT EXISTS sightings (
    run_id TEXT PRIMARY KEY, actor_key TEXT NOT NULL, repo TEXT NOT NULL, kind TEXT NOT NULL,
    number INTEGER, revision INTEGER NOT NULL, event_at TEXT NOT NULL, seen_at TEXT NOT NULL,
    content_sha256 TEXT, head_ref TEXT, tz_json TEXT, verdict TEXT, signal INTEGER NOT NULL DEFAULT 0,
    max_severity TEXT, rules_json TEXT, hits_json TEXT, content_hits_json TEXT, snapshot_sha TEXT,
    channel TEXT NOT NULL DEFAULT 'change', mixed INTEGER NOT NULL DEFAULT 0,
    own_signal INTEGER NOT NULL DEFAULT 0, parent TEXT);
CREATE INDEX IF NOT EXISTS sightings_actor ON sightings (actor_key, event_at);
CREATE INDEX IF NOT EXISTS sightings_change ON sightings (repo, kind, number);
CREATE TABLE IF NOT EXISTS iocs (
    run_id TEXT NOT NULL, ioc TEXT NOT NULL, PRIMARY KEY (run_id, ioc));
CREATE INDEX IF NOT EXISTS iocs_ioc ON iocs (ioc);
"""

SCHEMA_VERSION = 2

# How far back an earlier sighting still counts against an account.
_LOOKBACK = timedelta(days=30)
# `medium` and up: a `low` hit (an unsigned commit) is not infrastructure worth linking on.
_IOC_MIN_SEVERITY = "medium"


def actor_key(login: str, gh_id: Any = None, *, change: str = "") -> str:
    """The stable identity of an account: its immutable numeric id when known (rename-proof), else the login.

    GitHub's `ghost` is ONE shared identity for every deleted account, so it is not an actor: a `ghost` change
    keys on the change itself, and two unrelated deleted authors never share a history."""
    if (login or "").strip().lower() == "ghost":
        return f"ghost:{change}"
    if isinstance(gh_id, int) and not isinstance(gh_id, bool):
        return f"id:{gh_id}"
    return f"login:{(login or 'unknown').strip().lower()}"


def _change_of(event: dict) -> str:
    return f"{event.get('repo') or ''}#{event.get('kind') or ''}/{event.get('number')}"


def _to_dt(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        dt = value
    else:
        try:
            dt = datetime.fromisoformat(str(value))
        except (TypeError, ValueError):
            return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _utc(value: Any) -> str | None:
    dt = _to_dt(value)
    return dt.astimezone(UTC).isoformat(timespec="seconds") if dt else None


def extract_iocs(hits: Iterable[IndicatorHit]) -> list[str]:
    """Payload infrastructure named by a change's medium-and-up indicators (their evidence and de-obfuscated
    form), as the tokens `hosts.ioc_of` says are worth linking on.

    Reads only what the deterministic layer already recorded, never the raw change, and never fetches."""
    found: dict[str, None] = {}
    for h in hits:
        if severity_rank(h.severity) < severity_rank(_IOC_MIN_SEVERITY):
            continue
        for text in (h.evidence, h.decoded or ""):
            for host, path in fetch_targets(text):
                ioc = ioc_of(host, path)
                if ioc:
                    found.setdefault(ioc, None)
    return list(found)[:20]


def _longest_quiet_run(hours: list[int]) -> int:
    """The longest cyclic run of zero-activity hours. A human's account has a night; an unattended agent's
    does not. Meaningful only with enough events, so callers gate on the total."""
    if not any(hours):
        return 24
    best = run = 0
    for h in hours + hours:      # doubled, so a run that wraps midnight is counted whole
        run = run + 1 if h == 0 else 0
        best = max(best, run)
    return min(best, 24)


def _is_own(hit: IndicatorHit, login: str) -> bool:
    """A hit is the author's own unless it came from ANOTHER account's comment (`IndicatorHit.via`, a structured
    field set from where the text came from, never parsed out of the free-form `location`)."""
    return not hit.via or hit.via.strip().lower() == login.strip().lower()


# C0/C1 controls plus the characters that reorder or hide text on a terminal: bidi overrides, embeddings and
# isolates, the line and paragraph separators, the zero-width space, the word joiner, the byte-order mark, and the
# tag characters. The joiners and marks that real text needs (ZWJ in an emoji family, ZWNJ, LRM, RLM, ALM) stay.
_PRINTABLE = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\u200b\u2028-\u202e\u2060-\u2069\ufeff"
                        "\U000E0000-\U000E007F]")


def _clean(text: object) -> str:
    """Control characters replaced, for text that goes to a terminal: an attacker-influenced string in a dossier
    must not be able to move the cursor or rewrite earlier lines."""
    return _PRINTABLE.sub("?", str(text))


class ActorStore:
    def __init__(self, path: str, *, clock: Callable[[], datetime] | None = None, read_only: bool = False):
        self.path = path
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lock = threading.RLock()
        self._db = open_versioned(path, _SCHEMA, SCHEMA_VERSION, "sightings", read_only=read_only)

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # ── writing ────────────────────────────────────────────────────────────────────────────────────

    def record(self, event: dict, *, run_id: str, hits: list[IndicatorHit],
               content_hits: list[IndicatorHit], snapshot_sha: str | None = None) -> str:
        """Remember one sighting of a change (and refresh its author). Returns the actor key.

        Hits that came from another account's comment are split off and recorded against that commenter."""
        prov = event.get("provenance") if isinstance(event.get("provenance"), dict) else {}
        login = str(prov.get("author_login") or event.get("author") or "")
        key = actor_key(login, prov.get("author_id"), change=_change_of(event))
        now = _utc(self._clock())
        event_at = _utc(event.get("created_at") or prov.get("event_created_at")) or now
        own: list[IndicatorHit] = []
        theirs: dict[str, list[IndicatorHit]] = {}
        for h in hits:
            if _is_own(h, login):
                own.append(h)
            else:
                theirs.setdefault(h.via, []).append(h)
        top = max_severity([h.severity for h in own])
        signal = int(at_signal_floor(top))
        # "Mixed" = a third party wrote floor-level evidence. A sub-floor remark (a stray backtick, a passing
        # mention of a prompt) must not stop the model's verdict reaching the author's own record.
        mixed = any(at_signal_floor(max_severity([h.severity for h in chits])) for chits in theirs.values())
        repo, kind, number = str(event.get("repo") or ""), str(event.get("kind") or ""), event.get("number")
        with self._lock:
            revision = self._db.execute(
                "SELECT COUNT(*) FROM sightings WHERE repo=? AND kind=? AND number IS ? AND run_id!=? "
                "AND channel='change'", (repo, kind, number, run_id)).fetchone()[0]
            self._upsert_actor(key, login, prov.get("author_id"), _utc(prov.get("author_account_created_at")),
                               event_at)
            profile = self._profile_of(prov)
            if profile:
                blob = json.dumps(profile, sort_keys=True, ensure_ascii=False)
                sha = hashlib.sha256(blob.encode()).hexdigest()[:16]
                latest = self._db.execute("SELECT sha FROM profiles WHERE key=? ORDER BY id DESC LIMIT 1",
                                          (key,)).fetchone()
                if latest is None or latest["sha"] != sha:     # A → B → A is three profiles, not two
                    self._db.execute("INSERT INTO profiles (key, seen_at, sha, data) VALUES (?,?,?,?)",
                                     (key, now, sha, blob))
            self._db.execute(
                "INSERT OR REPLACE INTO sightings (run_id, actor_key, repo, kind, number, revision, event_at, "
                "seen_at, content_sha256, head_ref, tz_json, verdict, signal, max_severity, rules_json, "
                "hits_json, content_hits_json, snapshot_sha, channel, mixed, own_signal) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (run_id, key, repo, kind, number, revision, event_at, now,
                 event_metadata(event)["content_sha256"],
                 str(event.get("head_ref") or "")[:250],
                 json.dumps(prov.get("commit_tz_offsets") or {}),
                 None, signal, top, json.dumps(sorted({h.rule for h in own})),
                 json.dumps([h.model_dump() for h in own]),
                 json.dumps([h.model_dump() for h in content_hits]), snapshot_sha,
                 "change", int(mixed), signal))
            self._db.execute("DELETE FROM iocs WHERE run_id=?", (run_id,))
            self._db.executemany("INSERT OR IGNORE INTO iocs (run_id, ioc) VALUES (?,?)",
                                 [(run_id, i) for i in extract_iocs(own)])
            for who, chits in theirs.items():
                self._record_commenter(event, run_id, who, chits, event_at, now)
            self._db.commit()
        return key

    def _upsert_actor(self, key: str, login: str, gh_id: Any, created_at: str | None, at: str | None) -> None:
        self._db.execute(
            "INSERT INTO actors (key, login, gh_id, created_at, first_seen, last_seen) "
            "VALUES (?,?,?,?,?,?) ON CONFLICT(key) DO UPDATE SET login=excluded.login, "
            "created_at=COALESCE(excluded.created_at, actors.created_at), "
            "first_seen=MIN(actors.first_seen, excluded.first_seen), "
            "last_seen=MAX(actors.last_seen, excluded.last_seen)",
            (key, login, gh_id if isinstance(gh_id, int) and not isinstance(gh_id, bool) else None,
             created_at, at, at))

    def _record_commenter(self, event: dict, run_id: str, login: str, chits: list[IndicatorHit],
                          event_at: str | None, now: str | None) -> None:
        """A sighting of someone else's comment on this change, against the commenter. Recorded only when the
        comment reached the signal floor or fired a slash command: the rest (a backtick in prose) is noise that
        would put every commenter in the store."""
        top = max_severity([h.severity for h in chits])
        if not (at_signal_floor(top) or any(h.rule == "slash-command-trigger" for h in chits)):
            return
        comment = self._carrying_comment(event, login, chits)
        if not comment:
            return            # the comment is gone (deleted since); the sighting made when it existed stays as it was
        cid = comment.get("author_id")
        key = actor_key(login, cid, change=_change_of(event))
        at = _utc(comment.get("created_at")) or event_at
        signal = int(at_signal_floor(top))
        self._upsert_actor(key, login, cid, None, at)
        rid = f"{run_id}~{login}"
        self._db.execute(
            "INSERT OR REPLACE INTO sightings (run_id, actor_key, repo, kind, number, revision, event_at, "
            "seen_at, content_sha256, head_ref, tz_json, verdict, signal, max_severity, rules_json, "
            "hits_json, content_hits_json, snapshot_sha, channel, mixed, own_signal, parent) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (rid, key, str(event.get("repo") or ""), str(event.get("kind") or ""), event.get("number"), 0, at,
             now, None, "", "{}", None, signal, top, json.dumps(sorted({h.rule for h in chits})),
             json.dumps([h.model_dump() for h in chits]), json.dumps([h.model_dump() for h in chits]), None,
             "comment", 0, signal, run_id))
        self._db.execute("DELETE FROM iocs WHERE run_id=?", (rid,))
        self._db.executemany("INSERT OR IGNORE INTO iocs (run_id, ioc) VALUES (?,?)",
                             [(rid, i) for i in extract_iocs(chits)])

    @staticmethod
    def _carrying_comment(event: dict, login: str, chits: list[IndicatorHit]) -> dict:
        """The comment by `login` that produced these hits (so the sighting carries THAT comment's time), else
        their first comment on the change."""
        from .indicators import scan_indicators, scan_metadata

        mine = [c for c in event.get("comments") or []
                if isinstance(c, dict) and str(c.get("author") or "").strip().lower() == login.strip().lower()]
        wanted = {h.id for h in chits}
        author = str(event.get("author") or "")
        for c in mine:
            ids = {h.id for h in scan_indicators(str(c.get("body") or ""))}
            ids |= {h.id for h in scan_metadata({"author": author, "created_at": event.get("created_at"),
                                                  "comments": [c]})}
            if ids & wanted:
                return c
        return mine[0] if mine else {}   # nothing matched the hits exactly: their first comment, or none

    @staticmethod
    def _profile_of(prov: dict) -> dict:
        """The account facts worth tracking for change over time. Strings are the attacker's own words."""
        keys = ("author_display_name", "author_profile", "author_followers", "author_following",
                "author_public_repos", "author_public_gists")
        return {k: prov[k] for k in keys if prov.get(k) not in (None, "", {})}

    def finalize(self, run_id: str, *, verdict: str | None, signal: bool, max_severity: str) -> None:
        """Attach the model's outcome to a sighting once the run has finished.

        Attribution follows the evidence. If the change's floor-level evidence is a third party's comment (the
        author's own hits stayed below the floor), the verdict belongs to that commenter, not to the author."""
        with self._lock:
            row = self._db.execute("SELECT mixed, own_signal FROM sightings WHERE run_id=?", (run_id,)).fetchone()
            if row is not None and row["mixed"] and not row["own_signal"]:
                taken = self._db.execute(
                    "UPDATE sightings SET verdict=? WHERE parent=? AND channel='comment' AND signal=1",
                    (verdict, run_id)).rowcount
                if taken:
                    self._db.commit()
                    return
                # nobody else's sighting exists to carry it (the comment is gone, or its writer could not be
                # matched): the verdict is not lost, it stays with the change it was made about
            self._db.execute("UPDATE sightings SET verdict=?, signal=?, max_severity=? WHERE run_id=?",
                             (verdict, int(signal), max_severity, run_id))
            self._db.commit()

    # ── reading ────────────────────────────────────────────────────────────────────────────────────

    def correlate(self, event: dict, content_hits: list[IndicatorHit]) -> tuple[dict, list[dict]]:
        """Cross-event facts about this change's author and payload, for `scan_provenance`, plus the hits an
        earlier version of this same change raised (`prior_indicators`). Read-only; call it BEFORE `record`."""
        prov = event.get("provenance") if isinstance(event.get("provenance"), dict) else {}
        key = actor_key(str(prov.get("author_login") or event.get("author") or ""), prov.get("author_id"),
                        change=_change_of(event))
        t = _to_dt(event.get("created_at") or prov.get("event_created_at")) or self._clock()
        repo, kind, number = str(event.get("repo") or ""), str(event.get("kind") or ""), event.get("number")
        since = _utc(t - _LOOKBACK)
        login = str(prov.get("author_login") or event.get("author") or "")
        # What THIS author wrote. Another account's comment is judged (and remembered) against that account:
        # its payload host must not link the author's next change, and its deletion by a moderator is not the
        # author removing evidence.
        mine = [h for h in content_hits if _is_own(h, login)]
        facts: dict[str, Any] = {}
        prior: dict[str, dict] = {}
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM sightings WHERE actor_key=? AND event_at>=? ORDER BY event_at", (key, since)
            ).fetchall()
            same = self._db.execute(
                "SELECT content_hits_json FROM sightings WHERE repo=? AND kind=? AND number IS ? "
                "AND channel='change'", (repo, kind, number)).fetchall()
            iocs = extract_iocs(mine)
            reuse_rows = []
            if iocs:
                marks = ",".join("?" * len(iocs))
                # The payload link is EVIDENCE (the same infrastructure used again), so no verdict removes it:
                # only a prior sighting that reached the signal floor counts, whatever the model said of it.
                reuse_rows = self._db.execute(
                    f"SELECT DISTINCT i.ioc, s.repo, s.actor_key FROM iocs i JOIN sightings s "
                    f"ON s.run_id=i.run_id WHERE i.ioc IN ({marks}) AND s.signal=1 "
                    "AND NOT (s.repo=? AND s.kind=? AND s.number IS ?)",
                    (*iocs, repo, kind, number)).fetchall()

        others = [r for r in rows if (r["repo"], r["kind"], r["number"]) != (repo, kind, number)]
        hour = t - timedelta(hours=1)
        day = t - timedelta(hours=24)
        recent_1h = {(r["repo"], r["kind"], r["number"]) for r in others
                     if hour < (_to_dt(r["event_at"]) or t) <= t}
        if recent_1h:
            facts["actor_changes_1h"] = len(recent_1h)
        repos_24h = {r["repo"] for r in others if day < (_to_dt(r["event_at"]) or t) <= t} | {repo}
        if len(repos_24h) > 1:
            facts["actor_repos_24h"] = sorted(repos_24h)
        bad = sorted({r["repo"] for r in others if r["signal"] and r["verdict"] == "malicious"})
        if bad:
            facts["actor_known_bad_repos"] = bad
        # The account-level flag is an INFERENCE about a person, so a model's `benign` clears it: one false
        # positive must not taint an account for good. Not over a change that talked to the model, though: that
        # verdict may be the injection working.
        flagged = sorted({r["repo"] for r in others if r["signal"] and r["verdict"] != "malicious"
                          and self._stands(r)})
        if flagged:
            facts["actor_prior_flag_repos"] = flagged
        reuse: dict[str, set[str]] = {}
        for r in reuse_rows:
            reuse.setdefault(r["ioc"], set()).add(r["repo"])
        if reuse:
            facts["ioc_reuse"] = [{"ioc": i, "repos": sorted(rs)} for i, rs in sorted(reuse.items())]
        if same:
            facts["content_revisions"] = len(same)
            for row in same:
                for raw in json.loads(row["content_hits_json"] or "[]"):
                    held = prior.get(raw["id"])
                    if held is None or severity_rank(raw["severity"]) > severity_rank(held["severity"]):
                        prior[raw["id"]] = raw
            # "Scrubbed" means the KIND of evidence is gone from where it was, not that its text moved: a
            # hit is matched by rule and location, so reworded evidence or a flipped association does not
            # read as an author removing a payload.
            # ... and by whether that kind is still at the floor there: a payload rewritten to read as prose (the same
            # rule, now `medium`) is as gone, for the signal, as one deleted.
            fresh: dict[tuple[str, str], bool] = {}
            for h in mine:
                spot = (h.rule, h.location)
                fresh[spot] = fresh.get(spot, False) or at_signal_floor(h.severity)
            # Only evidence that could have signalled counts: dropping a `$(pwd)` from prose is an edit, not
            # a payload removal.
            scrubbed = sorted(h["id"] for h in prior.values()
                              if (not h.get("via") or h["via"].strip().lower() == login.strip().lower())
                              and not fresh.get((h["rule"], h.get("location", "")), False)
                              and at_signal_floor(h["severity"]))
            if scrubbed:
                facts["evidence_scrubbed"] = scrubbed[:10]
        return facts, list(prior.values())

    @staticmethod
    def _stands(r: sqlite3.Row) -> bool:
        """Whether an earlier sighting's flag survives its verdict: anything but `benign`, or a `benign` over a
        change that carried a prompt injection."""
        return r["verdict"] != "benign" or '"prompt-injection"' in (r["rules_json"] or "")

    def history(self, event: dict, *, recent: int = 30, flagged: int = 20) -> dict | None:
        """A bounded summary of this author's earlier sightings for the planner, or None for a first-timer.
        Host-derived; rendered as untrusted because the logins and refs inside came from GitHub users."""
        prov = event.get("provenance") if isinstance(event.get("provenance"), dict) else {}
        key = actor_key(str(prov.get("author_login") or event.get("author") or ""), prov.get("author_id"),
                        change=_change_of(event))
        repo, kind, number = str(event.get("repo") or ""), str(event.get("kind") or ""), event.get("number")
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM sightings WHERE actor_key=? ORDER BY event_at", (key,)).fetchall()
            rows = [r for r in rows if (r["repo"], r["kind"], r["number"]) != (repo, kind, number)]
            if not rows:
                return None
            actor = self._db.execute("SELECT * FROM actors WHERE key=?", (key,)).fetchone()
            profiles = self._db.execute(
                "SELECT seen_at, data FROM profiles WHERE key=? ORDER BY id", (key,)).fetchall()
        return {
            "actor": actor["login"] if actor else "",
            "account_created_at": actor["created_at"] if actor else None,
            "first_seen": rows[0]["event_at"], "changes": len({(r["repo"], r["kind"], r["number"]) for r in rows}),
            "repos": sorted({r["repo"] for r in rows})[:50],
            "flagged": [self._row_view(r) for r in rows if r["signal"]][-flagged:],
            "recent": [self._row_view(r) for r in rows][-recent:],
            "hour_utc": self._hours(rows),
            "profile_changes": self._profile_changes(profiles),
        }

    @staticmethod
    def _row_view(r: sqlite3.Row) -> dict:
        return {"at": r["event_at"], "repo": r["repo"], "kind": r["kind"], "number": r["number"],
                "channel": r["channel"], "verdict": r["verdict"], "max_severity": r["max_severity"],
                "rules": json.loads(r["rules_json"] or "[]")[:8]}

    @staticmethod
    def _hours(rows: Iterable[sqlite3.Row]) -> list[int]:
        """Hours of the day (UTC) the account acted, one count per CHANGE at the time of its first sighting,
        so an edit or a re-check of the same PR does not count as another act."""
        first: dict[tuple, datetime] = {}
        for r in rows:
            dt = _to_dt(r["event_at"])
            if dt is None:
                continue
            k = (r["repo"], r["kind"], r["number"], r["channel"])
            if k not in first or dt < first[k]:
                first[k] = dt
        hours = [0] * 24
        for dt in first.values():
            hours[dt.astimezone(UTC).hour] += 1
        return hours

    @staticmethod
    def _profile_changes(profiles: list[sqlite3.Row]) -> list[dict]:
        out = []
        for prev, cur in pairwise(profiles):
            a, b = json.loads(prev["data"]), json.loads(cur["data"])
            changed = sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k))
            if changed:
                out.append({"at": cur["seen_at"], "changed": changed})
        return out

    def dossier(self, who: str) -> dict | None:
        """The full record of one account (by login or `id:<n>` key): identity, when and where it acted, the
        timezone evidence, every change with its outcome, the payload hosts, and how its profile changed."""
        with self._lock:
            actor = self._db.execute(
                "SELECT * FROM actors WHERE key=? OR lower(login)=lower(?) ORDER BY last_seen DESC LIMIT 1",
                (who, who)).fetchone()
            if not actor:
                return None
            rows = self._db.execute(
                "SELECT * FROM sightings WHERE actor_key=? ORDER BY event_at", (actor["key"],)).fetchall()
            profiles = self._db.execute(
                "SELECT seen_at, data FROM profiles WHERE key=? ORDER BY id", (actor["key"],)).fetchall()
            iocs = self._db.execute(
                "SELECT i.ioc, GROUP_CONCAT(DISTINCT s.repo) AS repos FROM iocs i JOIN sightings s "
                "ON s.run_id=i.run_id WHERE s.actor_key=? GROUP BY i.ioc ORDER BY i.ioc",
                (actor["key"],)).fetchall()
        hours = self._hours(rows)
        offsets: dict[str, int] = {}
        for r in rows:
            for off, n in json.loads(r["tz_json"] or "{}").items():
                offsets[off] = offsets.get(off, 0) + int(n)
        created = _to_dt(actor["created_at"])
        first = _to_dt(rows[0]["event_at"]) if rows else None
        return {
            "login": actor["login"], "key": actor["key"], "github_id": actor["gh_id"],
            "account_created_at": actor["created_at"],
            # How long the account sat idle before its first observed act: the "warm-up" of the campaign.
            "account_age_at_first_seen_days": (first - created).days if created and first else None,
            "first_seen": actor["first_seen"], "last_seen": actor["last_seen"],
            "profile": json.loads(profiles[-1]["data"]) if profiles else {},
            "profile_changes": self._profile_changes(profiles),
            "repos": sorted({r["repo"] for r in rows}),
            "timeline": [{**self._row_view(r), "revision": r["revision"], "head_ref": r["head_ref"],
                          "run_id": r["run_id"], "snapshot": r["snapshot_sha"]} for r in rows],
            "hour_utc": hours,
            # The hour histogram is built from timestamps GitHub assigned, which no author can edit after the
            # fact (though the author still chooses WHEN to act). The offsets below are what the commits
            # CLAIM, since an author sets any date, so they corroborate and never establish anything.
            "longest_quiet_hours": _longest_quiet_run(hours) if sum(hours) >= 30 else None,
            "commit_tz_offsets_claimed": offsets,
            "iocs": [{"ioc": r["ioc"], "repos": (r["repos"] or "").split(",")} for r in iocs],
        }


def format_dossier(d: dict) -> str:
    """A human-readable rendering of `ActorStore.dossier` (times in UTC). Control characters are replaced, so an
    attacker-influenced string cannot move the cursor or rewrite earlier lines of the terminal."""
    return "\n".join(_clean(line) for line in _format_dossier(d).split("\n"))


def _format_dossier(d: dict) -> str:
    lines = [f"actor: {d['login']}  ({d['key']})",
             f"  account created : {d['account_created_at'] or 'unknown'}"
             + (f"  (idle {d['account_age_at_first_seen_days']}d before first observed act)"
                if d.get("account_age_at_first_seen_days") is not None else ""),
             f"  first / last    : {d['first_seen']}  →  {d['last_seen']}",
             f"  repos targeted  : {len(d['repos'])}  {', '.join(d['repos'][:8])}"]
    if d["profile"]:
        lines.append(f"  profile         : {json.dumps(d['profile'], ensure_ascii=False)}")
    for ch in d["profile_changes"]:
        lines.append(f"  profile changed : {ch['at']}  {', '.join(ch['changed'])}")
    hours = d["hour_utc"]
    if sum(hours):
        bars = " ".join(f"{h:02d}:{n}" for h, n in enumerate(hours) if n)
        lines.append(f"  active hours UTC: {bars}")
    if d.get("longest_quiet_hours") is not None:
        lines.append(f"  longest quiet   : {d['longest_quiet_hours']}h (a human account usually has a night;"
                     " an unattended agent does not)")
    if d["commit_tz_offsets_claimed"]:
        lines.append(f"  commit offsets  : {d['commit_tz_offsets_claimed']} (claimed by the commits, forgeable)")
    for i in d["iocs"]:
        lines.append(f"  payload host    : {i['ioc']}  in {', '.join(i['repos'])}")
    lines.append("  timeline (UTC):")
    for e in d["timeline"]:
        via = "  [comment]" if e.get("channel") == "comment" else ""
        lines.append(f"    {e['at']}  {e['repo']}#{e['number']} {e['kind']:<12} "
                     f"sev={e['max_severity']:<8} verdict={e['verdict'] or '-':<10} "
                     f"{','.join(e['rules'][:4])}"
                     + (f"  branch={e['head_ref']}" if e.get("head_ref") else "") + via)
    return "\n".join(lines)
