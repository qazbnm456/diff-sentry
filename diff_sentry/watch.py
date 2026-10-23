"""The watcher: continuous monitoring of a watchlist of repositories for the attacks that arrive as a PR or an issue.

    python -m diff_sentry watch --repos owner/name other/name        # poll, screen, queue for the model python -m diff_sentry watch --screen-only --repos-file repos.txt # deterministic tier only, no model

It is HOST-SIDE plumbing in front of `cli.run`, like `ingest` and `emit`: the planner never sees GitHub, the store, or the queue. One change moves through these stages:

    poll (ETag, sorted by update)  →  ingest (+ raw responses)  →  snapshot archive
      →  correlate (actor store)  →  screen (deterministic baseline; early SIEM alert at the floor) →  queue (priority order)   →  model run (`cli.run`)      →  finalize (verdict onto the sighting)

Design facts, each of which a test pins:

* **Time is the cost, not money.** The intended model is local, so every change reaches the model by default (`deep_min_severity="info"`); the screen decides the ORDER (highest severity first), never whether. The optional caps (`max_queue`, `max_deep_per_hour`, `deep_min_severity`) default to off and are env-driven.
* **The early alert does not wait for the model.** Evidence at the signal floor is emitted the moment the screen finishes (`stage=screen`); the model's own signal follows (`stage=final`) under the same run id. A later revision alerts early again only for evidence at the floor that no earlier revision already alerted.
* **Nothing is lost silently.** A change the queue sheds keeps its screened record and a `shed` state; a listing deeper than one pass can read is reported as truncated; a change that cannot be ingested is retried with backoff and, after `_MAX_FAILS`, parked as `error` and logged, never skipped without a trace.
* **The first copy is kept.** Every capture is archived before anything else happens to the change, and an edit adds a new revision (`-r1`, `-r2`, …) instead of overwriting: the original, and the trace of the run that judged it, stay. Hits an earlier revision raised ride into the next one, so removing a payload cannot remove the evidence.
* **A read that failed is not a change.** If a re-check cannot read the comment thread, it is retried later rather than judged as an edit that deleted the comments.
* **Re-checks catch what an author does afterwards.** A change is re-ingested on a schedule (15 min, 1 h, 6 h, 24 h by default) to see a deleted fork, a deleted account, or an edited body.

One poller thread and one worker thread. dspy's global configuration is bound to the thread that first set it up, so a run never shares a thread with another: with `workers=1` the worker thread runs the model itself, and with more each run goes to a process of its own (`spawn`, its own dspy), while the worker thread keeps every read and write of the state. Neither thread dies on an unexpected exception.

Pure stdlib + the package's own modules; no dspy at import (the default runner imports `cli` lazily).
"""

from __future__ import annotations

import json
import logging
import math
import multiprocessing
import os
import pickle
import re
import sqlite3
import threading
import time
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, Future, ProcessPoolExecutor, wait
from concurrent.futures.process import BrokenProcessPool
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from .actors import ActorStore
from .config import DetectConfig
from .dbutil import open_versioned
from .emit import emit_signal
from .ingest import GhApi, GhApiError, GhRaw, issue_event, pr_event, repo_workflows
from .normalize import OUTSIDER_ASSOCIATIONS, event_metadata
from .schema import IndicatorHit, at_signal_floor, severity_rank
from .snapshot import RecordingApi, SnapshotStore

log = logging.getLogger("diff_sentry.watch")

_WORKFLOWS_TTL_S = 3600     # a repository's workflow facts are read again after this
_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
# Re-check schedule: seconds after a change was first seen. Cut off at `recheck_s`.
_RECHECK_OFFSETS = (900, 3600, 6 * 3600, 24 * 3600)
_PAGE = 50
_MAX_PAGES = 40             # 2000 changes per listing per pass; a longer gap is reported as truncated
_MAX_FAILS = 6              # consecutive ingest failures before a change is parked as `error`
_MAX_ATTEMPTS = 10          # model runs a change gets when the run itself fails (an outage); ~4 h of backoff
_MAX_ALERT_TRIES = 20       # re-sends of an early alert the SIEM would not take
_ALERT_RETRIES_PER_POLL = 5  # so a hanging SIEM (15 s a POST) cannot stall polling for a whole backlog
_BACKOFF_CAP_S = 3600
SCHEMA_VERSION = 2
_DEAD = 2                   # `queue.claimed` value for a run that exhausted its attempts (kept for --requeue-failed)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS etags (url TEXT PRIMARY KEY, etag TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS watermarks (repo TEXT NOT NULL, kind TEXT NOT NULL, ts TEXT NOT NULL,
    PRIMARY KEY (repo, kind));
CREATE TABLE IF NOT EXISTS changes (
    repo TEXT NOT NULL, kind TEXT NOT NULL, number INTEGER NOT NULL, updated_at TEXT, content_sha256 TEXT,
    flags TEXT, revision INTEGER NOT NULL DEFAULT 0, run_id TEXT, state TEXT NOT NULL,
    first_seen TEXT NOT NULL, checks INTEGER NOT NULL DEFAULT 0, next_check_at TEXT, gone_at TEXT,
    fail_count INTEGER NOT NULL DEFAULT 0, retry_at TEXT, alerted TEXT, alert_pending TEXT,
    alert_fails INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (repo, kind, number));
CREATE TABLE IF NOT EXISTS queue (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT UNIQUE NOT NULL, priority INTEGER NOT NULL,
    enqueued_at TEXT NOT NULL, event_json TEXT NOT NULL, claimed INTEGER NOT NULL DEFAULT 0,
    attempts INTEGER NOT NULL DEFAULT 0, not_before TEXT);
CREATE TABLE IF NOT EXISTS deep_log (started_at TEXT NOT NULL);
"""


# ── configuration ─────────────────────────────────────────────────────────────────────────────────────

def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    try:
        return int(raw) if raw and raw.strip() else default
    except ValueError as exc:
        raise ValueError(f"{name}={raw!r} is not an integer") from exc


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    try:
        value = float(raw) if raw and raw.strip() else default
    except ValueError as exc:
        raise ValueError(f"{name}={raw!r} is not a number") from exc
    if not math.isfinite(value):
        raise ValueError(f"{name}={raw!r} must be finite")
    return value


def parse_repos(values: list[str]) -> tuple[str, ...]:
    """`owner/name` entries, deduplicated in order; comma-separated values and `#` comments are accepted."""
    out: list[str] = []
    for value in values:
        for line in value.splitlines():
            # comments are stripped per LINE, before splitting, or a comment's words would read as entries
            for part in re.split(r"[,\s]+", line.split("#", 1)[0]):
                if not part:
                    continue
                if not _REPO_RE.match(part):
                    raise ValueError(f"not an owner/name repository: {part!r}")
                if part not in out:
                    out.append(part)
    return tuple(out)


@dataclass(frozen=True)
class WatchConfig:
    repos: tuple[str, ...] = ()
    state_dir: str = "./output/state"
    out_dir: str = "./output"
    poll_interval_s: float = 60.0
    backfill_s: int = 0                 # on first sight of a repo: how far back to look (0 = only what is new)
    recheck_s: int = 24 * 3600          # re-examine a change for this long after it was first seen
    screen_only: bool = False           # deterministic tier only: never queue for the model
    # 0 / "info" = no cap and no gate. Time is the only cost, so these are OFF unless asked for.
    deep_min_severity: str = "info"     # a change whose screen is below this is not queued for the model
    max_queue: int = 0                  # 0 = unbounded; when set, the lowest priority is shed (recorded)
    max_deep_per_hour: int = 0          # 0 = unlimited model runs per hour
    rate_reserve: int = 200             # stop polling when the API's remaining budget falls below this
    workers: int = 1                    # model runs at once; above 1, each in a process of its own

    @classmethod
    def from_env(cls, **overrides: Any) -> WatchConfig:
        env = os.getenv("DS_WATCH_REPOS", "")
        base: dict[str, Any] = {
            "repos": parse_repos([env]) if env else (),
            "state_dir": os.getenv("DS_WATCH_STATE_DIR", "./output/state"),
            "poll_interval_s": _env_float("DS_WATCH_INTERVAL", 60.0),
            "backfill_s": int(_env_float("DS_WATCH_BACKFILL_HOURS", 0.0) * 3600),
            "recheck_s": int(_env_float("DS_WATCH_RECHECK_HOURS", 24.0) * 3600),
            "deep_min_severity": os.getenv("DS_WATCH_DEEP_MIN_SEVERITY", "info"),
            "max_queue": _env_int("DS_WATCH_MAX_QUEUE", 0),
            "max_deep_per_hour": _env_int("DS_WATCH_MAX_DEEP_PER_HOUR", 0),
            "rate_reserve": _env_int("DS_WATCH_RATE_RESERVE", 200),
            "workers": _env_int("DS_WATCH_WORKERS", 1),
        }
        base.update({k: v for k, v in overrides.items() if v is not None})
        return cls(**base)

    def __post_init__(self) -> None:
        if self.workers < 1:
            raise ValueError(f"workers must be at least 1, got {self.workers}")
        if severity_rank(self.deep_min_severity) < 0:
            raise ValueError(f"deep_min_severity must be one of info/low/medium/high/critical, "
                             f"got {self.deep_min_severity!r}")


# ── the list transport (ETag-aware) ───────────────────────────────────────────────────────────────────

@dataclass
class ListResult:
    status: int                         # 200, or 304 when the ETag still matches
    etag: str | None = None
    body: Any = None
    poll_interval: int | None = None    # GitHub's X-Poll-Interval, seconds, when it sends one
    rate_remaining: int | None = None
    rate_reset: int | None = None       # epoch seconds


ListApi = Callable[[str, "str | None"], ListResult]


def _gh_cli_list(timeout: float = 30.0) -> ListApi:
    """`gh api -i` with `If-None-Match`. A 304 makes `gh` exit non-zero but still print the status line and headers on stdout (verified against the live API), and a 304 does not spend rate limit."""
    def call(path: str, etag: str | None = None) -> ListResult:
        import subprocess  # host-side only; NEVER reached from inside the RLM

        cmd = ["gh", "api", "-i"] + (["-H", f"If-None-Match: {etag}"] if etag else []) + [path]
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        head, _, body = out.stdout.replace("\r\n", "\n").partition("\n\n")
        lines = head.splitlines()
        m = re.match(r"HTTP/\S+\s+(\d{3})", lines[0]) if lines else None
        if not m:
            raise GhApiError(f"gh api {path} gave no HTTP status (exit {out.returncode})", status=None)
        status = int(m.group(1))
        headers = {k.strip().lower(): v.strip() for k, _, v in (ln.partition(":") for ln in lines[1:])}

        def _int(key: str) -> int | None:
            v = headers.get(key, "")
            return int(v) if v.isdigit() else None

        common = {"poll_interval": _int("x-poll-interval"), "rate_remaining": _int("x-ratelimit-remaining"),
                  "rate_reset": _int("x-ratelimit-reset")}
        if status == 304:
            return ListResult(304, etag, None, **common)
        if status >= 400:
            try:
                detail = str(json.loads(body).get("message") or "")[:150]
            except (ValueError, AttributeError):
                detail = ""
            raise GhApiError(f"gh api {path} failed: HTTP {status}" + (f": {detail}" if detail else ""),
                             status=status)
        return ListResult(status, headers.get("etag"), json.loads(body), **common)

    return call


# ── durable state ─────────────────────────────────────────────────────────────────────────────────────

def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat(timespec="seconds")


def _backoff(fails: int) -> timedelta:
    return timedelta(seconds=min(60 * 2 ** max(fails - 1, 0), _BACKOFF_CAP_S))


class WatchState:
    def __init__(self, path: str, *, read_only: bool = False):
        self._lock = threading.RLock()
        self._db = open_versioned(path, _SCHEMA, SCHEMA_VERSION, "changes", read_only=read_only)

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def _q(self, sql: str, args: tuple = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self._db.execute(sql, args)
            self._db.commit()
            return cur

    def etag(self, url: str) -> str | None:
        with self._lock:
            row = self._db.execute("SELECT etag FROM etags WHERE url=?", (url,)).fetchone()
        return row["etag"] if row else None

    def set_etag(self, url: str, etag: str | None) -> None:
        if etag:
            self._q("INSERT INTO etags (url, etag) VALUES (?,?) ON CONFLICT(url) DO UPDATE SET etag=excluded.etag",
                    (url, etag))

    def watermark(self, repo: str, kind: str) -> str | None:
        with self._lock:
            row = self._db.execute("SELECT ts FROM watermarks WHERE repo=? AND kind=?", (repo, kind)).fetchone()
        return row["ts"] if row else None

    def set_watermark(self, repo: str, kind: str, ts: str) -> None:
        self._q("INSERT INTO watermarks (repo, kind, ts) VALUES (?,?,?) "
                "ON CONFLICT(repo, kind) DO UPDATE SET ts=MAX(watermarks.ts, excluded.ts)", (repo, kind, ts))

    def change(self, repo: str, kind: str, number: int) -> sqlite3.Row | None:
        with self._lock:
            return self._db.execute("SELECT * FROM changes WHERE repo=? AND kind=? AND number=?",
                                    (repo, kind, number)).fetchone()

    def upsert_change(self, repo: str, kind: str, number: int, **cols: Any) -> None:
        with self._lock:
            self._upsert(repo, kind, number, cols)
            self._db.commit()

    def _upsert(self, repo: str, kind: str, number: int, cols: dict[str, Any]) -> None:
        exists = self._db.execute("SELECT 1 FROM changes WHERE repo=? AND kind=? AND number=?",
                                  (repo, kind, number)).fetchone()
        if exists:
            sets = ", ".join(f"{k}=?" for k in cols)
            self._db.execute(f"UPDATE changes SET {sets} WHERE repo=? AND kind=? AND number=?",
                             (*cols.values(), repo, kind, number))
        else:
            names = ["repo", "kind", "number", *cols]
            marks = ",".join("?" * len(names))
            self._db.execute(f"INSERT INTO changes ({','.join(names)}) VALUES ({marks})",
                             (repo, kind, number, *cols.values()))

    def record_examined(self, repo: str, kind: str, number: int, cols: dict[str, Any], *,
                        queue: tuple[str, int, dict, datetime] | None = None, shed: str | None = None) -> None:
        """What one examination decided, in ONE transaction: the change row, its queue row (`queue`: run id, priority, event, time), and the change `shed` to make room. A failure writes none of them, so a change never reads `queued` without a queue row (the next poll would call it unchanged and never run it), and a worker never claims a queue row whose change has no row."""
        with self._lock:
            try:
                if shed is not None:
                    self._db.execute("DELETE FROM queue WHERE run_id=?", (shed,))
                    self._db.execute("UPDATE changes SET state='shed' WHERE run_id=?", (shed,))
                self._upsert(repo, kind, number, cols)
                if queue is not None:
                    run_id, priority, event, now = queue
                    self._db.execute(
                        "INSERT OR REPLACE INTO queue (run_id, priority, enqueued_at, event_json) VALUES (?,?,?,?)",
                        (run_id, priority, _iso(now), json.dumps(event, ensure_ascii=False, default=str)))
                self._db.commit()
            except BaseException:
                self._db.rollback()
                raise

    def due_checks(self, now: datetime) -> list[sqlite3.Row]:
        with self._lock:
            return self._db.execute(
                "SELECT * FROM changes WHERE next_check_at IS NOT NULL AND next_check_at<=? AND state!='gone' "
                "ORDER BY next_check_at", (_iso(now),)).fetchall()

    # ── the model queue: the table IS the queue, so a restart loses nothing ──
    def enqueue(self, run_id: str, priority: int, event: dict, now: datetime) -> None:
        self._q("INSERT OR REPLACE INTO queue (run_id, priority, enqueued_at, event_json) VALUES (?,?,?,?)",
                (run_id, priority, _iso(now), json.dumps(event, ensure_ascii=False, default=str)))

    def queue_size(self) -> int:
        """Changes waiting for the model (the one being run is not waiting)."""
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM queue WHERE claimed=0").fetchone()[0]

    def queued_run_ids(self) -> list[str]:
        """Runs waiting for the model (not the buried ones: those stay `failed` until `--requeue-failed`)."""
        with self._lock:
            return [r["run_id"] for r in self._db.execute("SELECT run_id FROM queue WHERE claimed=0").fetchall()]

    def lowest(self) -> sqlite3.Row | None:
        with self._lock:
            return self._db.execute("SELECT run_id, priority FROM queue WHERE claimed=0 "
                                    "ORDER BY priority ASC, seq DESC LIMIT 1").fetchone()

    def claim(self, now: datetime) -> sqlite3.Row | None:
        """Take the most urgent change that is ready. The row stays until `complete`, so a crash mid-run leaves it for `requeue_claimed` instead of losing the change. Claiming counts as an attempt, so an input that kills the process cannot loop forever across restarts."""
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM queue WHERE claimed=0 AND (not_before IS NULL OR not_before<=?) "
                "ORDER BY priority DESC, seq ASC LIMIT 1", (_iso(now),)).fetchone()
            if row:
                self._db.execute("UPDATE queue SET claimed=1, attempts=attempts+1 WHERE run_id=?", (row["run_id"],))
                self._db.commit()
            return row

    def unclaim(self, run_id: str) -> None:
        self._q("UPDATE queue SET claimed=0, attempts=MAX(attempts-1, 0) WHERE run_id=? AND claimed=1", (run_id,))

    def complete(self, run_id: str) -> None:
        self._q("DELETE FROM queue WHERE run_id=?", (run_id,))

    def retry(self, run_id: str, attempts: int, not_before: datetime) -> None:
        self._q("UPDATE queue SET claimed=0, attempts=?, not_before=? WHERE run_id=?",
                (attempts, _iso(not_before), run_id))

    def bury(self, run_id: str) -> None:
        """Keep a run that exhausted its attempts (its event included) so `--requeue-failed` can bring it back."""
        self._q("UPDATE queue SET claimed=? WHERE run_id=?", (_DEAD, run_id))

    def requeue_claimed(self) -> int:
        """Put back what a previous process was running when it stopped, unless it has used up its attempts."""
        self._q("UPDATE queue SET claimed=? WHERE claimed=1 AND attempts>=?", (_DEAD, _MAX_ATTEMPTS))
        return self._q("UPDATE queue SET claimed=0 WHERE claimed=1").rowcount

    def requeue_dead(self) -> list[str]:
        with self._lock:
            ids = [r["run_id"] for r in self._db.execute("SELECT run_id FROM queue WHERE claimed=?", (_DEAD,))]
            self._db.execute("UPDATE queue SET claimed=0, attempts=0, not_before=NULL WHERE claimed=?", (_DEAD,))
            self._db.commit()
        return ids

    def pending_alerts(self) -> list[sqlite3.Row]:
        with self._lock:
            return self._db.execute("SELECT * FROM changes WHERE alert_pending IS NOT NULL").fetchall()

    def drop(self, run_id: str) -> None:
        self._q("DELETE FROM queue WHERE run_id=?", (run_id,))

    def set_state_of_run(self, run_id: str, state: str) -> None:
        self._q("UPDATE changes SET state=? WHERE run_id=?", (state, run_id))

    def note_deep(self, now: datetime) -> None:
        self._q("INSERT INTO deep_log (started_at) VALUES (?)", (_iso(now),))
        self._q("DELETE FROM deep_log WHERE started_at<?", (_iso(now - timedelta(hours=2)),))

    def deep_last_hour(self, now: datetime) -> list[str]:
        with self._lock:
            rows = self._db.execute("SELECT started_at FROM deep_log WHERE started_at>? ORDER BY started_at",
                                    (_iso(now - timedelta(hours=1)),)).fetchall()
        return [r["started_at"] for r in rows]

    def stats(self) -> dict:
        with self._lock:
            states = {r["state"]: r["n"] for r in self._db.execute(
                "SELECT state, COUNT(*) AS n FROM changes GROUP BY state")}
            queued = self._db.execute("SELECT COUNT(*) FROM queue WHERE claimed=0").fetchone()[0]
            dead = self._db.execute("SELECT COUNT(*) FROM queue WHERE claimed=?", (_DEAD,)).fetchone()[0]
            revised = self._db.execute("SELECT COUNT(*) FROM changes WHERE revision>0").fetchone()[0]
        return {"changes": sum(states.values()), "states": states, "queued": queued, "failed_runs_kept": dead,
                "revised": revised}


# ── the watcher ───────────────────────────────────────────────────────────────────────────────────────

@dataclass
class PollReport:
    listed: int = 0
    examined: int = 0
    new: int = 0
    revised: int = 0
    unchanged: int = 0
    gone: int = 0
    alerts: int = 0
    queued: int = 0
    shed: int = 0
    errors: list[str] = field(default_factory=list)
    truncated: list[str] = field(default_factory=list)   # listings deeper than one pass could read
    rate_limited: bool = False


def run_id_for(repo: str, kind: str, number: int, revision: int) -> str:
    """`owner__name-pr-7` (`-r1` for a later revision). Owners cannot contain `_`, so the first `__` always splits owner from name and two different repositories can never share an id (`a-b/c` vs `a/b-c`)."""
    base = f"{repo.replace('/', '__')}-{'pr' if kind == 'pull_request' else 'issue'}-{number}"
    return base if revision == 0 else f"{base}-r{revision}"


def _priority(hits: list[IndicatorHit], prov: dict) -> int:
    """Screen order for the model queue: severity first, then how many DISTINCT rules fired (one rule matching fifteen times is one piece of evidence), then whether the author is an outsider. It only orders the queue: with no cap set, every change is still run."""
    top = max((severity_rank(h.severity) for h in hits), default=0)
    age = prov.get("author_account_age_days")
    outsider = (str(prov.get("author_association") or "").upper() in OUTSIDER_ASSOCIATIONS
                or (isinstance(age, int) and not isinstance(age, bool) and age < 30))
    return max(top, 0) * 1000 + min(len({h.rule for h in hits}), 99) * 10 + (5 if outsider else 0)


def _flags(event: dict) -> str:
    """The provenance facts that can change without the content changing (the author or fork disappearing)."""
    prov = event.get("provenance") or {}
    return json.dumps({k: prov.get(k) for k in ("author_not_found", "head_repo_deleted", "head_sha")},
                      sort_keys=True)


class _InstanceLock:
    """One `watch` per state directory. Two processes on the same files would each requeue the other's running change and could run one run id twice. An advisory `flock`; a platform without `fcntl` runs unguarded."""

    def __init__(self, state_dir: str):
        self._path = os.path.join(state_dir, "watch.lock")
        self._fh = None

    def acquire(self) -> None:
        try:
            import fcntl
        except ImportError:
            return
        self._fh = open(self._path, "a")  # noqa: SIM115 (held for the life of the lock)
        try:
            fcntl.flock(self._fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self._fh.close()
            self._fh = None
            raise RuntimeError(f"another diff-sentry watch is already using {os.path.dirname(self._path)}") from exc

    def release(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None


def requeue_failed(state_dir: str) -> list[str]:
    """Bring back every run that exhausted its attempts (a model that was down for hours). Returns their ids."""
    lock = _InstanceLock(state_dir)
    lock.acquire()
    state = WatchState(os.path.join(state_dir, "watch.db"))
    try:
        ids = state.requeue_dead()
        for run_id in ids:
            state.set_state_of_run(run_id, "queued")
        return ids
    finally:
        state.close()
        lock.release()


class Watcher:
    def __init__(
        self,
        config: WatchConfig,
        detect_config: DetectConfig | None = None,
        *,
        list_api: ListApi | None = None,
        api: GhApi | None = None,
        raw: GhRaw | None = None,
        runner: Callable[..., Any] | None = None,
        screener: Callable[..., Any] | None = None,
        poster: Callable[[str, dict, dict], int] | None = None,
        emit: bool = True,
        clock: Callable[[], datetime] | None = None,
        history: Callable[[str, datetime | None], dict] | None = None,
    ):
        self.config = config
        self._history = history
        self._workflows: dict[str, tuple[float, dict]] = {}     # repo -> (when read, its workflow facts)
        self.detect_config = detect_config or (DetectConfig.screen_from_env() if config.screen_only
                                               else DetectConfig.from_env())
        if config.workers > 1 and not config.screen_only:       # checked before any file is opened
            try:
                pickle.dumps((runner, poster, self.detect_config))
            except Exception as exc:
                raise ValueError("workers > 1 runs the model in other processes: the runner and the poster must "
                                 f"be importable functions, not closures ({exc})") from exc
        self._list_api = list_api or _gh_cli_list()
        self._api = api
        self._raw = raw
        self._runner = runner
        self._screener = screener
        self._poster = poster
        self._emit = emit
        self._clock = clock or (lambda: datetime.now(UTC))
        os.makedirs(config.state_dir, exist_ok=True)
        self.state = WatchState(os.path.join(config.state_dir, "watch.db"))
        self.actors = ActorStore(os.path.join(config.state_dir, "actors.db"), clock=self._clock)
        self.snapshots = SnapshotStore(os.path.join(config.state_dir, "snapshots"))
        self._lock = _InstanceLock(config.state_dir)
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._interval = config.poll_interval_s
        self._rate_wait_until: datetime | None = None
        self._rate_left: int | None = None                 # the API budget we believe is left
        self._rate_reset: datetime | None = None

    def recover(self) -> None:
        """Take the state directory's lock and put back whatever a previous process was judging when it stopped. `serve()` and `watch --once` call this; a read-only look at the state does not, so it cannot steal a running change from a live watcher."""
        self._lock.acquire()
        n = self.state.requeue_claimed()
        if n:
            log.info("requeued %d change(s) a previous run was judging when it stopped", n)
            for run_id in self.state.queued_run_ids():
                self.state.set_state_of_run(run_id, "queued")

    # ── polling ────────────────────────────────────────────────────────────────────────────────────

    def poll_once(self) -> PollReport:
        """One pass: list each repository (cheap, ETag), examine what is new or updated, then the re-checks that have come due. Never raises: a repository that fails is reported and the pass continues."""
        report = PollReport()
        now = self._clock()
        if self._rate_wait_until and now < self._rate_wait_until:
            report.rate_limited = True
            return report
        if self._rate_wait_until:                      # the wait is over: the budget is whatever GitHub says next
            self._rate_wait_until, self._rate_left = None, None
        self._retry_alerts(report)
        for repo in self.config.repos:
            for kind in ("pull_request", "issue"):
                try:
                    self._poll_list(repo, kind, report)
                except Exception as exc:  # noqa: BLE001 (one repo's failure must not stop the others)
                    if self._is_rate_limit(exc):
                        self._on_rate_limited(report)          # the list call itself was refused: wait, do not spin
                        return report
                    report.errors.append(f"{repo} {kind}: {type(exc).__name__}: {exc}")
                    log.warning("poll %s %s failed: %s", repo, kind, exc)
                if report.rate_limited:
                    return report
        try:
            due = self.state.due_checks(self._clock())
        except Exception as exc:  # noqa: BLE001
            report.errors.append(f"due re-checks: {type(exc).__name__}: {exc}")
            return report
        for row in due:
            if self._rate_low(report):
                break
            try:
                self._examine(row["repo"], row["kind"], row["number"], report, reason="recheck")
            except Exception as exc:  # noqa: BLE001
                if self._is_rate_limit(exc):
                    self._on_rate_limited(report)
                    break
                report.errors.append(f"recheck {row['repo']}#{row['number']}: {type(exc).__name__}: {exc}")
                log.warning("recheck %s#%s failed: %s", row["repo"], row["number"], exc)
                self._note_recheck_failure(row)
        return report

    def _list_path(self, repo: str, kind: str, page: int) -> str:
        endpoint = "pulls" if kind == "pull_request" else "issues"
        suffix = f"&page={page}" if page > 1 else ""
        return f"repos/{repo}/{endpoint}?state=all&sort=updated&direction=desc&per_page={_PAGE}{suffix}"

    def _poll_list(self, repo: str, kind: str, report: PollReport) -> None:
        mark = self.state.watermark(repo, kind)
        if mark is None:
            mark = _iso(self._clock() - timedelta(seconds=self.config.backfill_s))
            self.state.set_watermark(repo, kind, mark)
        newest = mark
        pending: list[tuple[str, int]] = []
        first: tuple[str, str | None] | None = None      # page 1's path and ETag, kept once it is all handled
        reached_mark = False
        full_last_page = False
        for page in range(1, _MAX_PAGES + 1):
            path = self._list_path(repo, kind, page)
            res = self._list_api(path, self.state.etag(path) if page == 1 else None)
            self._note_rate(res, report)
            if res.status == 304 or not isinstance(res.body, list):
                reached_mark = True
                break
            if page == 1:
                first = (path, res.etag)
            for item in res.body:
                if not isinstance(item, dict) or not isinstance(item.get("number"), int):
                    continue
                if kind == "issue" and item.get("pull_request"):
                    continue          # the issues endpoint also lists PRs; the pulls listing owns those
                updated = str(item.get("updated_at") or "")
                if updated and updated < mark:
                    reached_mark = True
                    break
                report.listed += 1
                row = self.state.change(repo, kind, item["number"])
                if row is None or row["updated_at"] != updated:
                    pending.append((updated, item["number"]))
                newest = max(newest, updated)
            full_last_page = len(res.body) >= _PAGE
            if reached_mark or not full_last_page:
                reached_mark = True
                break
        if not reached_mark and full_last_page:
            # The listing ran deeper than one pass reads. What is beyond it is not examined; say so.
            report.truncated.append(f"{repo} {kind}")
            log.warning("listing of %s %s is deeper than %d changes — older updates were not examined",
                        repo, kind, _MAX_PAGES * _PAGE)
        # Oldest first: the listing is newest-first, but correlation reads what came BEFORE a change (an account's earlier sightings, a payload host's earlier use), so a burst must be examined in the order it happened or its last member would see none of the others.
        held: str | None = None
        now = self._clock()
        for updated, number in sorted(pending):
            row = self.state.change(repo, kind, number)
            if row is not None and row["retry_at"] and row["retry_at"] > _iso(now):
                held = updated if held is None else min(held, updated)        # still backing off
                continue
            if self._rate_low(report):
                held = updated if held is None else min(held, updated)          # out of budget: keep the rest
                break
            try:
                self._examine(repo, kind, number, report, reason="listed")
            except Exception as exc:  # noqa: BLE001 (one bad change must not block the ones behind it)
                if self._is_rate_limit(exc):
                    self._on_rate_limited(report)          # GitHub said no: wait it out, do NOT count a failure
                    held = updated if held is None else min(held, updated)
                    break
                report.errors.append(f"{repo} {kind} #{number}: {type(exc).__name__}: {exc}")
                log.warning("examine %s %s#%s failed: %s", kind, repo, number, exc)
                if self._note_failure(repo, kind, number, updated, now):
                    held = updated if held is None else min(held, updated)
        # A failed change keeps the watermark from passing it AND the ETag from being stored (or the next listing would answer 304 and it would never be retried); the others behind it are recognised by their stored `updated_at` and skipped.
        if first is not None and held is None:
            self.state.set_etag(*first)
        self.state.set_watermark(repo, kind, min(newest, held) if held else newest)

    def _note_failure(self, repo: str, kind: str, number: int, updated: str, now: datetime) -> bool:
        """Record an ingest failure. Returns True while the change should still be retried; after `_MAX_FAILS` it is parked as `error` (logged, and no longer holding the watermark)."""
        row = self.state.change(repo, kind, number)
        fails = (row["fail_count"] if row else 0) + 1
        fresh = {} if row else {"first_seen": _iso(now)}
        if fails >= _MAX_FAILS:
            log.error("%s %s#%s failed %d times — parked as error", kind, repo, number, fails)
            self.state.upsert_change(repo, kind, number, state="error", updated_at=updated, fail_count=fails,
                                     retry_at=None, **fresh)
            return False
        self.state.upsert_change(repo, kind, number, fail_count=fails, retry_at=_iso(now + _backoff(fails)),
                                 **({} if row else {"state": "retry", **fresh}))
        return True

    def _note_recheck_failure(self, row: sqlite3.Row) -> None:
        fails = row["fail_count"] + 1
        nxt = None if fails >= _MAX_FAILS else _iso(self._clock() + _backoff(fails))
        self.state.upsert_change(row["repo"], row["kind"], row["number"], fail_count=fails, next_check_at=nxt)

    def _note_rate(self, res: ListResult, report: PollReport) -> None:
        if res.poll_interval:
            self._interval = max(self.config.poll_interval_s, float(res.poll_interval))
        if res.rate_remaining is not None:
            self._rate_left = res.rate_remaining
            self._rate_reset = datetime.fromtimestamp(res.rate_reset, UTC) if res.rate_reset else None
        self._rate_low(report)

    def _rate_low(self, report: PollReport) -> bool:
        """Whether the API budget we believe is left is under the reserve. The list responses report it; every ingest then spends about ten calls that report nothing, so `_ingest` subtracts what it used."""
        if self._rate_left is None or self._rate_left >= self.config.rate_reserve:
            return False
        self._rate_wait_until = self._rate_reset or self._clock() + timedelta(minutes=15)
        report.rate_limited = True
        log.warning("rate limit low (~%s left) — pausing until %s", self._rate_left, _iso(self._rate_wait_until))
        return True

    @staticmethod
    def _is_rate_limit(exc: Exception) -> bool:
        return isinstance(exc, GhApiError) and (exc.status == 429 or (exc.status == 403 and
                                                                     "rate limit" in str(exc).lower()))

    def _on_rate_limited(self, report: PollReport) -> None:
        """GitHub refused a call for rate limiting. Wait for the reset it reports (the `rate_limit` endpoint is free) or 15 minutes; a refusal is not a failure of the change, so it is never counted toward `error`."""
        reset = None
        try:
            data = (self._api or _default_api())("rate_limit")
            reset = datetime.fromtimestamp(int(data["resources"]["core"]["reset"]), UTC)
        except Exception:  # noqa: BLE001,S110 (best-effort; fall back to a fixed wait)
            pass
        self._rate_wait_until = reset if reset and reset > self._clock() else self._clock() + timedelta(minutes=15)
        report.rate_limited = True
        log.warning("GitHub rate-limited a request — pausing until %s", _iso(self._rate_wait_until))

    def _retry_alerts(self, report: PollReport) -> None:
        """Send again the early alerts a SIEM outage swallowed, from the screened record already on disk."""
        from .schema import DetectionResponse

        if not self._emit:
            return
        for row in self.state.pending_alerts()[:_ALERT_RETRIES_PER_POLL]:
            run_id = row["alert_pending"]
            try:
                with open(os.path.join(self.config.out_dir, "screened", f"{run_id}.json"), encoding="utf-8") as fh:
                    resp = DetectionResponse.model_validate_json(fh.read())
            except (OSError, ValueError):
                log.error("early alert for %s cannot be re-sent: its screened record is unreadable", run_id)
                self.state.upsert_change(row["repo"], row["kind"], row["number"], alert_pending=None)
                continue
            result = emit_signal(resp, self.detect_config, poster=self._poster, stage="screen")
            if result.ok:
                alerted = set(json.loads(row["alerted"] or "[]")) | {
                    h.id for h in resp.indicators if at_signal_floor(h.severity)}
                self.state.upsert_change(row["repo"], row["kind"], row["number"], alert_pending=None,
                                         alert_fails=0, alerted=json.dumps(sorted(alerted)))
                report.alerts += 1
            elif result.skipped_reason is not None:
                self.state.upsert_change(row["repo"], row["kind"], row["number"], alert_pending=None, alert_fails=0)
            elif row["alert_fails"] + 1 >= _MAX_ALERT_TRIES:
                log.error("early alert for %s failed %d times — giving up", run_id, _MAX_ALERT_TRIES)
                self.state.upsert_change(row["repo"], row["kind"], row["number"], alert_pending=None)
            else:
                self.state.upsert_change(row["repo"], row["kind"], row["number"],
                                         alert_fails=row["alert_fails"] + 1)

    # ── examining one change ───────────────────────────────────────────────────────────────────────

    def _repo_workflows(self, repo: str, call) -> dict:
        """The repository's workflow facts (`ingest.repo_workflows`), read once an hour: they change with a merge, not with each change."""
        now = time.monotonic()
        cached = self._workflows.get(repo)
        if cached is None or now - cached[0] > _WORKFLOWS_TTL_S:
            cached = (now, repo_workflows(repo, call))
            self._workflows[repo] = cached
        return cached[1]

    def _ingest(self, repo: str, kind: str, number: int) -> tuple[dict, dict]:
        rec = RecordingApi(self._api or _default_api())
        if kind == "pull_request":
            event = pr_event(repo, number, api=rec, raw=self._raw if self._raw is not None
                             else (None if self._api is not None else _default_raw()), history=self._history,
                             workflows=self._repo_workflows)
        else:
            event = issue_event(repo, number, api=rec, history=self._history, workflows=self._repo_workflows)
        if self._rate_left is not None:
            self._rate_left -= rec.calls
        return event, rec.records

    def _examine(self, repo: str, kind: str, number: int, report: PollReport, *, reason: str) -> None:
        from .cli import _baseline_indicators
        from .indicators import scan_change

        now = self._clock()
        prior_row = self.state.change(repo, kind, number)
        try:
            event, raw = self._ingest(repo, kind, number)
        except GhApiError as exc:
            if exc.status == 404 and prior_row is not None:
                # The author took it down after we captured it. The archive already holds the original.
                self.state.upsert_change(repo, kind, number, state="gone", gone_at=_iso(now), next_check_at=None)
                report.gone += 1
                kept = bool(self.snapshots.history(repo, kind, number))
                log.info("%s %s#%s is gone (404)%s", kind, repo, number,
                         " — the original is in the archive" if kept else " — and was never archived")
                return
            raise
        report.examined += 1

        prov0 = event.get("provenance") or {}
        digest = event_metadata(event)["content_sha256"]
        flags = _flags(event)
        updated = str(prov0.get("event_updated_at") or "")
        first_seen = prior_row["first_seen"] if prior_row else _iso(now)
        checks = (prior_row["checks"] if prior_row else 0) + (1 if reason == "recheck" else 0)
        next_check = self._next_check(first_seen, checks)
        healthy = {"fail_count": 0, "retry_at": None}

        if (prior_row is not None and prior_row["run_id"] and prov0.get("comments_incomplete")
                and prior_row["state"] != "gone"):
            # The comment thread could not be read this time. Judging that as "the comments are gone" would invent an edit, so keep what we have and look again later.
            self.state.upsert_change(repo, kind, number, checks=checks, next_check_at=next_check)
            report.unchanged += 1
            log.info("%s %s#%s: comments unreadable this pass — not judged as an edit", kind, repo, number)
            return

        if prior_row is not None and prior_row["state"] != "gone" and prior_row["content_sha256"] == digest \
                and prior_row["flags"] == flags:
            # Same content, same fork/author facts: activity that changes nothing we judge. Nothing to run.
            self.state.upsert_change(repo, kind, number, updated_at=updated or prior_row["updated_at"],
                                     checks=checks, next_check_at=next_check, **healthy)
            report.unchanged += 1
            return

        revision = (prior_row["revision"] + 1) if prior_row is not None and prior_row["run_id"] else 0
        run_id = run_id_for(repo, kind, number, revision)
        capture = self.snapshots.put(repo=repo, kind=kind, number=number, event=event, raw=raw,
                                     reason="first_seen" if revision == 0 else "changed", captured_at=now)

        content_hits = scan_change(event)
        facts, prior_hits = self.actors.correlate(event, content_hits)
        event.setdefault("provenance", {}).update(facts)
        if prior_hits:
            event["prior_indicators"] = prior_hits
        history = self.actors.history(event)
        if history:
            event["actor_history"] = history
        baseline = _baseline_indicators(event, content_hits=content_hits)   # the text is scanned once, not thrice
        hits = [IndicatorHit(**h) for h in baseline]
        self.actors.record(event, run_id=run_id, hits=hits, content_hits=content_hits,
                           snapshot_sha=capture.sha256)

        if revision:
            report.revised += 1
        else:
            report.new += 1

        # Alert early only for floor-level evidence no earlier revision already alerted: an edit or a comment on a change that was already flagged must not page the SIEM again with the same finding. Evidence counts as alerted only once the SIEM accepted it; a refused or failed POST is retried each poll.
        floor_ids = {h.id for h in hits if at_signal_floor(h.severity)}
        alerted = set(json.loads(prior_row["alerted"] or "[]")) if prior_row is not None else set()
        new_evidence = self._emit and bool(floor_ids - alerted)
        screened = self._screen(event, run_id, emit=new_evidence, baseline=baseline)
        result = getattr(screened, "emit", None)
        pending = None
        if new_evidence:
            if result is not None and result.ok:
                alerted |= floor_ids
                report.alerts += 1
            elif result is not None and result.skipped_reason is not None:
                pass               # no SIEM configured: nothing was sent, so nothing counts as sent
            else:
                pending = run_id   # refused, unreachable, or the screen itself failed: send again next poll
                log.warning("early alert for %s was not delivered — will retry", run_id)

        state, prio, victim = "screened", 0, None
        if not self.config.screen_only and self._wants_model(hits):
            state, prio, victim = self._admit(run_id, hits, event)
        self.state.record_examined(
            repo, kind, number,
            {"updated_at": updated, "content_sha256": digest, "flags": flags, "revision": revision, "run_id": run_id,
             "state": state, "first_seen": first_seen, "checks": checks, "next_check_at": next_check, "gone_at": None,
             "alerted": json.dumps(sorted(alerted)), "alert_pending": pending, "alert_fails": 0, **healthy},
            queue=(run_id, prio, event, now) if state == "queued" else None, shed=victim)
        if victim is not None or state == "shed":
            report.shed += 1
            log.info("queue full — shed %s", victim or run_id)
        report.queued += state == "queued"
        log.info("%s %s#%s rev=%d sev=%s hits=%d → %s", kind, repo, number, revision,
                 max((h.severity for h in hits), key=severity_rank, default="info"), len(hits), state)

    def _next_check(self, first_seen: str, checks: int) -> str | None:
        """The next scheduled re-check after `checks` have run: the first offset from `first_seen` that is still in the future (a poller that was down does not owe every missed check at once), or None when the schedule is spent."""
        offsets = [o for o in _RECHECK_OFFSETS if o <= self.config.recheck_s][checks:]
        base, now = datetime.fromisoformat(first_seen), self._clock()
        for offset in offsets:
            due = base + timedelta(seconds=offset)
            if due > now:
                return _iso(due)
        return None

    def _screen(self, event: dict, run_id: str, *, emit: bool, baseline: list[dict] | None = None):
        screener = self._screener
        if screener is None:
            from .cli import screen as screener
        try:
            extra = {"baseline": baseline} if baseline is not None and _accepts(screener, "baseline") else {}
            return screener(event, run_id=run_id, outdir=self.config.out_dir, config=self.detect_config,
                            emit=emit, poster=self._poster, **extra)
        except Exception as exc:  # noqa: BLE001 (the screen record is best-effort; the change is still queued)
            log.warning("screen %s failed: %s", run_id, exc)
            return None

    def _wants_model(self, hits: list[IndicatorHit]) -> bool:
        top = max((severity_rank(h.severity) for h in hits), default=0)
        return top >= severity_rank(self.config.deep_min_severity)

    def _admit(self, run_id: str, hits: list[IndicatorHit], event: dict) -> tuple[str, int, str | None]:
        """Whether the change joins the queue (`queued`) or is shed (`shed`), its priority, and the less urgent change to shed to make room when the queue is capped. Decides only: `record_examined` writes it all."""
        prio = _priority(hits, event.get("provenance") or {})
        cap = self.config.max_queue
        if cap and self.state.queue_size() >= cap:
            worst = self.state.lowest()
            if worst is not None and worst["priority"] < prio:
                return "queued", prio, worst["run_id"]      # make room by shedding the least urgent
            return "shed", prio, None
        return "queued", prio, None

    # ── the model worker ───────────────────────────────────────────────────────────────────────────

    def _may_run(self) -> bool:
        cap = self.config.max_deep_per_hour
        return not cap or len(self.state.deep_last_hour(self._clock())) < cap

    def _claim(self) -> tuple[sqlite3.Row, dict] | None:
        """Take the highest-priority ready change, unless the hourly cap is reached, and mark it running."""
        if not self._may_run():
            return None
        row = self.state.claim(self._clock())
        if row is None:
            return None
        try:
            event = json.loads(row["event_json"])
            self._mark(row["run_id"], event, "running")
            self.state.note_deep(self._clock())
        except Exception:
            self.state.unclaim(row["run_id"])            # nothing ran: give back the attempt it counted
            raise
        return row, event

    def _mark(self, run_id: str, event: dict, state: str) -> None:
        """Set the change's state, but only for its latest revision: an older one finishing, failing or starting again is not the state of the change."""
        repo, kind, number = event["repo"], event["kind"], event["number"]
        latest = self.state.change(repo, kind, number)
        if latest is None or latest["run_id"] == run_id:
            self.state.upsert_change(repo, kind, number, state=state)

    def _run_args(self, run_id: str) -> tuple:
        return (self._runner, run_id, self.config.out_dir, self.detect_config, self._emit, self._poster)

    def run_next(self) -> str | None:
        """Run the highest-priority ready change through the model, in this thread. Returns its run id, or None when nothing is ready or the hourly cap is reached. A run that itself fails (a model outage) is retried with backoff up to `_MAX_ATTEMPTS` times before the change is marked `failed`."""
        claimed = self._claim()
        if claimed is None:
            return None
        row, event = claimed
        self._settle(row, event, _run_model(event, *self._run_args(row["run_id"])))
        return row["run_id"]

    def _settle(self, row: sqlite3.Row, event: dict, outcome: tuple | None) -> None:
        """Record what a run produced: the verdict onto the sighting and the queue row done, or a retry with backoff, or after `_MAX_ATTEMPTS` the change buried as `failed`. `outcome` is `_outcome`'s tuple."""
        run_id = row["run_id"]
        try:
            if outcome is not None:
                verdict, signal, top = outcome
                self.actors.finalize(run_id, verdict=verdict, signal=signal, max_severity=top)
                self._mark(run_id, event, "done")
                self.state.complete(run_id)
            elif row["attempts"] + 1 < _MAX_ATTEMPTS:
                delay = _backoff(row["attempts"] + 1)
                self.state.retry(run_id, row["attempts"] + 1, self._clock() + delay)
                self._mark(run_id, event, "queued")
                log.warning("run %s failed (attempt %d) — retrying in %s", run_id, row["attempts"] + 1, delay)
            else:
                self._mark(run_id, event, "failed")
                self.state.bury(run_id)
                log.error("run %s failed %d times — marked failed (kept; `watch --requeue-failed` brings it back)",
                          run_id, _MAX_ATTEMPTS)
        except Exception:
            # The run itself happened; only the bookkeeping failed. Do not leave the row claimed for ever, and do not leave the change reading `running`.
            log.exception("bookkeeping for %s failed", run_id)
            self.state.complete(run_id)
            try:
                self.state.set_state_of_run(run_id, "done")
            except Exception:  # noqa: BLE001,S110 (the store itself is failing; the log line above is the record)
                pass

    # ── several runs at once: one process each ──

    def _new_pool(self) -> ProcessPoolExecutor:
        return ProcessPoolExecutor(max_workers=self.config.workers, mp_context=multiprocessing.get_context("spawn"),
                                   initializer=_child_init, initargs=(logging.getLogger().level, os.getpid()))

    def _pump(self, pool: ProcessPoolExecutor, inflight: dict[Future, tuple[sqlite3.Row, dict]],
              budget: int | None) -> tuple[int, bool]:
        """Fill the free processes with ready changes (at most `budget` more), then settle whatever finished within a second. Returns how many it started and whether the pool broke (a child died)."""
        started = 0
        while len(inflight) < self.config.workers and (budget is None or started < budget):
            try:
                claimed = self._claim()
            except Exception:
                log.exception("claiming the next change failed")             # the runs in flight go on
                break
            if claimed is None:
                break
            row, event = claimed
            try:
                inflight[pool.submit(_run_model, event, *self._run_args(row["run_id"]))] = claimed
            except Exception as exc:  # noqa: BLE001 (BrokenProcessPool, or a spawn that failed: ENOMEM, EMFILE)
                log.warning("could not start %s: %s", row["run_id"], exc)
                self._settle(row, event, None)
                return started, True                         # start over with a new pool, without waiting
            started += 1
        if not inflight:
            return started, False
        done, _ = wait(list(inflight), timeout=1, return_when=FIRST_COMPLETED)
        broken = False
        for fut in done:
            row, event = inflight.pop(fut)
            outcome, died = _result(fut, row["run_id"])
            broken = broken or died
            self._settle(row, event, outcome)
        return started, broken

    def _settle_all(self, inflight: dict[Future, tuple[sqlite3.Row, dict]]) -> None:
        """Settle every run still in flight from what its future holds: a finished one keeps its result, the rest count as a failed attempt (their process is gone or about to be)."""
        for fut, (row, event) in list(inflight.items()):
            inflight.pop(fut)
            self._settle(row, event, _result(fut, row["run_id"])[0] if fut.done() else None)

    def _run_pool(self, limit: int | None, *, serving: bool = False) -> int:
        """Run ready changes `workers` at a time until none is left and none is running (`drain`, at most `limit`), or, `serving`, until `stop()`. Returns how many it started. A stop or an interrupt leaves the runs it cuts off claimed for `recover()`; an error settles them, so a long-lived watcher strands nothing."""
        pool = self._new_pool()
        inflight: dict[Future, tuple[sqlite3.Row, dict]] = {}
        ran = 0
        failed = False
        try:
            while not self._stop.is_set():
                budget = None if limit is None else limit - ran
                started, broken = self._pump(pool, inflight, budget)
                ran += started
                if broken:                                   # every run in a broken pool fails; settle and start over
                    self._settle_all(inflight)
                    _terminate(pool)
                    pool = self._new_pool()
                    continue
                if not inflight:
                    if not serving:
                        break
                    self._wake.wait(timeout=30)
                    self._wake.clear()
        except Exception:
            failed = True
            raise
        finally:
            _terminate(pool)
            # An error settles what it cut off; a stop or an interrupt (Ctrl-C) leaves it claimed for `recover()`.
            if failed and inflight and not self._stop.is_set():
                self._settle_all(inflight)
        return ran

    def drain(self, limit: int | None = None) -> int:
        """Run ready changes until none is left (or `limit`, or the hourly cap). Returns how many ran."""
        if self.config.workers > 1:
            return self._run_pool(limit)
        ran = 0
        while (limit is None or ran < limit) and self.run_next() is not None:
            ran += 1
        return ran

    # ── serving ────────────────────────────────────────────────────────────────────────────────────

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()

    def serve(self) -> None:
        """Poll and run until `stop()`. The poller and the model worker are separate threads, so a slow local model never delays the screen or the early alert (a slow SIEM endpoint still delays polling: the POST is synchronous, bounded by its 15 s timeout)."""
        self.recover()
        worker = threading.Thread(target=self._work_loop if self.config.workers == 1 else self._pool_loop,
                                  name="diff-sentry-worker", daemon=True)
        if not self.config.screen_only:
            worker.start()
        try:
            while not self._stop.is_set():
                try:
                    report = self.poll_once()
                except Exception:
                    log.exception("poll pass failed")
                    report = PollReport()
                if report.new or report.revised or report.truncated:
                    self._wake.set()
                    log.info("poll: listed=%d new=%d revised=%d alerts=%d queued=%d shed=%d gone=%d "
                             "errors=%d truncated=%d", report.listed, report.new, report.revised,
                             report.alerts, report.queued, report.shed, report.gone, len(report.errors),
                             len(report.truncated))
                wait = self._interval
                if self._rate_wait_until:
                    wait = max(wait, (self._rate_wait_until - self._clock()).total_seconds())
                self._stop.wait(min(max(1.0, wait), 86_400.0))      # never longer than a day: Event.wait overflows
        finally:
            self.stop()
            if worker.is_alive():
                worker.join(timeout=5)

    def _work_loop(self) -> None:
        while not self._stop.is_set():
            try:
                ran = self.run_next()
            except Exception:
                log.exception("worker pass failed")
                self._stop.wait(5)
                continue
            if ran is None:
                self._wake.wait(timeout=30)
                self._wake.clear()

    def _pool_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._run_pool(None, serving=True)
            except Exception:
                log.exception("worker pass failed")
                self._stop.wait(5)

    def close(self) -> None:
        self.state.close()
        self.actors.close()
        self._lock.release()


def _outcome(arts: Any) -> tuple | None:
    """What the watcher keeps of a run: (verdict, signal, max severity), or None for a run that produced none."""
    assembled = getattr(arts, "assembled", None)
    if assembled is None:
        return None
    return assembled.verdict, assembled.signal, assembled.max_indicator_severity


def _run_model(event: dict, runner: Callable[..., Any] | None, run_id: str, out_dir: str, config: DetectConfig,
               emit: bool, poster: Callable[[str, dict, dict], int] | None) -> tuple | None:
    """One model run, in the worker thread or in a child process. Never raises: `cli.run` does not, and a custom runner that does counts as a failed run."""
    if runner is None:
        from .cli import run as runner
    try:
        extra = {"emit_failed": False} if _accepts(runner, "emit_failed") else {}
        return _outcome(runner(event, run_id=run_id, outdir=out_dir, config=config, emit=emit, poster=poster, **extra))
    except Exception as exc:  # noqa: BLE001 (`cli.run` never raises; a custom runner might)
        log.warning("run %s crashed: %s", run_id, exc)
        return None


def _child_init(level: int, parent: int) -> None:
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(processName)s %(message)s")

    def orphaned() -> None:
        # A watcher killed outright (SIGKILL, the OOM killer) cannot stop its children. One left running would finish its run while a restarted watcher runs the same run id again: exit as soon as the parent is gone.
        while os.getppid() == parent:
            time.sleep(1)
        os._exit(1)

    threading.Thread(target=orphaned, name="diff-sentry-orphan-watch", daemon=True).start()


def _result(fut: Future, run_id: str) -> tuple[tuple | None, bool]:
    """A finished future's outcome, and whether its process died. Whatever it raises counts as a failed run, a `KeyboardInterrupt` a child received with the terminal's Ctrl-C included, so the worker thread lives on."""
    try:
        return fut.result(), False
    except BrokenProcessPool:
        log.warning("the process running %s died", run_id)
        return None, True
    except BaseException as exc:  # noqa: BLE001 (a child's KeyboardInterrupt or SystemExit is its run failing)
        log.warning("run %s crashed: %r", run_id, exc)
        return None, False


def _terminate(pool: ProcessPoolExecutor) -> None:
    """Stop a pool now, its running children included (a model run can take minutes)."""
    for proc in list(getattr(pool, "_processes", {}).values()):
        if proc.is_alive():
            proc.terminate()
    pool.shutdown(wait=True, cancel_futures=True)


def _accepts(fn: Callable[..., Any], name: str) -> bool:
    """Whether `fn` takes keyword `name` (or `**kwargs`). A custom runner or screener written before a keyword existed must keep working, not fail every attempt with a TypeError."""
    import inspect

    try:
        params = inspect.signature(fn).parameters.values()
    except (TypeError, ValueError):
        return True
    return any(p.name == name or p.kind is inspect.Parameter.VAR_KEYWORD for p in params)


def _default_api() -> GhApi:
    from .ingest import _gh_cli_api
    return _gh_cli_api()


def _default_raw() -> GhRaw:
    from .ingest import _gh_cli_raw
    return _gh_cli_raw()
