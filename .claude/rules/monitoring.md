---
paths:
  - "diff_sentry/watch.py"
  - "diff_sentry/actors.py"
  - "diff_sentry/snapshot.py"
  - "diff_sentry/ingest.py"
  - "diff_sentry/hosts.py"
  - "diff_sentry/dbutil.py"
  - "tests/test_watch.py"
  - "tests/test_actors.py"
  - "tests/test_snapshot.py"
  - "tests/test_hosts.py"
  - "tests/test_ingest_metadata.py"
  - "tests/test_metadata_rules.py"
  - "tests/test_campaign_replay.py"
  - "tests/test_cli_watch.py"
  - "tests/corpus/hackerbot_claw_campaign.json"
---

# Monitoring: the watcher, the actor store, the archive

- **All of it is host-side.** `watch`, `actors`, `snapshot` and the ingest enrichment run outside the
  trajectory. The planner never queries the store, the queue, or GitHub. The one thing it receives is the
  `actor_history` summary (repositories, outcomes, rule names, hours, and which profile FIELDS changed, never
  the profile text), rendered as an untrusted section because the logins and refs in it came from users.
- **Cross-event facts are provenance, not a second signal.** `ActorStore.correlate` is read-only and runs
  BEFORE `record`. Its output lands in `event["provenance"]` under plain keys (`actor_*`, `ioc_reuse`,
  `content_revisions`, `evidence_scrubbed`) and `indicators.scan_provenance` turns them into baseline hits.
  Never add a hits or signal path from the store. A change scanned on its own carries none of those keys
  and fires none of those rules.
- **A deleted account is not an actor.** GitHub's `ghost` is one identity for every deleted user, so `actor_key`
  keys a `ghost` change on the change itself: two unrelated deleted authors never share a history.
- **Examine oldest first.** Correlation reads what came before a change, so the listing (newest first) is
  sorted ascending before it is examined. A burst examined newest-first would show its last member nothing.
- **Attribution follows the author of the text, decided structurally.** `IndicatorHit.via` names the commenter
  and is set from the segment KIND in `normalize.content_segments_ex`; it is never parsed out of `location`,
  which is a free-form file path an author can name `comment:alice`. A hit whose `via` is another account is
  recorded against that commenter (`channel='comment'`, only when it reached the floor or fired a slash
  command), and `correlate` reads only the author's own hits, so a drive-by's payload host does not link the
  maintainer's next change and a moderator deleting the comment is not the author scrubbing evidence. A verdict
  on a change whose floor-level evidence is only a third party's goes to that party (`finalize`).
- **A verdict clears an inference, never evidence.** (`actor-known-bad` is the one model-derived fact that
  enters the baseline: it needs a stored `malicious` verdict, expires after 30 days, and does not apply to
  `Bot` accounts.) A `benign` verdict clears the account-level flag
  (`actor-prior-flag`, an inference about a person), except over a prompt injection, where the verdict may be
  the injection working (`ActorStore._stands`, the only implementation). It never clears `ioc-reuse`, the
  payload-host link: a local model has a real false-benign rate, and letting its verdict erase evidence would
  let one missed payload launder a campaign. `actor-known-bad` needs a `malicious` verdict. The account-level
  rules do not apply to `Bot` accounts; the change-level ones do.
- **The first copy is kept.** `SnapshotStore.put` runs before anything else touches a change; objects are
  never rewritten and the index is append-only. An edit is a new revision with its own run id (`-r1`), so
  its trace never overwrites the original's, and `prior_indicators` carry the earlier hits forward so a
  removed payload cannot remove the evidence. `evidence-scrubbed` counts only floor-level hits (dropping a
  backtick from prose is an edit), matches a prior hit by rule and location rather than id, counts a kind that is
  still there but now below the floor (a payload rewritten to read as prose) as gone, and its evidence
  names the vanished hit ids, so a later edit that still lacks them is the same finding and does not page again.
  Snapshot the event as ingested (before correlation attaches facts) so the archive holds what GitHub said,
  not what we derived.
- **Time is the cost, not money.** With a local model every change reaches the model by default; the screen
  sets the order (`_priority`), not eligibility. The caps (`deep_min_severity`, `max_queue`,
  `max_deep_per_hour`) default off. A shed change keeps its `screened/` record and a `shed` state.
- **The screen is not a trajectory.** `cli.screen` writes `screened/{run_id}.json`, never a trace, so the
  rollout corpus stays trajectories. Its early alert is `stage=screen`; the run's own is `stage=final`.
- **One model worker.** dspy's global configuration is bound to the thread that first set it up. The poller
  is a second thread and touches no model. Do not add a worker pool without proving `setup` is safe there.
- **A failed change must not block the ones behind it, and must be retried.** A failure holds the
  watermark below it and withholds the page-1 ETag (or the next listing answers 304 and it is never
  retried), backs off exponentially, and after `_MAX_FAILS` is parked as `error` so it stops holding the
  listing. The others are skipped by their stored `updated_at`. A listing deeper than `_MAX_PAGES` is reported
  as truncated, never advanced past silently. A rate-limit refusal (`429`, or `403` saying so) is not a failure
  of the change: wait for the reset, and `_ingest` subtracts the calls it made from the budget the list
  responses report.
- **A read that failed is not a change.** `_comments` returns None on failure and the event carries
  `comments_incomplete`; the watcher then keeps what it has instead of judging the empty thread as an edit.
  Anything that feeds the digest must distinguish "none" from "could not read".
- **Run ids are unambiguous.** `owner__name-pr-7` (`-r1` per revision; the one-off `pr`/`issue` commands keep their
  older `owner-name-pr-7` scheme, which can collide across repositories): owners cannot contain `_`, so two
  repositories never collide. A run that fails is retried with backoff up to `_MAX_ATTEMPTS` (about four
  hours: a local model restarting must not fail the queue) and `cli.run` is told `emit_failed=False`, so a
  failed attempt pages nothing, then buried (`claimed=2`, event kept) for
  `--requeue-failed`. Claiming counts as an attempt, so an input that kills the process cannot loop across
  restarts. The queue row stays claimed until the run completes, and `recover()` (called by `serve` and
  `--once`, never by a read-only look) requeues it under a per-directory `flock`. Neither thread may die on
  an unexpected exception.
- **Undelivered alerts are retried a few at a time.** `_retry_alerts` re-sends at most `_ALERT_RETRIES_PER_POLL`
  (5) per poll, so a SIEM that hangs (a POST is bounded by 15 s) cannot stall polling for a whole backlog.
- **An alert counts once delivered.** `changes.alerted` gains ids only after the SIEM answered 2xx
  (`EmitResult.ok`); a refusal or outage leaves `alert_pending`, re-sent from `screened/{run_id}.json` on later
  polls. `emitted` alone is also True for a 5xx.
- **State files are versioned.** `dbutil.open_versioned` stamps `PRAGMA user_version` and refuses a file with
  tables but another stamp; there is no migration, and the error says to move the directory aside.
- **Account age is measured as of the event.** `_age_days(created_at, as_of)` takes the event's own time;
  the wall clock is only the fallback for a payload with none. A replay of a historical incident must
  carry `created_at`, or every old attacker looks established (`test_campaign_replay` pins this).
- **Attacker-authored strings stay out of the MF1 sandwich.** Profile fields, branch names, and comments
  are bounded at ingest and rendered in the untrusted section only. Comments are text-scanned only when
  the change's author or an outsider wrote them and the commenter is not a `Bot`: maintainers quote
  install commands and release notes constantly.
- **Data minimization.** The `email` fields of a profile and of commits are reduced to a domain in the event
  and masked in the archive (`snapshot.scrub_emails`). Free text is archived as captured: it is evidence.
  Nothing prunes the archive, the store, or queued events.
- **Adding a fact:** capture it in `ingest.py` (best-effort: a failed call omits the key, unless the value feeds
  the digest, in which case mark the event incomplete instead of reporting "none"), put it in
  `provenance` (or a bounded event field), read it in `scan_provenance` / `scan_metadata` with a negative
  case, and keep it sub-floor unless it is standalone evidence. Replay the incident corpus.
- **Read-only means read-only.** `--stats` and `actor` open the state `mode=ro` (`open_versioned(read_only=True)`)
  and neither create, stamp, nor requeue anything. Only `serve` and `--once` call `recover()`, under the lock.
- **Terminal output is sanitized.** `format_dossier` replaces control characters; `_json_out` escapes the C1 range
  `json.dumps` leaves raw; URL and token parsing cut at the first control character. A string an attacker wrote
  must not be able to drive the operator's terminal.
