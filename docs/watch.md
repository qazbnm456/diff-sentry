# Watching a watchlist

`watch` turns the classifier into a monitor. It polls the repositories you name and runs every new or updated PR and issue through the same pipeline, host-side, in front of `cli.run`.

```bash
uv run diff-sentry watch --repos owner/name other/name        # poll, screen, queue for the model
uv run diff-sentry watch --screen-only --repos-file repos.txt # deterministic tier only: no model roles (gh must be logged in)
uv run diff-sentry watch --once --repos owner/name            # one pass, run the queue, exit
uv run diff-sentry watch --stats                              # the watcher's state counts (read-only)
uv run diff-sentry watch --requeue-failed                     # bring back runs that exhausted their attempts
uv run diff-sentry actor mallory                              # the dossier of an account it has seen
uv run diff-sentry archive verify                             # re-hash every object in the snapshot archive
```

```
poll (ETag) → ingest → snapshot archive → actor store → screen → queue → model run → verdict
                                                          └─ early SIEM alert at the signal floor
```

**Time is the cost.** The intended model is a local one, so every change reaches it by default and the deterministic screen only decides the order: highest severity first. The optional caps are off unless you set them: `DS_WATCH_DEEP_MIN_SEVERITY`, `DS_WATCH_MAX_QUEUE`, `DS_WATCH_MAX_DEEP_PER_HOUR`. A change the queue sheds keeps its screened record and a `shed` state. The queue is a table, so a restart loses nothing. The poller and the model worker are separate threads, so a slow model never delays the screen or its alert. One model run takes minutes, so a busy watchlist outruns a single run at a time: `--workers N` (`DS_WATCH_WORKERS`, default 1) runs N at once, each in a process of its own, as many as the model host serves.

**The alert does not wait for the model.** Evidence at the signal floor is emitted the moment the screen finishes (`"stage": "screen"`); the model's own signal follows under the same `run_id` (`"stage": "final"`). A later revision alerts early again only for floor-level evidence no earlier revision already raised, judged by hit id: an edit next to a payload changes the surrounding text that id includes, so it can page again. Each revision is its own run, so it also gets its own final signal.

**Nothing is dropped without a trace.** A listing deeper than one pass reads (2000 changes) is reported as truncated. A change that cannot be ingested is retried with exponential backoff and parked as `error` after six failures; a rate-limit refusal is waited out and is not a failure. A model run that fails is retried up to ten times over about four hours and then kept as `failed`; stop the watcher and run `watch --requeue-failed` to bring it back. An early alert the SIEM refused is sent again on later polls (twenty tries). One `watch` may use a state directory at a time.

**The first copy is kept.** Every capture, with the raw API responses beside the derived event, goes into a content-addressed archive before anything else happens, so `archive verify` detects a changed or missing object. The index is append-only but not hash-chained, and nothing prunes the archive, the store or the queue's events, so size them yourself. An edit is a new revision (`…-r1`) with its own trace, never an overwrite, and the hits an earlier revision raised ride into the next one, so removing a payload cannot remove the evidence. Changes are re-examined after 15 minutes, 1 hour, 6 hours and 24 hours to see a deleted fork, account or PR (`--recheck-hours` can shorten that schedule, not extend it).

**The store remembers the account.** It keys accounts on GitHub's numeric id, so a rename does not reset the record. Cross-event facts (the same account in several repositories within a day, a burst from a new account, a payload host a flagged change already used) reach the signal through the ordinary provenance path.

Evidence is attributed by where the text came from, never by a label an author could choose: a payload in someone else's comment is recorded against the commenter, not the PR's author. Only a comment that reaches the signal floor, or fires a slash command, puts its writer in the store. A model's `benign` verdict clears the account-level flag on an earlier change (one false positive must not taint an account), except over a change that carried a prompt injection, because that verdict may be the injection working. It never clears the payload-host link, which is evidence rather than an inference: a local model has a real false-benign rate, and one missed payload must not launder a campaign.

What the dossier holds, and how far to trust it:

| Fact | Source | Trust |
|---|---|---|
| Account creation time, profile, follower and repo counts | `users/{id}` | GitHub-authoritative; the profile strings are the attacker's words |
| Event created / updated / closed / merged | the PR or issue | timestamps GitHub assigns; an author cannot edit them |
| Account age as of the event | derived | measured on the day, so a replay of an old incident sees the account as it was |
| Head fork, its creation time, whether it was later deleted | the PR | GitHub-authoritative |
| Head branch name, comment thread | the PR | untrusted text, bounded |
| Hour-of-day histogram, longest quiet stretch | the store's own sightings (one count per change), or `actor --live` | built from GitHub's timestamps, which cannot be edited afterwards; the author still chooses when to act |
| Commit UTC offsets | the `.patch` mbox `Date:` header | what the commits claim; REST and GraphQL return UTC and drop the offset |
| Email addresses | the `email` fields of a profile and of commits, the `<name@host>` lines of a signed commit's payload, and commit-message trailers (`Signed-off-by:`, `Co-authored-by:`, …) are reduced to their domain in the event and masked in the archive | data minimization; the rest of a body, a patch, or a commit message is archived as captured |
