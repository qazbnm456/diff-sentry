# Context preservation (read before auto-compacting)

diff-sentry routes durable knowledge into its tracked docs — keep using them, and when the conversation
is about to compact, preserve only what they do NOT already hold:

- **Stable invariants** → the **Hard invariants** section of `CLAUDE.md`.
- **Resolved decisions / shipped changes** → the commit message (grow a `CHANGELOG.md` at the first
  version bump, like the siblings).
- **Open / proposed work** → the issue tracker, or the `README.md` **Status** section.

So a handoff summary should carry the *in-flight session state* those files miss. Prioritize, in order:

1. **Decisions we agreed on this session** not yet in CLAUDE.md / a commit — design choices and the
   *reason* (e.g. "judgement-only SUBMIT + union-on-read so a benign self-report can't suppress
   evidence", "the fetch allowlist is GitHub-only because the input is attacker-authored", "workflow
   edits are `medium` so a benign workflow PR doesn't force a signal"). Promote durable ones into
   CLAUDE.md (invariant) before they fade.
2. **Files / symbols changed**, as `path:symbol` one-liners on the *final* shape — e.g.
   `assemble.py:assemble_verdict — signal = verdict∈emit_on OR severity≥floor`,
   `indicators.py:make_indicator_tool — registers as scan_indicators (dspy __name__)`.
   Drop diffs and intermediate revisions.
3. **Current status.** What passes the suite (and the count), what's broken, last command + result.
   One paragraph. (Suite: `uv run pytest` from the repo root, plus `uvx ruff check .`.)
4. **Open suggestions / TODOs** not yet tracked — mark each `proposed`, `accepted-not-done`, or
   `rejected`; move durable ones to the issue tracker.
5. **The seams' status.** (a) `classify_backend` — still `"self"` (a general model) or a dedicated
   second-stage backend in progress; (b) the cheap host-side pre-filter tier + live GitHub/SIEM wiring
   (the README's "next increments"); (c) the rlm-kit dep — still the editable `../rlm-kit` path or
   switched to a commit-pinned git source. A resumed session must not re-open a seam that moved.
6. **In-flight user intent + acceptance criteria** for this session. Without it a resumed session drifts.

**Do NOT preserve** (reconstructable / already durable):

- Anything already in `CLAUDE.md`, `README.md`, `.env.example`, or `pyproject.toml`.
- Tool-call transcripts, `grep` output, file listings, full file contents readable from disk.
- Step-by-step exploration narration; speculative reasoning that led to no decision.

**Format for a handoff summary** (use when compaction is imminent or the user asks for a recap):

```
## Session state
- Goal: <one sentence>
- Status: <what passes the suite, what doesn't, last command + result>
- Seams: <classify backend | pre-filter/live wiring | rlm-kit dep — one line each if touched>

## Decisions
- <decision> — <why>   (→ promote to CLAUDE.md invariant / the commit message)

## Changed
- <path:symbol> — <what & why>

## Open
- [proposed|accepted-not-done|rejected] <item>   (→ issue tracker if durable)
```

Keep it under ~40 lines. If something fits one of the tracked docs, put it THERE instead of the summary.
