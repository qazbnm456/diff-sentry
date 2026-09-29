# Context preservation (read before auto-compacting)

Durable knowledge belongs in tracked files; a handoff summary carries only the in-flight session state
they do not hold yet.

- **Stable invariants** → `AGENTS.md` **Hard invariants**, or the topic rule under `.claude/rules/`.
- **Shipped changes** → the commit message, and a `CHANGELOG.md` entry at release.
- **Open / proposed work** → the issue tracker, or `AGENTS.md` **Layout** (next increments).

A handoff summary covers, in order:

1. **Decisions agreed this session** that are not yet in those files, each with its reason. Promote
   durable ones into `AGENTS.md` or a topic rule before they fade.
2. **Files / symbols changed**, as `path:symbol — final shape` one-liners (e.g.
   `assemble.py:assemble_verdict — signal = verdict∈emit_on OR severity≥floor`). No diffs, no
   intermediate revisions.
3. **Current status**: what passes (`uv run pytest`, the eval suite, `uvx ruff check .`) with counts,
   what is broken, the last command and its result. One paragraph.
4. **Open items** not yet tracked, each marked `proposed`, `accepted-not-done`, or `rejected`.
5. **Seams touched**: `classify_backend` (`"self"` or a dedicated backend in progress), the host-side
   pre-filter / live GitHub+SIEM wiring, and the rlm-harness pin. A resumed session must not re-open a
   seam that moved.
6. **The user's in-flight intent and acceptance criteria.**

Do not preserve anything already in `AGENTS.md`, `README.md`, `.env.example`, or `pyproject.toml`; tool
output, file listings, or file contents readable from disk; or exploration narration that led to no
decision.

Format (keep it under ~40 lines):

```
## Session state
- Goal: <one sentence>
- Status: <what passes, what doesn't, last command + result>
- Seams: <only the ones touched, one line each>

## Decisions
- <decision> — <why>   (→ AGENTS.md / topic rule / commit message)

## Changed
- <path:symbol> — <what & why>

## Open
- [proposed|accepted-not-done|rejected] <item>
```
