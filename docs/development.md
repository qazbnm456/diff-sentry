# Development

The offline suite covers the pipeline with no live model, no network, and no Deno; the corpus pins the rules' hit and miss behavior; the eval member has its own suite.

```bash
uv sync --group dev
uv run pytest                                                     # core
uv run --package diff-sentry-eval --extra dev python -m pytest eval/tests
uvx ruff@0.16.0 check .
```

CI runs the published Action against this repository's own pull requests (`uses: ./`), so a change that breaks the Action fails here before it reaches anyone's install.

[`AGENTS.md`](../AGENTS.md) holds the design invariants a change must keep, and `.claude/rules/` the per-area detail (indicator rules, model roles, monitoring, the rubric and eval member). diff-sentry is built on [`rlm-harness`](https://github.com/qazbnm456/rlm-harness).
