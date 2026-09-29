---
name: release
description: Cut a diff-sentry release — bump the five version sites together, write the CHANGELOG entry, and publish the GitHub Release that ships PyPI + the Marketplace Action. Use when asked to release, bump the version, or tag vX.Y.Z.
---

# Cut a diff-sentry release

A release moves FIVE version sites together, plus a `CHANGELOG.md` entry:

1. `pyproject.toml` `[project].version`
2. `diff_sentry/__init__.py` `__version__`
3. `action.yml` `inputs.version.default` (decides which PyPI release a consumer's `uses: …@vX.Y.Z` installs)
4. `README.md` quickstart `uses: qazbnm456/diff-sentry@vX.Y.Z`
5. `uv.lock`, via `uv lock`

`release.yml` fails the build unless the tag, the built wheel's version, the installed `__version__`, and
the `action.yml` default all agree, and it checks that the installed console script flags a known-malicious
diff. Nothing gates the README `uses:` line: a stale one sends new adopters to the previous release, so
check it by hand.

## Steps

1. Freeze the boundary: `git log v<last>..HEAD`. Every `feat:` / `fix:` / `deps:` commit inside it is a
   CHANGELOG candidate.
2. Write the `CHANGELOG.md` entry in the file's existing style: one sentence per user-visible outcome,
   breaking changes and required actions explicit, no debugging story.
3. Bump sites 1–4, run `uv lock`, then verify: `uv run pytest`, the eval suite
   (`uv run --package diff-sentry-eval --extra dev python -m pytest eval/tests`), `uvx ruff check .`.
4. Commit (`chore: release X.Y.Z`) and push to `main` once the user approves.
5. Publishing a GitHub Release tagged `vX.Y.Z` (with "Publish this Action to the GitHub Marketplace"
   ticked) is what builds, verifies, and uploads to PyPI via Trusted Publishing. The upload is
   irreversible; confirm with the user before publishing.
