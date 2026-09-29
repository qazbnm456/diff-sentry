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
4. Commit (`chore: release X.Y.Z`) and push to `main` once the user approves. CI's `consumer install
   path (PyPI)` job then goes RED on this commit, by design: it installs `action.yml`'s default version
   from PyPI, which does not exist until step 5. Every other job must be green before you continue.
5. Create a DRAFT release (`gh release create vX.Y.Z --draft --target <release sha> --title … --notes-file
   …`, notes = the CHANGELOG section). The user publishes it in the web UI with "Publish this Action to
   the GitHub Marketplace" ticked (the CLI cannot tick it). Publishing is what builds, verifies, and
   uploads to PyPI via Trusted Publishing, and the upload is irreversible.
6. After `release.yml` succeeds, re-run the failed consumer-install job
   (`gh run rerun <ci run id> --failed`); green proves the published package installs and scans.
