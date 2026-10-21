# Watching releases

A pull request scan cannot see a release that never went through a pull request. litellm 1.107.0 was built from an attacker's repository after stolen credentials changed its release workflow, and 1.82.8 was uploaded with a stolen token; in both, the wheels on PyPI held files the previous release did not. `release-watch` compares each new release of the PyPI packages you name with the release before it, and screens what changed with the same rules as a pull request.

```bash
uv run diff-sentry release-watch --packages litellm requests            # poll every 5 minutes, alert on what the rules find
uv run diff-sentry release-watch --packages-file packages.txt --once    # one pass, then exit
uv run diff-sentry release-watch --check litellm 1.106.2                # judge one release against the one before it, now
```

It needs no model and no GitHub credentials. Set `DS_SIEM_WEBHOOK_URL` to receive alerts; `DS_RELEASE_PACKAGES` and `DS_RELEASE_INTERVAL` take the place of the flags. A package whose files are larger than 256 MB raises an alert that it was not compared; raise `DS_RELEASE_MAX_ARTIFACT_MB` for it.

## What it does

1. **Polls each package's simple index** on pypi.org. The first time it sees a package, every file already there is the baseline and is not judged. Every file that appears after that is judged, including a wheel uploaded to a release after the rest of it.
2. **Downloads the new files and the previous release's**, as data. Nothing is installed or unpacked to disk, every download is checked against the index's sha256, and downloads, decompressed bytes and kept text are bounded. The previous release is the highest version below the new one with a file that is not yanked.
3. **Builds a change from the difference**: each file of the new artifacts whose content the previous release did not have becomes a file of the change, at the path it installs to (`wheel/cook.pth`) or its path in the source tree (`sdist/pyproject.toml`), with the diff as its patch.
4. **Screens that change** like a pull request, so the startup-hook, packed-loader, download-and-run and every other rule read the new files. It adds the facts only a release shows: a top-level name the wheels newly install into site-packages, a new dependency, and attestations the previous release had and this one lacks. Whatever it could not read alerts on its own: a changed file that runs but could not be read as text, two files that install to the same path, and an artifact that could not be downloaded or read to its end.
5. **Alerts** when the evidence reaches the floor, and archives the comparison in `snapshots/`, so the evidence survives PyPI removing the release.

## What it does not do

- It sees a release only while PyPI lists it. A release removed within minutes of upload can be gone before the next poll.
- It compares a release with the previous one, not with the git tag, so a payload that every release has carried since before the watch started is part of the baseline.
- A prompt injection in a package's files stays below the alert floor here: the files are read by the programs that import them, and an LLM library names "the system prompt" in its own code every release.
- It watches PyPI only. npm packages and container images are not compared (litellm's Docker tags carried the same 1.107.0 payload).
- It does not run the model on a release. The screened response under `screened/` is the record.
