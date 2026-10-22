# Watching releases

A pull request scan cannot see a release that never went through a pull request. litellm 1.107.0 was built from an attacker's repository after an organisation owner's stolen GitHub CLI token was used to force-push a change to its release workflow, and 1.82.8 was uploaded with a stolen token; in both, the wheels on PyPI held files the previous release did not. `release-watch` compares each new release of the PyPI packages you name with the release before it, and screens what changed with the same rules as a pull request.

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
4. **Screens that change** like a pull request, so the startup-hook, packed-loader, download-and-run and every other rule read the new files. It adds the facts only a release shows: a top-level name the wheels newly install into site-packages, a new dependency, attestations the previous release had and this one lacks, and a Trusted Publisher the previous release's attestations did not name (another repository, workflow, environment or account; `critical` when the repository's owner imitates the previous one's, such as `Acme-Corp` for `AcmeCorp`). A publisher is the repository whose workflow uploaded the files, not the one it built from, and the check needs the previous release to be attested. Whatever it could not read alerts on its own: a changed file that runs but could not be read as text, two files that install to the same path, and an artifact that could not be downloaded or read to its end.
5. **Alerts** when the evidence reaches the floor, and archives the comparison in `snapshots/`, so the evidence survives PyPI removing the release.

## Container images

```bash
uv run diff-sentry release-watch --images ghcr.io/berriai/litellm docker.io/litellm/litellm --image-tags latest main-stable
```

litellm's 1.107.0 images, and the `latest` and `main-stable` tags moved onto them, carried the same payload as the wheels and stayed up longer. `release-watch --images` reads each image's build provenance (the SLSA attestation BuildKit attaches), never its layers. A repository holds images from several workflows (releases, nightlies, branch builds), so an image is judged against what the repository is known to be built from and by: on first sight, the provenance of the watched floating tags and the newest version tags; after that, every image judged clean. An image that raised an alert never becomes what is known.

After first sight, it judges every new tag, every watched floating tag (`latest` by default) that moves to another image, and any of the ten newest plain release tags (not a `-nightly` or `-rc` build) that is pushed again. cosign's `.sig`, `.att` and `.sbom` tags are not images and are skipped.

On GHCR, the namespace an image is published under is a GitHub owner and counts as known from the start.

- **`image-source-lookalike`**, **`image-builder-lookalike`** (`critical`): the repository the image was built from (`vcs:source`), or the one whose workflow built it, has an owner that imitates a known owner, as the 1.107.0 images' `Berri-AI/litellm` did `BerriAI`.
- **`image-source-changed`**, **`image-builder-changed`** (`high`): a source or a building repository of an owner the repository is not known to use. Another repository of a known owner is `medium`.
- **`image-ref-unprotected`** (`high`): a workflow whose known builds ran from protected refs built the image from an unprotected one. litellm's attacker turned branch protection off before pushing the workflow change.
- **`image-provenance-dropped`** (`high`): an image without the provenance the repository's images carry. A platform image no attestation names, an attestation that names an image outside its own index, and a provenance whose subject is not that image are alerts too (`release-not-fully-read`).
- **`image-workflow-changed`** (`medium`, evidence below the floor): a workflow of a known owner the repository is not known to use, such as a branch build.

If the images the watch starts from already come from owners that imitate each other, it cannot tell which is real: it alerts once (`image-source-lookalike`), learns neither, and alerts on every image of the repository (`image-owner-unresolved`, `high`) until you investigate and delete `images.db` to start again.

It reads GHCR and Docker Hub only, with anonymous pull tokens. It checks digests with HEAD requests, which Docker Hub does not count toward its pull limit, and a rate-limited poll waits for the next one. The provenance is not signed: whoever controls the push can write any statement, so a provenance that matches proves nothing, and a payload in a layer is not read.

## What it does not do

- It sees a release only while PyPI lists it. A release removed within minutes of upload can be gone before the next poll.
- It compares a release with the previous one, not with the git tag, so a payload that every release has carried since before the watch started is part of the baseline.
- A prompt injection in a package's files stays below the alert floor here: the files are read by the programs that import them, and an LLM library names "the system prompt" in its own code every release. So do the rules that only see a code-owners file, a workflow file or a CI skip mentioned, since a package governs no repository and a comment mentions them as readily as code; package code that writes only a code-owners file is below the floor. A workflow's dangerous content (a pull request's head checked out under a privileged trigger, write-all permissions) keeps its severity in every file: a package's code or build can push it into someone's repository, and a project whose own workflow has that shape has a vulnerability worth the alert.
- A package whose job is to carry attack patterns, such as a scanner's rules and test fixtures (diff-sentry's own), alerts on every release that changes them.
- A legitimate change of publisher alerts too: a renamed or transferred repository, a renamed workflow, a new deployment environment. So does a project that stops attesting its releases.
- It watches PyPI only. npm packages and container images are not compared (litellm's Docker tags carried the same 1.107.0 payload).
- It does not run the model on a release. The screened response under `screened/` is the record.
