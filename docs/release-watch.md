# Watching releases

A pull request scan cannot see a release that never went through a pull request. litellm 1.107.0 was built from an attacker's repository after an organisation owner's stolen GitHub CLI token was used to force-push a change to its release workflow, and 1.82.8 was uploaded with a stolen token; in both, the wheels on PyPI held files the previous release did not. `release-watch` compares each new release of the PyPI packages you name with the release before it, and screens what changed with the same rules as a pull request. It watches npm packages and container images the same way (see below).

```bash
uv run diff-sentry release-watch --packages litellm requests            # poll every 5 minutes, alert on what the rules find
uv run diff-sentry release-watch --packages-file packages.txt --once    # one pass, then exit
uv run diff-sentry release-watch --check litellm 1.106.2                # judge one release against the one before it, now
uv run diff-sentry release-watch --packages litellm --sources litellm=BerriAI/litellm   # also compare each release with its git tag
```

It needs no model, and no GitHub credentials unless it compares many releases with their tags. Set `DS_SIEM_WEBHOOK_URL` to receive alerts; `DS_RELEASE_PACKAGES` and `DS_RELEASE_INTERVAL` take the place of the flags. A package whose files are larger than 256 MB raises an alert that it was not compared; raise `DS_RELEASE_MAX_ARTIFACT_MB` for it.

## What it does

1. **Polls each package's simple index** on pypi.org. The first time it sees a package, every file already there is the baseline and is not judged. Every file that appears after that is judged, including a wheel uploaded to a release after the rest of it.
2. **Downloads the new files and the previous release's**, as data. Nothing is installed or unpacked to disk, every download is checked against the index's sha256, and downloads, decompressed bytes and kept text are bounded. The previous release is the highest version below the new one with a file that is not yanked.
3. **Builds a change from the difference**: each file of the new artifacts whose content the previous release did not have becomes a file of the change, at the path it installs to (`wheel/cook.pth`) or its path in the source tree (`sdist/pyproject.toml`), with the diff as its patch.
4. **Screens that change** like a pull request, so the startup-hook, packed-loader, download-and-run and every other rule read the new files. It adds the facts only a release shows: a top-level name the wheels newly install into site-packages, a new dependency, attestations the previous release had and this one lacks, and a Trusted Publisher the previous release's attestations did not name (another repository, workflow, environment or account; `critical` when the repository's owner imitates the previous one's, such as `Acme-Corp` for `AcmeCorp`). A publisher is the repository whose workflow uploaded the files, not the one it built from, and the check needs the previous release to be attested. Whatever it could not read alerts on its own: a changed file that runs but could not be read as text, two files that install to the same path, and an artifact that could not be downloaded or read to its end.
5. **Compares the release with its git tag**, when it knows the GitHub repository the package is built from (`--sources` or `DS_RELEASE_SOURCES`, or else the repository of the previous release's Trusted Publisher). See below.
6. **Alerts** when the evidence reaches the floor, and archives the comparison in `snapshots/`, so the evidence survives PyPI removing the release.

## Container images

```bash
uv run diff-sentry release-watch --images ghcr.io/berriai/litellm docker.io/litellm/litellm --image-tags latest main-stable
```

litellm's 1.107.0 images, and the `latest` and `main-stable` tags moved onto them, carried the same payload as the wheels and stayed up longer. `release-watch --images` reads each image's build provenance (the SLSA attestation BuildKit attaches) and the files it changes (below). A repository holds images from several workflows (releases, nightlies, branch builds), so an image is judged against what the repository is known to be built from and by: on first sight, the provenance of the watched floating tags and the newest version tags; after that, every image judged clean. An image that raised an alert never becomes what is known.

After first sight, it judges every new tag, every watched floating tag (`latest` by default) that moves to another image, and any of the ten newest plain release tags (not a `-nightly` or `-rc` build) that is pushed again. cosign's `.sig`, `.att` and `.sbom` tags are not images and are skipped.

On GHCR, the namespace an image is published under is a GitHub owner and counts as known from the start.

- **`image-source-lookalike`**, **`image-builder-lookalike`** (`critical`): the repository the image was built from (`vcs:source`), or the one whose workflow built it, has an owner that imitates a known owner, as the 1.107.0 images' `Berri-AI/litellm` did `BerriAI`.
- **`image-source-changed`**, **`image-builder-changed`** (`high`): a source or a building repository of an owner the repository is not known to use. Another repository of a known owner is `medium`.
- **`image-ref-unprotected`** (`high`): a workflow whose known builds ran from protected refs built the image from an unprotected one. litellm's attacker turned branch protection off before pushing the workflow change.
- **`image-provenance-dropped`** (`high`): an image without the provenance the repository's images carry. A platform image no attestation names, an attestation that names an image outside its own index, and a provenance whose subject is not that image are alerts too (`release-not-fully-read`).
- **`image-workflow-changed`** (`medium`, evidence below the floor): a workflow of a known owner the repository is not known to use, such as a branch build.

If the images the watch starts from already come from owners that imitate each other, it cannot tell which is real: it alerts once (`image-source-lookalike`), learns neither, and alerts on every image of the repository (`image-owner-unresolved`, `high`) until you investigate and delete `images.db` to start again.

It reads GHCR and Docker Hub only, with anonymous pull tokens. It checks digests with HEAD requests, which Docker Hub does not count toward its pull limit, and a rate-limited poll waits for the next one. The provenance is not signed: whoever controls the push can write any statement, so a provenance that matches proves nothing.

So it also reads what an image changes. A judged image is compared with the image it replaces: a moved floating tag with the image it pointed at, and a new tag with the newest release below it (or, in a repository with no release tags, the image a watched floating tag points at). Only the layers the two do not share are downloaded, because a shared layer is the same bytes, and their files are compared by path, platform by platform, so a rebuilt layer shows only the files that changed in it. Those files are screened by the same rules as a release, so a `.pth` startup hook or a packed loader in an image's site-packages alerts as it does in a wheel. Each platform's run configuration is compared too, even when every layer is shared, and screened as Dockerfile lines (`linux-amd64/{config}`): **`image-run-config-changed`** (`high`) is another entrypoint, command, shell, user, working directory, healthcheck or build trigger, and **`image-loader-env`** (`high`) an environment variable that loads code into its processes or chooses which program a name runs (any `LD_` or `DYLD_` variable, `PYTHONPATH`, `PYTHONWARNINGS`, `NODE_OPTIONS`, `GCONV_PATH`, `PATH` and the like) set or changed. A layer it cannot read (larger than `DS_RELEASE_MAX_LAYER_MB`, 1024 by default; compressed with zstd; not matching its digest), a platform the previous image did not have, and two images for one platform, alert that the image was not fully read.

Python can run a cached `.pyc` instead of the source beside it, and no text rule reads bytecode. So a `.pyc` whose code changed is checked against its source: both are compiled or unmarshalled, never run, by an interpreter of the same Python version in a separate process, and the two code objects compared. Bytecode that is its source compiled, line numbers included, is expected; other bytecode, bytecode without its source, and bytecode no interpreter on the host can check (install the image's `python3.N` beside the watcher) alert. A wheel's bytecode is checked the same way. Layers are read as data in memory and never unpacked or run; a release's differing layers can be several hundred MB.

## npm packages

```bash
uv run diff-sentry release-watch --npm @acme/widget left-pad
uv run diff-sentry release-watch --check npm:@sigstore/sign 5.0.0
```

The npm worms of 2025 published new versions of popular packages with stolen tokens, each with a `preinstall` or `postinstall` script that runs the payload on every install. A version published with a stolen token also lacks the provenance a package's own release workflow attaches. `--npm` (or `DS_RELEASE_NPM`) compares each new version of an npm package with the version before it in semver order, as it does a PyPI release: the tarball is read as data and checked against the registry's sha512, and every new or changed file is screened by the same rules. It adds what only npm shows:

- **`npm-install-script-added`** (`high`): a script npm runs at install (`preinstall`, `install`, `postinstall`, or the `node-gyp rebuild` a `binding.gyp` implies) that the previous version did not have, in the package or in a dependency it bundles. The manifests are read as npm reads them, and one that cannot be read alerts.
- **`npm-install-script-changed`** (`medium`, evidence below the floor): one of those scripts with another command.
- **`npm-dependency-source`** (`high`): a dependency installed from a git repository, a URL, a path or an `npm:` alias that the previous version did not install from there. npm fetches that code at install and runs its install scripts, so a version needs no script of its own to run code.
- **`release-attestation-dropped`**, **`release-publisher-changed`** and **`release-publisher-lookalike`**: as for PyPI, from the SLSA provenance the registry holds for each version, which names the repository and workflow that published it. A provenance that names another tarball's digest is not trusted and alerts.
- **`npm-dependency-runs-at-install`**, **`npm-dependency-young`** (`high`): a dependency newly taken from the registry whose versions run a script at install, or that was created in the last 30 days or is not on the registry. A compromised version need not carry the payload: it can depend on a package published hours before whose install script runs it. Each dependency newly taken from the registry, in the package or a dependency it bundles, is looked up there, and its age is measured as of the version's publish time; one whose registry document is too large to read alerts that it was not read.
- **`release-new-dependency`** (`low`): a name newly in `dependencies`, `optionalDependencies` or `peerDependencies`.

It reads `registry.npmjs.org` only. A version's tarball served from another host is not read.

## Comparing a release with its git tag

litellm 1.107.0 was built from `Berri-AI/litellm`, and `BerriAI/litellm` has no `v1.107.0` tag. With the source repository known, each release's files that Python runs (`.py`, `.pyw`, `.pth` and the build files) are compared with the repository's tag for that version, by git blob hash, so nothing is downloaded from GitHub but its tag list and two file trees:

- **`release-differs-from-tag`** (`high`): a file the tag does not hold, or holds with other content.
- **`release-tag-missing`**: the repository tagged the previous release and has no tag for this one. Many projects push the tag after they upload, so this is `medium` at first and is looked at again on every poll. When the tag appears, the release is compared with it; a release still without its tag an hour after it was judged raises a `high` alert of its own. A tag names its version as `v1.2.3`, `1.2.3`, `v1.2.3-rc.1` or with another prefix; one with the prefix the previous release's tag used is preferred.

A build writes files no tag holds, such as a version file. So the previous release is compared with its own tag first, and a file that differed there at the same path is expected. Files Python does not run, such as a web bundle a build names anew each time, are screened by the rules but not compared. On litellm 1.106.2 that leaves no difference in 22,214 files. CRLF line endings, as a Windows wheel carries them, count as the same content. If the previous release has no tag, the release is not compared.

Without credentials, GitHub's API allows 60 requests an hour, and each release takes two; set `GITHUB_TOKEN` to raise the limit. A release judged past the limit is compared once it lifts, which downloads its files again. Three cases alert that a release was not compared: a comparison still impossible six hours after the judgment, for any reason; a repository named with `--sources` that GitHub no longer serves (private, renamed or deleted); and a tree GitHub sends only part of (past 100,000 entries or 7 MB).

Without `--sources`, the watch uses the repository of the previous release's Trusted Publisher. That needs the previous release to be attested, and it names the repository whose workflow uploaded, so a private releaser repository compares nothing.

## What it does not do

- It sees a release only while PyPI lists it. A release removed within minutes of upload can be gone before the next poll.
- Without a source repository, it compares a release with the previous one only, so a payload that every release has carried since before the watch started is part of the baseline. With one, a payload in a file the build rewrites every release (such as a version file) is screened by the rules but is not a difference from the tag.
- A tag only proves what the repository holds. An attacker who can push to the repository can tag the payload too, and it then matches.
- A prompt injection in a package's files stays below the alert floor here: the files are read by the programs that import them, and an LLM library names "the system prompt" in its own code every release. So do the rules that only see a code-owners file, a workflow file or a CI skip mentioned, since a package governs no repository and a comment mentions them as readily as code; package code that writes only a code-owners file is below the floor. A workflow's dangerous content (a pull request's head checked out under a privileged trigger, write-all permissions) keeps its severity in every file: a package's code or build can push it into someone's repository, and a project whose own workflow has that shape has a vulnerability worth the alert.
- A package whose job is to carry attack patterns, such as a scanner's rules and test fixtures (diff-sentry's own), alerts on every release that changes them.
- A legitimate change of publisher alerts too: a renamed or transferred repository, a renamed workflow, a new deployment environment. So does a project that stops attesting its releases.
- It does not compare an npm version with its git tag, and it reads the public registry only.
- A changed native binary in an image (an ELF under `usr/bin`, a `.so` under a name the previous image had) is compared but not read: a rebuild changes them all, so they alert only as a new native module.
- It does not run the model on a release. The screened response under `screened/` is the record.
