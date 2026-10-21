---
name: package-and-build-hooks
description: "Package manifests, lockfiles and build hooks: code that runs on install, build or test (npm lifecycle scripts, setup.py, build.rs, conftest.py, Makefile), dependency swaps, and registry redirects."
---

# Package and build hooks

Installing or building a project runs code nobody reads: lifecycle scripts, build scripts, test bootstraps. An attack here gets a payload run on every developer machine and CI runner that installs, builds or tests. Public archetypes: Shai-Hulud 2025 (`postinstall: node bundle.js`, later `preinstall` installing a second runtime and starting a huge bundle), s1ngularity/nx 2025 (`postinstall` driving local AI CLIs to inventory secrets), xz-utils 2024 (a build script reading "test fixtures" that were the payload), ordinary typosquats.

## Footprints

**Run entries**
- npm lifecycle hooks run without anyone naming them: `preinstall`, `install`, `postinstall`, `prepare`, `prepublish`, `prepublishOnly`, `prepack`, `postpack`. A new or changed one is the first thing to read.
- An existing script with a new command put IN FRONT of its old one (`"start": "node api.js && node ./out/index.js"`): the payload rides a command people run anyway.
- A run entry whose target the same change adds, especially a large single-line file, a file under a test, fixture or asset directory, or a file whose extension is not code.
- `setup.py` / `setup.cfg` / `pyproject.toml` build backends running code at install; `build.rs`; Makefile, `justfile` and `Taskfile` default targets; Dockerfile `RUN` lines; `conftest.py` and `.pth` files (Python runs them on test or interpreter start).
- `chmod +x` on a file the change adds, then running it.

**Dependencies and registries**
- A dependency renamed by one character, an unscoped name that looks internal, a git or tarball URL in place of a version, a new dependency that has an install script.
- Lockfile entries whose `resolved` host leaves the registry, or whose `integrity` changes while the version does not.
- `.npmrc`, `.yarnrc.yml`, `pip.conf`, `--extra-index-url`, `PIP_INDEX_URL` pointing at a new host.

**Build-time staging**
- A build or test script that reads, decompresses or decodes a fixture and executes or links the result.
- Binary test fixtures added with no test that reads them.

## Verify (read, never run)

1. List every script entry the change writes. For each, split it into commands; for each command whose program is a runtime (`node`, `bun`, `deno`, `python`, `sh` and the like) find the file it runs and read that file.
2. For a changed existing script, compare old and new: is the old command intact at the end with something new in front? That is the riding shape; a repointed path or an appended step is ordinary refactoring.
3. For dependencies: compare names letter by letter with the ones they replace; check `resolved` hosts and versions in the lockfile against `package.json`.
4. Read any script a lifecycle hook or build step runs, and any file it reads: decode, then scan with `decoded_from`.

## Look-alikes (benign, seen in practice)

- A codegen script added with its npm entry (`"gen:icons": "node scripts/gen-icons.mjs"`).
- `husky install`, `prisma generate`, `node-gyp rebuild`, `patch-package`, native-binary fetchers (`esbuild`, `sharp`) in `postinstall`.
- Upstream refactors that repoint scripts at moved files, or append a check after an existing one.
- Registry mirror rewrites across a whole lockfile, made by a maintainer.
- Automated dependency bumps by a real `Bot` account with consistent versions.
- An official vendor installer in a Dockerfile `RUN` (`curl -fsSL https://deb.nodesource.com/... | bash`): judge the host.

## Rules that fire here

`run-entry-new-file` (medium; high for a lifecycle hook or a command put in front of an old one), `asset-run-as-code`, `make-executable`, `curl-pipe-shell`, `remote-fetch-to-disk`, `inline-code-exec`, `obfuscated-payload`, `high-entropy-blob`. No rule reads: lockfile hosts and integrity, typosquats, registry config files, `setup.py`/`build.rs`/`conftest.py` bodies. Those are yours to read.
