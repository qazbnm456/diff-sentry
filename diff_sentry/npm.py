"""npm watch: each new version of a watched npm package, compared with the version before it.

The npm worms of 2025 published versions of popular packages with stolen tokens, each with a `preinstall` or `postinstall` script that runs the payload on every install; a version published with a stolen token also lacks the provenance a package's own release workflow attaches. So a version is a release like a PyPI one (`releases.release_event` with `registry="npm"`): its one tarball, read as DATA and never installed, against the previous version's, every new or changed file screened by the same rules, and the facts only npm shows added here. Every version's tarball is checked against the registry's sha512 `integrity`; publishers are read from the registry's SLSA provenance, bound to the tarball by its digest.

Host-side plumbing like `releases`: it fetches only from `registry.npmjs.org`, through `releases._httpx_fetch`. Pure stdlib; no dspy.
"""

from __future__ import annotations

import base64
import io
import json
import logging
import posixpath
import re
import tarfile
from datetime import UTC, datetime
from urllib.parse import quote, urlsplit

from .releases import DownloadError, Fetch, ReleaseFile, ReleaseWatcher

log = logging.getLogger(__name__)

_PACKUMENT_URL = "https://registry.npmjs.org/{name}"
_ACCEPT = "application/vnd.npm.install-v1+json"      # the abbreviated document npm itself installs from
_MAX_PACKUMENT_BYTES = 64 << 20
_MAX_ATTESTATION_BYTES = 4 << 20
_MAX_MANIFEST_BYTES = 16 << 20     # one package.json
_SLSA = "https://slsa.dev/provenance/v1"
_NAME_RE = re.compile(r"(?:@[A-Za-z0-9][A-Za-z0-9._~-]{0,212}/)?[A-Za-z0-9][A-Za-z0-9._~-]{0,212}")
_SEMVER_RE = re.compile(r"v?([0-9]{1,20})\.([0-9]{1,20})\.([0-9]{1,20})(?:-([0-9A-Za-z.-]{1,200}))?(?:\+[0-9A-Za-z.-]{1,200})?")
_GITHUB_RE = re.compile(r"https://github\.com/([A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}?)(?:\.git)?/?")
# the scripts npm runs when a package is installed from the registry (`prepare` runs only for a git or local install)
_INSTALL_SCRIPTS = ("preinstall", "install", "postinstall")
_YOUNG_DAYS = 30                   # a dependency created this recently is not yet a known package
_MAX_DEPENDENCY_LOOKUPS = 50
_MAX_FULL_DOCUMENT_BYTES = 64 << 20  # the full document gives the creation and publish times
_DEPENDENCY_KEYS = ("dependencies", "optionalDependencies", "peerDependencies")      # npm 7 and later installs peers
# a semver range or a dist-tag never holds `:` or `/`; a git, URL, path, `github:` or `npm:` alias spec does
_OFF_REGISTRY_RE = re.compile(r"[:/\\]")


class _Semver(tuple):
    """A semver version's order: numbers, then a release after its pre-releases, whose identifiers order numbers first."""

    @property
    def is_prerelease(self) -> bool:
        return not self[3]


def semver_key(version: str) -> _Semver | None:
    m = _SEMVER_RE.fullmatch(version)
    if not m:
        return None
    pre = m.group(4)
    ids = tuple((0, int(x), "") if x.isdigit() else (1, 0, x) for x in pre.split(".")) if pre else ()
    return _Semver((int(m.group(1)), int(m.group(2)), int(m.group(3)), pre is None, ids))


def parse_npm_packages(texts: list[str]) -> list[str]:
    """npm package names (`left-pad`, `@scope/name`) from arguments and files: whitespace, comma or newline separated, `#` comments allowed."""
    out: list[str] = []
    for text in texts:
        for line in text.splitlines() or [text]:
            for word in line.split("#", 1)[0].replace(",", " ").split():
                if len(word) > 214 or not _NAME_RE.fullmatch(word):
                    raise ValueError(f"not an npm package name: {word!r}")
                if word not in out:
                    out.append(word)
    return out


def parse_packument(body: bytes) -> list[ReleaseFile]:
    """Each version of an abbreviated packument as its one tarball, with the registry's sha512 and whether the registry holds its provenance. A tarball served from another host is left out: only the registry's are read."""
    data = json.loads(body.decode("utf-8"))
    out: list[ReleaseFile] = []
    for version, meta in (data.get("versions") or {}).items():
        dist = meta.get("dist") if isinstance(meta, dict) else None
        if not isinstance(dist, dict) or semver_key(str(version)) is None:
            continue
        url = str(dist.get("tarball") or "")
        if urlsplit(url).scheme != "https" or urlsplit(url).hostname != "registry.npmjs.org":
            continue
        integrity = str(dist.get("integrity") or "")
        attestations = dist.get("attestations") if isinstance(dist.get("attestations"), dict) else {}
        out.append(ReleaseFile(
            filename=f"{posixpath.basename(urlsplit(url).path)}", url=url, version=str(version), kind="npm", size=0,
            sha256="", upload_time="", yanked=False, attested=bool((attestations or {}).get("provenance")),
            provenance=str(attestations.get("url") or "") if attestations else "",
            sha512=integrity[len("sha512-"):] if integrity.startswith("sha512-") else ""))
    return out


def npm_publishers(fetch: Fetch, f: ReleaseFile, notes: list[str]) -> set[str]:
    """The publisher a version's SLSA provenance names, as `releases.publisher_identity` would write it (`github:owner/name:.github/workflows/x.yml::`). The statement must name the tarball's own sha512, or it is a note."""
    try:
        status, _, body = fetch(f.provenance, {"Accept": "application/json"}, _MAX_ATTESTATION_BYTES)
    except ValueError as exc:
        notes.append(f"{f.filename}: its provenance was not read ({str(exc)[:120]})")
        return set()
    if status == 404:
        return set()
    if status != 200:
        raise DownloadError(f"{f.filename}: its provenance answered HTTP {status}")
    found: set[str] = set()
    try:
        for att in json.loads(body.decode("utf-8")).get("attestations") or []:
            if att.get("predicateType") != _SLSA:
                continue
            statement = json.loads(base64.b64decode(att["bundle"]["dsseEnvelope"]["payload"]))
            digests = {str((s.get("digest") or {}).get("sha512") or "") for s in statement.get("subject") or []}
            if not f.sha512 or base64.b64decode(f.sha512).hex() not in digests:
                notes.append(f"{f.filename}: its provenance names another tarball, or the registry gives no sha512 to bind it to")
                continue
            workflow = statement["predicate"]["buildDefinition"]["externalParameters"]["workflow"]
            m = _GITHUB_RE.fullmatch(str(workflow.get("repository") or ""))
            repo = m.group(1).lower() if m else str(workflow.get("repository") or "").lower()
            kind = "github" if m else "other"
            found.add(":".join(str(x).replace(":", "_") for x in (kind, repo, workflow.get("path") or "", "", "")))
    except (ValueError, TypeError, KeyError, AttributeError):
        notes.append(f"{f.filename}: its provenance could not be read")
    return found


def tarball_manifests(filename: str, data: bytes) -> tuple[dict[str, dict], set[str], list[str]]:
    """Every `package.json` of a tarball as npm reads it, by the directory of its package (`""` the root, `node_modules/helper` a bundled dependency, whose install scripts npm runs too), with the package directories that hold a `binding.gyp`, and notes for what could not be read. As npm extracts: the first path component dropped (a member at the root is not installed), the last entry of a path standing, the bytes decoded as UTF-8 with a BOM dropped and invalid bytes replaced. Read from the tarball itself, never through the screen's text budget, and an unreadable manifest is a note (`release-not-fully-read`), never a package without scripts."""
    from .releases import _MAX_MEMBERS, _MAX_READ_BYTES, _Capped, _decompressed

    raw: dict[str, bytes | None] = {}
    gyp: set[str] = set()
    notes: list[str] = []
    try:
        stream = io.BufferedReader(_Capped(_decompressed(data), _MAX_READ_BYTES))
        with tarfile.open(fileobj=stream, mode="r|") as tf:
            for count, info in enumerate(tf, 1):
                if count > _MAX_MEMBERS:
                    notes.append(f"{filename}: more than {_MAX_MEMBERS} members, its manifests not read past them")
                    break
                parts = [p for p in info.name.split("/") if p not in ("", ".")]
                if len(parts) < 2 or ".." in parts:          # npm refuses a path that climbs out
                    continue
                path = "/".join(parts[1:])
                folder, base = posixpath.dirname(path), posixpath.basename(path).lower()
                if not _package_dir(folder):
                    continue
                if base == "binding.gyp":                    # npm on a case-insensitive file system finds `Binding.gyp` too
                    gyp.add(folder)
                if base != "package.json":
                    continue
                if not info.isfile() or info.size > _MAX_MANIFEST_BYTES:
                    raw[path] = None
                    continue
                fh = tf.extractfile(info)
                raw[path] = fh.read() if fh is not None else None
    except Exception as exc:  # noqa: BLE001 (fail CLOSED: a tarball whose manifests cannot be read is evidence)
        notes.append(f"{filename}: its manifests were not read to the end ({type(exc).__name__})")
    folded: dict[str, list[str]] = {}
    for path in raw:
        folded.setdefault(path.lower(), []).append(path)
    for paths in folded.values():
        if len(paths) > 1:      # which one npm reads depends on the file system: each is read, and the pair alerts
            notes.append(f"{filename}: manifests whose paths differ only in case ({', '.join(sorted(paths))})"[:240])
    manifests: dict[str, dict] = {}
    for path, body in raw.items():
        folder, where = posixpath.dirname(path), path
        key = folder if posixpath.basename(path) == "package.json" else f"{folder} [{posixpath.basename(path)}]".strip()
        if body is None:
            notes.append(f"{filename}: {where} is not a regular file of at most {_MAX_MANIFEST_BYTES >> 20} MiB")
            continue
        try:
            manifest = json.loads(body.decode("utf-8-sig", "replace"))
        except (ValueError, RecursionError):
            notes.append(f"{filename}: {where} could not be read as JSON")
            continue
        if isinstance(manifest, dict):
            manifests[key] = manifest
        else:
            notes.append(f"{filename}: {where} is not a JSON object")
    if "" not in manifests and not notes:
        notes.append(f"{filename}: no package.json")
    return manifests, gyp, notes


def _package_dir(folder: str) -> bool:
    """The root, or a dependency's directory under `node_modules`, at any depth (`node_modules/@s/x/node_modules/y`)."""
    parts = folder.split("/") if folder else []
    i = 0
    while i < len(parts):
        if parts[i] != "node_modules" or i + 1 >= len(parts):
            return False
        i += 3 if parts[i + 1].startswith("@") else 2
        if i > len(parts):
            return False
    return True


def _install_scripts(manifests: dict[str, dict], gyp: set[str]) -> dict[str, str]:
    """The scripts an install from the registry runs, by `<package dir> <script>`: `preinstall`, `install`, `postinstall`, and the `node-gyp rebuild` npm runs for a `binding.gyp` when neither install script is given."""
    found: dict[str, str] = {}
    for folder, manifest in manifests.items():
        scripts = manifest.get("scripts")
        mine = {k: str(v) for k, v in (scripts.items() if isinstance(scripts, dict) else []) if k in _INSTALL_SCRIPTS}
        if folder.split(" [", 1)[0] in gyp and not {"install", "preinstall"} & set(mine):
            mine["install"] = "node-gyp rebuild (implied by binding.gyp)"
        found.update({f"{folder} {k}".strip(): v for k, v in mine.items()})
    return found


def _dependencies(manifest: dict) -> set[str]:
    return {str(name) for key in _DEPENDENCY_KEYS if isinstance(manifest.get(key), dict) for name in manifest[key]}


def _registry_dependencies(manifests: dict[str, dict]) -> set[str]:
    """Each dependency npm takes from the registry, by `<package dir> <name>`, in every manifest (a bundled package's missing dependencies are installed too)."""
    return {f"{folder} {name}".strip() for folder, manifest in manifests.items() for key in _DEPENDENCY_KEYS
            if isinstance(manifest.get(key), dict) for name, spec in manifest[key].items()
            if not (_OFF_REGISTRY_RE.search(str(spec)) or str(spec).strip().startswith((".", "~/")))}


def published_at(fetch: Fetch, package: str, version: str) -> datetime | None:
    """When the registry says `version` of `package` was published (`time[version]` of its full document), so a dependency's age is measured as of the version, not the clock; None when that cannot be read."""
    try:
        status, _, body = fetch(_PACKUMENT_URL.format(name=quote(package, safe="@")), {"Accept": "application/json"},
                                _MAX_FULL_DOCUMENT_BYTES)
        return datetime.fromisoformat(str(json.loads(body.decode("utf-8"))["time"][version])) if status == 200 else None
    except (ValueError, KeyError, TypeError, AttributeError):
        return None


def dependency_facts(fetch: Fetch, names: list[str], notes: list[str], now: datetime | None = None) -> dict:
    """What the registry says of each dependency a version newly takes from it: one whose versions run a script at install (`hasInstallScript`), and one created within `_YOUNG_DAYS` before `now` (the version's publish time) or not on the registry at all. A compromised version need not carry the payload itself: it can depend on a package published hours before, whose install script runs it. A full document past its bound is a note, never an established package: an author pads a package's versions as easily as they publish them."""
    now = now or datetime.now(UTC)
    runs, young = [], []
    if len(names) > _MAX_DEPENDENCY_LOOKUPS:
        notes.append(f"{len(names)} new dependencies, the first {_MAX_DEPENDENCY_LOOKUPS} looked up")
    for name in names[:_MAX_DEPENDENCY_LOOKUPS]:
        if not _NAME_RE.fullmatch(name):
            continue
        url = _PACKUMENT_URL.format(name=quote(name, safe="@"))
        status, _, body = fetch(url, {"Accept": _ACCEPT}, _MAX_PACKUMENT_BYTES)
        if status == 404:
            young.append(f"{name} (not on the registry)")
            continue
        if status != 200:
            raise DownloadError(f"the registry's document of {name} answered HTTP {status}")
        try:
            versions = json.loads(body.decode("utf-8")).get("versions") or {}
            scripted = sorted((v for v, meta in versions.items() if isinstance(meta, dict) and meta.get("hasInstallScript")),
                              key=lambda v: (semver_key(v) is not None, semver_key(v) or (), v))
        except (ValueError, AttributeError):
            notes.append(f"the registry's document of {name} could not be read")
            continue
        if scripted:
            runs.append(f"{name} ({len(scripted)} of {len(versions)} versions, {scripted[-1]} the last)"[:200])
        try:
            status, _, body = fetch(url, {"Accept": "application/json"}, _MAX_FULL_DOCUMENT_BYTES)
        except ValueError:
            notes.append(f"the registry's full document of {name} is past {_MAX_FULL_DOCUMENT_BYTES >> 20} MiB, so its age was not read")
            continue
        if status != 200:
            raise DownloadError(f"the registry's full document of {name} answered HTTP {status}")
        try:
            created = datetime.fromisoformat(str(json.loads(body.decode("utf-8"))["time"]["created"]))
        except (ValueError, KeyError, TypeError, AttributeError):
            notes.append(f"the registry does not say when {name} was created")
            continue
        if (now - created).days < _YOUNG_DAYS:
            young.append(f"{name} (created {created.date().isoformat()})")
    return {"dependencies_run_at_install": runs, "dependencies_young": young}


def _sources(manifests: dict[str, dict]) -> dict[str, str]:
    """Each dependency npm installs from somewhere other than the registry, by `<package dir> <name>`: a git repository, a URL, a path, or an `npm:` alias to another package. npm fetches that code at install and runs its install scripts (a git dependency's `prepare` too), so a version needs no script of its own to run code."""
    found: dict[str, str] = {}
    for folder, manifest in manifests.items():
        for key in _DEPENDENCY_KEYS:
            deps = manifest.get(key)
            for name, spec in (deps.items() if isinstance(deps, dict) else []):
                spec = str(spec).strip()
                if _OFF_REGISTRY_RE.search(spec) or spec.startswith((".", "~/")):
                    found[f"{folder} {name}".strip()] = spec
    return found


def npm_facts(new: list[tuple[str, bytes]], old: list[tuple[str, bytes]], notes: list[str],
              fetch: Fetch | None = None, package: str = "", version: str = "") -> dict:
    """What a version runs at install and what it depends on, against the previous version, from the tarballs' manifests (`tarball_manifests`): an install script it adds (`npm-install-script-added`, high) or changes (`npm-install-script-changed`, medium), its own or a bundled dependency's, a dependency it now installs from outside the registry or from another such source (`npm-dependency-source`, high), and a new dependency (low). What of the new version's manifests could not be read is a note; the previous version's unread manifests count as none, so a script there is added. A new dependency from the registry is looked up there (`dependency_facts`)."""
    if not new:
        return {}
    manifests, gyp = {}, set()
    for filename, body in new:
        found, dirs, unread = tarball_manifests(filename, body)
        manifests.update(found)
        gyp |= dirs
        notes.extend(unread)
    before_manifests, before_gyp = {}, set()
    for filename, body in old:
        found, dirs, _ = tarball_manifests(filename, body)
        before_manifests.update(found)
        before_gyp |= dirs
    now, before = _install_scripts(manifests, gyp), _install_scripts(before_manifests, before_gyp)
    sources, before_sources = _sources(manifests), _sources(before_manifests)
    # a dependency newly taken from the registry, in any manifest: a new name, or one that came from elsewhere before
    added = sorted({key.rsplit(" ", 1)[-1] for key in _registry_dependencies(manifests) - _registry_dependencies(before_manifests)})
    looked = {}
    if old and added and fetch is not None:
        looked = dependency_facts(fetch, added, notes, published_at(fetch, package, version) if package else None)
    return {
        **looked,
        "dependency_sources": [f"{k}: {v}"[:200] for k, v in sorted(sources.items()) if before_sources.get(k) != v]
                              if old else [],
        "install_scripts_added": [f"{k}: {v}"[:200] for k, v in sorted(now.items()) if k not in before] if old else [],
        "install_scripts_changed": [f"{k}: {before[k]}"[:100] + f" -> {v}"[:100] for k, v in sorted(now.items())
                                    if k in before and before[k] != v],
        "new_requires": sorted(_dependencies(manifests.get("", {})) - _dependencies(before_manifests.get("", {})))[:50]
                        if old else [],
    }


class NpmWatcher(ReleaseWatcher):
    """`ReleaseWatcher` over the npm registry: the same per-file state, retries and alerts, in `npm.db`, with a version's tarball as its one file."""

    registry = "npm"
    state_file = "npm.db"

    def _order(self, version: str):
        return semver_key(version)

    def _index(self, package: str, etag: str | None) -> tuple[list[ReleaseFile] | None, str | None]:
        headers = {"Accept": _ACCEPT, **({"If-None-Match": etag} if etag else {})}
        status, resp_headers, body = self.fetch(_PACKUMENT_URL.format(name=quote(package, safe="@")), headers,
                                                _MAX_PACKUMENT_BYTES)
        if status == 304:
            return None, etag
        if status != 200:
            raise RuntimeError(f"the registry's document of {package} answered HTTP {status}")
        return parse_packument(body), {k.lower(): v for k, v in resp_headers.items()}.get("etag")
