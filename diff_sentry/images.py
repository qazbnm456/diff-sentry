"""Image watch: each new or moved tag of a watched container image, judged by its build provenance against what the repository's images have been built from before, and by the files it changes.

litellm 1.107.0's images on GHCR and Docker Hub, `latest` and `main-stable` among them, were built by its own release workflow from the attacker's `Berri-AI/litellm`, and BuildKit wrote that in each image's SLSA provenance (`vcs:source`). So the provenance of an image names where it was built from and what built it. A repository holds images from several workflows (releases, nightlies, branch builds), so an image is judged against the set of sources and builders the repository is known to use, learned from a sample at first sight and from every image judged clean since, never from one that raised an alert. The provenance is unsigned, so the image's content is read too: the layers it does not share with the image it replaces, compared file by file (`layer_change`). The comparison is screened like a release (`kind="release"`, facts in `release.image`, changed files as the event's files), and `scan_image` turns the provenance into baseline hits.

Host-side plumbing, like `releases`: it reads the registry's API only (manifests, the provenance attestation, the layers two images do not share), from the registries' own hosts and anonymous pull tokens, with every response bounded. A layer is read as data in memory, never unpacked to disk or run. Pure stdlib + httpx; no dspy.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import posixpath
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import quote, urlsplit

from .dbutil import open_versioned
from .releases import Artifact
from .schema import IndicatorHit

log = logging.getLogger(__name__)

# A fetch maps (url, request headers, byte limit) to (status, response headers, body), and never follows a redirect. A request header `X-Method: HEAD` asks for a HEAD (a digest without the manifest, which Docker Hub does not count).
Fetch = Callable[[str, dict, int], tuple[int, dict, bytes]]

# The registries an image may be read from, the hosts their tokens come from, and the hosts their blobs redirect to.
_REGISTRIES = {"ghcr.io": "ghcr.io", "docker.io": "registry-1.docker.io", "registry-1.docker.io": "registry-1.docker.io"}
_ALLOWED_HOSTS = frozenset({"ghcr.io", "registry-1.docker.io", "auth.docker.io", "pkg-containers.githubusercontent.com",
                            "production.cloudflare.docker.com", "production.cloudfront.docker.com"})
_INDEX_TYPES = ("application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json")
_MANIFEST_TYPES = ("application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json")
_MAX_MANIFEST_BYTES = 4 << 20
_MAX_PROVENANCE_BYTES = 16 << 20
_MAX_TAG_PAGES = 50
_MAX_PLATFORMS = 32
# One path component of an image name, and a registry host (a component with a dot), each bounded.
_NAME_PART_RE = re.compile(r"[a-z0-9]{1,128}(?:[._-]{1,2}[a-z0-9]{1,128}){0,16}")
_HOST_RE = re.compile(r"[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63}){1,8}")
_TOKEN_PARAM_RE = re.compile(r'(?<!\w)(\w{1,40})="([^"]{0,400})"')
# A GitHub repository URL, the host exactly github.com (`https://`, `git://`, `ssh://git@`, or `git@github.com:`).
_GITHUB_REPO_RE = re.compile(r"(?:(?:https?|git|ssh)://(?:git@)?|git@)github\.com[/:]([A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}?)(?:\.git)?/?",
                             re.IGNORECASE)
# The tags cosign pushes beside an image (a signature, an attestation, an SBOM): not images of the repository.
_COSIGN_TAG_RE = re.compile(r"sha256-[0-9a-f]{64}\.(?:sig|att|sbom)")
_MAX_NEW_TAGS = 50          # tags judged per image per poll; the rest wait for the next poll
_RECHECKED_VERSIONS = 10    # the newest version tags whose digest is checked again each poll (a re-pushed tag)
_SAMPLED_VERSIONS = 5       # the newest version tags whose provenance seeds what the repository is known to use


@dataclass(frozen=True)
class ImageRef:
    registry: str           # the API host
    name: str               # the repository path (`berriai/litellm`, `library/python`)

    @property
    def label(self) -> str:
        return f"{'docker.io' if self.registry == 'registry-1.docker.io' else self.registry}/{self.name}"


def parse_image(text: str) -> ImageRef:
    """`ghcr.io/berriai/litellm`, `docker.io/litellm/litellm` or `litellm/litellm` (Docker Hub), without a tag."""
    parts = text.strip().lower().split("/")
    host = parts.pop(0) if len(parts) > 1 and _HOST_RE.fullmatch(parts[0]) else "docker.io"
    if not parts or len(parts) > 8 or not all(_NAME_PART_RE.fullmatch(p) for p in parts):
        raise ValueError(f"not an image name: {text!r}")
    if host not in _REGISTRIES:
        raise ValueError(f"{host} is not a registry release-watch reads (ghcr.io, docker.io)")
    name = "/".join(parts)
    if _REGISTRIES[host] == "registry-1.docker.io" and "/" not in name:
        name = f"library/{name}"
    return ImageRef(_REGISTRIES[host], name)


def _httpx_fetch(timeout: float = 60.0) -> Fetch:
    def fetch(url: str, headers: dict, limit: int) -> tuple[int, dict, bytes]:
        import httpx

        host = urlsplit(url).hostname or ""
        if urlsplit(url).scheme != "https" or host not in _ALLOWED_HOSTS:
            raise ValueError(f"refusing to fetch from {host!r}: only the registries' own hosts are read")
        headers = dict(headers)
        method = headers.pop("X-Method", "GET")
        with httpx.stream(method, url, headers=headers, timeout=timeout, follow_redirects=False) as resp:
            body = bytearray()
            for chunk in resp.iter_bytes():
                body += chunk
                if len(body) > limit:
                    raise ValueError(f"{url} is larger than {limit} bytes")
            return resp.status_code, dict(resp.headers), bytes(body)

    return fetch


class RateLimited(RuntimeError):
    """The registry answered 429: the poll stops for that image and nothing counts as a failure."""


class Registry:
    """A registry's API read anonymously: a pull token is asked for when the registry answers 401 with a Bearer challenge (again when a token expires), from the realm it names (an allowed host), kept per registry and repository; a blob's redirect is followed to an allowed host only."""

    def __init__(self, fetch: Fetch):
        self.fetch = fetch
        self.tokens: dict[tuple[str, str], str] = {}

    def _get(self, ref: ImageRef, path: str, accept: tuple[str, ...] | None, limit: int,
             head: bool = False) -> tuple[int, dict, bytes]:
        url = f"https://{ref.registry}/v2/{ref.name}/{path}"
        key = (ref.registry, ref.name)
        for attempt in range(2):
            headers = {"Accept": ", ".join(accept)} if accept else {}
            if head:
                headers["X-Method"] = "HEAD"
            if key in self.tokens:
                headers["Authorization"] = f"Bearer {self.tokens[key]}"
            status, resp_headers, body = self.fetch(url, headers, limit)
            lower = {k.lower(): v for k, v in resp_headers.items()}
            if status == 401 and attempt == 0 and "www-authenticate" in lower:
                self.tokens[key] = self._token(lower["www-authenticate"], ref)     # none yet, or an expired one
                continue
            if status in (301, 302, 303, 307, 308) and "location" in lower:
                status, resp_headers, body = self.fetch(lower["location"], {}, limit)
            if status == 429:
                raise RateLimited(f"{ref.label}: the registry is rate-limiting this client")
            return status, resp_headers, body
        return status, resp_headers, body

    def _token(self, challenge: str, ref: ImageRef) -> str:
        params = dict(_TOKEN_PARAM_RE.findall(challenge))
        realm = params.get("realm", "")
        if not challenge.lower().startswith("bearer ") or (urlsplit(realm).hostname or "") not in _ALLOWED_HOSTS:
            raise ValueError(f"{ref.label}: the registry asked for credentials release-watch does not hold")
        query = f"service={quote(params.get('service', ''))}&scope={quote(f'repository:{ref.name}:pull')}"
        status, _, body = self.fetch(f"{realm}?{query}", {}, 64 << 10)
        if status != 200:
            raise RuntimeError(f"{ref.label}: the token endpoint answered HTTP {status}")
        data = json.loads(body.decode("utf-8"))
        return str(data.get("token") or data.get("access_token") or "")

    def tags(self, ref: ImageRef) -> list[str]:
        out: list[str] = []
        path = "tags/list?n=1000"
        for _ in range(_MAX_TAG_PAGES):
            status, headers, body = self._get(ref, path, None, _MAX_MANIFEST_BYTES)
            if status != 200:
                raise RuntimeError(f"{ref.label}: the tag list answered HTTP {status}")
            out += [str(t) for t in json.loads(body.decode("utf-8")).get("tags") or []]
            link = {k.lower(): v for k, v in headers.items()}.get("link", "")
            nxt = re.search(r"<[^>]{0,400}?/tags/list\?([^>]{1,400})>", link)
            if not nxt:
                return out
            path = f"tags/list?{nxt.group(1)}"
        raise RuntimeError(f"{ref.label}: more than {_MAX_TAG_PAGES} pages of tags")

    def digest(self, ref: ImageRef, reference: str) -> str:
        """The digest a tag names, from a HEAD (which Docker Hub does not count toward its pull limit)."""
        status, headers, _ = self._get(ref, f"manifests/{reference}", _INDEX_TYPES + _MANIFEST_TYPES, 1, head=True)
        digest = {k.lower(): v for k, v in headers.items()}.get("docker-content-digest", "")
        if status != 200 or not digest:
            raise RuntimeError(f"{ref.label}:{reference}: the manifest's digest answered HTTP {status}")
        return digest

    def manifest(self, ref: ImageRef, reference: str) -> tuple[str, dict]:
        """The manifest or index a tag or digest names, and its digest (the registry's `Docker-Content-Digest`)."""
        status, headers, body = self._get(ref, f"manifests/{reference}", _INDEX_TYPES + _MANIFEST_TYPES, _MAX_MANIFEST_BYTES)
        if status != 200:
            raise RuntimeError(f"{ref.label}:{reference}: the manifest answered HTTP {status}")
        digest = {k.lower(): v for k, v in headers.items()}.get("docker-content-digest", "")
        return digest or reference, json.loads(body.decode("utf-8"))

    def blob(self, ref: ImageRef, digest: str, limit: int) -> bytes:
        status, _, body = self._get(ref, f"blobs/{digest}", None, limit)
        if status != 200:
            raise RuntimeError(f"{ref.label}@{digest[:19]}: the blob answered HTTP {status}")
        return body


# ── provenance ───────────────────────────────────────────────────────────────────────────────────────────

def _source_repo(url: str) -> str:
    """`owner/name` of a GitHub repository URL, lower case; any other source as written, lower case (never read as a GitHub owner, so a lookalike is only ever judged between GitHub repositories)."""
    m = _GITHUB_REPO_RE.fullmatch((url or "").strip())
    return m.group(1).lower() if m else (url or "").strip().lower()


def provenance_facts(statement: dict) -> dict:
    """What a BuildKit SLSA provenance (v0.2 or v1) says about where an image was built from and what built it: the source repository and revision, and the GitHub repository, workflow (without its ref) and ref protection of the run."""
    predicate = statement.get("predicate") or {}
    meta = ((predicate.get("runDetails") or {}).get("metadata") or predicate.get("metadata") or {})
    vcs = (meta.get("buildkit_metadata") or meta.get("https://mobyproject.org/buildkit@v1#metadata") or {}).get("vcs") or {}
    definition = predicate.get("buildDefinition") or {}
    internal = definition.get("internalParameters") or (predicate.get("invocation") or {}).get("environment") or {}
    if not vcs:
        root = (((definition.get("externalParameters") or {}).get("request") or {}).get("root") or {}).get("request") or {}
        args = root.get("args") or {}
        vcs = {"source": args.get("vcs:source", ""), "revision": args.get("vcs:revision", "")}
    workflow = str(internal.get("github_workflow_ref") or "").split("@", 1)[0]
    protected = internal.get("github_ref_protected")
    return {
        "source": _source_repo(str(vcs.get("source") or "")),
        "revision": str(vcs.get("revision") or ""),
        "builder": str(internal.get("github_repository") or "").lower(),
        "workflow": workflow.lower(),
        "ref": str(internal.get("github_ref") or ""),
        "ref_protected": None if protected is None else str(protected).lower() == "true",
        "event": str(internal.get("github_event_name") or ""),
    }


def image_provenance(registry: Registry, ref: ImageRef, reference: str) -> tuple[str, list[dict], list[str], bool]:
    """The image's digest, the provenance facts of each platform it carries, notes on what could not be read, and whether it is a multi-platform index (a single manifest carries no BuildKit attestation). An attestation counts only when it names (`vnd.docker.reference.digest`) a platform image of the same index; a platform image no attestation names is a note."""
    digest, top = registry.manifest(ref, reference)
    notes: list[str] = []
    if top.get("mediaType") not in _INDEX_TYPES and "manifests" not in top:
        return digest, [], notes, False
    entries = top.get("manifests") or []
    attestations = [m for m in entries if (m.get("annotations") or {}).get("vnd.docker.reference.type") == "attestation-manifest"]
    platforms = {m.get("digest") for m in entries if m not in attestations}
    if len(attestations) > _MAX_PLATFORMS:
        notes.append(f"{len(attestations)} attestation manifests, the first {_MAX_PLATFORMS} read")
    facts: list[dict] = []
    attested: set[str] = set()
    for att in attestations[:_MAX_PLATFORMS]:
        named = (att.get("annotations") or {}).get("vnd.docker.reference.digest")
        if named not in platforms:
            notes.append(f"an attestation names {str(named)[:19]}, no platform image of this index")
            continue
        try:
            _, manifest = registry.manifest(ref, att["digest"])
            layers = [layer for layer in manifest.get("layers") or []
                      if "provenance" in str((layer.get("annotations") or {}).get("in-toto.io/predicate-type") or "")]
            for layer in layers[:1]:
                statement = json.loads(registry.blob(ref, layer["digest"], _MAX_PROVENANCE_BYTES))
                subjects = {f"sha256:{(s.get('digest') or {}).get('sha256', '')}" for s in statement.get("subject") or []}
                if named not in subjects:                   # BuildKit names the image it attests; none named is no binding
                    notes.append(f"a provenance's subject is not the image its attestation names ({str(named)[:19]})")
                    continue
                facts.append(provenance_facts(statement))
                attested.add(named)
        except RateLimited:
            raise
        except (ValueError, TypeError, AttributeError, KeyError, RuntimeError) as exc:
            notes.append(f"a provenance attestation could not be read ({type(exc).__name__})")
    if facts and platforms - attested:
        notes.append(f"{len(platforms - attested)} platform image(s) of the index carry no provenance")
    return digest, facts, notes, True


# ── layers ───────────────────────────────────────────────────────────────────────────────────────────────

_MAX_LAYER_BYTES = int(os.getenv("DS_RELEASE_MAX_LAYER_MB", "1024") or "1024") << 20   # one compressed layer
_MAX_LAYERS_BYTES = 4 << 30        # every differing layer of one comparison, both images and all platforms
_MAX_LAYER_READ = 8 << 30          # what one layer may decompress to


def _platform(desc: dict) -> str:
    p = desc.get("platform") or {}
    return "-".join(str(x) for x in (p.get("os"), p.get("architecture"), p.get("variant")) if x) or "default"


def _platforms(registry: Registry, ref: ImageRef, digest: str, notes: list[str]) -> dict[str, dict]:
    """Each platform image of an index (attestation manifests aside), or the one image of a single manifest, by platform. A runtime pulls the first entry for its platform, so that one is kept, and a second entry for a platform is a note."""
    _, top = registry.manifest(ref, digest)
    if top.get("mediaType") not in _INDEX_TYPES and "manifests" not in top:
        return {"default": top}
    images = [d for d in top.get("manifests") or [] if isinstance(d, dict)
              and (d.get("annotations") or {}).get("vnd.docker.reference.type") != "attestation-manifest"]
    if len(images) > _MAX_PLATFORMS:
        notes.append(f"{len(images)} platform images, the first {_MAX_PLATFORMS} compared")
    out: dict[str, dict] = {}
    for desc in images[:_MAX_PLATFORMS]:
        key = _platform(desc)
        if key in out:
            notes.append(f"{key}: two images for one platform; the first, which a runtime pulls, is compared")
            continue
        out[key] = registry.manifest(ref, desc["digest"])[1]
    return out


def _layer_path(name: str) -> str | None:
    """A layer member's path in the image's file system (`./usr/bin/x` and `/usr/bin/x` are `usr/bin/x`)."""
    parts = [p for p in name.split("/") if p not in ("", ".")]
    return None if not parts or ".." in parts or name.endswith("/") else "/".join(parts)


def _filesystem(kind: str, layers: list[tuple[str, bytes]], budget) -> Artifact:
    """The files a run of layers leaves, applied in order as a container runtime applies them: a layer's whiteouts (`.wh.name`, `.wh..wh..opq`) first remove what the layers beneath it hold, then its files replace earlier ones (no shadow)."""
    from .releases import _read_tar, _Spent

    merged = Artifact(kind, kind)
    for digest, body in layers:
        layer = Artifact(f"{kind} layer {digest[7:19]}", kind)
        try:
            _read_tar(layer, body, budget, path_of=_layer_path, limit=_MAX_LAYER_READ)
        except _Spent:
            layer.notes.append(f"{layer.filename}: not read to its end (more than {_MAX_LAYER_READ >> 30} GiB decompressed)")
        except Exception as exc:  # noqa: BLE001 (fail CLOSED: a layer this cannot read is evidence)
            layer.notes.append(f"{layer.filename}: not read to its end ({str(exc)[:80] or type(exc).__name__})")
        merged.notes += layer.notes
        # a layer's whiteouts remove what the layers beneath it hold, never what the layer itself adds (the OCI layer spec): so they apply first
        for member in layer.members.values():
            folder, base = posixpath.split(member.path)
            if base == ".wh..wh..opq":
                for gone in [k for k in merged.members if k.startswith(f"{folder}/" if folder else "")]:
                    del merged.members[gone]
            elif base.startswith(".wh."):
                target = posixpath.join(folder, base[4:])
                for gone in [k for k in merged.members if k == target or k.startswith((f"{target}/", f"{target}\0"))]:
                    del merged.members[gone]
        for key, member in layer.members.items():
            if not posixpath.basename(member.path).startswith(".wh."):
                merged.members[key] = member
    return merged


# what the config sets that decides what a container runs, and the environment variables that load code into a process
_RUN_KEYS = ("Entrypoint", "Cmd", "Shell", "User", "WorkingDir", "OnBuild", "Healthcheck")
_LOADER_ENV = frozenset({"PATH", "PYTHONWARNINGS", "PYTHONEXECUTABLE", "PYTHONPLATLIBDIR", "GCONV_PATH", "NODE_EXTRA_CA_CERTS", "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME",
                         "PYTHONINSPECT", "PYTHONUSERBASE", "NODE_OPTIONS", "NODE_PATH", "BASH_ENV", "ENV", "PERL5OPT",
                         "PERL5LIB", "RUBYOPT", "RUBYLIB", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "DYLD_INSERT_LIBRARIES"})
_MAX_CONFIG_BYTES = 4 << 20


def _config(registry: Registry, ref: ImageRef, manifest: dict, notes: list[str]) -> dict | None:
    """A platform image's run configuration (its config blob's `config`), checked against its digest; None, with a note, when it cannot be read."""
    desc = manifest.get("config") if isinstance(manifest.get("config"), dict) else {}
    digest = str(desc.get("digest") or "")
    try:
        body = registry.blob(ref, digest, _MAX_CONFIG_BYTES)
        if not digest.startswith("sha256:") or hashlib.sha256(body).hexdigest() != digest[7:]:
            raise ValueError("does not match its digest")
        config = json.loads(body.decode("utf-8")).get("config") or {}
        return config if isinstance(config, dict) else {}
    except RateLimited:
        raise
    except (RuntimeError, ValueError, AttributeError) as exc:
        notes.append(f"the image config {digest[7:19]} was not read ({str(exc)[:80]})")
        return None


def _env(config: dict) -> dict[str, str]:
    return {str(e).split("=", 1)[0]: str(e).split("=", 1)[-1] for e in config.get("Env") or [] if isinstance(e, str)}


def _render_config(config: dict) -> str:
    """The run configuration as a Dockerfile would write it, one setting a line, so the text rules read its commands."""
    lines = [f"{key.upper()} {json.dumps(config[key])}" for key in _RUN_KEYS if config.get(key) not in (None, [], "")]
    lines += [f"ENV {k}={v}" for k, v in sorted(_env(config).items())]
    return "\n".join(lines) + "\n"


def layer_change(registry: Registry, ref: ImageRef, digest: str, previous: str) -> tuple[list[dict], list[str], list[str], dict]:
    """The files an image changes against the image it replaces, platform by platform, and its run configuration against the replaced one's (`{config}`, rendered as Dockerfile lines, with the run settings and loader variables it changes as facts): only the layers the two do not share are read (a shared layer is the same bytes), in two passes like a release (`releases.release_event`), and their files compared by path, so a rebuilt layer shows only what changed in it. Returns the change's files, the members that run and were not shown as text, and notes on what was not read. Layers are read as DATA, in memory, and never unpacked or run."""
    from .releases import _Budget, _patch, pyc_source, release_files

    files: list[dict] = []
    unread: list[str] = []
    notes: list[str] = []
    runs: list[str] = []
    loaders: list[str] = []
    now, before = _platforms(registry, ref, digest, notes), _platforms(registry, ref, previous, [])
    budget = [_MAX_LAYERS_BYTES]

    def download(layers: list[dict]) -> list[tuple[str, bytes]]:
        out = []
        for layer in layers:
            size, digest_ = int(layer.get("size") or 0), str(layer.get("digest") or "")
            if size > _MAX_LAYER_BYTES or size > budget[0]:
                notes.append(f"layer {digest_[7:19]}: {size} bytes, not read (more than DS_RELEASE_MAX_LAYER_MB, or the comparison's budget)")
                continue
            body = registry.blob(ref, digest_, _MAX_LAYER_BYTES)
            if not digest_.startswith("sha256:") or hashlib.sha256(body).hexdigest() != digest_[7:]:
                notes.append(f"layer {digest_[7:19]}: the download does not match its digest")
                continue
            budget[0] -= len(body)
            out.append((digest_, body))
        return out

    for platform, manifest in now.items():
        old = before.get(platform)
        if old is None:
            notes.append(f"{platform}: a platform the previous image did not have, so its layers were not compared")
            continue
        config, before_config = _config(registry, ref, manifest, notes), _config(registry, ref, old, notes)
        if config is not None and before_config is not None and config != before_config:
            patch, added, removed, _ = _patch(_render_config(before_config), _render_config(config))
            files.append({"filename": f"{platform}/{{config}}", "status": "modified", "additions": added,
                          "deletions": removed, "patch": patch})
            for key in _RUN_KEYS:
                if config.get(key) != before_config.get(key):
                    runs.append(f"{platform} {key}: {json.dumps(config.get(key))}"[:200])
            env, before_env = _env(config), _env(before_config)
            loaders.extend(f"{platform} {k}={v}"[:200] for k, v in sorted(env.items())
                           if (k in _LOADER_ENV or k.startswith(("LD_", "DYLD_"))) and before_env.get(k) != v)
        mine = [layer for layer in manifest.get("layers") or [] if isinstance(layer, dict)]
        theirs = [layer for layer in old.get("layers") or [] if isinstance(layer, dict)]
        shared = {layer.get("digest") for layer in mine} & {layer.get("digest") for layer in theirs}
        if all(layer.get("digest") in shared for layer in mine):
            continue
        new_bodies = download([layer for layer in mine if layer.get("digest") not in shared])
        old_bodies = download([layer for layer in theirs if layer.get("digest") not in shared])
        skim = _Budget(keep=lambda path, digest_: False)
        old_digests = {(m.path, m.digest) for m in _filesystem(platform, old_bodies, skim).members.values()}
        wanted = {(m.path, m.digest) for m in _filesystem(platform, new_bodies, skim).members.values()
                  if (m.path, m.digest) not in old_digests}
        paths = {p for p, _ in wanted}
        sources = {src for p in paths if (src := pyc_source(p))}       # read too, to check the bytecode against
        text = _Budget()
        new = _filesystem(platform, new_bodies, _Budget.share(
            text, lambda path, digest_, w=wanted, s=sources: (path, digest_) in w or path in s))
        old_fs = _filesystem(platform, old_bodies, _Budget.share(text, lambda path, digest_, p=paths: path in p))
        notes += new.notes
        changed, missed = release_files([new], [old_fs])
        files += changed
        unread += missed
    return files, unread[:50], notes[:50], {"config_run_changed": runs[:50], "config_loader_env": loaders[:50]}


# ── facts as evidence ────────────────────────────────────────────────────────────────────────────────────

def _owner(repo: str) -> str:
    return repo.split("/", 1)[0] if repo.count("/") == 1 else ""


def _imitates(owner: str, owners: set[str]) -> bool:
    from .indicators import lookalike_owner

    return bool(owner) and any(lookalike_owner(owner, o) == "hyphen" for o in owners if o)


def scan_image(facts: dict) -> list[IndicatorHit]:
    """An image's provenance against what its repository is known to be built from and by (`known`) and, on GHCR, the namespace it is published under (a GitHub owner). A source or building repository whose owner imitates a known owner is `critical`; one of an owner not known is `high`; another repository or workflow of a known owner is `medium` (a repository's nightly and branch builds run other workflows, even from another repository of the same organisation); a build from an unprotected ref by a workflow whose known builds ran from protected refs is `high` (litellm's attacker turned protection off first). An image without provenance where the repository's images carry it is `high`, and so is anything that could not be read. The provenance is unsigned: whoever controls the push can write any statement, so a match proves nothing and only a mismatch is evidence."""
    from .indicators import _hit

    if not isinstance(facts, dict) or not facts:
        return []
    where = f"{facts.get('image', '')}:{facts.get('tag', '')}"
    now = facts.get("provenance") or []
    known = facts.get("known") or {}
    sources = set(known.get("sources") or [])
    builders = set(known.get("builders") or [])
    repos = {b.split(" ", 1)[0] for b in builders}
    protected = set(known.get("protected") or [])
    suspect = set(known.get("suspect") or [])
    # the owners an image is held against: the known ones, the GHCR namespace, and the unresolved ones of the first sight
    owners = ({_owner(r) for r in sources | repos} | {str(facts.get("namespace") or "")} | suspect) - {""}
    hits: list[IndicatorHit] = []
    if facts.get("baseline_lookalikes"):
        hits.append(_hit("image-source-lookalike", "critical",
                         "the images the watch started from were built from owners that imitate each other; which is real is not known",
                         ", ".join(sorted(facts["baseline_lookalikes"]))[:240], location=where))
    if (sources or builders) and not now:
        hits.append(_hit("image-provenance-dropped", "high", "the image carries no build provenance, which the repository's images do",
                         str(facts.get("digest", ""))[:80], location=where))
    if suspect:                                     # unresolved: every image alerts, with provenance or without, and none is learned, until a reset
        built = "; ".join(f"{i.get('source') or '(no source)'} by {i.get('builder') or '(no builder)'}" for i in now) or "no provenance"
        hits.append(_hit("image-owner-unresolved", "high",
                         "the images the watch started from came from owners that imitate each other, and that is not resolved",
                         f"{built}; unresolved: {', '.join(sorted(suspect))}"[:240], location=where))
    for item in now:
        source = str(item.get("source") or "")
        repo = str(item.get("builder") or "")
        builder = f"{repo} {item.get('workflow', '')}".strip()
        if _imitates(_owner(source), owners - {_owner(source)}):
            hits.append(_hit("image-source-lookalike", "critical",
                             "the image was built from a repository whose owner imitates one the repository is built from or published under",
                             f"{source} (known: {', '.join(sorted(sources)) or 'none'})"[:240], location=where))
        elif sources and source not in sources:
            same_owner = bool(_owner(source)) and _owner(source) in owners
            hits.append(_hit("image-source-changed", "medium" if same_owner else "high",
                             "the image was built from another repository of a known owner" if same_owner
                             else "the image was built from a source the repository is not known to be built from",
                             f"{source or '(no source recorded)'} (known: {', '.join(sorted(sources))})"[:240], location=where))
        if _imitates(_owner(repo), owners - {_owner(repo)}):
            hits.append(_hit("image-builder-lookalike", "critical",
                             "the image was built by a repository whose owner imitates one the repository is built by or from",
                             builder[:240], location=where))
        elif repos and _owner(repo) not in owners:
            hits.append(_hit("image-builder-changed", "high", "the image was built by a repository of an owner the repository is not known to be built by",
                             builder[:240], location=where))
        elif builders and builder not in builders:
            hits.append(_hit("image-workflow-changed", "medium",
                             "the image was built by a repository or workflow of a known owner that the repository is not known to use",
                             builder[:240], location=where))
        if item.get("workflow") in protected and item.get("ref_protected") is False:
            hits.append(_hit("image-ref-unprotected", "high",
                             "a workflow whose known builds ran from protected refs built this image from an unprotected one",
                             f"{item.get('workflow')} @ {item.get('ref')}"[:240], location=where))
    if facts.get("config_run_changed"):
        hits.append(_hit("image-run-config-changed", "high",
                         "the image runs another entrypoint, command, shell, user, healthcheck or build trigger than the image it replaces",
                         "; ".join(str(x) for x in facts["config_run_changed"])[:240], location=where))
    if facts.get("config_loader_env"):
        hits.append(_hit("image-loader-env", "high",
                         "the image sets an environment variable that loads code into its processes (LD_PRELOAD, PYTHONPATH, NODE_OPTIONS...)",
                         "; ".join(str(x) for x in facts["config_loader_env"])[:240], location=where))
    notes = [str(n) for n in facts.get("notes") or []]
    if notes:
        hits.append(_hit("release-not-fully-read", "high", "part of the image's provenance was not read",
                         "; ".join(notes)[:240], location=where))
    return hits


def _learn(known: dict, facts: list[dict]) -> dict:
    """`known` with the sources, builders and protected workflows of `facts` added."""
    sources = set(known.get("sources") or []) | {f["source"] for f in facts if f.get("source")}
    builders = set(known.get("builders") or []) | {f"{f.get('builder', '')} {f.get('workflow', '')}".strip() for f in facts}
    protected = set(known.get("protected") or []) | {f["workflow"] for f in facts if f.get("ref_protected") and f.get("workflow")}
    return {"sources": sorted(sources), "builders": sorted(b for b in builders if b), "protected": sorted(protected),
            "suspect": list(known.get("suspect") or [])}


def _without_lookalikes(known: dict, namespace: str) -> tuple[dict, list[str]]:
    """`known` without any source or building repository whose owner imitates another known owner or the namespace: a first-sight sample that already holds a lookalike cannot tell which side is the real one, so neither is learned: both owners are kept as `suspect`, and every image from either is `high` (`image-owner-unresolved`) until the state is reset after an investigation."""
    repos = set(known.get("sources") or []) | {b.split(" ", 1)[0] for b in known.get("builders") or []}
    owners = {_owner(r) for r in repos} | {namespace}
    suspect = {o for o in owners if o and _imitates(o, owners - {o})}
    if not suspect:
        return known, []
    kept = {
        "sources": [r for r in known.get("sources") or [] if _owner(r) not in suspect],
        "builders": [b for b in known.get("builders") or [] if _owner(b.split(" ", 1)[0]) not in suspect],
        "protected": [w for w in known.get("protected") or [] if _owner(w.split("/.github/", 1)[0]) not in suspect],
        "suspect": sorted(suspect),
    }
    return kept, sorted(suspect)


# ── the watcher ──────────────────────────────────────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS images (image TEXT PRIMARY KEY, first_seen TEXT NOT NULL, known TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tags (image TEXT NOT NULL, tag TEXT NOT NULL, digest TEXT, first_seen TEXT NOT NULL,
    PRIMARY KEY (image, tag));
CREATE TABLE IF NOT EXISTS image_judgments (
    run_id TEXT PRIMARY KEY, image TEXT NOT NULL, tag TEXT NOT NULL, digest TEXT, first_seen TEXT NOT NULL,
    state TEXT NOT NULL, signal INTEGER, error TEXT, fail_count INTEGER NOT NULL DEFAULT 0,
    alert_pending INTEGER NOT NULL DEFAULT 0, alert_fails INTEGER NOT NULL DEFAULT 0);
"""
_SCHEMA_VERSION = 2
_MAX_FAILS = 5
_ALERT_RETRIES_PER_POLL = 5
_MAX_ALERT_FAILS = 20
_VERSION_TAG_RE = re.compile(r"(?<![\w.])v?\d{1,9}(?:\.\d{1,9}){1,3}(?:[-+][A-Za-z0-9.]{1,40})?")


def image_run_id(ref: ImageRef, tag: str, digest: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", f"oci__{ref.label}-{tag}-{digest.split(':')[-1][:12]}")[:220]


_VERSION_NUMBERS_RE = re.compile(r"v?(\d{1,9}(?:\.\d{1,9}){0,3})")


def _version_key(tag: str) -> tuple:
    """Order tags by the version numbers they start with (`v1.106.2` after `v1.83.9-nightly`), a plain release after its suffixed builds, and tags without numbers before every version; ties by name."""
    m = _VERSION_NUMBERS_RE.match(tag)
    if not m:
        return ((), 0, tag)
    numbers = tuple(int(x) for x in m.group(1).split("."))
    return (numbers, 1 if m.end() == len(tag) else 0, tag)


def _releases(tags: list[str]) -> list[str]:
    """The version tags that are plain releases (`v1.106.2`, `1.106.2`, not `-nightly` or `-rc.1`), oldest first: the images a re-push would hurt, which a run of one version's pre-releases must not crowd out of a window."""
    return sorted((t for t in tags if _VERSION_TAG_RE.fullmatch(t) and _version_key(t)[1] == 1), key=_version_key)


def _namespace(ref: ImageRef) -> str:
    """The GitHub owner an image is published under: GHCR's first path component; none on Docker Hub."""
    return ref.name.split("/", 1)[0] if ref.registry == "ghcr.io" else ""


class ImageWatcher:
    """Polls each image's tags. On first sight every tag is the baseline, and the provenance of the watched floating tags and the newest version tags seeds what the repository is known to be built from and by. After that a new tag (cosign's `.sig`/`.att`/`.sbom` tags aside, at most `_MAX_NEW_TAGS` a poll), a watched floating tag that points at another image, and one of the newest version tags re-pushed, are judged; an image judged clean adds what built it to what is known."""

    def __init__(self, images: list[str], *, state_dir: str, out_dir: str, floating: tuple[str, ...] = ("latest",),
                 fetch: Fetch | None = None, emit: bool = True, poster=None, config=None,
                 now: Callable[[], datetime] | None = None):
        self.refs = [parse_image(i) for i in images]
        os.makedirs(state_dir, exist_ok=True)
        self.floating = tuple(floating)
        self.out_dir = out_dir
        self.registry = Registry(fetch or _httpx_fetch())
        self.emit, self.poster, self.config = emit, poster, config
        self.now = now or (lambda: datetime.now(UTC))
        self.db = open_versioned(os.path.join(state_dir, "images.db"), _SCHEMA, _SCHEMA_VERSION, "image_judgments")

    def close(self) -> None:
        self.db.close()

    def _stamp(self) -> str:
        return self.now().isoformat(timespec="seconds")

    def poll_once(self) -> list[dict]:
        self._retry_alerts()
        results: list[dict] = []
        for ref in self.refs:
            try:
                results += self._poll(ref)
            except Exception as exc:  # noqa: BLE001 (one image's failure must not stop the watch)
                log.warning("image %s: %s", ref.label, exc)
        return results

    def _known(self, ref: ImageRef) -> dict:
        row = self.db.execute("SELECT known FROM images WHERE image=?", (ref.label,)).fetchone()
        return json.loads(row["known"]) if row else {}

    def _baseline(self, ref: ImageRef, tags: list[str]) -> None:
        stamp = self._stamp()
        versions = _releases(tags)
        sample = [t for t in self.floating if t in tags] + versions[-_SAMPLED_VERSIONS:]
        known: dict = {}
        unread: list[str] = []
        for tag in dict.fromkeys(sample):
            try:
                _, facts, notes, _ = image_provenance(self.registry, ref, tag)
            except RateLimited:
                raise
            except (RuntimeError, ValueError) as exc:
                unread.append(f"{tag}: {exc}")
                continue
            unread += notes
            known = _learn(known, facts)
        if unread and not (known.get("sources") or known.get("builders")):
            # nothing was learned and something could not be read: no baseline, so no first attested image goes unjudged
            raise RuntimeError(f"{ref.label}: the first-sight sample could not be read ({'; '.join(unread)[:200]})")
        known, suspect = _without_lookalikes(known, _namespace(ref))
        if suspect:
            log.warning("image watch: %s: the first-sight sample holds owners that imitate each other (%s); neither is learned",
                        ref.label, ", ".join(suspect))
            run_id = image_run_id(ref, "first-sight", "lookalike")
            if self.db.execute("SELECT 1 FROM image_judgments WHERE run_id=?", (run_id,)).fetchone() is None:
                from .cli import screen

                image = {"image": ref.label, "tag": "(first sight)", "baseline_lookalikes": suspect, "known": known}
                art = screen(self._event(ref, "(first sight)", image), run_id=run_id, outdir=self.out_dir,
                             config=self.config, emit=self.emit, poster=self.poster)
                self._settle(run_id, ref, "(first sight)", None, stamp, art.response, art.emit)
                self.db.commit()
        watched = [t for t in self.floating if t in tags] + versions[-_RECHECKED_VERSIONS:]
        digests = {t: self.registry.digest(ref, t) for t in dict.fromkeys(watched)}
        self.db.execute("INSERT INTO images VALUES (?, ?, ?)", (ref.label, stamp, json.dumps(known)))
        self.db.executemany("INSERT OR IGNORE INTO tags VALUES (?, ?, ?, ?)",
                            [(ref.label, t, digests.get(t), stamp) for t in tags])
        self.db.commit()
        log.info("image watch: %s has %d tag(s), taken as the baseline (known: %s)", ref.label, len(tags), known)

    def _poll(self, ref: ImageRef) -> list[dict]:
        tags = [t for t in self.registry.tags(ref) if not _COSIGN_TAG_RE.fullmatch(t)]
        if self.db.execute("SELECT 1 FROM images WHERE image=?", (ref.label,)).fetchone() is None:
            self._baseline(ref, tags)
            return []
        known = {r["tag"]: r["digest"] for r in self.db.execute("SELECT tag, digest FROM tags WHERE image=?", (ref.label,))}
        pending = {r["tag"] for r in self.db.execute(
            "SELECT tag FROM image_judgments WHERE image=? AND state='error' AND fail_count<?", (ref.label, _MAX_FAILS))}
        fresh = sorted((t for t in tags if t not in known or t in pending), key=_version_key, reverse=True)[:_MAX_NEW_TAGS]
        results = []
        for tag in fresh:                           # newest first: junk tags cannot hold a new release back
            result = self.judge(ref, tag, record=True, previous=known.get(tag) or self._predecessor(tag, known))
            if result.get("rate_limited"):
                return results
            results.append(result)
        versions = [t for t in _releases(tags) if t in known]
        for tag in dict.fromkeys([*(t for t in self.floating if t in tags), *versions[-_RECHECKED_VERSIONS:]]):
            if tag in fresh or known.get(tag) is None and tag not in self.floating:
                continue
            digest = self.registry.digest(ref, tag)
            if known.get(tag) != digest:
                results.append(self.judge(ref, tag, record=True, digest=digest,
                                          previous=known.get(tag) or self._predecessor(tag, known)))
        return results

    def judge(self, ref: ImageRef, tag: str, *, record: bool = False, digest: str | None = None,
              previous: str | None = None) -> dict:
        """Judge the image a tag names against what the repository is known to use, screen it (the early SIEM alert when its evidence reaches the floor), and record it; a comparison that fails is retried, then screened as not compared (`release-not-fully-read`, which alerts). Never raises."""
        from .cli import screen

        stamp = self._stamp()
        known = self._known(ref)
        try:
            digest, facts, notes, index = image_provenance(self.registry, ref, digest or tag)
            image = {"image": ref.label, "tag": tag, "digest": digest, "index": index, "provenance": facts, "known": known,
                     "namespace": _namespace(ref), "notes": notes[:50]}
            event = self._event(ref, tag, image)
            if previous and previous != digest:     # the files the image changes against the one it replaces
                files, unread, layer_notes, config_facts = layer_change(self.registry, ref, digest, previous)
                event["files"] = files
                image.update(config_facts)
                event["release"].update({"previous": previous, "unread_code": unread, "notes": layer_notes})
            run_id = image_run_id(ref, tag, digest)
            art = screen(event, run_id=run_id, outdir=self.out_dir, config=self.config, emit=self.emit, poster=self.poster)
        except RateLimited as exc:                 # not a failure of the image: the next poll tries again
            log.warning("image %s:%s: %s", ref.label, tag, exc)
            return {"image": ref.label, "tag": tag, "rate_limited": True}
        except Exception as exc:  # noqa: BLE001 (a comparison that fails is retried, then alerts as not compared)
            log.warning("image %s:%s: %s", ref.label, tag, exc)
            return self._failed(ref, tag, digest, stamp, record, f"{type(exc).__name__}: {exc}")
        resp = art.response
        self._settle(run_id, ref, tag, digest, stamp, resp, art.emit)
        if record:
            self.db.execute("INSERT OR REPLACE INTO tags VALUES (?, ?, ?, ?)", (ref.label, tag, digest, stamp))
            if not resp.signal and facts:           # a clean image teaches what the repository uses; an alert never does
                self.db.execute("UPDATE images SET known=? WHERE image=?", (json.dumps(_learn(known, facts)), ref.label))
        self.db.commit()
        log.info("image %s:%s %s: signal=%s floor=%s", ref.label, tag, digest[:19], resp.signal, resp.floor_indicator_severity)
        return {"image": ref.label, "tag": tag, "digest": digest, "run_id": run_id, "signal": bool(resp.signal),
                "floor": resp.floor_indicator_severity, "path": art.path,
                "indicators": [(h.rule, h.severity, h.location) for h in resp.indicators]}

    def _predecessor(self, tag: str, known: dict[str, str | None]) -> str | None:
        """The image a new tag is compared with: the newest release tag below it (by the version numbers it starts with) whose digest is known, or the newest such release when the tag carries no version; without one, a watched floating tag's image (a repository tagged only `latest` and `sha-…`)."""
        releases = [t for t in _releases([t for t, d in known.items() if d]) if t != tag]
        below = [t for t in releases if _version_key(t) < _version_key(tag)] if _VERSION_NUMBERS_RE.match(tag) else releases
        if below:
            return known[below[-1]]
        return next((known[t] for t in self.floating if known.get(t) and t != tag), None)

    @staticmethod
    def _event(ref: ImageRef, tag: str, image: dict) -> dict:
        return {"repo": f"oci/{ref.label}", "kind": "release", "number": None, "author": "", "body": "", "files": [],
                "title": f"{ref.label}:{tag}", "release": {"image": image}}

    def _settle(self, run_id: str, ref: ImageRef, tag: str, digest: str | None, stamp: str, resp, emit) -> None:
        pending = int(bool(resp.signal) and emit is not None and emit.skipped_reason is None and not emit.ok)
        self.db.execute(
            "INSERT INTO image_judgments (run_id, image, tag, digest, first_seen, state, signal, alert_pending) VALUES "
            "(?, ?, ?, ?, ?, 'screened', ?, ?) ON CONFLICT(run_id) DO UPDATE SET state='screened', signal=excluded.signal, "
            "alert_pending=excluded.alert_pending, error=NULL",
            (run_id, ref.label, tag, digest, stamp, int(bool(resp.signal)), pending))

    def _failed(self, ref: ImageRef, tag: str, digest: str | None, stamp: str, record: bool, error: str) -> dict:
        from .cli import screen

        run_id = image_run_id(ref, tag, digest or "unknown")
        self.db.execute(
            "INSERT INTO image_judgments (run_id, image, tag, digest, first_seen, state, error, fail_count) VALUES "
            "(?, ?, ?, ?, ?, 'error', ?, 1) ON CONFLICT(run_id) DO UPDATE SET error=excluded.error, fail_count=fail_count+1",
            (run_id, ref.label, tag, digest, stamp, error[:500]))
        fails = self.db.execute("SELECT fail_count FROM image_judgments WHERE run_id=?", (run_id,)).fetchone()[0]
        if record and fails >= _MAX_FAILS:          # given up: alert that it was not compared, stop retrying
            if digest is None:                      # the digest it holds now, so a re-check does not judge it again
                try:
                    digest = self.registry.digest(ref, tag)
                except Exception:  # noqa: BLE001 (the tag is recorded either way)
                    digest = None
            self.db.execute("INSERT OR REPLACE INTO tags VALUES (?, ?, ?, ?)", (ref.label, tag, digest, stamp))
            image = {"image": ref.label, "tag": tag, "digest": digest or "", "notes": [f"not compared after {_MAX_FAILS} attempts: {error[:200]}"]}
            try:
                art = screen(self._event(ref, tag, image), run_id=run_id, outdir=self.out_dir, config=self.config,
                             emit=self.emit, poster=self.poster)
                pending = int(art.emit is not None and art.emit.skipped_reason is None and not art.emit.ok)
                self.db.execute("UPDATE image_judgments SET signal=1, alert_pending=? WHERE run_id=?", (pending, run_id))
            except Exception as exc:  # noqa: BLE001 (the error row already records why)
                log.warning("image %s:%s: the give-up alert failed: %s", ref.label, tag, exc)
        self.db.commit()
        return {"image": ref.label, "tag": tag, "run_id": run_id, "error": error}

    def _retry_alerts(self) -> None:
        """Send again, a few per poll, the early alerts the SIEM did not accept, from the screened response on disk."""
        if not self.emit:
            return
        from .config import DetectConfig
        from .emit import emit_signal
        from .schema import DetectionResponse

        rows = self.db.execute("SELECT run_id FROM image_judgments WHERE alert_pending=1 AND alert_fails<? "
                               "ORDER BY first_seen LIMIT ?", (_MAX_ALERT_FAILS, _ALERT_RETRIES_PER_POLL)).fetchall()
        for row in rows:
            try:
                with open(os.path.join(self.out_dir, "screened", f"{row['run_id']}.json"), encoding="utf-8") as fh:
                    resp = DetectionResponse.model_validate_json(fh.read())
                ok = emit_signal(resp, self.config or DetectConfig.screen_from_env(), poster=self.poster,
                                 stage="screen").ok
            except (OSError, ValueError) as exc:
                log.warning("image alert %s: %s", row["run_id"], exc)
                ok = False
            self.db.execute("UPDATE image_judgments SET alert_pending=?, alert_fails=alert_fails+? WHERE run_id=?",
                            (0 if ok else 1, 0 if ok else 1, row["run_id"]))
        self.db.commit()

    def run(self, interval: float, *, stop: Callable[[], bool] = lambda: False) -> None:
        while not stop():
            started = time.monotonic()
            self.poll_once()
            while not stop() and time.monotonic() - started < interval:
                time.sleep(min(1.0, interval))
