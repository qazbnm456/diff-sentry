"""Release watch: each new file of a watched PyPI package, compared with the release before it.

A compromised release need not pass through any pull request: litellm 1.107.0 was built from the attacker's `Berri-AI/litellm` by a release workflow changed with stolen tokens, and 1.82.8 was uploaded with a stolen token, and in both the wheels held files the previous release did not (a `.pth` startup hook, a packed stealer). So the release itself is the change. Its artifacts are downloaded as DATA (never installed, never unpacked to disk), their members are compared with the previous release's, and every new or changed member becomes a file of a change event (`kind="release"`) whose patch is the unified diff. That event goes through the same deterministic screen as a pull request (`cli.screen`), so every text and file-structure rule reads it, and the facts only the release shows join the baseline through `scan_release`.

What cannot be read is evidence, never a silence: a member that would run (Python source, a `.pth`, a script) and could not be shown as text, two members that install to one path, and an artifact not read to its end are `high`.

With the package's GitHub repository known, the release's code is also compared with the repository's tag for its version (`tag_facts`).

Host-side plumbing, like `ingest` and `watch`: it fetches only from PyPI's own hosts and GitHub's (a repository's refs and trees, never its code), with every download, every decompressed byte and all text kept bounded. Pure stdlib + httpx (+ `packaging` for version order); no dspy.
"""

from __future__ import annotations

import base64
import bz2
import codecs
import difflib
import gzip
import hashlib
import io
import json
import logging
import lzma
import os
import posixpath
import re
import tarfile
import time
import zipfile
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from packaging.version import InvalidVersion, Version

from .dbutil import open_versioned
from .schema import IndicatorHit

log = logging.getLogger(__name__)

# A fetch maps (url, request headers, byte limit) to (status, response headers, body). Injectable, so tests and an air-gapped mirror need no network; the default refuses any host but PyPI's, npm's and GitHub's own.
Fetch = Callable[[str, dict, int], tuple[int, dict, bytes]]

_SIMPLE_URL = "https://pypi.org/simple/{name}/"
_SIMPLE_ACCEPT = "application/vnd.pypi.simple.v1+json"
_ALLOWED_HOSTS = frozenset({"pypi.org", "files.pythonhosted.org", "github.com", "api.github.com", "registry.npmjs.org"})

_MAX_INDEX_BYTES = 32 << 20        # a project's simple index (litellm's, with every release, is about 2 MiB)
# One wheel or sdist; a package larger than this is not compared, which is `high` (`release-not-fully-read`), so a watchlist with large packages raises it.
_MAX_ARTIFACT_BYTES = int(os.getenv("DS_RELEASE_MAX_ARTIFACT_MB", "256") or "256") << 20
_MAX_RELEASE_BYTES = max(1 << 30, 4 * _MAX_ARTIFACT_BYTES)   # every artifact of a release and the one before it
_MAX_MEMBERS = 50_000              # members of one artifact
_MAX_DIRECTORY_BYTES = 32 << 20    # a zip's central directory, which zipfile parses whole (whatever count it states)
_MAX_MEMBER_BYTES = 1 << 20        # a member past this is compared by its sha256, never read as text
_MAX_READ_BYTES = 256 << 20        # what one artifact may decompress to, in all (tar headers included)
_MAX_TEXT_BYTES = 256 << 20        # text kept for one comparison, the new and the previous release together
_MAX_PATCH_CHARS = 16 << 20        # the patches of one release event, in all
_MAX_PATCH_LINES = 20_000          # one member's patch

# Members derived from the rest, which change with every release and say nothing of their own: the wheel's file list, tag and metadata (whose long description is the README, read as its own file in the sdist), and the sdist's `PKG-INFO` and `*.egg-info/`.
_WHEEL_DERIVED = frozenset({"{dist-info}/RECORD", "{dist-info}/WHEEL", "{dist-info}/METADATA"})
_ALWAYS_TEXT = _WHEEL_DERIVED | {"package.json"}     # read as text in both releases: the dependency and install-script facts
_REQUIRES_RE = re.compile(r"^Requires-Dist:[ \t]*([A-Za-z0-9][A-Za-z0-9._-]{0,99})", re.MULTILINE)
_WHEEL_DATA_RE = re.compile(r"^[^/]+\.data/(purelib|platlib|scripts|headers|data)/(.*)$")
_DIST_INFO_RE = re.compile(r"^[^/]+\.dist-info/(.*)$")
# Members that run, or decide what a build runs: unreadable, they are `high` rather than a note.
_PYTHON_RUN = (".py", ".pyw", ".pth")
_CODE_SUFFIXES = (".py", ".pyw", ".pth", ".pyc", ".pyo", ".sh", ".bat", ".cmd", ".ps1", ".js", ".cjs", ".mjs")
_BUILD_FILES = frozenset({"pyproject.toml", "setup.cfg", "setup.py"})
# Compiled code: never text, so a new or changed one is not read (`.pyc` runs without its source, and Python may load a cached one over it). A native module counts only when the release before had no module of that name.
_BYTECODE_SUFFIXES = (".pyc", ".pyo")
_NATIVE_SUFFIXES = (".so", ".pyd", ".dll", ".dylib")
_SO_VERSION_RE = re.compile(r"\.so\.[0-9.]{1,40}$")         # `libfoo.so.1.2`
# A PEP 263 coding declaration, looked for anywhere on a source file's first two lines: CPython's own rule (a comment, line 2 only after a blank or comment line 1) is not reproduced, so a file that declares one is read both ways.
_CODING_RE = re.compile(r"coding[:=][ \t]*([-\w.]{1,200})([-\w.])?")
_MAX_CODING_NAME = 200      # a longer name is not resolved: it is `release-code-not-read`
_UTF8_CODECS = frozenset({"utf-8", "utf-8-sig"})


def normalize_name(name: str) -> str:
    """A project name in PEP 503's normalized form: `Foo_Bar.baz` and `foo-bar-baz` are one project."""
    return re.sub(r"[-_.]+", "-", name).lower()


def artifact_version(filename: str) -> tuple[str, str] | None:
    """`(version, kind)` of a wheel or an sdist's file name, `kind` being `wheel` or `sdist`; None for another file."""
    if filename.endswith(".whl"):
        parts = filename[:-4].split("-")
        return (parts[1], "wheel") if len(parts) >= 5 else None
    for ext in (".tar.gz", ".zip", ".tar.bz2", ".tgz"):
        if filename.endswith(ext):
            base = filename[:-len(ext)]
            return (base.rsplit("-", 1)[1], "sdist") if "-" in base else None
    return None


def _version_key(version: str) -> Version | None:
    try:
        return Version(version)
    except InvalidVersion:
        return None


def _wheel_tag(filename: str) -> str:
    return "-".join(filename[:-4].split("-")[-3:])


def _is_code(path: str) -> bool:
    low = path.lower()
    return low.endswith(_CODE_SUFFIXES) or low.startswith("{scripts}/") or posixpath.basename(low) in _BUILD_FILES


# ── reading artifacts as data ────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Member:
    """One file of an artifact, at the path it installs to (a wheel) or the path in the source tree (an sdist)."""
    path: str
    size: int
    digest: str                     # sha256 of the bytes, or the archive's checksum of a member past the read budget
    text: str | None                # the member as text, when it was read as text
    unread: str | None = None       # why a member that runs was not read as text
    blobs: tuple[str, ...] = ()     # the git blob sha1 of the bytes when they were read, and of them with CRLF as LF (a Windows checkout's), to compare with a source tag


@dataclass
class Artifact:
    filename: str
    kind: str                                               # `wheel` or `sdist`
    members: dict[str, Member] = field(default_factory=dict)   # by path; a second member at a path gets `path\0n`
    notes: list[str] = field(default_factory=list)          # what of the artifact was not read, and why
    shadowed: list[str] = field(default_factory=list)       # paths that two members install to

    def add(self, m: Member) -> None:
        if m.path not in self.members:
            self.members[m.path] = m
            return
        self.shadowed.append(m.path)
        n = 1
        while f"{m.path}\0{n}" in self.members:
            n += 1
        self.members[f"{m.path}\0{n}"] = m


class _Budget:
    """The text one comparison may keep, shared by every artifact it reads, and which members it keeps text for (`keep(path, digest)`): a first pass keeps none, to learn what changed; the second keeps only that."""

    def __init__(self, text: int = _MAX_TEXT_BYTES, keep: Callable[[str, str], bool] | None = None):
        self.text = text
        self.keep = keep or (lambda path, digest: True)
        self._shared: _Budget | None = None

    @staticmethod
    def share(pool: _Budget, keep: Callable[[str, str], bool]) -> _Budget:
        """A view of `pool`'s text budget with its own `keep`."""
        view = _Budget(0, keep)
        view._shared = pool
        return view

    def spend(self, n: int) -> bool:
        """Take `n` characters of the budget, or say there are not that many left."""
        pool = self._shared or self
        if n > pool.text:
            return False
        pool.text -= n
        return True


def _install_path(path: str) -> str | None:
    """Where a wheel member lands relative to site-packages: `x.data/purelib/cook.pth` is `cook.pth` (its root), `x.dist-info/RECORD` is `{dist-info}/RECORD` (its directory carries the version), `x.data/scripts/y` is `{scripts}/y`. None for a directory entry."""
    if not path or path.endswith("/"):
        return None
    data = _WHEEL_DATA_RE.match(path)
    if data:
        return data.group(2) if data.group(1) in ("purelib", "platlib") else f"{{{data.group(1)}}}/{data.group(2)}"
    info = _DIST_INFO_RE.match(path)
    return f"{{dist-info}}/{info.group(1)}" if info else path


def _source_path(path: str) -> str | None:
    """An sdist member without its top directory (`litellm-1.107.0/pyproject.toml` is `pyproject.toml`). A member at the root stays where it is: pip builds from the root when the members share no top directory."""
    if not path or path.endswith("/"):
        return None
    _, sep, rest = path.partition("/")
    return rest if sep else path


def _member(path: str, size: int, data: bytes | None, checksum: str, budget: _Budget, why: str = "") -> Member:
    m = _read_member(path, size, data, checksum, budget, why)
    if data is None:
        return m
    return replace(m, blobs=tuple(_blob(d) for d in (data, data.replace(b"\r\n", b"\n") if b"\r\n" in data else None)
                                  if d is not None))


def _blob(data: bytes) -> str:
    blob = hashlib.sha1(b"blob %d\0" % len(data), usedforsecurity=False)
    blob.update(data)
    return blob.hexdigest()


def _read_member(path: str, size: int, data: bytes | None, checksum: str, budget: _Budget, why: str = "") -> Member:
    code = _is_code(path)
    if data is None:
        return Member(path, size, checksum, None, (why or "not read") if code else None)
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    if len(data) > _MAX_MEMBER_BYTES:
        return Member(path, size, digest, None, f"larger than {_MAX_MEMBER_BYTES >> 20} MiB" if code else None)
    if not budget.keep(path, digest):
        return Member(path, size, digest, None, None)
    if path.lower().endswith(_BYTECODE_SUFFIXES):
        return Member(path, size, digest, None, "compiled bytecode")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        # a source file may hold bytes Python reads another way: what runs is read with its bytes kept
        text = data.decode("utf-8", "replace") if code else None
    coding = _declared_coding(data) if path.lower().endswith((".py", ".pyw")) else None
    if coding is not None:
        # read as declared too (`coding: utf-7` hides code from a UTF-8 read), and keep both readings: which one Python takes depends on where the declaration sits, and the union leaves neither to the author
        try:
            declared = data.decode(coding, "replace")
        except (LookupError, UnicodeError, ValueError, TypeError):
            return Member(path, size, digest, None, f"declares a coding it cannot be read in ({coding[:40]})")
        text = f"{text}\n{declared}" if text is not None and declared != text else declared
    if text is not None and "\0" in text and not code:
        text = None
    if text is not None and not budget.spend(len(text)):
        return Member(path, size, digest, None, "the comparison's text budget is spent" if code else None)
    return Member(path, size, digest, text)


def _declared_coding(data: bytes) -> str | None:
    """A coding a Python source file may declare on its first two lines, unless it is UTF-8."""
    head = b"\n".join(data.split(b"\n", 2)[:2]).decode("latin-1")     # a declaration is ASCII; any byte maps to one char
    m = _CODING_RE.search(head)
    if not m:
        return None
    if m.group(2):                                  # longer than any name this resolves: never guessed at
        return "a name too long to resolve"
    try:
        # resolved as CPython resolves it (`utf` + hyphens + `7` is UTF-7): a name that is UTF-8 is no other reading
        return None if codecs.lookup(m.group(1)).name in _UTF8_CODECS else m.group(1)
    except LookupError:
        return m.group(1)


class _Spent(Exception):
    """More was decompressed than an artifact may be."""


def read_artifact(filename: str, data: bytes, budget: _Budget | None = None, kind: str | None = None) -> Artifact:
    """The members of a wheel or an sdist, read from memory with every size bounded. Never raises on a malformed archive: what could not be read is a note, and a note is `high` evidence (`release-not-fully-read`)."""
    budget = budget or _Budget()
    found = artifact_version(filename)
    art = Artifact(filename, kind or (found[1] if found else "sdist"))
    try:
        if filename.endswith((".whl", ".zip")):
            _read_zip(art, data, budget)
        else:
            _read_tar(art, data, budget)
    except _Spent:
        art.notes.append(f"{filename}: not read to its end (more than {_MAX_READ_BYTES >> 20} MiB decompressed)")
    except Exception as exc:  # noqa: BLE001 (fail CLOSED: any archive this cannot read is evidence, never an outage)
        art.notes.append(f"{filename}: not read to its end ({type(exc).__name__})")
    return art


def _zip_directory(data: bytes) -> int | None:
    """The size in bytes of a zip's central directory, as its end record (or zip64 end record) states it: what zipfile reads and parses whole, whatever member count the record claims. None when the record cannot be found."""
    end = data.rfind(b"PK\x05\x06", max(0, len(data) - 65_557))
    if end < 0 or end + 22 > len(data):
        return None
    size = int.from_bytes(data[end + 12:end + 16], "little")
    marked = size == 0xFFFFFFFF or int.from_bytes(data[end + 10:end + 12], "little") == 0xFFFF
    # zipfile reads a zip64 end record whenever its locator sits right before the classic one, marked or not
    locator = end - 20 if end >= 20 and data[end - 20:end - 16] == b"PK\x06\x07" else -1
    if locator < 0:
        return None if marked else size
    # zipfile reads the zip64 record right before the locator and ignores the locator's offset; take the larger of that record, the one the offset names, and an unmarked classic size, so no record can understate the directory
    sizes = [] if marked else [size]
    for offset in (locator - 56, int.from_bytes(data[locator + 8:locator + 16], "little")):
        if 0 <= offset and data[offset:offset + 4] == b"PK\x06\x06":
            sizes.append(int.from_bytes(data[offset + 40:offset + 48], "little"))
    return max(sizes) if sizes else None


def _read_zip(art: Artifact, data: bytes, budget: _Budget) -> None:
    directory = _zip_directory(data)
    if directory is None or directory > _MAX_DIRECTORY_BYTES:
        art.notes.append(f"{art.filename}: a central directory of {directory if directory is not None else 'unknown'} "
                         f"bytes, not read (at most {_MAX_DIRECTORY_BYTES >> 20} MiB)")
        return
    left = _MAX_READ_BYTES
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        infos = zf.infolist()
        if len(infos) > _MAX_MEMBERS:
            art.notes.append(f"{art.filename}: {len(infos)} members, not read past the first {_MAX_MEMBERS}")
        for info in infos[:_MAX_MEMBERS]:
            path = _install_path(info.filename) if art.kind == "wheel" else _source_path(info.filename)
            if path is None or info.is_dir():
                continue
            with zf.open(info) as fh:            # read to what remains of the budget: a declared size may lie
                raw = fh.read(left + 1)
            left -= len(raw)
            if left < 0:
                art.notes.append(f"{art.filename}: not read past {path[:120]} (more than {_MAX_READ_BYTES >> 20} MiB "
                                 "decompressed)")
                art.add(_member(path, info.file_size, None, f"crc32:{info.CRC:08x}:{info.file_size}", budget,
                                "the artifact's read budget is spent"))
                return
            art.add(_member(path, info.file_size, raw, "", budget))


class _Capped(io.RawIOBase):
    """A decompressed stream that raises `_Spent` past `limit` bytes, headers included: tarfile reads a pax header whole before any member, so a bound on member sizes alone does not bound what it holds in memory."""

    def __init__(self, stream, limit: int):
        self._stream = stream
        self._left = limit

    def readable(self) -> bool:
        return True

    def readinto(self, buf) -> int:
        if self._left <= 0:
            raise _Spent
        view = memoryview(buf)[:self._left]
        data = self._stream.read(len(view))
        view[:len(data)] = data
        self._left -= len(data)
        return len(data)


def _decompressed(data: bytes):
    raw = io.BytesIO(data)
    if data[:2] == b"\x1f\x8b":
        return gzip.GzipFile(fileobj=raw)
    if data[:3] == b"BZh":
        return bz2.BZ2File(raw)
    if data[:6] == b"\xfd7zXZ\x00":
        return lzma.LZMAFile(raw)
    return raw


def _read_tar(art: Artifact, data: bytes, budget: _Budget) -> None:
    stream = io.BufferedReader(_Capped(_decompressed(data), _MAX_READ_BYTES))
    with tarfile.open(fileobj=stream, mode="r|") as tf:
        for count, info in enumerate(tf, 1):
            if count > _MAX_MEMBERS:
                art.notes.append(f"{art.filename}: more than {_MAX_MEMBERS} members, not read past them")
                return
            path = _source_path(info.name)
            if path is None or not info.isfile():
                if path is not None and (info.issym() or info.islnk()) and _is_code(path):
                    art.add(Member(path, 0, f"link:{info.linkname[:200]}", None, "a link"))
                continue
            fh = tf.extractfile(info)
            art.add(_member(path, info.size, fh.read() if fh is not None else None, f"size:{info.size}", budget))


# ── the change between two releases ──────────────────────────────────────────────────────────────────────

def _patch(old: str, new: str) -> tuple[str, int, int, bool]:
    """A GitHub-style patch (hunks only) from `old` to `new`: its text, added and removed line counts, and whether it was cut at `_MAX_PATCH_LINES`."""
    lines = list(difflib.unified_diff(old.splitlines(), new.splitlines(), lineterm="", n=3))[2:]
    cut = len(lines) > _MAX_PATCH_LINES
    lines = lines[:_MAX_PATCH_LINES]
    added = sum(1 for line in lines if line.startswith("+"))
    removed = sum(1 for line in lines if line.startswith("-"))
    return "\n".join(lines), added, removed, cut


def _native_module(path: str) -> str | None:
    """A native extension's module path without its ABI tag (`pkg/_core.cpython-313-x86_64-linux-gnu.so` is `pkg/_core`), so a release that only adds a wheel for a new Python does not read as a new module."""
    if not path.lower().endswith(_NATIVE_SUFFIXES) and not _SO_VERSION_RE.search(path):
        return None
    head, _, name = path.rpartition("/")
    stem = name.split(".", 1)[0]
    return f"{head}/{stem}" if head else stem


def _derived(kind: str, path: str) -> bool:
    if kind == "wheel":
        return path in _WHEEL_DERIVED
    return path == "PKG-INFO" or path.endswith("/PKG-INFO") or ".egg-info/" in path


def release_files(new: list[Artifact], old: list[Artifact]) -> tuple[list[dict], list[str]]:
    """The files of the release's change event: every member of the new artifacts whose content no artifact of the same kind in the old release has at that path, as an event file (`added` or `modified`) labelled `<kind>/<path>` (a second variant of a path gets its wheel's tag, a second member at one path `shadow-n`). Also returns the members that run but were not shown as text, each with why (`release-code-not-read`)."""
    old_by: dict[tuple[str, str], dict[str, Member]] = {}
    for art in old:
        for m in art.members.values():
            old_by.setdefault((art.kind, m.path), {}).setdefault(m.digest, m)
    old_native = {n for art in old for m in art.members.values() if (n := _native_module(m.path))}
    files: list[dict] = []
    unread: list[str] = []
    labels: set[str] = set()
    shown: set[tuple[str, str, str]] = set()
    chars = 0
    for art in new:
        for key, m in art.members.items():
            shadow = "\0" in key
            if _derived(art.kind, m.path) and not shadow:
                continue
            seen = (art.kind, m.path, m.digest)
            before = old_by.get((art.kind, m.path), {})
            if not shadow and (seen in shown or m.digest in before):
                continue
            shown.add(seen)
            label = f"{art.kind}/{m.path}"
            if shadow:
                label = f"{art.kind}[shadow-{key.split(chr(0))[1]}]/{m.path}"
            elif label in labels:
                label = f"{art.kind}[{_wheel_tag(art.filename) if art.kind == 'wheel' else art.filename}]/{m.path}"
            labels.add(label)
            why = m.unread
            native = _native_module(m.path)
            if native and old and native not in old_native:
                why = "a native module the previous release did not have"
            patch, added, removed = "", 0, 0
            if m.text is not None:
                prior = next((o.text for o in before.values() if o.text is not None), "")
                patch, added, removed, cut = _patch(prior, m.text)
                if cut and _is_code(m.path):
                    why = f"a diff of more than {_MAX_PATCH_LINES} lines"
                if chars + len(patch) > _MAX_PATCH_CHARS:
                    patch, added, removed = "", 0, 0
                    why = "the event's patch budget is spent" if _is_code(m.path) else None
                chars += len(patch)
            if why:
                unread.append(f"{label} ({why})")
            files.append({"filename": label, "status": "modified" if before else "added",
                          "additions": added, "deletions": removed, "patch": patch})
    return files, unread


def _requires(arts: list[Artifact]) -> set[str]:
    """The projects the wheels' metadata requires (`Requires-Dist`), normalized."""
    return {normalize_name(m.group(1)) for art in arts if art.kind == "wheel"
            for mem in art.members.values() if mem.path == "{dist-info}/METADATA" and mem.text
            for m in _REQUIRES_RE.finditer(mem.text)}


def _roots(arts: list[Artifact]) -> set[str]:
    """The top-level names the wheels install into site-packages (`litellm`, `cook.py`, `cook.pth`)."""
    return {m.path.split("/", 1)[0] for art in arts if art.kind == "wheel" for m in art.members.values()
            if not m.path.startswith("{")}


# ── facts only a release shows ───────────────────────────────────────────────────────────────────────────

def scan_release(facts: dict) -> list[IndicatorHit]:
    """The release's own facts as indicators, host-side like `scan_provenance`. A Trusted Publisher the previous release's attestations did not name is `high` (`release-publisher-changed`), and `critical` when its owner differs from a previous publisher's only by hyphens (a stolen token publishing from an `Acme-Corp` that imitates `AcmeCorp`). It needs the previous release to be attested; a publisher names the repository whose workflow uploaded, not the one it built from. What was not read is `high`: a member that runs and was not shown as text, two members at one install path, an artifact not read to its end. A name the wheels newly install at the root of site-packages is `medium`, a new dependency `low`. Text and file-structure rules read the release's files through the ordinary screen."""
    from .indicators import _hit, lookalike_owner

    if not isinstance(facts, dict) or not facts:
        return []
    where = f"{facts.get('package', '')} {facts.get('version', '')}".strip()
    hits: list[IndicatorHit] = []

    def listed(key: str) -> list[str]:
        return [str(x) for x in facts.get(key) or []]

    if listed("new_roots") and facts.get("previous"):
        hits.append(_hit("release-new-install-root", "medium",
                         "the wheels install a top-level name into site-packages that the previous release did not",
                         ", ".join(sorted(listed("new_roots")))[:240], location=where))
    if facts.get("previous_attested") and not facts.get("attested"):
        hits.append(_hit("release-attestation-dropped", "high",
                         "the previous release carried PyPI attestations and this one does not (published another way)",
                         f"{facts.get('previous')} attested, {facts.get('version')} not", location=where))
    publishers, before = set(listed("publishers")), set(listed("previous_publishers"))

    def owner(identity: str) -> str:
        return (identity.split(":") + ["", ""])[1].split("/")[0]

    if before and not publishers and not (facts.get("previous_attested") and not facts.get("attested")):
        hits.append(_hit("release-attestation-dropped", "high",
                         "the previous release carried PyPI attestations and none of these files does (published another way)",
                         f"{facts.get('previous')} attested by {', '.join(sorted(before))}"[:240], location=where))
    if publishers and before and publishers - before:
        new_owners = {owner(p) for p in publishers - before}
        old_owners = {owner(p) for p in before}
        how = {lookalike_owner(n, o) for n in new_owners for o in old_owners} - {None}
        evidence = f"{', '.join(sorted(before))} -> {', '.join(sorted(publishers - before))}"[:240]
        if "hyphen" in how:
            hits.append(_hit("release-publisher-lookalike", "critical",
                             "the release was published from a repository whose owner imitates the previous release's publisher",
                             evidence, location=where))
        else:
            hits.append(_hit("release-publisher-changed", "high",
                             "the release was published by another repository, workflow or environment than the previous release",
                             evidence, location=where))
    if facts.get("tag_still_missing"):
        hits.append(_hit("release-tag-missing", "high",
                         "the source repository tagged the previous release and still has no tag for this one",
                         str(facts["tag_still_missing"])[:240], location=where))
    elif facts.get("tag_missing"):
        hits.append(_hit("release-tag-missing", "medium",
                         "the source repository tagged the previous release and has no tag for this one yet (looked at again)",
                         str(facts["tag_missing"])[:240], location=where))
    if listed("tag_differs"):
        hits.append(_hit("release-differs-from-tag", "high",
                         "a file that runs differs from the source repository's tag where the previous release matched its own",
                         f"{facts.get('tag')}: {'; '.join(listed('tag_differs'))}"[:240], location=where))
    if listed("install_scripts_added"):
        hits.append(_hit("npm-install-script-added", "high",
                         "the version runs a script at install that the previous version did not",
                         "; ".join(listed("install_scripts_added"))[:240], location=where))
    if listed("dependency_sources"):
        hits.append(_hit("npm-dependency-source", "high",
                         "the version installs a dependency from a git repository, a URL, a path or an alias the previous version did not",
                         "; ".join(listed("dependency_sources"))[:240], location=where))
    if listed("dependencies_run_at_install"):
        hits.append(_hit("npm-dependency-runs-at-install", "high",
                         "the version newly depends on a package whose versions run a script at install",
                         "; ".join(listed("dependencies_run_at_install"))[:240], location=where))
    if listed("dependencies_young"):
        hits.append(_hit("npm-dependency-young", "high",
                         "the version newly depends on a package created days ago, or not on the registry",
                         "; ".join(listed("dependencies_young"))[:240], location=where))
    if listed("install_scripts_changed"):
        hits.append(_hit("npm-install-script-changed", "medium", "the version changes a script it runs at install",
                         "; ".join(listed("install_scripts_changed"))[:240], location=where))
    if listed("new_requires") and facts.get("previous"):
        hits.append(_hit("release-new-dependency", "low", "the release requires a project the previous release did not",
                         ", ".join(listed("new_requires"))[:240], location=where))
    if listed("shadowed"):
        hits.append(_hit("release-shadowed-member", "high",
                         "two members of one artifact install to the same path (the one that lands is not the one reviewed)",
                         ", ".join(sorted(set(listed("shadowed"))))[:240], location=where))
    if listed("unread_code"):
        hits.append(_hit("release-code-not-read", "high", "a changed member that runs could not be read as text",
                         "; ".join(listed("unread_code"))[:240], location=where))
    if listed("notes"):
        hits.append(_hit("release-not-fully-read", "high", "part of the release was not read (a size or count bound)",
                         "; ".join(listed("notes"))[:240], location=where))
    return hits


# Rules about a repository and its reviewers that only see something mentioned: a prompt injection (read in a package by
# the programs that import it, and an LLM library's own code talks about its prompts every release), a code-owners file,
# a workflow file, a privileged trigger, a CI skip. A comment mentions these as readily as code and a package governs no
# repository, so they stay below the floor anywhere in a release. The rules that see a workflow's dangerous content (a
# pull request's head checked out under a privileged trigger, write-all permissions) keep their severity in every file:
# wherever a package carries such a workflow, its code or its build can push it into someone's repository.
_MENTION_RULES = frozenset({"prompt-injection", "codeowners-tamper", "workflow-tamper", "privileged-fork-trigger",
                            "ci-bypass"})


def release_scope(hits: list[IndicatorHit]) -> list[IndicatorHit]:
    """The mention rules of a release stay in the evidence at `medium`, below the floor; everything else keeps its
    severity."""
    return [h.model_copy(update={"severity": "medium",
                                 "title": f"{h.title} (in a released package's files, below the floor)"})
            if h.severity in ("high", "critical") and h.rule in _MENTION_RULES else h for h in hits]


def scan_release_change(event: dict) -> list[IndicatorHit]:
    """`scan_change` for a release event, with the mention rules below the floor (`release_scope`)."""
    from .indicators import scan_change

    return release_scope(scan_change(event))


# ── PyPI ─────────────────────────────────────────────────────────────────────────────────────────────────

def _httpx_fetch(timeout: float = 60.0) -> Fetch:
    def fetch(url: str, headers: dict, limit: int) -> tuple[int, dict, bytes]:
        import httpx

        host = urlsplit(url).hostname or ""
        if urlsplit(url).scheme != "https" or host not in _ALLOWED_HOSTS:
            raise ValueError(f"refusing to fetch from {host!r}: only PyPI's, npm's and GitHub's own hosts are read")
        with httpx.stream("GET", url, headers=headers, timeout=timeout, follow_redirects=False) as resp:
            body = bytearray()
            for chunk in resp.iter_bytes():
                body += chunk
                if len(body) > limit:
                    raise ValueError(f"{url} is larger than {limit} bytes")
            return resp.status_code, dict(resp.headers), bytes(body)

    return fetch


@dataclass
class ReleaseFile:
    filename: str
    url: str
    version: str
    kind: str
    size: int
    sha256: str
    upload_time: str
    yanked: bool
    attested: bool
    provenance: str = ""        # the URL of the file's attestations on pypi.org (or the npm registry), when it holds any
    sha512: str = ""            # an npm tarball's `integrity`, base64 as the registry gives it


def parse_index(body: bytes) -> list[ReleaseFile]:
    """The wheels and sdists of a PEP 691 JSON simple index, each with whether PyPI holds an attestation for it."""
    data = json.loads(body.decode("utf-8"))
    out: list[ReleaseFile] = []
    for f in data.get("files") or []:
        if not isinstance(f, dict):
            continue
        name = str(f.get("filename") or "")
        found = artifact_version(name)
        if not found:
            continue
        out.append(ReleaseFile(
            filename=name, url=str(f.get("url") or ""), version=found[0], kind=found[1],
            size=int(f.get("size") or 0), sha256=str((f.get("hashes") or {}).get("sha256") or ""),
            upload_time=str(f.get("upload-time") or ""), yanked=bool(f.get("yanked")),
            attested=bool(f.get("provenance")),
            provenance=str(f.get("provenance")) if isinstance(f.get("provenance"), str) else ""))
    return out


def previous_version(version: str, files: list[ReleaseFile], order: Callable[[str], Any] | None = None) -> str | None:
    """The highest version below `version` with a file that is not yanked; a pre-release is compared only with a release when `version` is not one itself."""
    order = order or _version_key
    key = order(version)
    if key is None:
        return None
    candidates = {f.version for f in files if not f.yanked}
    ordered = sorted((k, v) for v in candidates if (k := order(v)) is not None and k < key
                     and (key.is_prerelease or not k.is_prerelease))
    return ordered[-1][1] if ordered else None


class DownloadError(RuntimeError):
    """A download PyPI did not serve: the comparison is retried rather than judged on part of the release."""


def _download(fetch: Fetch, f: ReleaseFile, budget: list[int], notes: list[str]) -> bytes | None:
    if f.size > _MAX_ARTIFACT_BYTES or f.size > budget[0]:
        notes.append(f"{f.filename}: {f.size} bytes, not compared (more than DS_RELEASE_MAX_ARTIFACT_MB)")
        return None
    status, _, body = fetch(f.url, {}, _MAX_ARTIFACT_BYTES)
    if status != 200:
        raise DownloadError(f"{f.filename}: HTTP {status}")
    if f.sha256 and hashlib.sha256(body).hexdigest() != f.sha256:
        notes.append(f"{f.filename}: the download does not match the index's sha256")
        return None
    if f.sha512 and base64.b64encode(hashlib.sha512(body).digest()).decode() != f.sha512:
        notes.append(f"{f.filename}: the download does not match the registry's sha512")
        return None
    budget[0] -= len(body)
    return body


_MAX_PROVENANCE_BYTES = 4 << 20    # one file's attestation bundles
_MAX_PROVENANCE_FILES = 500        # files whose attestations are read, on each side of a comparison


def publisher_identity(publisher: dict) -> str:
    """A Trusted Publisher as one comparable string: its kind, repository, workflow, environment and (a Google publisher's)
    email, names that ignore case in lower case. PyPI verified the attestation against it at upload, so it names what published."""
    workflow = publisher.get("workflow") or publisher.get("workflow_filepath") or ""
    return ":".join(str(x).replace(":", "_") for x in (
        str(publisher.get("kind") or "").lower(), str(publisher.get("repository") or "").lower(), workflow,
        str(publisher.get("environment") or "").lower(), str(publisher.get("email") or "").lower()))


def _publishers(fetch: Fetch, files: list[ReleaseFile], notes: list[str]) -> list[str]:
    """The Trusted Publishers of the files' attestations, read from PyPI. A file PyPI holds no attestation for has none;
    an attestation PyPI does not serve is retried like a download; one that cannot be read is a note."""
    found: set[str] = set()
    attested = [f for f in files if f.provenance]
    if len(attested) > _MAX_PROVENANCE_FILES:
        notes.append(f"{len(attested)} attested files, the attestations of the first {_MAX_PROVENANCE_FILES} read")
    for f in attested[:_MAX_PROVENANCE_FILES]:
        if f.kind == "npm":
            from .npm import npm_publishers

            found |= npm_publishers(fetch, f, notes)
            continue
        try:
            status, _, body = fetch(f.provenance, {"Accept": "application/json"}, _MAX_PROVENANCE_BYTES)
        except ValueError as exc:               # past the size bound, or a URL the fetch refuses: not read
            notes.append(f"{f.filename}: its attestations were not read ({str(exc)[:120]})")
            continue
        if status != 200:
            raise DownloadError(f"{f.filename}: its attestations answered HTTP {status}")
        try:
            bundles = json.loads(body.decode("utf-8")).get("attestation_bundles") or []
            for bundle in bundles:
                found.add(publisher_identity(bundle["publisher"]))
        except (ValueError, TypeError, KeyError, AttributeError):
            notes.append(f"{f.filename}: its attestations could not be read")
    return sorted(found)


def release_event(package: str, version: str, files: list[ReleaseFile], fetch: Fetch,
                  only: set[str] | None = None, source: str | None = None, registry: str = "pypi") -> dict:
    """The change event of a release, or of the files in `only` (a wheel uploaded after the rest): its artifacts against the previous release's, as files whose patches are the diff, with the release's facts in `release`. `registry` is `pypi` or `npm` (`diff_sentry.npm`), which orders versions by semver, keeps the name as written, and reads a version's one tarball as kind `npm`."""
    npm = registry == "npm"
    if npm:
        from .npm import npm_facts, semver_key
    name = package if npm else normalize_name(package)
    prev = previous_version(version, files, semver_key if npm else None)
    kinds = {f.filename: f.kind for f in files}
    notes: list[str] = []
    budget = [_MAX_RELEASE_BYTES]

    def download(v: str | None, keep: set[str] | None) -> list[tuple[str, bytes]]:
        out = []
        for f in (x for x in files if x.version == v and (keep is None or x.filename in keep)):
            body = _download(fetch, f, budget, notes)
            if body is not None:
                out.append((f.filename, body))
        return out

    def read(bodies: list[tuple[str, bytes]], text: _Budget) -> list[Artifact]:
        return [read_artifact(filename, body, text, kinds.get(filename)) for filename, body in bodies]

    new_bodies = download(version, only)
    old_bodies = download(prev, None) if prev else []
    # first pass: digests only, to learn which members changed; the second keeps text for those alone (and the metadata the dependency fact reads), so a release of many platform wheels does not spend the text budget
    skim = _Budget(keep=lambda path, digest: False)
    old_digests = {(art.kind, m.path, m.digest) for art in read(old_bodies, skim) for m in art.members.values()}
    first = read(new_bodies, skim)
    wanted = {(art.kind, m.path, m.digest) for art in first for m in art.members.values()
              if (art.kind, m.path, m.digest) not in old_digests} | {
              (art.kind, m.path, m.digest) for art in first for k, m in art.members.items() if "\0" in k}
    paths = {p for _, p, _ in wanted} | _ALWAYS_TEXT
    text = _Budget()

    def changed_in(kind: str) -> Callable[[str, str], bool]:
        return lambda path, digest: (kind, path, digest) in wanted or path in _ALWAYS_TEXT

    new = [read_artifact(art.filename, body, _Budget.share(text, changed_in(art.kind)), art.kind)
           for art, (_, body) in zip(first, new_bodies, strict=True)]
    old = [read_artifact(fn, body, _Budget.share(text, lambda path, digest: path in paths), kinds.get(fn))
           for fn, body in old_bodies]
    for art in new + old:
        notes.extend(art.notes)
    changed, unread = release_files(new, old)
    mine = [f for f in files if f.version == version and (only is None or f.filename in only)]
    theirs = [f for f in files if f.version == prev]
    facts = {
        "package": name, "version": version, "previous": prev,
        "artifacts": [f.filename for f in mine],
        "attested": bool(mine) and all(f.attested for f in mine),
        "previous_attested": bool(theirs) and all(f.attested for f in theirs),
        "publishers": _publishers(fetch, mine, notes),
        "previous_publishers": _publishers(fetch, theirs, notes),
        "uploaded": min((f.upload_time for f in mine if f.upload_time), default=""),
        "yanked": bool(mine) and all(f.yanked for f in mine),
        "new_roots": sorted(_roots(new) - _roots(old)) if old else [],
        "new_requires": sorted(_requires(new) - _requires(old)) if old else [],
        "shadowed": sorted({p for art in new for p in art.shadowed})[:50],
        "unread_code": unread[:50],
    }
    if npm:
        facts.update(npm_facts(new_bodies, old_bodies, notes, fetch, name, version))
    configured = source is not None
    if source is None and not npm:      # without a configured repository, the one the previous release's Trusted Publisher names
        repos = {p.split(":")[1] for p in facts["previous_publishers"] if p.startswith("github:")}
        source = repos.pop() if len(repos) == 1 and _REPO_RE.fullmatch(next(iter(repos))) else None
    if source and not npm:
        facts.update(tag_facts(name, version, prev, new, old, source, fetch, notes, configured=configured))
    facts["notes"] = notes[:50]
    return {
        "repo": f"{registry}/{name}", "kind": "release", "number": None, "author": "",
        "title": f"{name} {version}" + (f" (after {prev})" if prev else " (first release seen)"),
        "body": "", "created_at": facts["uploaded"] or None, "files": changed, "release": facts,
    }


# ── the source repository's tag ──────────────────────────────────────────────────────────────────────────

_REFS_URL = "https://github.com/{repo}.git/info/refs?service=git-upload-pack"
_TREE_URL = "https://api.github.com/repos/{repo}/git/trees/{sha}?recursive=1"
_MAX_REFS_BYTES = 64 << 20         # a repository's refs (litellm's, with every pull request's, are about 3 MiB)
_MAX_TREE_BYTES = 64 << 20         # one commit's recursive tree (litellm's 17,000 entries are about 3 MiB)
_MAX_PREFIX_VOTES = 2000           # members whose blobs vote for where the artifact sits in the repository
_REPO_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}")
_REF_LINE_RE = re.compile(r"(?:0000)?[0-9a-f]{4}([0-9a-f]{40}) refs/tags/([^\s\x00^]{1,250})(\^\{\})?")
_TAG_RE = re.compile(r"([^0-9]{0,100})([0-9][^\s]{0,150})")


def parse_sources(texts: list[str]) -> dict[str, str]:
    """`package=owner/name` pairs from arguments and the environment: the GitHub repository each package is built from."""
    out: dict[str, str] = {}
    for text in texts:
        for word in text.replace(",", " ").split():
            package, sep, repo = word.partition("=")
            if not sep or not _REPO_RE.fullmatch(repo):
                raise ValueError(f"not a package=owner/name source: {word!r}")
            out[parse_packages([package])[0]] = repo
    return out


def tag_commits(fetch: Fetch, repo: str) -> dict[str, str] | None:
    """The repository's tags and the commit each names (an annotated tag's peeled commit), from the refs GitHub advertises to `git fetch`, which no API rate limit counts. None when GitHub serves no such public repository (a 401 or 404, or a redirect for one renamed)."""
    status, _, body = fetch(_REFS_URL.format(repo=repo), {}, _MAX_REFS_BYTES)
    if status in (401, 404) or 300 <= status < 400:
        return None
    if status != 200:
        raise DownloadError(f"the refs of {repo}: HTTP {status}")
    tags: dict[str, str] = {}
    for line in body.decode("latin-1").split("\n"):
        m = _REF_LINE_RE.match(line)
        if m and (m.group(3) or m.group(2) not in tags):
            tags[m.group(2)] = m.group(1)
    return tags


def _tags_of(tags: dict[str, str], version: str) -> dict[str, str]:
    """The tags that name `version` (`v1.107.0-rc.1` names `1.107.0rc1`), by the prefix before their version."""
    want = _version_key(version)
    found: dict[str, str] = {}
    for name in tags:
        m = _TAG_RE.fullmatch(name)
        if m and want is not None and _version_key(m.group(2)) == want:
            found.setdefault(m.group(1), name)
    return found


def _pick(prefixes, package: str) -> str:
    """One tag prefix of several: one that names the package (a monorepo's `demo-v`), else the shortest."""
    return min(prefixes, key=lambda p: (normalize_name(package) not in normalize_name(p), len(p), p))


class _GitHubLimited(Exception):
    """GitHub's API refused for its rate limit: the release is not compared with its tag, which is a fact, not an alert."""


def _tree(fetch: Fetch, repo: str, sha: str, notes: list[str]) -> dict[str, str] | None:
    """A commit's files (path to blob sha), or None with a note when GitHub sends only part of it."""
    token = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
    headers = {"Accept": "application/vnd.github+json", **({"Authorization": f"Bearer {token}"} if token else {})}
    status, _, body = fetch(_TREE_URL.format(repo=repo, sha=sha), headers, _MAX_TREE_BYTES)
    if status in (403, 429):
        raise _GitHubLimited(f"GitHub's API answered HTTP {status} (its rate limit; set GITHUB_TOKEN)")
    if status != 200:
        raise DownloadError(f"the tree of {repo} at {sha[:12]}: HTTP {status}")
    data = json.loads(body.decode("utf-8"))
    if data.get("truncated"):
        notes.append(f"{repo} at {sha[:12]}: GitHub sent part of its tree, so the release was not compared with its tag")
        return None
    return {str(e.get("path")): str(e.get("sha")) for e in data.get("tree") or []
            if isinstance(e, dict) and e.get("type") == "blob" and e.get("mode") != "120000"}


def _compared(art: Artifact) -> list[Member]:
    """The members of an artifact compared with a tag: what Python runs (a `.py`, `.pyw` or `.pth`, and a build file), not what a build writes (a wheel's `.dist-info` and scripts, an sdist's `PKG-INFO` and `.egg-info`). Other files, a rebuilt web bundle among them, are screened by the rules but not compared, since a build names them anew each time."""
    return [m for k, m in art.members.items() if "\0" not in k and m.blobs and not m.path.startswith("{")
            and (m.path.lower().endswith(_PYTHON_RUN) or posixpath.basename(m.path) in _BUILD_FILES)
            and not _derived(art.kind, m.path)]


def _prefix(members: list[Member], files: dict[str, str]) -> str:
    """Where the artifact's paths sit in the repository (`src/`, a monorepo's `python/`): the directory most of its members' blobs are found under."""
    by_blob: dict[str, list[str]] = {}
    for path, sha in files.items():
        by_blob.setdefault(sha, []).append(path)
    votes: dict[str, int] = {}
    for m in members[:_MAX_PREFIX_VOTES]:
        for path in (p for blob in m.blobs for p in by_blob.get(blob, [])[:20]):
            if path == m.path or path.endswith("/" + m.path):
                votes[path[:len(path) - len(m.path)]] = votes.get(path[:len(path) - len(m.path)], 0) + 1
    return max(sorted(votes), key=lambda p: votes[p]) if votes else ""


def _differences(art: Artifact, files: dict[str, str]) -> dict[str, str]:
    """Each compared member that the tag does not hold as it is, by its path in the artifact."""
    members = _compared(art)
    prefix = _prefix(members, files)
    return {m.path: f"{art.kind}/{m.path} (" + ("differs from the tag)" if prefix + m.path in files else "not in the tag)")
            for m in members if files.get(prefix + m.path) not in m.blobs}


def _resolve_tag(package: str, version: str, prev: str | None, source: str, fetch: Fetch, notes: list[str],
                 configured: bool) -> tuple[dict, tuple[dict[str, str], dict[str, str]] | None]:
    """The tag facts that need no artifact, and the two trees to compare with (the version's tag's, the previous release's tag's), or None when there is nothing to compare with."""
    facts: dict = {"source": source}
    if not prev:
        return {**facts, "tag_compared": "no previous release to measure the build by"}, None
    tags = tag_commits(fetch, source)
    if tags is None:
        if configured:
            notes.append(f"GitHub does not serve the repository {source}, so the release was not compared with its tag")
        return {**facts, "tag_compared": f"GitHub does not serve the repository {source}"}, None
    before, after = _tags_of(tags, prev), _tags_of(tags, version)
    if not before:
        return {**facts, "tag_compared": f"{source} has no tag for the previous release {prev}"}, None
    both = [p for p in before if p in after]
    previous_tag = before[_pick(both or before, package)]
    facts["previous_tag"] = previous_tag
    if not after:
        return {**facts, "tag_missing": f"{source} tags {prev} as {previous_tag} and has no tag for {version}"}, None
    tag = after[_pick(both or after, package)]
    facts["tag"] = tag
    try:
        trees = (_tree(fetch, source, tags[tag], notes), _tree(fetch, source, tags[previous_tag], notes))
    except _GitHubLimited as exc:
        log.warning("release %s %s: not compared with %s: %s", package, version, tag, exc)
        return {**facts, "tag_compared": f"not compared yet: {exc}", "tag_limited": True}, None
    if trees[0] is None or trees[1] is None:
        return facts, None
    return facts, (trees[0], trees[1])


def _compare_tag(facts: dict, trees: tuple[dict[str, str], dict[str, str]], new: list[Artifact],
                 old: list[Artifact]) -> dict:
    expected = {(art.kind, path) for art in old for path in _differences(art, trees[1])}
    differs = {label for art in new for path, label in _differences(art, trees[0]).items() if (art.kind, path) not in expected}
    return {**facts, "tag_differs": sorted(differs)[:50],
            "tag_compared": f"{sum(len(_compared(a)) for a in new)} files compared with {facts['tag']}"}


def tag_facts(package: str, version: str, prev: str | None, new: list[Artifact], old: list[Artifact], source: str,
              fetch: Fetch, notes: list[str], *, configured: bool = True) -> dict:
    """The release's code against the source repository's tag for its version, where the previous release had a tag to measure what a build adds. A file the previous release also differed by at the same path (a version file the build writes) is expected; any other difference is `release-differs-from-tag`. With no tag for this version yet (`tag_missing`), or GitHub's API refusing for its limit (`tag_limited`), the watcher owes the comparison and makes it later (`ReleaseWatcher._recheck_tags`). Each artifact is compared by the git blob sha1 of its members, so nothing of the repository is downloaded but its refs and two trees. A configured repository GitHub does not serve is a note; the Trusted Publisher's is only a fact."""
    facts, trees = _resolve_tag(package, version, prev, source, fetch, notes, configured)
    return _compare_tag(facts, trees, new, old) if trees is not None else facts


def tag_event(package: str, version: str, files: list[ReleaseFile], fetch: Fetch, source: str,
              configured: bool = True) -> dict:
    """A release against its tag alone, for a comparison its judgment could not make (no tag yet, or GitHub's API limit): the tag and both trees first, then, only when there is something to compare with, the release and the previous one downloaded again and read for their blobs. An event with no files whose facts are the tag's, so the content findings are not sent twice."""
    name = normalize_name(package)
    prev = previous_version(version, files)
    notes: list[str] = []
    facts, trees = _resolve_tag(name, version, prev, source, fetch, notes, configured)
    if trees is not None:
        budget = [_MAX_RELEASE_BYTES]
        skim = _Budget(keep=lambda path, digest: False)

        def arts(v: str | None) -> list[Artifact]:
            out = []
            for f in (x for x in files if x.version == v):
                body = _download(fetch, f, budget, notes)
                if body is not None:
                    art = read_artifact(f.filename, body, skim)
                    notes.extend(art.notes)
                    out.append(art)
            return out

        new = arts(version)
        if not new:
            notes.append(f"PyPI serves no file of {version} any more, so it was not compared with its tag")
        facts = _compare_tag(facts, trees, new, arts(prev))
    return {"repo": f"pypi/{name}", "kind": "release", "number": None, "author": "", "body": "", "files": [],
            "title": f"{name} {version} (against its tag)", "created_at": None,
            "release": {"package": name, "version": version, "previous": prev, **facts, "notes": notes[:50]}}


def run_id_for(package: str, version: str, revision: int = 0, registry: str = "pypi") -> str:
    """`pypi__<name>-<version>` (`npm__<name>-<version>`), `-r<n>` for a later look at files added to the same release. A name and a version come from the registry, so anything but `[A-Za-z0-9._-]` is replaced (`@scope/name` is `_scope_name`) and the id is never a path."""
    name = package if registry == "npm" else normalize_name(package)
    rid = re.sub(r"[^A-Za-z0-9._-]", "_", f"{registry}__{name}-{version}")[:200]
    return f"{rid}-r{revision}" if revision else rid


# ── the watcher ──────────────────────────────────────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS packages (package TEXT PRIMARY KEY, first_seen TEXT NOT NULL, etag TEXT);
CREATE TABLE IF NOT EXISTS artifacts (
    package TEXT NOT NULL, filename TEXT NOT NULL, version TEXT NOT NULL, first_seen TEXT NOT NULL, run_id TEXT,
    PRIMARY KEY (package, filename));
CREATE TABLE IF NOT EXISTS judgments (
    run_id TEXT PRIMARY KEY, package TEXT NOT NULL, version TEXT NOT NULL, first_seen TEXT NOT NULL,
    state TEXT NOT NULL, files TEXT NOT NULL, max_severity TEXT, signal INTEGER, error TEXT,
    fail_count INTEGER NOT NULL DEFAULT 0, alert_pending INTEGER NOT NULL DEFAULT 0,
    alert_fails INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS tag_checks (
    run_id TEXT PRIMARY KEY, package TEXT NOT NULL, version TEXT NOT NULL, source TEXT NOT NULL,
    configured INTEGER NOT NULL, first_seen TEXT NOT NULL, missing TEXT NOT NULL, state TEXT NOT NULL,
    opened INTEGER NOT NULL DEFAULT 1);
"""
_SCHEMA_VERSION = 2
_MAX_FAILS = 5
_TAG_GRACE = 3600              # seconds a release may wait for its tag before that is `high` (a project tagging after it uploads)
_TAG_DEADLINE = 6 * 3600       # seconds a comparison with the tag may stay owed before that alerts (`release-not-fully-read`)
_ALERT_RETRIES_PER_POLL = 5    # a SIEM that hangs costs one poll at most this many bounded POSTs
_MAX_ALERT_FAILS = 20


def parse_packages(texts: list[str]) -> list[str]:
    """Package names from arguments and files: whitespace or newline separated, `#` comments allowed."""
    out: list[str] = []
    for text in texts:
        for line in text.splitlines() or [text]:
            for word in line.split("#", 1)[0].split():
                name = normalize_name(word)
                if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,98}[a-z0-9])?", name):
                    raise ValueError(f"not a PyPI project name: {word!r}")
                if name not in out:
                    out.append(name)
    return out


class ReleaseWatcher:
    registry = "pypi"
    state_file = "releases.db"

    """Polls the simple index of each package. On first sight of a package, every file it already has is the baseline and is not judged; each file that appears after that is, grouped by release and compared with the release before. A file is recorded only once its comparison is screened, and the index's ETag only once every file of it is, so a watcher stopped mid-comparison judges the same files on its next pass."""

    def __init__(self, packages: list[str], *, state_dir: str, out_dir: str, fetch: Fetch | None = None,
                 emit: bool = True, poster=None, config=None, archive: bool = True,
                 now: Callable[[], datetime] | None = None, sources: dict[str, str] | None = None):
        os.makedirs(state_dir, exist_ok=True)
        self.packages = packages
        self.sources = sources or {}
        self.out_dir = out_dir
        self.fetch = fetch or _httpx_fetch()
        self.emit = emit
        self.poster = poster
        self.config = config
        self.now = now or (lambda: datetime.now(UTC))
        self.db = open_versioned(os.path.join(state_dir, self.state_file), _SCHEMA, _SCHEMA_VERSION, "judgments")
        self.archive = None
        if archive:
            from .snapshot import SnapshotStore
            self.archive = SnapshotStore(os.path.join(state_dir, "snapshots"))

    def close(self) -> None:
        self.db.close()

    def _stamp(self) -> str:
        return self.now().isoformat(timespec="seconds")

    def _order(self, version: str):
        return _version_key(version)

    def _index(self, package: str, etag: str | None) -> tuple[list[ReleaseFile] | None, str | None]:
        headers = {"Accept": _SIMPLE_ACCEPT, **({"If-None-Match": etag} if etag else {})}
        status, resp_headers, body = self.fetch(_SIMPLE_URL.format(name=package), headers, _MAX_INDEX_BYTES)
        if status == 304:
            return None, etag
        if status != 200:
            raise RuntimeError(f"the index of {package} answered HTTP {status}")
        return parse_index(body), {k.lower(): v for k, v in resp_headers.items()}.get("etag")

    def poll_once(self) -> list[dict]:
        """One pass over the packages: returns a summary per comparison screened. A package that fails is logged and tried again on the next pass; it never stops the others."""
        self._retry_alerts()
        self._recheck_tags()
        results = []
        for package in self.packages:
            try:
                results += self._poll_package(package)
            except Exception as exc:  # noqa: BLE001 (one package's failure must not stop the watch)
                log.warning("release index %s: %s", package, exc)
        return results

    def _poll_package(self, package: str) -> list[dict]:
        row = self.db.execute("SELECT etag FROM packages WHERE package=?", (package,)).fetchone()
        retrying = self.db.execute("SELECT 1 FROM judgments WHERE package=? AND state='error' AND fail_count<?",
                                   (package, _MAX_FAILS)).fetchone()
        files, etag = self._index(package, None if row is None or retrying else row["etag"])
        if files is None:
            return []
        stamp = self._stamp()
        if row is None:
            self.db.execute("INSERT INTO packages VALUES (?, ?, ?)", (package, stamp, etag))
            self.db.executemany("INSERT OR IGNORE INTO artifacts (package, filename, version, first_seen) "
                                "VALUES (?, ?, ?, ?)", [(package, f.filename, f.version, stamp) for f in files])
            self.db.commit()
            log.info("release watch: %s has %d file(s), taken as the baseline", package, len(files))
            return []
        known = {r["filename"] for r in self.db.execute("SELECT filename FROM artifacts WHERE package=?", (package,))}
        fresh: dict[str, set[str]] = {}
        for f in files:
            if f.filename not in known:
                fresh.setdefault(f.version, set()).add(f.filename)
        # a pending error over a set of files that is no longer the set to judge (a file added or removed since) is superseded: the current set is judged instead, and the old row no longer holds the index's ETag back
        current = [json.dumps(sorted(names)) for names in fresh.values()]
        self.db.execute(f"UPDATE judgments SET state='superseded' WHERE package=? AND state='error' AND fail_count<? "
                        f"AND files NOT IN ({','.join('?' * len(current))})", (package, _MAX_FAILS, *current))
        self.db.commit()
        results = []
        clean = True
        for version in sorted(fresh, key=lambda v: (self._order(v) is None, self._order(v) or (), v)):
            result = self.judge(package, version, files, only=fresh[version], record=True)
            results.append(result)
            clean = clean and "error" not in result
        if clean:
            self.db.execute("UPDATE packages SET etag=? WHERE package=?", (etag, package))
            self.db.commit()
        return results

    def judge(self, package: str, version: str, files: list[ReleaseFile], *, only: set[str] | None = None,
              record: bool = False, run_id: str | None = None) -> dict:
        """Compare a release (or its files in `only`) with the release before it, archive the comparison, and screen it (the early SIEM alert when its evidence reaches the floor). With `record`, the files are marked judged once it is screened, and a comparison that fails is retried on later passes and kept as `error` after five. Never raises."""
        from .cli import screen

        names = sorted(only) if only is not None else sorted(f.filename for f in files if f.version == version)
        key = json.dumps(names)
        if run_id is None:      # a release's own revisions: not a `--check`, and not a tag comparison (whose files are `[]`)
            prior = self.db.execute("SELECT run_id FROM judgments WHERE package=? AND version=? AND files=? "
                                    "AND run_id NOT LIKE '%-check' AND files!='[]'", (package, version, key)).fetchone()
            done = self.db.execute("SELECT COUNT(*) FROM judgments WHERE package=? AND version=? "
                                   "AND run_id NOT LIKE '%-check' AND files!='[]'", (package, version)).fetchone()[0]
            run_id = prior["run_id"] if prior else run_id_for(package, version, done, self.registry)
        stamp = self._stamp()
        try:
            event = release_event(package, version, files, self.fetch, only=set(names), source=self.sources.get(package),
                                  registry=self.registry)
            if self.archive is not None:
                self.archive.put(repo=event["repo"], kind="release", number=None, event=event, raw={
                    "files": [f.__dict__ for f in files if f.version in (version, event["release"]["previous"])]})
            art = screen(event, run_id=run_id, outdir=self.out_dir, config=self.config, emit=self.emit,
                         poster=self.poster)
        except Exception as exc:  # noqa: BLE001 (a comparison that fails is retried, then kept as `error`)
            log.warning("release %s %s: %s", package, version, exc)
            self.db.execute(
                "INSERT INTO judgments (run_id, package, version, first_seen, state, files, error, fail_count) "
                "VALUES (?, ?, ?, ?, 'error', ?, ?, 1) ON CONFLICT(run_id) DO UPDATE SET "
                "error=excluded.error, fail_count=fail_count+1",
                (run_id, package, version, stamp, key, f"{type(exc).__name__}: {exc}"[:500]))
            fails = self.db.execute("SELECT fail_count FROM judgments WHERE run_id=?", (run_id,)).fetchone()[0]
            if record and fails >= _MAX_FAILS:         # given up: alert that it was not compared, stop retrying
                self.db.executemany("INSERT OR IGNORE INTO artifacts (package, filename, version, first_seen, run_id) "
                                    "VALUES (?, ?, ?, ?, ?)", [(package, n, version, stamp, run_id) for n in names])
                self._give_up(package, version, names, run_id, f"{type(exc).__name__}: {exc}")
            self.db.commit()
            return {"package": package, "version": version, "run_id": run_id, "error": str(exc)}
        resp = art.response
        pending = int(bool(resp.signal) and art.emit is not None and art.emit.skipped_reason is None and not art.emit.ok)
        self.db.execute(
            "INSERT INTO judgments (run_id, package, version, first_seen, state, files, max_severity, signal, "
            "alert_pending) VALUES (?, ?, ?, ?, 'screened', ?, ?, ?, ?) ON CONFLICT(run_id) DO UPDATE SET "
            "state='screened', max_severity=excluded.max_severity, signal=excluded.signal, "
            "alert_pending=excluded.alert_pending, error=NULL",
            (run_id, package, version, stamp, key, resp.floor_indicator_severity, int(bool(resp.signal)), pending))
        if record:
            self.db.executemany("INSERT OR IGNORE INTO artifacts (package, filename, version, first_seen, run_id) "
                                "VALUES (?, ?, ?, ?, ?)", [(package, n, version, stamp, run_id) for n in names])
            facts = event["release"]
            if facts.get("tag_missing") or facts.get("tag_limited"):
                # a closed row is opened again with fresh clocks: a wheel added to the release later owes its own comparison
                self.db.execute("INSERT INTO tag_checks (run_id, package, version, source, configured, first_seen, "
                                "missing, state) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending') ON CONFLICT(run_id) DO UPDATE SET "
                                "state='pending', first_seen=excluded.first_seen, missing=excluded.missing, "
                                "source=excluded.source, configured=excluded.configured, opened=opened+1 "
                                "WHERE state!='pending'",
                                (f"{run_id_for(package, version)}-tag", package, version, facts["source"],
                                 int(package in self.sources),
                                 stamp, facts.get("tag_missing") or ""))
        self.db.commit()
        log.info("release %s %s (after %s): signal=%s floor=%s files=%d", package, version,
                 event["release"]["previous"], resp.signal, resp.floor_indicator_severity, len(event["files"]))
        return {"package": package, "version": version, "run_id": run_id, "previous": event["release"]["previous"],
                "artifacts": names, "signal": bool(resp.signal), "floor": resp.floor_indicator_severity,
                "path": art.path, "indicators": [(h.rule, h.severity, h.location) for h in resp.indicators]}

    def _give_up(self, package: str, version: str, names: list[str], run_id: str, error: str) -> None:
        """A comparison that failed `_MAX_FAILS` times is screened as a release that could not be read (`high`), so the files it held back still raise an alert rather than going quiet."""
        from .cli import screen

        name = package if self.registry == "npm" else normalize_name(package)
        event = {"repo": f"{self.registry}/{name}", "kind": "release", "number": None, "author": "", "body": "",
                 "files": [], "title": f"{name} {version} (not compared)",
                 "release": {"package": name, "version": version, "artifacts": names,
                             "notes": [f"not compared after {_MAX_FAILS} attempts: {error[:200]}"]}}
        try:
            art = screen(event, run_id=run_id, outdir=self.out_dir, config=self.config, emit=self.emit,
                         poster=self.poster)
        except Exception as exc:  # noqa: BLE001 (the error row already records why)
            log.warning("release %s %s: the give-up alert failed: %s", package, version, exc)
            return
        pending = int(art.emit is not None and art.emit.skipped_reason is None and not art.emit.ok)
        self.db.execute("UPDATE judgments SET signal=1, max_severity=?, alert_pending=? WHERE run_id=?",
                        (art.response.floor_indicator_severity, pending, run_id))

    def _recheck_tags(self) -> None:
        """Make the comparisons with a tag that judgments could not: a release judged before its tag existed, or while GitHub's API refused. Once a tag for the version appears and the API has room, the release is compared with it (`tag_event`) and screened under `<run id>-tag`. A release still without a tag `_TAG_GRACE` after it was judged is `release-tag-missing` (`high`), and a comparison still owed `_TAG_DEADLINE` after it, for any reason, is `release-not-fully-read`: nothing owed is dropped without an alert. A Trusted Publisher's repository GitHub stops serving ends the check, as it would at judgment."""
        for row in self.db.execute("SELECT * FROM tag_checks WHERE state='pending'").fetchall():
            name = normalize_name(row["package"])
            waited = (self.now() - datetime.fromisoformat(row["first_seen"])).total_seconds()
            base = {"package": name, "version": row["version"], "source": row["source"]}
            try:
                tags = tag_commits(self.fetch, row["source"])
                if tags is None and not row["configured"]:
                    self.db.execute("UPDATE tag_checks SET state='unserved' WHERE run_id=?", (row["run_id"],))
                    self.db.commit()
                    continue
                if tags is None:
                    self._screen_tag(row, {**base, "notes": [
                        f"GitHub does not serve the repository {row['source']}, so the release was not compared with its tag"]})
                    continue
                if _tags_of(tags, row["version"]):
                    if self._api_room():
                        status, _, body = self.fetch(_SIMPLE_URL.format(name=row["package"]),
                                                     {"Accept": _SIMPLE_ACCEPT}, _MAX_INDEX_BYTES)
                        if status != 200:
                            raise RuntimeError(f"the index of {row['package']} answered HTTP {status}")
                        event = tag_event(row["package"], row["version"], parse_index(body), self.fetch, row["source"],
                                          configured=bool(row["configured"]))
                        if not event["release"].get("tag_limited"):
                            self._screen_tag(row, event["release"])
                            continue
                elif waited >= _TAG_GRACE:
                    missing = row["missing"] or f"{row['source']} has no tag for {row['version']}"
                    self._screen_tag(row, {**base, "tag_still_missing":
                                           f"{missing}, {int(waited // 60)} minutes after it was judged"})
                    continue
            except Exception as exc:  # noqa: BLE001 (looked at again on the next poll, until the deadline)
                log.warning("release %s %s: its tag: %s", row["package"], row["version"], exc)
            if waited >= _TAG_DEADLINE:
                try:
                    self._screen_tag(row, {**base, "notes": [
                        f"not compared with its tag within {_TAG_DEADLINE // 3600} hours of its judgment"]})
                except Exception as exc:  # noqa: BLE001 (screened again on the next poll)
                    log.warning("release %s %s: the tag alert failed: %s", row["package"], row["version"], exc)

    def _api_room(self) -> bool:
        """Whether GitHub's API has the two calls a comparison takes (its `rate_limit` endpoint counts toward nothing)."""
        token = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
        try:
            status, _, body = self.fetch("https://api.github.com/rate_limit", {
                "Accept": "application/vnd.github+json", **({"Authorization": f"Bearer {token}"} if token else {})}, 1 << 20)
            return status != 200 or int(json.loads(body)["resources"]["core"]["remaining"]) >= 2
        except (ValueError, KeyError, TypeError):
            return True

    def _screen_tag(self, row, facts: dict) -> None:
        """Screen a release's tag facts alone (an event with no files) under the row's `<run id>-tag`, and close the row."""
        from .cli import screen

        # each opening of the row screens under its own id, so a refused alert of an earlier one is never overwritten
        run_id = row["run_id"] + (str(row["opened"]) if row["opened"] > 1 else "")
        package, version = row["package"], row["version"]
        event = {"repo": f"pypi/{facts['package']}", "kind": "release", "number": None, "author": "", "body": "",
                 "files": [], "title": f"{facts['package']} {version} (against its tag)", "created_at": None,
                 "release": facts}
        art = screen(event, run_id=run_id, outdir=self.out_dir, config=self.config, emit=self.emit, poster=self.poster)
        resp = art.response
        pending = int(bool(resp.signal) and art.emit is not None and art.emit.skipped_reason is None and not art.emit.ok)
        self.db.execute("INSERT OR REPLACE INTO judgments (run_id, package, version, first_seen, state, files, "
                        "max_severity, signal, alert_pending) VALUES (?, ?, ?, ?, 'screened', '[]', ?, ?, ?)",
                        (run_id, package, version, self._stamp(), resp.floor_indicator_severity, int(bool(resp.signal)),
                         pending))
        self.db.execute("UPDATE tag_checks SET state='done' WHERE run_id=?", (row["run_id"],))
        self.db.commit()

    def _retry_alerts(self) -> None:
        """Send again, a few per poll, the early alerts the SIEM did not accept (a refusal or an outage), from the screened response on disk; an alert counts once the SIEM answered 2xx."""
        if not self.emit:
            return
        from .config import DetectConfig
        from .emit import emit_signal
        from .schema import DetectionResponse

        rows = self.db.execute("SELECT run_id FROM judgments WHERE alert_pending=1 AND alert_fails<? "
                               "ORDER BY first_seen LIMIT ?", (_MAX_ALERT_FAILS, _ALERT_RETRIES_PER_POLL)).fetchall()
        for row in rows:
            try:
                with open(os.path.join(self.out_dir, "screened", f"{row['run_id']}.json"), encoding="utf-8") as fh:
                    resp = DetectionResponse.model_validate_json(fh.read())
                ok = emit_signal(resp, self.config or DetectConfig.screen_from_env(), poster=self.poster,
                                 stage="screen").ok
            except (OSError, ValueError) as exc:
                log.warning("release alert %s: %s", row["run_id"], exc)
                ok = False
            self.db.execute("UPDATE judgments SET alert_pending=?, alert_fails=alert_fails+? WHERE run_id=?",
                            (0 if ok else 1, 0 if ok else 1, row["run_id"]))
        self.db.commit()

    def check(self, package: str, version: str) -> dict:
        """Judge one release now against the one before it, whatever the state says, under its own run id (`...-check`): a one-off look never stands in for the watcher's judgment."""
        files, _ = self._index(package, None)
        return self.judge(package, version, files or [], run_id=f"{run_id_for(package, version, 0, self.registry)}-check")

    def run(self, interval: float, *, stop: Callable[[], bool] = lambda: False) -> None:
        while not stop():
            started = time.monotonic()
            self.poll_once()
            while not stop() and time.monotonic() - started < interval:
                time.sleep(min(1.0, interval))
