"""Release watch: each new file of a watched PyPI package, compared with the release before it.

A compromised release need not pass through any pull request: litellm 1.107.0 was built from a lookalike fork and
1.82.8 was uploaded with a stolen token, and in both the wheels held files the previous release did not (a `.pth`
startup hook, a packed stealer). So the release itself is the change. Its artifacts are downloaded as DATA (never
installed, never unpacked to disk), their members are compared with the previous release's, and every new or
changed member becomes a file of a change event (`kind="release"`) whose patch is the unified diff. That event goes
through the same deterministic screen as a pull request (`cli.screen`), so every text and file-structure rule reads
it, and the facts only the release shows join the baseline through `scan_release`.

What cannot be read is evidence, never a silence: a member that would run (Python source, a `.pth`, a script) and
could not be shown as text, two members that install to one path, and an artifact not read to its end are `high`.

Host-side plumbing, like `ingest` and `watch`: it fetches only from PyPI's own hosts, with every download, every
decompressed byte and all text kept bounded. Pure stdlib + httpx (+ `packaging` for version order); no dspy.
"""

from __future__ import annotations

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
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import urlsplit

from packaging.version import InvalidVersion, Version

from .dbutil import open_versioned
from .schema import IndicatorHit

log = logging.getLogger(__name__)

# A fetch maps (url, request headers, byte limit) to (status, response headers, body). Injectable, so tests and an
# air-gapped mirror need no network; the default refuses any host but PyPI's own.
Fetch = Callable[[str, dict, int], tuple[int, dict, bytes]]

_SIMPLE_URL = "https://pypi.org/simple/{name}/"
_SIMPLE_ACCEPT = "application/vnd.pypi.simple.v1+json"
_ALLOWED_HOSTS = frozenset({"pypi.org", "files.pythonhosted.org"})

_MAX_INDEX_BYTES = 32 << 20        # a project's simple index (litellm's, with every release, is about 2 MiB)
# One wheel or sdist; a package larger than this is not compared, which is `high` (`release-not-fully-read`), so a
# watchlist with large packages raises it.
_MAX_ARTIFACT_BYTES = int(os.getenv("DS_RELEASE_MAX_ARTIFACT_MB", "256") or "256") << 20
_MAX_RELEASE_BYTES = max(1 << 30, 4 * _MAX_ARTIFACT_BYTES)   # every artifact of a release and the one before it
_MAX_MEMBERS = 50_000              # members of one artifact
_MAX_DIRECTORY_BYTES = 32 << 20    # a zip's central directory, which zipfile parses whole (whatever count it states)
_MAX_MEMBER_BYTES = 1 << 20        # a member past this is compared by its sha256, never read as text
_MAX_READ_BYTES = 256 << 20        # what one artifact may decompress to, in all (tar headers included)
_MAX_TEXT_BYTES = 256 << 20        # text kept for one comparison, the new and the previous release together
_MAX_PATCH_CHARS = 16 << 20        # the patches of one release event, in all
_MAX_PATCH_LINES = 20_000          # one member's patch

# Members derived from the rest, which change with every release and say nothing of their own: the wheel's file list,
# tag and metadata (whose long description is the README, read as its own file in the sdist), and the sdist's
# `PKG-INFO` and `*.egg-info/`.
_WHEEL_DERIVED = frozenset({"{dist-info}/RECORD", "{dist-info}/WHEEL", "{dist-info}/METADATA"})
_REQUIRES_RE = re.compile(r"^Requires-Dist:[ \t]*([A-Za-z0-9][A-Za-z0-9._-]{0,99})", re.MULTILINE)
_WHEEL_DATA_RE = re.compile(r"^[^/]+\.data/(purelib|platlib|scripts|headers|data)/(.*)$")
_DIST_INFO_RE = re.compile(r"^[^/]+\.dist-info/(.*)$")
# Members that run, or decide what a build runs: unreadable, they are `high` rather than a note.
_CODE_SUFFIXES = (".py", ".pyw", ".pth", ".pyc", ".pyo", ".sh", ".bat", ".cmd", ".ps1", ".js", ".cjs", ".mjs")
_BUILD_FILES = frozenset({"pyproject.toml", "setup.cfg", "setup.py"})
# Compiled code: never text, so a new or changed one is not read (`.pyc` runs without its source, and Python may load
# a cached one over it). A native module counts only when the release before had no module of that name.
_BYTECODE_SUFFIXES = (".pyc", ".pyo")
_NATIVE_SUFFIXES = (".so", ".pyd", ".dll", ".dylib")
_SO_VERSION_RE = re.compile(r"\.so\.[0-9.]{1,40}$")         # `libfoo.so.1.2`
# A PEP 263 coding declaration, looked for anywhere on a source file's first two lines: CPython's own rule (a comment,
# line 2 only after a blank or comment line 1) is not reproduced, so a file that declares one is read both ways.
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
    """The text one comparison may keep, shared by every artifact it reads, and which members it keeps text for
    (`keep(path, digest)`): a first pass keeps none, to learn what changed; the second keeps only that."""

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
    """Where a wheel member lands relative to site-packages: `x.data/purelib/cook.pth` is `cook.pth` (its root),
    `x.dist-info/RECORD` is `{dist-info}/RECORD` (its directory carries the version), `x.data/scripts/y` is
    `{scripts}/y`. None for a directory entry."""
    if not path or path.endswith("/"):
        return None
    data = _WHEEL_DATA_RE.match(path)
    if data:
        return data.group(2) if data.group(1) in ("purelib", "platlib") else f"{{{data.group(1)}}}/{data.group(2)}"
    info = _DIST_INFO_RE.match(path)
    return f"{{dist-info}}/{info.group(1)}" if info else path


def _source_path(path: str) -> str | None:
    """An sdist member without its top directory (`litellm-1.107.0/pyproject.toml` is `pyproject.toml`). A member at the
    root stays where it is: pip builds from the root when the members share no top directory."""
    if not path or path.endswith("/"):
        return None
    _, sep, rest = path.partition("/")
    return rest if sep else path


def _member(path: str, size: int, data: bytes | None, checksum: str, budget: _Budget, why: str = "") -> Member:
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
        # read as declared too (`coding: utf-7` hides code from a UTF-8 read), and keep both readings: which one
        # Python takes depends on where the declaration sits, and the union leaves neither to the author
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


def read_artifact(filename: str, data: bytes, budget: _Budget | None = None) -> Artifact:
    """The members of a wheel or an sdist, read from memory with every size bounded. Never raises on a malformed
    archive: what could not be read is a note, and a note is `high` evidence (`release-not-fully-read`)."""
    budget = budget or _Budget()
    found = artifact_version(filename)
    art = Artifact(filename, found[1] if found else "sdist")
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
    """The size in bytes of a zip's central directory, as its end record (or zip64 end record) states it: what zipfile
    reads and parses whole, whatever member count the record claims. None when the record cannot be found."""
    end = data.rfind(b"PK\x05\x06", max(0, len(data) - 65_557))
    if end < 0 or end + 22 > len(data):
        return None
    size = int.from_bytes(data[end + 12:end + 16], "little")
    marked = size == 0xFFFFFFFF or int.from_bytes(data[end + 10:end + 12], "little") == 0xFFFF
    # zipfile reads a zip64 end record whenever its locator sits right before the classic one, marked or not
    locator = end - 20 if end >= 20 and data[end - 20:end - 16] == b"PK\x06\x07" else -1
    if locator < 0:
        return None if marked else size
    # zipfile reads the zip64 record right before the locator and ignores the locator's offset; take the larger of
    # that record, the one the offset names, and an unmarked classic size, so no record can understate the directory
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
    """A decompressed stream that raises `_Spent` past `limit` bytes, headers included: tarfile reads a pax header
    whole before any member, so a bound on member sizes alone does not bound what it holds in memory."""

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
    """A GitHub-style patch (hunks only) from `old` to `new`: its text, added and removed line counts, and whether it
    was cut at `_MAX_PATCH_LINES`."""
    lines = list(difflib.unified_diff(old.splitlines(), new.splitlines(), lineterm="", n=3))[2:]
    cut = len(lines) > _MAX_PATCH_LINES
    lines = lines[:_MAX_PATCH_LINES]
    added = sum(1 for line in lines if line.startswith("+"))
    removed = sum(1 for line in lines if line.startswith("-"))
    return "\n".join(lines), added, removed, cut


def _native_module(path: str) -> str | None:
    """A native extension's module path without its ABI tag (`pkg/_core.cpython-313-x86_64-linux-gnu.so` is
    `pkg/_core`), so a release that only adds a wheel for a new Python does not read as a new module."""
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
    """The files of the release's change event: every member of the new artifacts whose content no artifact of the same
    kind in the old release has at that path, as an event file (`added` or `modified`) labelled `<kind>/<path>` (a
    second variant of a path gets its wheel's tag, a second member at one path `shadow-n`). Also returns the members
    that run but were not shown as text, each with why (`release-code-not-read`)."""
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
    """The release's own facts as indicators, host-side like `scan_provenance`. What was not read is `high`: a member
    that runs and was not shown as text, two members at one install path, an artifact not read to its end. A name the
    wheels newly install at the root of site-packages is `medium`, a new dependency `low`. Text and file-structure
    rules read the release's files through the ordinary screen."""
    from .indicators import _hit

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


def release_scope(hits: list[IndicatorHit]) -> list[IndicatorHit]:
    """The kind of a release changes one rule: a `prompt-injection` in a package's files is read by the programs that
    import it, not by a reviewer of a pull request, and an LLM library's own code talks about its prompts on every
    release. It stays in the evidence at `medium`, below the floor; what runs code keeps its severity."""
    return [h.model_copy(update={"severity": "medium",
                                 "title": f"{h.title} (in a released package's files, below the floor)"})
            if h.rule == "prompt-injection" and h.severity in ("high", "critical") else h for h in hits]


# ── PyPI ─────────────────────────────────────────────────────────────────────────────────────────────────

def _httpx_fetch(timeout: float = 60.0) -> Fetch:
    def fetch(url: str, headers: dict, limit: int) -> tuple[int, dict, bytes]:
        import httpx

        host = urlsplit(url).hostname or ""
        if urlsplit(url).scheme != "https" or host not in _ALLOWED_HOSTS:
            raise ValueError(f"refusing to fetch from {host!r}: only PyPI's own hosts are read")
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
            attested=bool(f.get("provenance"))))
    return out


def previous_version(version: str, files: list[ReleaseFile]) -> str | None:
    """The highest version below `version` with a file that is not yanked; a pre-release is compared only with a
    release when `version` is not one itself."""
    key = _version_key(version)
    if key is None:
        return None
    candidates = {f.version for f in files if not f.yanked}
    ordered = sorted((k, v) for v in candidates if (k := _version_key(v)) is not None and k < key
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
    budget[0] -= len(body)
    return body


def release_event(package: str, version: str, files: list[ReleaseFile], fetch: Fetch,
                  only: set[str] | None = None) -> dict:
    """The change event of a release, or of the files in `only` (a wheel uploaded after the rest): its artifacts
    against the previous release's, as files whose patches are the diff, with the release's facts in `release`."""
    name = normalize_name(package)
    prev = previous_version(version, files)
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
        return [read_artifact(filename, body, text) for filename, body in bodies]

    new_bodies = download(version, only)
    old_bodies = download(prev, None) if prev else []
    # first pass: digests only, to learn which members changed; the second keeps text for those alone (and the
    # metadata the dependency fact reads), so a release of many platform wheels does not spend the text budget
    skim = _Budget(keep=lambda path, digest: False)
    old_digests = {(art.kind, m.path, m.digest) for art in read(old_bodies, skim) for m in art.members.values()}
    first = read(new_bodies, skim)
    wanted = {(art.kind, m.path, m.digest) for art in first for m in art.members.values()
              if (art.kind, m.path, m.digest) not in old_digests} | {
              (art.kind, m.path, m.digest) for art in first for k, m in art.members.items() if "\0" in k}
    paths = {p for _, p, _ in wanted} | set(_WHEEL_DERIVED)
    text = _Budget()

    def changed_in(kind: str) -> Callable[[str, str], bool]:
        return lambda path, digest: (kind, path, digest) in wanted or path in _WHEEL_DERIVED

    new = [read_artifact(art.filename, body, _Budget.share(text, changed_in(art.kind)))
           for art, (_, body) in zip(first, new_bodies, strict=True)]
    old = [read_artifact(fn, body, _Budget.share(text, lambda path, digest: path in paths)) for fn, body in old_bodies]
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
        "uploaded": min((f.upload_time for f in mine if f.upload_time), default=""),
        "yanked": bool(mine) and all(f.yanked for f in mine),
        "new_roots": sorted(_roots(new) - _roots(old)) if old else [],
        "new_requires": sorted(_requires(new) - _requires(old)) if old else [],
        "shadowed": sorted({p for art in new for p in art.shadowed})[:50],
        "unread_code": unread[:50],
        "notes": notes[:50],
    }
    return {
        "repo": f"pypi/{name}", "kind": "release", "number": None, "author": "",
        "title": f"{name} {version}" + (f" (after {prev})" if prev else " (first release seen)"),
        "body": "", "created_at": facts["uploaded"] or None, "files": changed, "release": facts,
    }


def run_id_for(package: str, version: str, revision: int = 0) -> str:
    """`pypi__<name>-<version>`, `-r<n>` for a later look at files added to the same release. A version string comes
    from PyPI, so anything but `[A-Za-z0-9._-]` is replaced and the id is never a path."""
    rid = re.sub(r"[^A-Za-z0-9._-]", "_", f"pypi__{normalize_name(package)}-{version}")[:200]
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
"""
_SCHEMA_VERSION = 2
_MAX_FAILS = 5
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
    """Polls the simple index of each package. On first sight of a package, every file it already has is the baseline
    and is not judged; each file that appears after that is, grouped by release and compared with the release before.
    A file is recorded only once its comparison is screened, and the index's ETag only once every file of it is, so a
    watcher stopped mid-comparison judges the same files on its next pass."""

    def __init__(self, packages: list[str], *, state_dir: str, out_dir: str, fetch: Fetch | None = None,
                 emit: bool = True, poster=None, config=None, archive: bool = True,
                 now: Callable[[], datetime] | None = None):
        os.makedirs(state_dir, exist_ok=True)
        self.packages = packages
        self.out_dir = out_dir
        self.fetch = fetch or _httpx_fetch()
        self.emit = emit
        self.poster = poster
        self.config = config
        self.now = now or (lambda: datetime.now(UTC))
        self.db = open_versioned(os.path.join(state_dir, "releases.db"), _SCHEMA, _SCHEMA_VERSION, "judgments")
        self.archive = None
        if archive:
            from .snapshot import SnapshotStore
            self.archive = SnapshotStore(os.path.join(state_dir, "snapshots"))

    def close(self) -> None:
        self.db.close()

    def _stamp(self) -> str:
        return self.now().isoformat(timespec="seconds")

    def _index(self, package: str, etag: str | None) -> tuple[list[ReleaseFile] | None, str | None]:
        headers = {"Accept": _SIMPLE_ACCEPT, **({"If-None-Match": etag} if etag else {})}
        status, resp_headers, body = self.fetch(_SIMPLE_URL.format(name=package), headers, _MAX_INDEX_BYTES)
        if status == 304:
            return None, etag
        if status != 200:
            raise RuntimeError(f"the index of {package} answered HTTP {status}")
        return parse_index(body), {k.lower(): v for k, v in resp_headers.items()}.get("etag")

    def poll_once(self) -> list[dict]:
        """One pass over the packages: returns a summary per comparison screened. A package that fails is logged and
        tried again on the next pass; it never stops the others."""
        self._retry_alerts()
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
        # a pending error over a set of files that is no longer the set to judge (a file added or removed since) is
        # superseded: the current set is judged instead, and the old row no longer holds the index's ETag back
        current = [json.dumps(sorted(names)) for names in fresh.values()]
        self.db.execute(f"UPDATE judgments SET state='superseded' WHERE package=? AND state='error' AND fail_count<? "
                        f"AND files NOT IN ({','.join('?' * len(current))})", (package, _MAX_FAILS, *current))
        self.db.commit()
        results = []
        clean = True
        for version in sorted(fresh, key=lambda v: (_version_key(v) is None, _version_key(v) or v)):
            result = self.judge(package, version, files, only=fresh[version], record=True)
            results.append(result)
            clean = clean and "error" not in result
        if clean:
            self.db.execute("UPDATE packages SET etag=? WHERE package=?", (etag, package))
            self.db.commit()
        return results

    def judge(self, package: str, version: str, files: list[ReleaseFile], *, only: set[str] | None = None,
              record: bool = False, run_id: str | None = None) -> dict:
        """Compare a release (or its files in `only`) with the release before it, archive the comparison, and screen it
        (the early SIEM alert when its evidence reaches the floor). With `record`, the files are marked judged once it
        is screened, and a comparison that fails is retried on later passes and kept as `error` after five. Never raises."""
        from .cli import screen

        names = sorted(only) if only is not None else sorted(f.filename for f in files if f.version == version)
        key = json.dumps(names)
        if run_id is None:
            prior = self.db.execute("SELECT run_id FROM judgments WHERE package=? AND version=? AND files=? "
                                    "AND run_id NOT LIKE '%-check'", (package, version, key)).fetchone()
            done = self.db.execute("SELECT COUNT(*) FROM judgments WHERE package=? AND version=? "
                                   "AND run_id NOT LIKE '%-check'", (package, version)).fetchone()[0]
            run_id = prior["run_id"] if prior else run_id_for(package, version, done)
        stamp = self._stamp()
        try:
            event = release_event(package, version, files, self.fetch, only=set(names))
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
        self.db.commit()
        log.info("release %s %s (after %s): signal=%s floor=%s files=%d", package, version,
                 event["release"]["previous"], resp.signal, resp.floor_indicator_severity, len(event["files"]))
        return {"package": package, "version": version, "run_id": run_id, "previous": event["release"]["previous"],
                "artifacts": names, "signal": bool(resp.signal), "floor": resp.floor_indicator_severity,
                "path": art.path, "indicators": [(h.rule, h.severity, h.location) for h in resp.indicators]}

    def _give_up(self, package: str, version: str, names: list[str], run_id: str, error: str) -> None:
        """A comparison that failed `_MAX_FAILS` times is screened as a release that could not be read (`high`), so the
        files it held back still raise an alert rather than going quiet."""
        from .cli import screen

        name = normalize_name(package)
        event = {"repo": f"pypi/{name}", "kind": "release", "number": None, "author": "", "body": "", "files": [],
                 "title": f"{name} {version} (not compared)",
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

    def _retry_alerts(self) -> None:
        """Send again, a few per poll, the early alerts the SIEM did not accept (a refusal or an outage), from the
        screened response on disk; an alert counts once the SIEM answered 2xx."""
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
        """Judge one release now against the one before it, whatever the state says, under its own run id
        (`...-check`): a one-off look never stands in for the watcher's judgment."""
        status, _, body = self.fetch(_SIMPLE_URL.format(name=package), {"Accept": _SIMPLE_ACCEPT}, _MAX_INDEX_BYTES)
        if status != 200:
            raise RuntimeError(f"the index of {package} answered HTTP {status}")
        return self.judge(package, version, parse_index(body), run_id=f"{run_id_for(package, version)}-check")

    def run(self, interval: float, *, stop: Callable[[], bool] = lambda: False) -> None:
        while not stop():
            started = time.monotonic()
            self.poll_once()
            while not stop() and time.monotonic() - started < interval:
                time.sleep(min(1.0, interval))
