"""Append-only, content-addressed archive of what the ingest saw — the forensic record.

An attacker can delete the PR, edit the issue body, force-push the branch, or delete the account, and the
GitHub API then answers 404 or shows the cleaned-up version (the hackerbot-claw artifacts were 404 within
days). The only copy of the original is the one taken when the change was first seen. So the watcher
archives it then, and again whenever the content changes.

Layout under `root`::

    objects/<aa>/<sha256>.json.gz   the canonical JSON of one capture, named by the hash of its bytes
    index.jsonl                     one line per capture: when, which change, why, which object

Objects are never rewritten and the index is append-only by convention, so a later capture adds history
without replacing an earlier one. `verify` re-hashes every object, so a changed or missing object is
detected; the index is not hash-chained, so a tampered index line is only caught when it points nowhere.
Nothing prunes the archive.

Pure stdlib; no dspy. The transport wrapper `RecordingApi` lets the ingest run unchanged while the raw
responses are captured alongside the derived event.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

SCHEMA = "diff-sentry/snapshot/v1"


_ANGLE_EMAIL = re.compile(r"<[^<>\s@]+@([^<>\s]+)>")
_TRAILER_LINE = re.compile(
    r"(?:^|(?<=\r))((?:Signed-off-by|Co-authored-by|Reviewed-by|Acked-by|Tested-by|Reported-by|Suggested-by):"
    r"[^\r\n]*)(?=[\r\n]|\Z)",
    re.IGNORECASE | re.MULTILINE)


def scrub_emails(obj: Any) -> Any:
    """A copy of `obj` with personal email addresses reduced to `***@domain`: every `email` field, the
    `<name@host>` lines inside a commit's signature `payload`, and the address in a commit-message trailer
    (`Signed-off-by:`, `Co-authored-by:`, …). The dossier needs the domain, not the address. Everything else,
    including the rest of a commit message, a body and a patch, is left exactly as captured: it is evidence."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k == "email" and isinstance(v, str):
                out[k] = _mask(v)
            elif k == "payload" and isinstance(v, str):
                out[k] = _ANGLE_EMAIL.sub(r"<***@\1>", v)
            elif k == "message" and isinstance(v, str):
                out[k] = _TRAILER_LINE.sub(lambda m: _ANGLE_EMAIL.sub(r"<***@\1>", m.group(1)), v)
            else:
                out[k] = scrub_emails(v)
        return out
    if isinstance(obj, list):
        return [scrub_emails(v) for v in obj]
    return obj


def _mask(addr: str) -> str:
    return "***@" + addr.rsplit("@", 1)[1] if "@" in addr else addr


class RecordingApi:
    """Wraps a `gh api` transport and remembers every response by path. Errors propagate untouched (the
    ingest's best-effort handling still sees them); only successful bodies are recorded."""

    def __init__(self, inner: Callable[[str], Any]):
        self._inner = inner
        self.records: dict[str, Any] = {}
        self.calls = 0                       # every request made, including failed ones (they spend budget too)

    def __call__(self, path: str) -> Any:
        self.calls += 1
        body = self._inner(path)
        self.records[path] = body
        return body


@dataclass(frozen=True)
class Capture:
    sha256: str
    path: str
    is_new: bool        # False when an identical capture already existed (deduplicated)


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      default=str).encode("utf-8")


class SnapshotStore:
    def __init__(self, root: str):
        self.root = root
        self._objects = os.path.join(root, "objects")
        self._index = os.path.join(root, "index.jsonl")
        self._lock = threading.Lock()
        os.makedirs(self._objects, exist_ok=True)

    def _object_path(self, sha: str) -> str:
        if not re.fullmatch(r"[0-9a-f]{64}", sha or ""):
            raise ValueError(f"not a sha256 address: {sha!r}")     # never build a path from free text
        return os.path.join(self._objects, sha[:2], f"{sha}.json.gz")

    def put(self, *, repo: str, kind: str, number: int | None, event: dict, raw: dict | None = None,
            reason: str = "first_seen", captured_at: datetime | None = None) -> Capture:
        """Archive one capture. Identical content deduplicates to the same object; the index still records
        the sighting, so `history` shows every time the change was looked at."""
        payload = {"schema": SCHEMA, "repo": repo, "kind": kind, "number": number,
                   "event": scrub_emails(event), "raw": scrub_emails(raw or {})}
        body = _canonical(payload)
        sha = hashlib.sha256(body).hexdigest()
        path = self._object_path(sha)
        with self._lock:
            is_new = not os.path.exists(path)
            if is_new:
                os.makedirs(os.path.dirname(path), exist_ok=True)
                tmp = f"{path}.tmp"
                with open(tmp, "wb") as raw_fh, gzip.GzipFile(fileobj=raw_fh, mode="wb", mtime=0) as gz:
                    gz.write(body)
                os.replace(tmp, path)   # atomic: a reader never sees a partial object
            ts = (captured_at or datetime.now(UTC)).astimezone(UTC).isoformat(timespec="seconds")
            row = {"ts": ts, "repo": repo, "kind": kind, "number": number, "sha256": sha, "reason": reason}
            with open(self._index, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")
        return Capture(sha, path, is_new)

    def get(self, sha: str) -> dict:
        with gzip.open(self._object_path(sha), "rb") as fh:
            return json.loads(fh.read().decode("utf-8"))

    def history(self, repo: str, kind: str, number: int | None) -> list[dict]:
        """Every capture of one change, oldest first."""
        rows = []
        if not os.path.exists(self._index):
            return rows
        with open(self._index, encoding="utf-8") as fh:
            for line in fh:
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                if (row.get("repo"), row.get("kind"), row.get("number")) == (repo, kind, number):
                    rows.append(row)
        return rows

    def verify(self) -> list[str]:
        """Problems found re-checking the store: an object whose bytes no longer hash to its name, an index
        row pointing at a missing object, or an unreadable index line. Empty means intact."""
        problems: list[str] = []
        for d, _, names in os.walk(self._objects):
            for name in names:
                if not name.endswith(".json.gz"):
                    continue
                sha = name[:-len(".json.gz")]
                try:
                    with gzip.open(os.path.join(d, name), "rb") as fh:
                        digest = hashlib.sha256(fh.read()).hexdigest()
                except (OSError, EOFError) as exc:
                    problems.append(f"{sha}: unreadable ({exc})")
                    continue
                if digest != sha:
                    problems.append(f"{sha}: content hashes to {digest}")
        if os.path.exists(self._index):
            with open(self._index, encoding="utf-8") as fh:
                for n, line in enumerate(fh, 1):
                    try:
                        row = json.loads(line)
                    except ValueError:
                        problems.append(f"index line {n}: not JSON")
                        continue
                    try:
                        present = os.path.exists(self._object_path(str(row.get("sha256", ""))))
                    except ValueError:
                        problems.append(f"index line {n}: {row.get('sha256')!r} is not a sha256 address")
                        continue
                    if not present:
                        problems.append(f"index line {n}: object {row.get('sha256')} is missing")
        return problems
