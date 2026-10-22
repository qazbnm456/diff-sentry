"""Compiled bytecode against the source it sits beside, without running either.

Python loads a cached `.pyc` instead of its source when the pyc's header matches the source (its mtime and size, or its hash) or is never checked (an unchecked hash-based pyc), and an archive sets both the header and the source's mtime. So a release that edits `x.py` harmlessly can ship `__pycache__/x.cpython-313.pyc` holding other code, and no text rule reads bytecode. Each such pair is checked here: the source is compiled and the bytecode unmarshalled, and the two code objects compared (code equality ignores the file name it was compiled under). Neither is run: `compile` and `marshal.loads` build objects and execute nothing.

That needs an interpreter of the pyc's own Python version, since bytecode and its marshal format change with every minor version. The check runs in a separate `python3.X -I -S` process found on `PATH` (or this one, when its magic number matches), so a crafted pyc that crashes the unmarshaller ends that process, never the watcher; its address space and CPU are capped too, so one that asks for gigabytes is refused there. A pyc no interpreter here can check is reported as such, and stays unread code. Pure stdlib; no dspy.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import sys

log = logging.getLogger(__name__)

_MAGIC = "import importlib.util, sys; sys.stdout.write(importlib.util.MAGIC_NUMBER.hex())"
_CHECK = r"""
import json, marshal, sys
out = []
for item in json.load(sys.stdin):
    try:
        code = marshal.loads(bytes.fromhex(item["pyc"])[16:])
        out.append(code == compile(bytes.fromhex(item["src"]), item["file"], "exec", dont_inherit=True, optimize=item["opt"]))
    except Exception:
        out.append(None)
json.dump(out, sys.stdout)
"""
_TIMEOUT = 120
_BATCH = 500
_MAX_CHILD_MEMORY = 2 << 30        # a crafted marshal header can ask for gigabytes: the child is refused past this
_MAX_CHILD_CPU = 120
_interpreters: dict[str, str] | None = None


def interpreters() -> dict[str, str]:
    """The Python interpreters on this host by bytecode magic number (hex): this one, and each `python3.N` on `PATH`."""
    global _interpreters
    if _interpreters is None:
        found: dict[str, str] = {}
        candidates = [sys.executable] + [p for minor in range(8, 25) if (p := shutil.which(f"python3.{minor}"))]
        for exe in dict.fromkeys(candidates):
            try:
                done = subprocess.run([exe, "-I", "-S", "-c", _MAGIC], capture_output=True, timeout=30, check=True)
            except (OSError, subprocess.SubprocessError):
                continue
            found.setdefault(done.stdout.decode("ascii", "replace").strip()[:8], exe)
        _interpreters = found
    return _interpreters


def _limits() -> None:
    """Run in the child before it starts: cap its address space and CPU, so a crafted pyc ends the child, never the host."""
    import resource

    for limit, value in ((resource.RLIMIT_AS, _MAX_CHILD_MEMORY), (resource.RLIMIT_CPU, _MAX_CHILD_CPU)):
        try:
            resource.setrlimit(limit, (value, value))
        except (ValueError, OSError):      # a platform that does not enforce one (macOS and RLIMIT_AS) keeps the timeout
            pass


def check_bytecode(pairs: list[tuple[bytes, bytes, str, int]]) -> list[bool | None]:
    """For each `(pyc, source, file name, optimization level)`: True when the bytecode is the source compiled, False when it is other code, None when no interpreter here can tell (no interpreter of its version, an unreadable pyc, a crash)."""
    results: list[bool | None] = [None] * len(pairs)
    by_magic: dict[str, list[int]] = {}
    for i, (pyc, *_rest) in enumerate(pairs):
        if len(pyc) >= 16:
            by_magic.setdefault(pyc[:4].hex(), []).append(i)
    for magic, indexes in by_magic.items():
        exe = interpreters().get(magic)
        if exe is None:
            continue
        for start in range(0, len(indexes), _BATCH):
            chunk = indexes[start:start + _BATCH]
            payload = json.dumps([{"pyc": pairs[i][0].hex(), "src": pairs[i][1].hex(), "file": pairs[i][2], "opt": pairs[i][3]}
                                  for i in chunk])
            try:
                done = subprocess.run([exe, "-I", "-S", "-c", _CHECK], input=payload.encode(), capture_output=True,
                                      timeout=_TIMEOUT, check=True, preexec_fn=_limits)
                answers = json.loads(done.stdout)
            except (OSError, subprocess.SubprocessError, ValueError) as exc:
                log.warning("bytecode check under %s: %s", exe, exc)
                continue
            for i, answer in zip(chunk, answers, strict=False):
                results[i] = answer if isinstance(answer, bool) else None
    return results
