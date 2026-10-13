"""The watcher runs the deterministic rules on text ANY GitHub user can write (a body may be 65,536 characters),
on one poller thread, so a rule that is quadratic or worse on a hostile input is a denial of service on the whole
watchlist: nothing else is polled or alerted while it runs. Every module-level regex is held to a linear-time
budget here, and a new pattern is picked up without registering it."""

from __future__ import annotations

import re
import subprocess
import sys
import time
from pathlib import Path

import pytest

from diff_sentry import hosts, indicators, normalize
from diff_sentry.indicators import scan_change

_HOSTILE = {
    "spaces": "x" + " " * 65_000,
    "tabs": "x" + "\t" * 65_000,
    "newlines": "\n" * 40_000,
    "curl_newlines": "curl " + "\n" * 40_000,
    "space_newline": " \n" * 30_000,
    "plus_spaces": "+" + " " * 65_000,
    "dashes": "-" * 65_000,
    "slashes": "http://" + "a." * 20_000 + "b/" + "/" * 20_000,
    "percent": "https://sh.rustup.rs/" + "%2e" * 20_000,
    "quotes": "curl " + "'a' " * 15_000,
    "yaml": ("on:\n  " + "pull_request_target: " * 600 + "\n") * 5,        # ~63 KB: a body's size limit
    "dollars": "${" * 30_000 + "IFS" * 5_000,
    "b64": "A" * 65_000,
    "pipe_hash": "|#" * 32_768, "pipe_space_hash": "| #" * 21_845, "pipe_tab_hash": "|\t#" * 21_845,
    "curl_dots": "curl." * 13_108, "curl_semicolons": "curl;" * 13_108, "wget_colons": "wget:" * 13_108,
    "iwr_dots": "iwr." * 16_000, "curl_parens": "curl(" * 16_000,
    "ref_blanks": "on:\n  pull_request_target:\nref: " + " \t" * 32_000, "binding_blanks": "HEAD:" + " " * 65_000 + "x",
    "iex_spaces": "iex" + " " * 65_000 + "x",
    "invoke_expression_tabs": "Invoke-Expression" + "\t" * 65_000 + "x",
    "iex_parens": "iex" + "( " * 30_000,
}
_BUDGET_S = 1.0


def _patterns():
    for mod in (indicators, hosts, normalize):
        for name, value in vars(mod).items():
            if isinstance(value, re.Pattern):
                yield f"{mod.__name__.rsplit('.', 1)[-1]}.{name}", value


@pytest.mark.parametrize("label,pattern", list(_patterns()), ids=[n for n, _ in _patterns()])
def test_every_regex_is_fast_on_hostile_input(label, pattern):
    for name, text in _HOSTILE.items():
        started = time.process_time()
        pattern.search(text)
        elapsed = time.process_time() - started
        assert elapsed < _BUDGET_S, f"{label} took {elapsed:.2f}s on {name}"


@pytest.mark.parametrize("name", list(_HOSTILE))
def test_scanning_a_hostile_event_is_bounded_in_every_channel(name):
    text = _HOSTILE[name]
    event = {"repo": "a/b", "kind": "issue", "number": 1, "author": "x", "title": text[:256], "body": text,
             "head_ref": text[:250], "files": [{"filename": "a.md", "status": "added", "additions": 1,
                                                "deletions": 0, "patch": "+" + text}],
             "comments": [{"author": "c", "author_type": "User", "association": "NONE", "created_at": "",
                           "body": text}]}
    started = time.process_time()
    scan_change(event)
    # the same 65 KB is scanned as five channels (title, body, branch, file, comment); the worst shape costs about 1.3 s
    # CPU per channel, and a quadratic path is minutes
    assert time.process_time() - started < 10.0, name


def test_a_body_of_blank_lines_before_a_workflow_key_still_finds_it():
    # blank lines in front of the keys do not hide a privileged trigger, a permissions grant, or a padded line
    text = "on:\n  pull_request_target:\n    types: [opened]\n" + "jobs:\n  x:\n    steps:\n      - uses: actions/checkout@v4\n" \
        "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
    assert any(h.rule == "pwn-request" for h in indicators.scan_indicators(text))
    assert any(h.rule == "workflow-permission-escalation" for h in indicators.scan_indicators("permissions: write-all\n"))
    assert any(h.rule == "diff-viewport-evasion" for h in indicators.scan_indicators("x" + " " * 300 + "eval(1)"))


# ── hostile input ──────────────────────────────────────────────────────────────────────

def test_the_named_vectors_are_bounded():
    """Named vectors: an alternation that could parse `${{x}}` two ways (exponential in
    the number of repetitions), and `git checkout ` / `refs/pull/` repeated after a privileged trigger."""
    shapes = {
        "interpolation_60": "pull_request_target:\nref: refs/pull/" + "${{x}}" * 60,
        "interpolation_8000": "pull_request_target:\nref: refs/pull/" + "${{x}}" * 8000,
        "checkout_x5000": "pull_request_target:\n" + "git checkout " * 5000,
        "refs_x6500": "pull_request_target:\n" + "refs/pull/" * 6500,
        "dollars": "pull_request_target:\nref: refs/pull/" + "$" * 30000,
        "binding": "pull_request_target:\n" + "HEAD: " * 8000,
    }
    for name, text in shapes.items():
        started = time.process_time()
        scan_change({"repo": "a/b", "kind": "issue", "number": 1, "author": "x", "title": "t", "body": text,
                     "files": []})
        assert time.process_time() - started < 3.0, name


_CHILD = r"""
import re, sys, time, importlib
mods = ["diff_sentry.indicators", "diff_sentry.hosts", "diff_sentry.normalize", "diff_sentry.ingest",
        "diff_sentry.actors", "diff_sentry.snapshot", "diff_sentry.watch", "diff_sentry.cli"]
SIZE, BUDGET = 65536, 2.0
def literals(p):
    words = re.findall(r"[A-Za-z_][A-Za-z_./-]{2,}", p.pattern.replace("\\", " "))
    return sorted(set(words), key=lambda w: -len(w))[:4]
SHARED = ["${{x}}" * 40 + " ", "refs/pull/" + "${{x}}" * 30, "pull_request_target:\n" + "git checkout " * 10,
          "-" * 40, "a." * 40, "%2e" * 40, "\n" * 40, " \t" * 40, "curl x | a " + " " * 60 + "| b " + " " * 60,
          "curl x " + "| a b c d " * 12, "curl 'a' \"b\" ' " * 12, "curl x \\\n| " * 20, "sudo -u a b c d e " * 10,
          "<!-- " * 30, "> - # 1) \"( " * 20, "\ufeff" * 40, "curl | sh\n" * 20]
for mod in mods:
    m = importlib.import_module(mod)
    for name, pat in vars(m).items():
        if not isinstance(pat, re.Pattern):
            continue
        cases = []
        for lit in literals(pat):
            for unit in (lit + " ", lit, lit + "\n", lit + ":\n"):
                cases.append(unit * max(1, SIZE // len(unit)))
            # ONE literal followed by one long run: the shape that makes adjacent optional quantifiers cubic
            for run in (" ", "\t", "(", " (", "-", "|", "\"", "'", "*"):
                cases.append(lit + run * SIZE)
        # one short prefix and then a single long run of letters/digits: the shape of `-c…c1`, which a pattern with no
        # literal of three letters (and so no case above) can still be cubic on
        for prefix in ("x -", "x ", "-", "https://x/"):
            for run in ("c", "a", "1"):
                cases.append(prefix + run * SIZE + "1")
        for unit in SHARED:
            cases.append(unit * max(1, SIZE // len(unit)))
            cases.append("pull_request_target:\nref: " + unit * max(1, SIZE // len(unit)))
        for i, text in enumerate(cases):
            print(f"START {mod}.{name} #{i}", flush=True)
            t = time.process_time()
            sum(1 for _ in pat.finditer(text))
            dt = time.process_time() - t
            if dt > BUDGET:
                print(f"SLOW {mod}.{name} #{i} {dt:.2f}s", flush=True)
print("DONE", flush=True)
"""


def test_no_pattern_is_superlinear_on_inputs_built_from_its_own_literals():
    """A generic guard, in a subprocess because a runaway `re` match holds the GIL and cannot be interrupted: for
    every module-level regex in the package, run inputs assembled from that pattern's own literals (repeated with
    spaces, newlines, colons, nested interpolations) and require each to finish inside the budget. A pattern that
    hangs is named by the last `START` line."""
    try:
        done = subprocess.run([sys.executable, "-c", _CHILD], capture_output=True, text=True, timeout=420,
                              cwd=str(Path(__file__).resolve().parents[1]), check=False)
    except subprocess.TimeoutExpired as exc:
        out = (exc.stdout or b"")
        out = out.decode() if isinstance(out, bytes) else out
        last = [line for line in out.splitlines() if line.startswith("START")][-1:]
        pytest.fail(f"a regex did not finish in 420s; last started: {last}")
    assert "DONE" in done.stdout, done.stderr[-500:]
    slow = [line for line in done.stdout.splitlines() if line.startswith("SLOW")]
    assert not slow, slow
