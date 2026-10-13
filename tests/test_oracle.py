"""Ground truth for the download-and-execute rules, by execution (see `tests/oracle/__init__.py`).

Three properties, over seeded random candidates:

* RECALL. Whatever a real `bash` or `dash` runs as a downloaded script must be `critical` in a code file. (The reverse is not
  asked: a rule may report more than what runs.)
* RECALL IN PROSE. The same download written into documentation (emphasis, HTML, typographic quotes, CJK prose, a label
  glued to the command) stays `critical` in a body, a comment and a README: the softening is for known installers only.
* SOUNDNESS OF THE PROSE SOFTENING. Whatever the rules reduce to `medium` in prose must, when it is really run, fetch
  nothing but a known installer and call nothing else. A `medium` that fetches an attacker's URL or calls `evil`, `docker`
  or `ssh` is a payload that got through.

Opt-in: `DS_ORACLE=1` (and Docker with the `python:3.11-slim` image). `DS_ORACLE_N` scales the number of candidates.
"""

from __future__ import annotations

import os
import random

import pytest

from diff_sentry.indicators import scan_change
from tests.conftest import BENIGN_EVENT
from tests.oracle import grammar, harness

pytestmark = pytest.mark.skipif(os.getenv("DS_ORACLE") != "1" or not harness.docker_ready(),
                                reason="set DS_ORACLE=1 and pull python:3.11-slim to run the shell oracle")
_N = int(os.getenv("DS_ORACLE_N", "400"))
_SEED = int(os.getenv("DS_ORACLE_SEED", "20260930"))


def _severity(hits) -> str:
    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return max((h.severity for h in hits if h.rule == "curl-pipe-shell"), key=order.__getitem__, default="none")


def _in_code_file(text: str) -> str:
    patch = "".join(f"+{line}\n" for line in text.split("\n"))
    return _severity(scan_change({**BENIGN_EVENT, "files": [{"filename": "install.sh", "status": "added",
                                                              "additions": text.count("\n") + 1, "deletions": 0, "patch": patch}]}))


def _in_prose(text: str, where: str) -> str:
    if where == "body":
        event = {"body": text}
    elif where == "comment":
        event = {"comments": [{"author": "b", "author_type": "User", "association": "NONE",
                               "created_at": "2026-02-27T05:16:00Z", "body": text}]}
    else:
        event = {"files": [{"filename": "README.md", "status": "modified", "additions": 1, "deletions": 0,
                            "patch": "".join(f"+{ln}\n" for ln in text.split("\n"))}]}
    return _severity(scan_change({**BENIGN_EVENT, **event}))


_CHANNELS = ("body", "comment", "readme")


def test_every_download_a_real_shell_runs_is_critical_in_a_code_file():
    rng = random.Random(_SEED)
    candidates = [grammar.payload(rng) for _ in range(_N)]
    misses = [c for c, row in zip(candidates, harness.execute(candidates), strict=True)
              if harness.really_runs_the_download(row) and _in_code_file(c) != "critical"]
    assert not misses, f"{len(misses)} of {len(candidates)} run a download but are not critical:\n" + "\n".join(repr(m) for m in misses[:15])


def test_every_download_a_real_shell_runs_is_critical_in_prose_too():
    """RECALL in documentation: the softening applies to a known installer only, so an attacker's download stays `critical`
    whatever Markdown, HTML, quotes or language the sentence around it is written in (a payload in `_x_` emphasis, in CJK prose
    with no spaces, in typographic quotes, behind a label, is still a payload)."""
    rng = random.Random(_SEED)
    candidates = [grammar.payload(rng, prose=True) for _ in range(_N)]
    forced = [(c, ctx) for c in grammar.LEADING_PIPE for ctx in grammar.CO_RESIDENT]       # a known installer beside each
    candidates += [c for c, _ in forced]
    misses = []
    # what a reader copies out of the rendered text is what runs: `curl … | <b>sh</b>` is `curl … | sh`
    rows = harness.execute([grammar.rendered(c) for c in candidates])
    for k, (c, row) in enumerate(zip(candidates, rows, strict=True)):
        if not harness.really_runs_the_download(row):
            continue
        if k >= _N:                                           # the forced pairs: candidate and the context written beside it
            ctx = forced[k - _N][1]
            text = ctx.format(x=c)
            severities = [_in_prose(text, where) for where in _CHANNELS]
            if any(s != "critical" for s in severities):
                misses.append((text, severities))
            continue
        # a backtick inside a code span is ill-formed, and HTML or an entity inside a Markdown code span is literal text, not markup
        context = rng.choice(grammar.CONTEXTS + grammar.CO_RESIDENT if "`" not in c else grammar.BARE)
        while ("`" in context.replace("{x}", "") and ("<" in c or "&" in c)) or ("\n" in c and context.lstrip().startswith("|")):
            context = rng.choice(grammar.CONTEXTS + grammar.CO_RESIDENT)           # (a Markdown table row cannot hold a line break)
        text = context.format(x=c)
        if "\n" in text and rng.random() < 0.15:
            text = "\n".join(f"> {line}" for line in text.split("\n"))        # a blockquote: every line carries its marker
        severities = [_in_prose(text, where) for where in _CHANNELS]
        if any(s != "critical" for s in severities):
            misses.append((text, severities))
    assert not misses, f"{len(misses)} prose texts run a download but are not critical:\n" + "\n".join(repr(m) for m in misses[:15])


def test_what_the_prose_softening_reduces_to_medium_fetches_only_known_installers_and_calls_nothing_else():
    rng = random.Random(_SEED)
    cases = []
    for _ in range(_N):
        crumbs = rng.random() < 0.1                          # a dedicated share: 4+ breadcrumbs, then a program or a path
        x = grammar.documented(rng, lead=rng.choice(grammar.CRUMB_LEADS) if crumbs else None)
        # a context whose whole text a shell would also read as a command (`curl \`evil\` \`…\``) is run whole; the rest are
        # prose around the command, and only the command runs
        whole = "`" not in x and rng.random() < 0.3
        # a command that holds a backtick of its own (`evil` in front) is not put inside a code span: the span would be ill-formed
        contexts = grammar.WHOLE if whole else grammar.CONTEXTS if "`" not in x else grammar.BARE
        context = rng.choice(grammar.CRUMBS if crumbs and not whole and "`" not in x else contexts).format(x=x)
        prologue = rng.choice(grammar.PROLOGUE)
        cases.append((prologue + context, grammar.rendered(prologue) + grammar.rendered(context if whole else x)))
    for lead, suffix in grammar.PIPE_LEADS:                  # a line that looks like a table row, with `evil` as a stage in front
        for _ in range(max(4, _N // 200)):
            cases.append((lead + (x := grammar.documented(rng)) + suffix, lead + x + suffix))
    softened = [(text, run) for text, run in cases if any(_in_prose(text, where) == "medium" for where in _CHANNELS)]
    assert softened, "the generator produced no documented-installer command at all"
    rows = harness.execute([run for _, run in softened])
    known = set(grammar.KNOWN_URLS)
    violations = [(text, harness.fetch_violations(row, known)) for (text, _), row in zip(softened, rows, strict=True)]
    violations = [v for v in violations if v[1]]
    assert not violations, f"{len(violations)} of {len(softened)} softened commands did something else:\n" + "\n".join(
        f"{v[0]!r}: {v[1][:3]}" for v in violations[:15])
