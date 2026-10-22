"""The watcher runs the deterministic rules on text ANY GitHub user can write (a body may be 65,536 characters), on one poller thread, so a rule that is quadratic or worse on a hostile input is a denial of service on the whole watchlist: nothing else is polled or alerted while it runs. Every module-level regex is held to a linear-time budget here: a new pattern in a listed module is picked up without registering it, and a module that compiles a regex must be listed."""

from __future__ import annotations

import re
import subprocess
import sys
import time
from pathlib import Path

import pytest

from diff_sentry import hosts, indicators, linewide, normalize, shelllex
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
    "quote_then_newline_blanks": 'bash -c "' + "\n " * 30_000,        # the blank context lines of a diff
    "newline_blanks": "\n " * 30_000,
    "sudo_quote_then_newline_blanks": 'env FOO=1 sh -c "' + "\n+ " * 20_000,
    "yaml": ("on:\n  " + "pull_request_target: " * 600 + "\n") * 5,        # ~63 KB: a body's size limit
    "dollars": "${" * 30_000 + "IFS" * 5_000,
    "b64": "A" * 65_000,
    "pipe_hash": "|#" * 32_768, "pipe_space_hash": "| #" * 21_845, "pipe_tab_hash": "|\t#" * 21_845,
    "curl_dots": "curl." * 13_108, "curl_semicolons": "curl;" * 13_108, "wget_colons": "wget:" * 13_108,
    "iwr_dots": "iwr." * 16_000, "curl_parens": "curl(" * 16_000,
    "curl_ansi_c_strings": "curl " + "$'a'" * 16_000, "curl_dollar_quotes": "curl " + "$'" * 30_000,
    "curl_escaped_quotes": "curl " + "\\'" * 20_000, "curl_backslash_curl_quotes": 'curl\\"' * 10_000, "curl_backslash_runs": "curl " + "\\" * 60_000 + "'",
    "ref_blanks": "on:\n  pull_request_target:\nref: " + " \t" * 32_000, "binding_blanks": "HEAD:" + " " * 65_000 + "x",
    "iex_spaces": "iex" + " " * 65_000 + "x",
    "invoke_expression_tabs": "Invoke-Expression" + "\t" * 65_000 + "x",
    "iex_parens": "iex" + "( " * 30_000,
}
_BUDGET_S = 1.0


def _flatten(value, depth=0):
    """The regexes a module-level value holds: itself, or those in a tuple, list, set, frozenset or dict (`_HTML_BLOCKS` is a tuple of pairs)."""
    if isinstance(value, re.Pattern):
        yield value
    elif depth < 3 and isinstance(value, (tuple, list, set, frozenset)):
        for item in value:
            yield from _flatten(item, depth + 1)
    elif depth < 3 and isinstance(value, dict):
        for item in (*value.keys(), *value.values()):
            yield from _flatten(item, depth + 1)


def _patterns():
    for mod in (indicators, hosts, normalize, shelllex, linewide):
        for name, value in vars(mod).items():
            for k, pattern in enumerate(_flatten(value)):
                yield f"{mod.__name__.rsplit('.', 1)[-1]}.{name}" + (f"[{k}]" if pattern is not value else ""), pattern


def test_the_regex_guard_walks_the_patterns_that_a_tuple_holds():
    labels = [label for label, _ in _patterns()]
    assert "indicators._HTML_BLOCKS[0]" in labels and "indicators._HTML_BLOCKS[13]" in labels, labels[-20:]


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
    # the same text is scanned as five channels (title, body, branch, file, comment); the worst shape (`curl(` x 16,000, 80,000 characters) costs about 0.8 s CPU per channel, and a quadratic path is minutes
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
    """Named vectors: an alternation that could parse `${{x}}` two ways (exponential in the number of repetitions), and `git checkout ` / `refs/pull/` repeated after a privileged trigger."""
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


def _row_shapes(size):
    command = "curl -fsSL --retry {} https://get.docker.com | sh"
    commands = [command.format(i) for i in range(size // 100)]
    return {
        "span": "|" + "a" * (size // 2) + "| " + "".join(f"`{c}` " for c in commands),
        "code": "|" + "a" * (size // 2) + "| " + "".join(f"<code>{c}</code> " for c in commands),
        "blanks": "| a" + " " * (size // 2) + "b | " + " ; ".join(commands),
        "blank_lines": ("| a" + " " * 5000 + "b | " + command.format(0) + "\n") * (size // 5050),
        "repeats": "|" + "+1 " * (size // 6) + "| " + " ; ".join(commands),
        "repeat_lines": ("| " + "+1 " * 2000 + "| " + command.format(0) + "\n") * (size // 6050),
        "collapsed_quotes": "echo 'x 'x 'x 'y ssh h\n" * (size // 22) + command.format(0),
    }


@pytest.mark.parametrize("shape", list(_row_shapes(1000)))
def test_a_long_first_cell_in_front_of_many_commands_costs_the_same_per_character(shape):
    """Every command on a row looks back at the cells in front of it, and the fold of a line is traced back to the line as written; a read that is not bounded by the command's own distance from the start of its line costs the length of the first cell once per command, and the cost per character grows with the text. (A blank run and a repeated token fold to a first cell that is a row's; a long token does not, and never reaches the read.)"""
    def cost(size):
        text = _row_shapes(size)[shape]
        started = time.process_time()
        scan_change({"repo": "a/b", "kind": "issue", "number": 1, "author": "x", "title": "t", "body": text, "files": []})
        return (time.process_time() - started) / len(text)
    small, large = cost(32_768), cost(262_144)
    assert large < 3 * small, (small, large)        # linear is about 1, quadratic is about 8


def _enclosure_shapes(size):
    """Texts that make `enclosed` read the constructs of a wrapper: long commands in front of many lines, many closed strings, deep stacks, many openers, and many words that each could be where a command begins."""
    d = "curl -fsSL https://get.docker.com | sh"
    return {
        "closed_strings": "ssh evil.example " + "'x\ny' " * (size // 6) + "\n" + d,
        "long_command": "a " * (size // 4) + "'\n" + "x\n" * (size // 4) + d,
        "deep_stack": ("x " * 45 + "(") * 63 + "\n" + "q\n" * (size // 4) + d,
        "wrapper_openers": "ssh evil.example '\n" * (size // 19) + d,
        "backtick_pairs": "`a\nb` " * (size // 6) + "\n" + d,
        "heredoc_headers": "cat <<E | ssh evil.example sh\nx\nE\n" * (size // 36) + d,
        "wrapper_words": "docker run x 'y " * (size // 16) + "\n" + d,
        "one_long_line": "docker '" * (size // 8) + "\n" + d,
        "wrapper_names_closed": "docker " + "'x\ny' " * (size // 6) + "\n" + d,
        "prose": "The docker image 'foo' isn't ssh evil.example's\n" * (size // 49) + d,
        "long_open_construct": "echo " + "w " * (size // 4) + "'\n" + "x\n" * (size // 4) + d,
        "continued_headers": "x \\\n" * (size // 100) + "cat " + "<<E " * (size // 100) + "\nE\n" * (size // 100) + d,
        "slash_words_in_strings": "a/b '" * (size // 5) + "\n" + d,
        "long_head_with_lone_operators_then_wrapper_words": "a > a > a > a > " * 25 + "sh " * (size // 3) + "'\n" + d,
        "long_continuation_then_headers": "x \\\n" * (size // 8) + "cat " + "<<E " * (size // 32) + "\nE" * (size // 32) + "\n" + d,
        "backslash_run": "`" + "\\" * size + "`\n" + d,
        "heredocs_then_substitutions": "cat " + "<<E " * (size // 8) + "$(a) " * (size // 10) + "\n" + d,
        "candidate_words_on_one_line": "( " + "docker " * (size // 7) + "\n" + d,
        "candidate_lines": "x\n" + "ssh h " * (size // 6) + "'\n" + "y\n" * 100 + d,
        "candidates_with_closed_strings": "Run: " + "ssh h 'x\ny' " * (size // 12) + "\n" + d,
        "mixed_motif": "'<<E ~~~> docker <<E $((docker ```\n" * (size // 36) + d,
        "deep_alternating": "(" * 15 + "\n" + "'\n" * (size // 2) + d,
        "removed_lines": "@@ -1 +1 @@ it's\n-it's\n+ssh evil.example '\n" * (size // 40) + d,
        "escaped_quotes": "ssh evil.example \\'\n" * (size // 20) + d,
        "comment_after_a_long_prompt_then_wrapper_words": " " * (size // 2) + "# ' " + "ssh h " * (size // 12) + "\n" + d,
        "piped_script_of_wrapper_words": ('echo "\n' + "ssh h '" * 285 + '\n" | sh\n') * (size // 2010) + d,
        "eval_value_of_wrapper_words": ("eval '\n" + "$(ssh h <<E`" * 125 + "\n'\n") * (size // 1400) + d,
        "long_command_front_then_candidates_then_a_comment_quote": "x " * (size // 2 - size // 22) + "docker " * (size // 150) + "# '" + "\n" + d,
        "open_braces_on_one_line": "{" * size + "\n" + d,
        "array_openers_on_one_line": "a=(" * (size // 3) + ")\n" + d,
    }


@pytest.mark.parametrize("shape", list(_enclosure_shapes(1000)))
def test_reading_what_a_wrapper_encloses_costs_the_same_per_character_at_every_size(shape):
    """Each construct is judged once, however many lines it spans, by a bounded slice of its command; a hypothesis that a command begins at a wrapper word reads at most a window of lines after it and the reads are held to a budget."""
    def cost(size):
        text = _enclosure_shapes(size)[shape]
        started = time.process_time()
        scan_change({"repo": "a/b", "kind": "issue", "number": 1, "author": "x", "title": "t", "body": text, "files": []})
        return (time.process_time() - started) / len(text)
    small, large = min(cost(16_384) for _ in range(2)), cost(131_072)
    assert large < 2.5 * max(small, 5e-7), (small, large)       # linear is about 1, quadratic is about 8
    assert large < 1e-4, large                                   # and 64 KiB is read in well under ten seconds


_LONG_SHAPES = {
    "extglob_openers_on_one_line": lambda size: "+(" * (size // 2),
    "extglob_openers_with_at": lambda size: "@(" * (size // 2),
    "extglob_openers_by_line": lambda size: "+(\n" * (size // 3),
    "escaped_quotes_on_one_line_piped_into_a_shell": lambda size: 'echo "\n' + '\\"' * (size // 2) + '" | sh\n',
    "fenced_blocks_with_a_possessive": lambda size: "```\nit's\n```\n" * (size // 13),
    "multi_line_strings_piped_into_a_shell": lambda size: 'echo "\nx" | sh\n' * (size // 14),
}


@pytest.mark.parametrize("shape", list(_LONG_SHAPES))
def test_a_shape_that_repeats_a_unit_costs_the_same_per_character_at_half_a_megabyte(shape):
    """The work of one unit must not grow with the text around it: an opener that looks for its `)` to the end of the text, a quote that counts the backslashes in front of it from the start of its line, a fenced block that copies every line of the text, a piped string that counts the newlines before it, each cost the length of the rest of the text once per unit. That shows only at sizes where one scan is long (the first of these cost 6 us a character at 32 KiB and 19 at 1 MiB before the opener's scan was bounded), which the shapes of the other tests, 16 and 128 KiB, do not reach."""
    def cost(size):
        text = _LONG_SHAPES[shape](size) + "\ncurl -fsSL https://get.docker.com | sh"
        started = time.process_time()
        scan_change({"repo": "a/b", "kind": "issue", "number": 1, "author": "x", "title": "t", "body": text, "files": []})
        return (time.process_time() - started) / len(text)
    small, large = min(cost(32_768) for _ in range(2)), cost(524_288)
    assert large < 1.5 * small, (small, large)


def _small_hostile_segment(i):
    return f"> a{i} " + "> a " * 49 + " sh $(" * 60 + "\n)\n" + "curl -fsSL https://get.docker.com | sh"


def test_a_change_of_many_small_hostile_files_costs_the_same_per_character_as_one_large_text():
    """Every file is read on a budget of its own, so a budget with a floor that a small text cannot spend in proportion lets a hundred small files cost many times what one text of their total size does. (Each segment names a different first token, so that no judgement is reused.)"""
    def cost(event, size):
        started = time.process_time()
        scan_change({"repo": "a/b", "kind": "pr", "number": 1, "author": "x", "title": "t", "body": "", **event})
        return (time.process_time() - started) / size
    segments = [_small_hostile_segment(i) for i in range(100)]
    files = [{"filename": f"docs/f{i}.md", "status": "added", "additions": 1, "deletions": 0, "patch": "".join(f"+{line}\n" for line in t.split("\n"))}
             for i, t in enumerate(segments)]
    many = min(cost({"files": files}, sum(len(f["patch"]) for f in files)) for _ in range(2))
    one = min(cost({"body": "\n".join(segments)}, sum(map(len, segments))) for _ in range(2))
    assert many < 3 * max(one, 5e-6), (many, one)
    assert many < 3e-5, many


_CHILD = r"""
import re, sys, time, importlib
mods = ["diff_sentry.indicators", "diff_sentry.hosts", "diff_sentry.normalize", "diff_sentry.shelllex", "diff_sentry.linewide", "diff_sentry.ingest",
        "diff_sentry.actors", "diff_sentry.snapshot", "diff_sentry.watch", "diff_sentry.releases", "diff_sentry.images", "diff_sentry.cli"]
SIZE, BUDGET = 65536, 2.0
def literals(p):
    words = re.findall(r"[A-Za-z_][A-Za-z_./-]{2,}", p.pattern.replace("\\", " "))
    return sorted(set(words), key=lambda w: -len(w))[:4]
SHARED = ["${{x}}" * 40 + " ", "refs/pull/" + "${{x}}" * 30, "pull_request_target:\n" + "git checkout " * 10,
          "-" * 40, "a." * 40, "%2e" * 40, "\n" * 40, " \t" * 40, "curl x | a " + " " * 60 + "| b " + " " * 60,
          "curl x " + "| a b c d " * 12, "\n " * 40, "bash -c \"" + "\n " * 30, "curl 'a' \"b\" ' " * 12, "curl x \\\n| " * 20, "sudo -u a b c d e " * 10,
          "<!-- " * 30, "> - # 1) \"( " * 20, "\ufeff" * 40, "curl | sh\n" * 20, "-node\n" * 20, "@node\n" * 20]
def flatten(value, depth=0):
    if isinstance(value, re.Pattern):
        yield value
    elif depth < 3 and isinstance(value, (tuple, list, set, frozenset)):
        for item in value:
            yield from flatten(item, depth + 1)
    elif depth < 3 and isinstance(value, dict):
        for item in (*value.keys(), *value.values()):
            yield from flatten(item, depth + 1)
for mod in mods:
    m = importlib.import_module(mod)
    for name, held in vars(m).items():
      for k, pat in enumerate(flatten(held)):
        label = name if pat is held else f"{name}[{k}]"
        cases = []
        for lit in literals(pat):
            for unit in (lit + " ", lit, lit + "\n", lit + ":\n"):
                cases.append(unit * max(1, SIZE // len(unit)))
            # ONE literal followed by one long run: the shape that makes adjacent optional quantifiers cubic
            for run in (" ", "\t", "(", " (", "-", "|", "\"", "'", "*"):
                cases.append(lit + run * SIZE)
            # and after a key's colon or an assignment's `=`, where a value's lead (tags, anchors, quotes, blanks) begins
            for sep in (":", "=", ": "):
                cases.append(lit + sep + " " * SIZE + "!")
        # one short prefix and then a single long run of letters/digits: the shape of `-c…c1`, which a pattern with no
        # literal of three letters (and so no case above) can still be cubic on
        for prefix in ("x -", "x ", "-", "https://x/"):
            for run in ("c", "a", "1"):
                cases.append(prefix + run * SIZE + "1")
        for unit in SHARED:
            cases.append(unit * max(1, SIZE // len(unit)))
            cases.append("pull_request_target:\nref: " + unit * max(1, SIZE // len(unit)))
        for i, text in enumerate(cases):
            print(f"START {mod}.{label} #{i}", flush=True)
            t = time.process_time()
            sum(1 for _ in pat.finditer(text))
            dt = time.process_time() - t
            if dt > BUDGET:
                print(f"SLOW {mod}.{label} #{i} {dt:.2f}s", flush=True)
print("DONE", flush=True)
"""


def test_every_module_that_compiles_a_regex_is_held_to_the_budget():
    listed = set(re.findall(r'"diff_sentry\.(\w+)"', _CHILD.split("for mod in mods")[0]))
    root = Path(__file__).resolve().parents[1] / "diff_sentry"
    compiling = {path.stem for path in root.glob("*.py") if "re.compile(" in path.read_text(encoding="utf-8")}
    assert compiling <= listed, sorted(compiling - listed)


def test_no_pattern_is_superlinear_on_inputs_built_from_its_own_literals():
    """A generic guard, in a subprocess because a runaway `re` match holds the GIL and cannot be interrupted: for every module-level regex in the package, run inputs assembled from that pattern's own literals (repeated with spaces, newlines, colons, nested interpolations) and require each to finish inside the budget. A pattern that hangs is named by the last `START` line."""
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


_INSTALLER = "curl -fsSL https://get.docker.com | sh"


def _scan_body(body):
    return scan_change({"repo": "a/b", "kind": "issue", "number": 1, "author": "x", "title": "t", "body": body, "files": []})


def test_a_word_a_dollar_cuts_into_tokens_never_makes_a_scan_raise():
    """The candidates of a hypothesis are asked of the lexer in ascending order; `a$/sh` is cut by the `$` and is also a whole word, and neither reading raises out of `scan_change`."""
    hits = _scan_body("e a$/sh` u$/podman\n" + _INSTALLER)
    assert not [h for h in hits if h.rule == "scanner-error"] and [h.rule for h in hits if h.rule == "curl-pipe-shell"]


def test_texts_of_words_a_dollar_or_a_brace_cuts_never_make_a_scan_raise():
    import random
    rng = random.Random(58)
    vocabulary = ["a$X/ssh", "u$/podman", "e", "sh`", "ssh", "bin/$N", "x{a,b}/sudo", "\u00ef/$(a)", "'", '"', "`", "docker run", "nohup", "<<E", "$(", "#", "\\\n", "\n", "\n", "A=1", "/*/ssh"]
    for _ in range(1500):
        body = "".join(rng.choice(vocabulary) + rng.choice(["", " ", " "]) for _ in range(rng.randint(2, 14))) + "\n" + _INSTALLER
        assert not [h for h in _scan_body(body) if h.rule == "scanner-error"], body


def test_candidates_are_ascending_and_unique():
    line = "x a$X/ssh h '"
    found = indicators._quoted_programs(line, indicators._wrapper_words(list(indicators._TOKEN_RE.finditer(line))))
    assert found == sorted(set(found)) and found


def test_the_lexer_answers_probes_given_in_any_order_and_twice():
    lexed = shelllex.line_states("ssh h 'x\nz", probes=(9, 1, 9, 4))
    assert sorted(lexed.probed) == [1, 4, 9]


def test_a_crash_of_the_softening_keeps_the_installer_as_strict_as_the_detector_found_it(monkeypatch):
    def broken(*_args, **_kwargs):
        raise RuntimeError("boom")
    monkeypatch.setattr(indicators, "_enclosing_lines", broken)
    hits = _scan_body("Install it:\n\n" + _INSTALLER)
    assert [h.severity for h in hits if h.rule == "curl-pipe-shell"] == ["critical"] and [h for h in hits if h.rule == "scanner-error"]
