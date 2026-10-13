"""The edges of the patterns, the shape gate, the rendered view and the shield, each pinned by the shortest text that tells the code from one mutant of it.

`_EDGE_ROWS` holds, per pattern, a text and the span `search` finds in it (None: no match): each row is the shortest text on which a mutant of the pattern (one alternative
dropped, a quantifier removed or changed, a class member removed, a bound moved, an anchor or a lookaround removed) answers differently. The functions below pin the defaults of
the softening and the rendered view, the window of the list strings, the strings a gate decodes, and the shield's fence and HTML-block ends."""

from __future__ import annotations

import pytest

from diff_sentry import indicators
from diff_sentry.indicators import (
    _enclosing_lines,
    _extras_of_view,
    _holds_json_strings,
    _names_a_program,
    _rendered,
    _rendered_extras,
    _segment_hits,
    _shield_html_fences,
    _soften_prose,
    scan_diff,
)

_UV = "curl -LsSf https://astral.sh/uv/install.sh | sh"
_FENCED = f"ssh evil.example $(x\n```\n{_UV}\n```"          # `$(`, not a quote: the line-wide floor counts quotes and would keep the installer critical


def _installer_severities(hits) -> list[str]:
    return [h.severity for h in hits if h.rule == "curl-pipe-shell"]


_EDGE_ROWS = {
    '_ARRAY_OPEN_RE': [
        ('M=(', (0, 3)),
    ],
    '_PLACEHOLDER_RE': [
        ('<%"\'"', (0, 5)),
        ('<%"`"', (0, 5)),
        ('<%\'"\'', (0, 5)),
        ("<%'`'", (0, 5)),
        ('<?"\'"', (0, 5)),
        ('<?"`"', (0, 5)),
        ('<?\'"\'', (0, 5)),
        ("<?'`'", (0, 5)),
        ('<%\n\'"\'', None),
        ('<%%"`"', None),
        ('<?\n"\'"', None),
        ("<??'`'", None),
        ('<?{\'"\'', (0, 6)),
    ],
    '_CODE_QUOTE_RE': [
        ('``', None),
        ('`"`', (0, 3)),
        ("`'`", (0, 3)),
        ("9`'`", None),
        ('A`"`', None),
        ('\\`"`', None),
        ('_`"`', None),
        ("`\t'`", (0, 4)),
        ('` "`', (0, 4)),
        ('`"\t`', (0, 4)),
        ('`"``', None),
        ("`' `", (0, 4)),
        ('`\'"`', (0, 4)),
        ('``"`', None),
        ("b`'`", None),
    ],
    '_CURL_SUBST_SHELL_RE': [
        ('. $(curl', (0, 8)),
        ('.\t- `curl', (0, 9)),
        ('.\t- \t`curl', (0, 10)),
        ('. -< `curl', None),
        ('. -c\t`curl', (0, 10)),
        ('. -c `curl', (0, 10)),
        ('SH -o`curl', None),
        ('. +e $(curl', (0, 11)),
        ('eval -`curl', None),
        ('sh\t-\t$(curl', (0, 11)),
        ('.\t- - <(wget', None),
        ('. -1  $(curl', (0, 12)),
        ('. -o a\t<(curl', (0, 13)),
        ('sh\t- - $(curl', None),
        ('sh "-o <(curl', (0, 13)),
        ('sh ++x $(curl', (0, 13)),
        ('sh -o\tl `curl', (0, 13)),
        ('sh -o" <(curl', (0, 13)),
        ('sh -vx\t$(curl', (0, 13)),
        ('sh -x\t\t$(curl', (0, 13)),
        ('. -o _b\t<(curl', (0, 14)),
        ('SH +o e $(curl', (0, 14)),
        ("perl '+a `curl", (0, 14)),
        ("perl +b' `curl", (0, 14)),
        ('sh\t-o  p `curl', (0, 14)),
        ('sh +++x $(curl', None),
        ('sh -o x $(curl', (0, 14)),
        ('sh -o "\t"$(curl', None),
        ('python -- <(curl', (0, 16)),
        ('sh --rcfile\tg\t`curl', (0, 19)),
        ('sh --rcfile f\t`curl', (0, 19)),
        ('sh --rcfile ++ $(curl', (0, 21)),
        ('sh --init-file f `curl', (0, 22)),
        ('sh --\t-b\t-c -c -x `curl', (0, 23)),
        ('sh --init-file  f $(curl', (0, 24)),
        ('sh -x -x\t+x -e -c\t-l <(curl', None),
    ],
    '_FD_DUP_RE': [
        ('&5', None),
        ('<&', None),
        ('<&7', (0, 3)),
        ('<&2 ', None),
        ('<<&1', (0, 4)),
        ('<&027', (0, 5)),
        ('827>&2', (0, 6)),
        ('>&8494', None),
        ('6252>&5', (1, 7)),
    ],
    '_HASH_PROMPT_RE': [
        ('#', None),
        ('\t#\t', (0, 3)),
        ('#\t ', (0, 3)),
        ('*# ', (0, 3)),
        ('+#\t', (0, 3)),
        ('># ', (0, 3)),
        ('#######\t', None),
        ('####### ', None),
    ],
    '_LIST_DOWNLOAD_RE': [
        ('irm', (0, 3)),
        ('iwr', (0, 3)),
        ('iwRr', None),
        ('wget', (0, 4)),
        ('Invoke-RestMethod', (0, 17)),
        ('Invoke-WebRequest', (0, 17)),
        ('IInvoke-WebRequest', None),
    ],
    '_LIST_MARKER_RE': [
        ('+\t ', (0, 3)),
        ('x*\t', None),
    ],
    '_LIST_STRING_RE': [
        ('""', (0, 2)),
        ("''", (0, 2)),
        ('\t""', (0, 3)),
        ('"\n"', None),
        ('""#', (0, 2)),
        ('"")', (0, 2)),
        ('""x', None),
        ('"\\"', None),
        ("'\n'", None),
        ("''\t", (0, 3)),
        ("'''", None),
        ("'\\'", None),
        ('(""', (1, 3)),
        ("{''", (1, 3)),
        ('"". ', (0, 2)),
        ('""..', None),
        ('"".9', None),
        ('"".Z', None),
        ("''//", (0, 2)),
        ("'\\<'", (0, 4)),
    ],
    '_NOTEBOOK_KEY_RE': [
        ('"":[', (0, 4)),
        ('"\n":[', None),
        ('"\\":[', None),
    ],
    '_SPLIT_WORDS_RE': [
        ('&', (0, 1)),
        ('(', (0, 1)),
        (')', (0, 1)),
        ('<', (0, 1)),
        ('>', (0, 1)),
        (';\n', (0, 2)),
    ],
    '_YAML_OPEN_QUOTE_RE': [
        ("-'=''", None),
        (": '''", None),
        ("-\t'>''", (0, 6)),
        ("-\t'{''", (0, 6)),
        ("- '\n''", None),
        ("- ''''", None),
        ("-\t'\t''\t", (0, 7)),
        (":\t\t'/''", (0, 7)),
        (":\t')'' ", (0, 7)),
        (": '<''}", None),
    ],
}


_EDGE_CASES = [(name, text, span) for name, group in _EDGE_ROWS.items() for text, span in group]


@pytest.mark.parametrize(("name", "text", "span"), _EDGE_CASES, ids=[f"{n}-{i}" for i, (n, _, _) in enumerate(_EDGE_CASES)])
def test_a_pattern_finds_the_span_that_tells_it_from_each_of_its_mutants(name, text, span):
    m = getattr(indicators, name).search(text)
    assert (m.span() if m else None) == span


def test_strings_of_a_list_are_pieces_of_one_up_to_the_window_and_not_beyond():
    dl = '"curl x | sh"'
    for gap in range(1, 6):
        assert _holds_json_strings('"ssh",' + "\nx" * (gap - 1) + "\n" + dl), gap
    for gap in (6, 7, 12):
        assert not _holds_json_strings('"ssh",' + "\nx" * (gap - 1) + "\n" + dl), gap


def test_a_string_that_leaves_the_window_does_not_take_the_ones_inside_it_along():
    """The oldest string of the window is dropped by its LINE, not by what it holds: a download four lines in and a program two lines later are still pieces of one list."""
    assert _holds_json_strings("\n" * 4 + '"curl x | sh"' + "\n\n" + '"ssh"')
    assert _holds_json_strings('"a"\n"b"\n' + "\n" * 3 + '"curl x | sh"' + "\n" + '"ssh"')


@pytest.mark.parametrize("string", ['"a(ssh)"', '"ssh)x"', '"\\x64ist"', '"x;ssh"', '"x&ssh"', '"x<ssh"', '"x>ssh"'])
def test_a_string_with_a_separator_in_front_of_a_program_or_that_json_cannot_decode_could_be_a_command(string):
    assert _names_a_program(string), string


def test_a_double_quoted_string_is_decoded_as_json_and_a_single_quoted_one_as_python():
    assert _names_a_program('"\\x64ist"') and not _names_a_program('"dist\\u0021"') and not _names_a_program("'dist\\x21'")


@pytest.mark.parametrize(("text", "rendered"), [("a ` ' ` b", "a ' b"), ('a `  "  ` b', 'a " b'), ('x ` " `', 'x "'), ("`'` y", "' y"), ('a `"` `\'` b', 'a " \' b')])
def test_a_code_span_of_a_quote_and_blanks_is_that_quote_to_the_rendered_view(text, rendered):
    assert _rendered(text) == rendered


@pytest.mark.parametrize(("text", "shielded"), [
    ("<!-- c -->\n```\nx", "<!-- c -->\n```\nx"),                                          # a comment that ends on its own line ends the block: the fence after it is a fence
    ("<div>\n```\n</div>", "<div>\n   \n</div>"),
    ("```\n   ```\n<div>\n```\n</div>", "```\n   ```\n<div>\n   \n</div>"),                # a closing fence may be three blanks in
    ("```\n    ```\n<div>\n```\n</div>", "```\n    ```\n<div>\n```\n</div>"),            # ... and not four
    ("```\n  ```\n<div>\n```", "```\n  ```\n<div>\n   "),
    ("```a`b\n<div>\n```", "```a`b\n<div>\n   "),                                          # a backtick fence whose info string holds a backtick is no fence
    ("~~~a`b\n<div>\n```", "~~~a`b\n<div>\n```"),                                          # a tilde fence is one whatever its info string holds
])
def test_the_shield_blanks_a_fence_marker_only_inside_an_html_block(text, shielded):
    assert _shield_html_fences(text) == shielded


def test_the_softening_defaults_are_a_body_that_is_a_patch_with_markdown_and_a_file_that_is_no_prose():
    prose = f"Install: {_UV}"
    assert _installer_severities(_soften_prose(scan_diff(prose), prose, "file")) == ["critical"]
    patch = f"+ssh evil.example $(\n+{_UV}"
    assert _installer_severities(_soften_prose(scan_diff(patch), patch, "body")) == ["critical"]
    assert _installer_severities(_soften_prose(scan_diff(_FENCED), _FENCED, "body")) == ["medium"]


def test_the_rendered_extras_defaults_are_a_patch_that_is_softened_as_prose_in_markdown_and_a_file_that_is_no_prose():
    assert _installer_severities(_rendered_extras([], f"<code>{_UV}</code>", "file", scan_diff)) == ["critical"]
    assert _installer_severities(_rendered_extras([], f"<code>{_UV}</code>", "body", scan_diff)) == ["medium"]
    assert _installer_severities(_rendered_extras([], f"+<b>ssh</b> evil.example $(\n+{_UV}", "body", scan_diff)) == ["critical"]
    assert _installer_severities(_rendered_extras([], f"<b>ssh</b> evil.example $(x\n```\n{_UV}\n```", "body", scan_diff)) == ["medium"]


def test_the_view_of_a_text_is_softened_as_prose_and_in_markdown_unless_it_is_told_otherwise():
    assert _installer_severities(_extras_of_view([], _UV, "body", scan_diff, prose_file=True, diff=False)) == ["medium"]
    assert _installer_severities(_extras_of_view([], _FENCED, "body", scan_diff, prose_file=True, diff=False)) == ["medium"]


def test_a_segment_is_read_as_markdown_unless_it_is_told_otherwise():
    assert _installer_severities(_segment_hits(_FENCED, "body", scan_diff, prose_file=True, diff=False)) == ["medium"]
    assert _installer_severities(_segment_hits(_FENCED, "body", scan_diff, prose_file=True, diff=False, markdown=False)) == ["critical"]


def test_a_wrapper_in_a_text_with_a_fence_after_it_is_cut_by_the_fence_when_the_text_is_markdown():
    assert _enclosing_lines(["ssh evil.example 'x", "```", _UV, "```"], False) == [False, False, False, False]
    assert _enclosing_lines(["ssh evil.example 'x", "```", _UV, "```"], False, markdown=False) == [False, True, True, True]


def test_the_first_line_of_a_document_that_is_no_markdown_is_read():
    assert _enclosing_lines(["ssh evil.example '", _UV], False, markdown=False) == [False, True]
    assert _enclosing_lines(["a", "ssh evil.example '", _UV], False, markdown=False) == [False, False, True]


@pytest.mark.parametrize("tail", [" ", "\t", " \t", "\t ", "  "])
@pytest.mark.parametrize("marker", ["> ", "- "])
def test_a_fence_behind_a_marker_is_closed_by_a_marker_line_with_nothing_but_blanks_after_it(marker, tail):
    lines = [f"{marker}```", f"{marker}ssh evil.example '", f"{marker}```{tail}", "```", _UV]
    assert _enclosing_lines(lines, False) == [False, False, True, False, False]


def test_a_list_string_is_judged_without_the_blanks_around_it():
    """A string that json cannot decode names a program, whatever blanks stand in front of it (the match of a list string starts at the blanks)."""
    assert _holds_json_strings(' "\\x64ist", "wget x"')
    assert not _holds_json_strings(' "dist", "wget x"')


@pytest.mark.parametrize(("line", "quotes"), [("b'\"x", ("'",)), ("b\"'x", ('"',)), ("b'$x", ("'",)), ("b'`x", ("'",)), ("b'<x", ("'",)), ("b'>x", ("'",)), ("b'&x", ("'",)), ("b' x", ("'",)), ("b'x", ())])
def test_a_quote_with_a_quoting_character_glued_after_it_may_end_a_string(line, quotes):
    from diff_sentry.indicators import _closing_quotes
    assert _closing_quotes(line) == quotes


def test_a_region_with_added_lines_and_a_bullet_and_no_header_is_not_softened_and_a_dash_elsewhere_is_no_bullet():
    tool = indicators.make_indicator_tool()
    assert "[critical] curl-pipe-shell" in tool(f"+{_UV}\n- bullet")
    assert "[critical] curl-pipe-shell" in tool(f"+{_UV}\n-\tbullet")
    assert "[medium] curl-pipe-shell" in tool(f"+{_UV}\nx - y")
    assert "[medium] curl-pipe-shell" in tool(f"+{_UV}\nx -\ty")
    assert "[medium] curl-pipe-shell" in tool(f"+{_UV}\n-x")


_BRACES = [
    ('{{ "\'" }}', True), ("{{ '\"' }}", True), ('{{ "\\"" }}', True), ("{{ '\\'' }}", True), ('{{ \\" }}', True), ("{{ \\' }}", True), ('{{ "`" }}', True), ('{{ \'`\' }}', True),
    ('{{ "\'"', True), ('}{{ "\'"', True), ('{{}} {{ "\'"', True), ('${{{ "\'"', True), ('{{ x }}{{ "\'" }}', True), ('a\n{{ "\'" }}', True),
    ('${{ "\'" }}', False), ('{{ x }} "\'"', False), ('x "\'" {{ y', False), ('{{\n"\'"', False), ('{{ "a" }}', False), ('{ "\'" }', False), ('{{', False), ('', False),
    ('{{ }} "\'" }}', False), ("{{ x }}\n{{ y", False),
]


@pytest.mark.parametrize(("text", "expected"), _BRACES)
def test_a_quote_spelled_between_double_braces_and_the_next_closing_brace_on_a_line_is_a_shape(text, expected):
    from diff_sentry.indicators import _spells_a_quote_in_braces
    assert _spells_a_quote_in_braces(text) is expected


_ARRAYS = [
    ("a=(", True), ("a=(\n", True), ("a+=(x", True), ("_a1=(b", True), ("a=(b) c=(", True), ("a=(b)\nc=(", True), ("x ) a=(", True), ("a=(\nb)", True), ("a=(b c", True),
    ("a=(b)", False), ("a=()", False), ("a=(b) c=(d)", False), ("a=( )", False), ("", False), ("a =(", False), ("9a=(", False), ("=(", False), ("a=b", False), ("a=(b)\nc", False), ("f(a=(b))", False),
]


@pytest.mark.parametrize(("text", "expected"), _ARRAYS)
def test_an_array_assignment_whose_closing_parenthesis_is_not_on_its_line_is_a_shape(text, expected):
    from diff_sentry.indicators import _opens_an_array
    assert _opens_an_array(text) is expected


@pytest.mark.parametrize("name", ["a.rst", "a.adoc", "a.html", "a.htm", "n.ipynb"])
def test_a_document_that_is_no_markdown_is_read_from_each_paragraph_with_the_backslashes_of_its_rendering_gone(name):
    """`ssh h \\'` is `ssh h '` once rendered: the reading from the start of the paragraph that drops the backslash is made in a file that is no Markdown too."""
    assert _enclosing_lines(["ssh evil.example \\'", _UV], False, markdown=False) == [False, True]
    assert _severities_in_file(name, f"ssh evil.example \\'\n{_UV}") == ["critical"]


def _severities_in_file(name: str, body: str) -> list[str]:
    patch = "".join(f"+{line}\n" for line in body.split("\n"))
    event = {"repo": "a/b", "kind": "pr", "number": 1, "author": "x", "title": "t", "body": "",
             "files": [{"filename": name, "status": "added", "additions": 1, "deletions": 0, "patch": patch}]}
    return sorted({h.severity for h in indicators.scan_change(event) if h.rule == "curl-pipe-shell"})


@pytest.mark.parametrize(("name", "severity"), [("a.html", "critical"), ("a.rst", "critical"), ("a.md", "medium")])
def test_a_file_that_is_no_markdown_is_rendered_and_read_with_no_fence_either(name, severity):
    found = _severities_in_file(name, f"<b>ssh</b> evil.example $(x\n```\n{_UV}\n```")          # the softened hit of the raw text and, where the rendered view reads the installer as enclosed, a critical one
    assert max(found, key=("medium", "critical").index) == severity, found


@pytest.mark.parametrize(("text", "shielded"), [
    ("<div>\n``` ```\nx", "<div>\n    ```\nx"),
    ("<div>\n```a```\nx", "<div>\n   a```\nx"),
    ("<div>\n- ``` ```\nx", "<div>\n-     ```\nx"),
    ("<div>\n~~~ ~~~ ~~~\nx", "<div>\n    ~~~ ~~~\nx"),
])
def test_the_shield_blanks_the_marker_of_a_fence_line_in_an_html_block_and_not_the_text_after_it(text, shielded):
    assert _shield_html_fences(text) == shielded


def test_a_script_nested_three_deep_is_read_to_its_innermost_line():
    """`eval '…echo "…eval \\"…<installer>…\\"…" | sh…'`: an `eval` value, a string piped into a shell and an `eval` value, one inside the other; the depth of three reads the innermost."""
    nested = "eval '\necho \"\neval \\\"\n" + _UV + "\n\\\"\n\" | sh\n'"
    event = {"repo": "a/b", "kind": "issue", "number": 1, "author": "x", "title": "t", "body": nested, "files": []}
    assert sorted({h.severity for h in indicators.scan_change(event) if h.rule == "curl-pipe-shell"}) == ["critical"]
    assert _enclosing_lines(nested.split("\n"), False) == [False, False, True, True, True, True, False]


def test_a_string_with_an_invalid_escape_is_judged_without_a_warning():
    import warnings
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        assert _names_a_program("'\\d'")
    assert not caught, [str(w.message) for w in caught]
