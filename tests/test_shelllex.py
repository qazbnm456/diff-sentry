"""`diff_sentry.shelllex`: what is still open where each line of a text begins. Without Docker; `tests/test_oracle.py` (opt-in)
holds the lexer to what real `bash -n` and `dash -n` say about thousands of generated fragments."""

from __future__ import annotations

import random
import time
from dataclasses import FrozenInstanceError

import pytest

from diff_sentry.shelllex import MAX_DEPTH, Opener, Probe, State, line_states


def kinds(text: str) -> list[tuple[str, ...]]:
    return [tuple(o.kind for o in s.openers) for s in line_states(text)]


def unknown(text: str) -> bool:
    return line_states(text)[-1].unknown


@pytest.mark.parametrize("text,expected", [
    ("ssh h 'x\ncurl X | sh\n'\nafter", [(), ("SQ",), ("SQ",), ()]),
    ('docker run x sh -c "a\nb"\nc', [(), ("DQ",), ()]),
    ("echo 'a\n\nb'\nc", [(), ("SQ",), ("SQ",), ()]),
    ("x=$(echo\ncurl X | sh\n)\ny", [(), ("CMD",), ("CMD",), ()]),
    ("x=`echo\ncurl X | sh\n`\ny", [(), ("BQ",), ("BQ",), ()]),
    ("diff <(a\nb)\nc", [(), ("PROC",), ()]),
    ("(a\nb)\nc", [(), ("SUB",), ()]),
    ("echo ${x:-a\nb}\nc", [(), ("PARAM",), ()]),
    ("echo $((1 +\n2))\nc", [(), ("ARITH",), ()]),
    ('x="$(echo \'a\n b\')"\nz', [(), ("DQ", "CMD", "SQ"), ()]),
    ("echo a\\\nb\nc", [(), (), ()]),                                    # a line continuation opens nothing
    ("echo 'a'\\''b\nc", [(), ("SQ",)]),                                  # `'a'` and `\'` are words, `'b` opens a string never closed
    ("echo 'a'\\'''b\nc", [(), ()]),                                      # `'a'`, `\'`, an empty string, then the word `b`
])
def test_what_is_open_where_a_line_begins(text, expected):
    assert kinds(text) == expected


def test_a_here_document_body_is_open_up_to_its_delimiter():
    assert kinds("cat <<E\nbody\nE\nafter") == [(), ("HEREDOC",), ("HEREDOC",), ()]
    assert kinds("cat <<-E\n\tbody\n\tE\nafter") == [(), ("HEREDOC",), ("HEREDOC",), ()]
    assert kinds("cat <<'E'\n$(x)\nE\nafter") == [(), ("HEREDOC",), ("HEREDOC",), ()]
    assert kinds("a <<E <<F\n1\nE\n2\nF\nz") == [(), ("HEREDOC",), ("HEREDOC",), ("HEREDOC",), ("HEREDOC",), ()]
    assert kinds("cat <<E\nbody\n") == [(), ("HEREDOC",), ("HEREDOC",)]                  # never closed: the end of the text is inside it
    assert kinds("cat <<E \\\n") == [(), ("HEREDOC",)]                                    # the line goes on and the body is the next one
    assert kinds("cat <<E\nbody\nE") == [(), ("HEREDOC",), ("HEREDOC",)]                  # the delimiter line begins inside the body


def test_a_here_document_inside_a_substitution_ends_with_its_delimiter():
    assert kinds("x=$(cat <<E\nbody\nE\n)\nz") == [(), ("CMD", "HEREDOC"), ("CMD", "HEREDOC"), ("CMD",), ()]


def test_the_opener_knows_the_command_that_holds_it():
    states = line_states("echo hi; ssh evil.example 'a\nb'")
    opener = states[1].openers[0]
    assert opener == Opener("SQ", opener.offset, 9)
    assert "echo hi; ssh evil.example 'a\nb'"[opener.command_at:opener.offset + 1] == "ssh evil.example '"
    nested = line_states('ssh h "$(echo\nx)"')[1].openers
    assert [o.kind for o in nested] == ["DQ", "CMD"] and nested[0].command_at == nested[1].command_at == 0


@pytest.mark.parametrize("text,opens", [
    ("# 'a\nb", False),                       # a comment
    ("echo a #'b\nc", False),                 # a comment after a blank
    ("echo a#'b\nc", True),                   # not at the start of a word: `a#` and the quote opens
    ("echo ; # 'a\nb", False),
    ("echo ${x#'a'}\nb", False),
    ("echo \\'a\nb", False),                  # an escaped quote
    ("echo \"it's\"\nb", False),              # a quote inside double quotes
    ("echo 'it\"s'\nb", False),
    ("echo $x\nb", False),
])
def test_comments_escapes_and_quotes_inside_quotes_open_nothing(text, opens):
    assert bool(line_states(text)[-1].openers) == opens


@pytest.mark.parametrize("text", [
    "echo $'a\\'b'\nz",                       # `$'…\'…'` is one string in bash and an error in dash
    "echo \"${x:-'}'}\"\nz",                  # a quote inside `${…}` inside double quotes
    "echo ${'a'}\nz",
    "x=$(case y in a) b ;; esac)\nz",         # the `)` of a pattern is not the end of the substitution
    "echo $((echo a); (echo b))\nz",          # bash reads a substitution, dash an error
    "echo $(('a'))\nz",
    "[[ $x =~ ^(a|b)$ ]]\nz",
    "shopt -s extglob\nls @(a|b)\nz",
    "cat <<$x\nz",                            # a delimiter that expands
    "echo `a \\`b\\` c`\nz",                  # a nested substitution
    "cat <<E\nab\\\nE\nE\nz",                 # an unquoted body joins lines through a backslash-newline
])
def test_what_bash_and_dash_read_differently_is_unknown(text):
    assert unknown(text)


def test_what_both_shells_read_the_same_is_known():
    for text in ["echo $'a'\nz", "echo 'a' \"b\" `c`\nz", "cat <<'E'\nab\\\nE\nz", "echo $((1+(2*3)))\nz", "f() { a; }\nz"]:
        assert not unknown(text), text


def test_nesting_deeper_than_the_cap_is_unknown_and_never_an_error():
    assert unknown("$(" * (MAX_DEPTH + 5) + "\nz")
    assert not unknown("$(" * (MAX_DEPTH - 5) + "\nz")


def test_a_text_may_start_inside_a_construct():
    assert [tuple(o.kind for o in s.openers) for s in line_states("a\nb' c\nd", start=(Opener("SQ", 0, 0),))] == [("SQ",), ("SQ",), ()]


def test_there_is_one_state_per_line_whatever_the_text_holds():
    atoms = ["'", '"', "`", "\\", "$(", "$((", "${", "$'", ")", "))", "}", "(", "<<E", "<<'E'", "<<-E", "#", "|", ";", "&&", " ", "a", "\n",
             "E\n", "echo ", "<(", "\t", "x=", "$a", "\\\n", "\n\n"]
    rng = random.Random(3)
    for _ in range(4000):
        text = "".join(rng.choice(atoms) for _ in range(rng.randint(0, 14)))
        assert len(line_states(text)) == text.count("\n") + 1, repr(text)


@pytest.mark.parametrize("shape", [
    "'", '"', "'a' ", "$(", "${", "`", "<<E\nE\n", "# ' \n", "\\\n", "$((", "(", "a'b\"c`d$(e${f\n", "<<E\n", "$'a'", "x=1 ; ", " | ",
    "a\\\n", "a\\\n\\\n", "\\\n\\\n\\\n", "a[", "a[1]", "a['", "a(", "a (", "a=\\\n(", "${a:x", "${a:'", "[x](#y)\n", "coproc a (", "$(( <(", "th\\\nen ", "a\\\n1a[", "for ((",
])
def test_the_cost_per_character_is_the_same_at_every_size(shape):
    """One pass, no backtracking: a hostile text of any shape costs the same per character at 64 KiB and at 1 MiB."""
    def cost(size: int) -> float:
        text = shape * (size // len(shape))
        started = time.process_time()
        line_states(text)
        return (time.process_time() - started) / len(text)
    small, large = min(cost(65_536) for _ in range(2)), min(cost(1_048_576) for _ in range(2))
    assert large < 3 * max(small, 2e-7), (shape, small, large)


def test_a_long_word_is_skipped_in_one_step():
    """A run of characters that mean nothing is jumped over, not walked: a word of 256 KiB costs what one of 64 KiB does per character."""
    def cost(size: int) -> float:
        text = "abcdefghij" * (size // 10) + " x"
        started = time.process_time()
        line_states(text)
        return (time.process_time() - started) / len(text)
    small, large = min(cost(65_536) for _ in range(2)), min(cost(262_144) for _ in range(2))
    assert large < 3 * max(small, 2e-7), (small, large)


def test_the_body_of_a_backtick_substitution_is_read_as_commands():
    """A Markdown code span is a backtick substitution to a shell: the body is cut at the first backtick that is not escaped and read
    as commands, so a string a wrapper opens inside it is open on the lines inside, and closed after it."""
    text = "Run `docker run x sh -c '\nset -e\ncurl X\n'` now\nafter"
    assert kinds(text) == [(), ("BQ", "SQ"), ("BQ", "SQ"), ("BQ", "SQ"), ()]
    heredoc = "With `ssh h <<'EOF'\nbody\nEOF` | sudo sh\nafter"
    assert kinds(heredoc) == [(), ("BQ", "HEREDOC"), ("BQ", "HEREDOC"), ()]
    states = line_states(text)
    inner = states[1].openers
    assert [o.kind for o in inner] == ["BQ", "SQ"]
    assert text[inner[1].command_at:inner[1].offset + 1] == "docker run x sh -c '"      # offsets are those of the whole text
    assert kinds("a `b\nc\nd") == [(), ("BQ",), ("BQ",)]                             # a substitution that is never closed runs to the end
    assert kinds("x=\"a `b\nc` d\"\ne") == [(), ("DQ", "BQ"), ()]


def test_a_parenthesis_inside_a_parameter_expansion_is_a_pattern_character():
    """`${x%% (*}` is a pattern: Homebrew's own scripts have it, and reading its `(` as a subshell left the rest of the file open."""
    assert kinds('a="${x%% (*}"\nb\n${y#(}\nc') == [(), (), (), ()]


def test_the_constructs_that_spanned_lines_and_closed_are_recorded_with_the_line_they_closed_on():
    lexed = line_states("ssh h 'x\ny'\nz\ncat <<E\nb\nE\n`a\nb` c")
    assert [(line, o.kind) for line, o in lexed.closed] == [(1, "SQ"), (5, "HEREDOC"), (7, "BQ")]
    assert not line_states("echo 'a b'\nz").closed                     # a string that began and ended on one line is not recorded


@pytest.mark.parametrize("word,expected", [("E", "E"), ("'E'", "E"), ("E\\\\", "E\\"), ("'E'x", "Ex"), ('E"x y"', "Ex y"), ("E\\\nE", "EE"), ('"E\\"F"', 'E"F')])
def test_a_here_document_delimiter_is_read_after_quote_removal(word, expected):
    from diff_sentry.shelllex import _unquote
    assert _unquote(word) == expected


@pytest.mark.parametrize("text", [
    "cat <<E $(echo)\nbody\nE\nz",            # the body may begin inside the substitution
    "cat <<E; ls @(a)\nbody\nE\nz",
    "echo ${$'a'}\nz",
    "echo ${#\\$}\nz",
])
def test_what_dash_reads_differently_around_parameter_expansions_and_here_documents_is_unknown(text):
    assert unknown(text)


@pytest.mark.parametrize("before", [
    "echo 'a'", 'echo "a"', "echo $x", "echo ${x}", "echo $(a)", "echo `a`", "echo \\a", "echo $((1))", "echo $'a'",
    "echo <(a)", "echo a}", "echo \"$(a)\"", "echo \"`a`\"", "echo \"${x}\"", "echo a<<<b", "echo a>b",
])
def test_a_hash_starts_a_comment_only_where_a_word_starts(before):
    """`#` after a word is part of it, so the quote that follows opens a string; after a blank it begins a comment."""
    assert line_states(before + "#'z\nw")[-1].openers, before
    assert not line_states(before + " #'z\nw")[-1].openers, before
    assert not line_states(before + ";#'z\nw")[-1].openers, before            # after `;` too


@pytest.mark.parametrize("text,command", [
    ("echo hi; ssh h 'x", "ssh h '"), ("echo hi && ssh h 'x", "ssh h '"), ("echo hi || ssh h 'x", "ssh h '"), ("echo hi | ssh h 'x", "ssh h '"),
    ("echo hi\nssh h 'x", "ssh h '"), ("echo hi & ssh h 'x", "ssh h '"), ("(ssh h 'x", "ssh h '"), ("$(ssh h 'x", "ssh h '"),
    ("  ssh h 'x", "ssh h '"), ("x=1 ssh h 'x", "x=1 ssh h '"), ("echo hi;\n\n  ssh h 'x", "ssh h '"), ("a=\"$(ssh h 'x", "ssh h '"),
])
def test_the_command_that_holds_an_opener_begins_after_the_last_separator(text, command):
    states = line_states(text + "\n")
    opener = states[-1].openers[-1]
    assert text[opener.command_at:opener.offset + 1] == command


def test_unknown_travels_out_of_a_backtick_body_and_a_here_document_body():
    assert unknown("`echo $'a\\'b'`\nz")
    assert not unknown("`echo 'a'`\nz")
    assert unknown("cat <<E\nab\\\nE\nz")                                    # unquoted: a backslash-newline joins lines
    assert not unknown("cat <<E\nbody\nE\nz")
    assert not unknown("cat <<'E'\nab\\\nE\nz")


@pytest.mark.parametrize("text,opens", [
    ("echo {'a'}\nz", False), ("echo a${'a'}\nz", True), ("echo ${\"a\"}\nz", True), ("echo {\"a\"}\nz", False), ("echo $(('a'))\nz", True),
    ("echo $((\"a\"))\nz", True), ("echo $(($'a'))\nz", True), ("echo ${x:-$'a'}\nz", True), ("echo ${x:-'a'}\nz", False), ("echo $x{'a'}\nz", False),
])
def test_a_quote_where_bash_and_dash_read_it_differently_is_unknown_and_elsewhere_it_is_not(text, opens):
    assert unknown(text) == opens


def test_a_shift_and_a_here_string_are_no_here_document():
    assert kinds("echo $((1 << 2))\nz") == [(), ()]
    assert kinds("cat <<<'a'\nz") == [(), ()]
    assert kinds("cat <<<a <<E\nb\nE\nz") == [(), ("HEREDOC",), ("HEREDOC",), ()]
    assert kinds("cat <<< a\nb") == [(), ()]


def test_a_here_document_with_no_final_newline_and_the_offsets_of_its_opener():
    assert kinds("cat <<E\nbody") == [(), ("HEREDOC",)]
    assert kinds("cat <<E\n") == [(), ("HEREDOC",)]
    pending = line_states("cat <<E \\\n")[-1].openers
    assert pending == (Opener("HEREDOC", 4, 0),)
    inside = line_states("x; cat <<E\nbody\nE")[1].openers
    assert inside == (Opener("HEREDOC", 7, 3),)


def test_the_opener_of_a_backtick_substitution_has_the_offsets_of_the_whole_text():
    text = "echo hi; ssh h `a\nb` c"
    assert line_states(text)[1].openers == (Opener("BQ", 15, 9),)
    inside = line_states("ssh h `a 'b\nc' d`\ne")[1].openers
    assert inside == (Opener("BQ", 6, 0), Opener("SQ", 9, 7))


def test_arithmetic_keeps_its_own_parenthesis_depth():
    assert kinds("echo $(( (1+2)*3 ))\nz") == [(), ()]
    assert kinds("echo $(( (1+2\n)*3 ))\nz") == [(), ("ARITH",), ()]
    assert unknown("echo $((1)\nz")                                             # `$((1)` is not closed by `))`


def test_empty_backticks_and_an_escape_right_before_the_closing_backtick_close_the_substitution():
    assert kinds("x=``\ny") == [(), ()]
    assert kinds("x=`a\\\\`\ny") == [(), ()]                                  # `\\` is a backslash: the backtick after it is the end
    assert kinds("x=`a\\`\ny") == [(), ("BQ",)]                               # `\`` is an escaped backtick: the substitution goes on
    assert kinds("x=`a\\``\ny") == [(), ()]                                   # ... until the backtick after it


def test_the_lines_a_construct_closed_on_inside_a_backtick_body_are_lines_of_the_whole_text():
    lexed = line_states("x\n`a 'b\nc' d`\ne")
    assert [(line, o.kind) for line, o in lexed.closed] == [(2, "SQ"), (2, "BQ")]
    lexed = line_states("cat <<E\nb\nE\n")
    assert lexed.closed == [(2, Opener("HEREDOC", 4, 0))]
    nested = line_states("x `cat <<E\nb\nE\n` y")
    assert nested.closed[0][1] == Opener("HEREDOC", 7, 3) and nested.closed[0][0] == 2


def test_a_here_document_waiting_for_its_body_at_the_end_of_a_backtick_body_has_the_offsets_of_the_whole_text():
    states = line_states("x `cat <<E \\\n` y")
    assert states[1].openers == (Opener("BQ", 2, 0), Opener("HEREDOC", 7, 3))


@pytest.mark.parametrize("text,command", [
    ("'ssh' h 'x", "'ssh' h '"), ('"ssh" h \'x', '"ssh" h \''), ("$X h 'x", "$X h '"), ("\\ssh h 'x", "\\ssh h '"), ("(\"ssh\" h 'x", "\"ssh\" h '"),
    ("diff <(ssh h 'x", "ssh h '"), ("echo $(a) h 'x", "echo $(a) h '"), ("ssh $(a) h 'x", "ssh $(a) h '"), ("echo ${a} h 'x", "echo ${a} h '"),
    ("ls | ssh h 'x", "ssh h '"), ("{ ssh h 'x", "ssh h '"),
])
def test_the_command_that_holds_an_opener_also_starts_with_a_quote_a_substitution_or_after_one(text, command):
    opener = line_states(text + "\n")[-1].openers[-1]
    assert text[opener.command_at:opener.offset + 1] == command


def test_a_dollar_brace_inside_double_quotes_is_a_parameter_expansion_and_a_dollar_before_the_closing_quote_is_a_dollar():
    assert kinds('echo "${x:-a\nb}"\nc') == [(), ("DQ", "PARAM"), ()]
    assert kinds('echo "a$"\nb') == [(), ()]
    assert kinds('echo "$(# \'x\nb)"\nc') == [(), ("DQ", "CMD"), ()]            # a comment inside the substitution


def test_a_regular_expression_operator_is_unknown_after_a_double_bracket_and_a_tilde_path_is_not():
    assert unknown("[[ $a =~ ^x ]]\nz")
    assert unknown("[[ $a == b && $c =~ ^x ]]\nz")
    assert unknown("echo [[ x\ny=~/z\nw")                     # once a `[[` is read, every `=~` after it may be the operator
    assert not unknown("x=~/dir\nz")
    assert not unknown("PATH=~/bin:$PATH\nz")
    assert not unknown("[ x =~ y ]\nz")                      # `=~` means nothing in a single bracket


@pytest.mark.parametrize("text,is_unknown", [
    # a parameter name or a special parameter may follow `${`, with `#` or `!` in front: anything else is read differently by dash
    ("echo ${\\a}\nz", True), ("echo ${#\\a}\nz", True), ("echo ${!\\a}\nz", True), ("${\\a}\nz", True), ("${#\\a}\nz", True),
    ("echo ${#'x'}\nz", True), ("echo ${!\"x\"}\nz", True), ("echo ${#\"x\"}\nz", True), ("echo ${'x'}\nz", True), ("echo ${`a`}\nz", True),
    ("echo ${ a}\nz", True), ("echo ${\nz", True), ("echo ${a$$((x}\nz", True), ("echo ${a b}\nz", True), ("echo ${#:-x}\nz", False), ("echo ${x:-$(a)}\nz", False), ("echo ${x[1]}\nz", False),
    ("echo ${!x*}\nz", False), ("echo ${x@Q}\nz", False), ("echo ${10}\nz", False), ("echo \"${#'x'}\"\nz", True), ("echo ${(a)}\nz", True),
    ("echo ${a}\nz", False), ("echo ${*}\nz", False), ("echo ${_x}\nz", False), ("echo ${1}\nz", False), ("echo ${@}\nz", False), ("echo ${#}\nz", False), ("echo ${##}\nz", False),
    ("echo ${!a}\nz", False), ("echo ${#a}\nz", False), ("echo ${-}\nz", False), ("echo ${?}\nz", False), ("echo ${$}\nz", False),
    ("echo ${a\\}b}\nz", True), ("echo $a\\b\nz", False), ("echo {\\a}\nz", False), ("echo ${a:-\\a}\nz", False),
    ("echo ${b{\\a}\nz", True), ("echo ${a:-'x'}\nz", False),
    ('echo "${\\a}"\nz', True), ('echo "${ a}"\nz', True), ('echo "${a}"\nz', False),
])
def test_what_follows_a_parameter_expansion_opener_decides_whether_it_is_unknown(text, is_unknown):
    assert unknown(text) == is_unknown


def test_a_here_document_on_the_line_of_a_process_substitution_is_unknown():
    assert unknown("cat <<E <(echo)\nbody\nE\nz")
    assert unknown("cat <<E; (echo)\nbody\nE\nz")
    assert not unknown("cat <<E\nbody\nE\nz <(echo)")


def test_a_state_handed_in_may_close_at_the_very_first_character():
    assert [s.openers for s in line_states("'a\nb", start=(Opener("SQ", -1, -1),))] == [(Opener("SQ", -1, -1),), ()]


def test_the_depth_cap_is_exactly_the_limit():
    assert MAX_DEPTH == 16
    assert not unknown("$(" * 16 + "\nx")
    assert unknown("$(" * 17 + "\nx")


def test_an_opener_a_state_and_a_probe_are_immutable_values_without_a_dict():
    o, s, p = Opener("SQ", 1, 0), State((), False), Probe((), 0, -1, False)
    for value, field in ((o, "kind"), (s, "unknown"), (p, "command_at")):
        with pytest.raises(FrozenInstanceError):
            setattr(value, field, "x")
        assert not hasattr(value, "__dict__")


def test_a_construct_handed_in_that_closes_on_the_first_line_is_recorded_as_closed():
    lexed = line_states("a'", start=(Opener("SQ", -1, -1),))
    assert lexed.closed == [(0, Opener("SQ", -1, -1))]
    lexed = line_states("a'\nb", start=(Opener("SQ", -1, -1),))
    assert lexed.closed == [(0, Opener("SQ", -1, -1))]


def test_an_arithmetic_expansion_handed_in_counts_its_inner_parentheses_from_zero():
    start = (Opener("ARITH", 0, 0),)
    assert [s.openers for s in line_states("(1)) x\ny", start=start)] == [start, ()]
    assert [s.openers for s in line_states("1)) x\ny", start=start)] == [start, ()]
    assert [s.openers for s in line_states("((1) +\n2)) x\ny", start=start)] == [start, start, ()]


def test_the_inner_parentheses_of_an_arithmetic_expansion_are_not_its_end():
    assert kinds("x=$(( (1) +\n 2 ))\ny") == [(), ("ARITH",), ()]
    assert kinds("x=$(( ((1)) + (2)\n+ 3 ))\ny") == [(), ("ARITH",), ()]
    assert kinds('x="$(( (1) +\n 2 ))"\ny') == [(), ("DQ", "ARITH"), ()]
    assert kinds('x="$(( 1 +\n 2 ))"\ny') == [(), ("DQ", "ARITH"), ()]
    assert kinds('x="$(echo\n b)"\ny') == [(), ("DQ", "CMD"), ()]


def test_lines_that_begin_alike_share_one_state():
    states = line_states("a\n" * 50)
    assert all(s is states[0] for s in states)
    states = line_states("a '\n" + "b\n" * 50)
    assert all(s is states[1] for s in states[1:])


def test_a_comment_starts_after_a_blank_or_an_opener_and_not_inside_a_word():
    assert kinds("echo hi # it's\nb") == [(), ()]
    assert kinds("echo hi#it's\nb") == [(), ("SQ",)]
    assert kinds("echo $(# it's\nb)\nc") == [(), ("CMD",), ()]
    assert kinds("cat <(# it's\nb)\nc") == [(), ("PROC",), ()]
    assert kinds("(# it's\nb)\nc") == [(), ("SUB",), ()]
    assert kinds("a;# it's\nb") == [(), ()]


def test_a_case_in_a_substitution_is_unknown_in_every_kind_of_substitution():
    assert unknown("echo $(case x in a) echo b;; esac)\nz")
    assert unknown('echo "$(case x in a) echo b;; esac)"\nz')
    assert unknown("diff <(case x in a) echo b;; esac)\nz")


def test_an_extglob_is_unknown_once_extglob_is_on_and_markdown_emphasis_is_not():
    assert unknown("shopt -s extglob\n@(a\nb)\nc")
    assert unknown("shopt -s extglob\nx@(a\nb)\nc")
    assert unknown("bash -O extglob\nls *(a\nb)\nc")
    assert not unknown("shopt -s extglob\nx (a\nb)\nc")
    assert unknown("@(a\nb)\nc")                            # the option is the shell's, not the text's: a startup file, another block or a quoted spelling turns it on
    assert unknown("ssh h @(a)#'x\nz")                        # a `#` glued behind the group is a comment without it and part of the word with it
    assert unknown("ssh h @(#'x\nz") and unknown("ssh h @(a(b)\nz")
    assert not unknown("ls @(a|b) *(c) +(d) !(e) ?(f)\nz") and not unknown("see *(the note) here\nz")       # a plain group that closes on its line moves no quote
    assert not unknown("**(Recommended)** curl\nz")
    assert not unknown("*(optional)*\nz")


def test_a_dollar_that_is_followed_by_a_quote_or_a_name_leaves_the_quote_to_open():
    assert kinds('echo $"a\nb"\nc') == [(), ("DQ",), ()]
    assert kinds("echo $a'b\nc'") == [(), ("SQ",)]


def test_a_shift_in_an_arithmetic_expansion_and_a_here_string_are_no_here_document():
    assert kinds("x=$((1<<2\n))\ny") == [(), ("ARITH",), ()]
    assert not unknown("x=$((1<<2\n))\ny")
    assert kinds("cat <<<a\nb\nc") == [(), (), ()]
    assert not unknown("cat <<<a\nb\nc")
    assert kinds("cat <<<'a\nb'\nc") == [(), ("SQ",), ()]


@pytest.mark.parametrize("text", ["cat <<E$x\nb\nE\nz", "cat <<E`x`\nb\nE\nz", "cat <<E$\nb\nE\nz", "cat <<$x\nb\nz", "cat <<\nb\nz"])
def test_a_here_document_delimiter_that_expands_or_is_not_a_word_is_unknown(text):
    assert unknown(text)


def test_a_here_document_waiting_at_the_end_of_a_backtick_body_names_the_command_that_holds_it():
    states = line_states("x `echo a; cat <<E \\\n` y")
    assert states[1].openers == (Opener("BQ", 2, 0), Opener("HEREDOC", 15, 11))


def test_a_comment_starts_at_the_beginning_of_a_line():
    assert kinds("a\n# it's\nb") == [(), (), ()]
    assert kinds("echo $(a\n# it's\nb)\nc") == [(), ("CMD",), ("CMD",), ()]


def test_the_inner_parentheses_of_an_arithmetic_expansion_leave_no_unknown_behind():
    assert not unknown("x=$(( (1) +\n 2 ))\ny")
    assert not unknown('x="$(( (1) +\n 2 ))"\ny')
    assert not unknown("x=$(( ((1)) + (2)\n+ 3 ))\ny")


def test_a_parenthesis_right_after_a_shift_in_an_arithmetic_expansion_is_a_parenthesis():
    assert kinds("x=$((1<<(2) +\n3))\ny") == [(), ("ARITH",), ()]
    assert not unknown("x=$((1<<(2) +\n3))\ny")
    assert kinds("x=$((1<<2 +\n3))\ny") == [(), ("ARITH",), ()]


@pytest.mark.parametrize("text,is_unknown", [
    # a line continuation inside a two-character token joins its halves, which this lexer does not follow
    ("$\\\n{\nz", True), ("$\\\n(a\nz", True), ("$(\\\n(1\nz", True), ("cat <\\\n<E\nz", True), ("cat <<\\\n-E\nz", True),
    ("cat >\\\n(a\nz", True), ("x=$((1)\\\n)\nz", True), ('echo "$\\\n(a"\nz', True), ('echo "$(\\\n(1))"\nz', True),
    # a continuation anywhere else is nothing
    ("cat > \\\nfile\nz", False), ("echo a)\\\n)\nz", False), ("echo $a\\\nb\nz", False), ("echo $a \\\nb\nz", False), ("echo ${a}\\\nb\nz", False),
    ("x=$((1))\\\nz", False), ('echo "$a"\\\nz', False), ("cat <<E \\\nb\nE\nz", False),
    ("cat <<<\\\na\nz", False),                # nothing in a here-string depends on what follows it
    ("cat <a\\\nb\nz", False), ("cat a \\\nb\nz", False), ("cat a\\\n b\nz", False), ("x=$(( (\\\n1) ))\nz", False),
])
def test_a_line_continuation_inside_a_two_character_token_is_unknown(text, is_unknown):
    assert unknown(text) == is_unknown


@pytest.mark.parametrize("text,is_unknown", [
    # dash reads an unquoted here-document body as if in double quotes, at parse time: a construct that runs past its line hides the delimiter
    ("cat <<E\n${{x\nE\nz", True), ("cat <<E\n$(echo\nE\n)\nz", True), ("cat <<E\n`a\nE\nz", True), ("<<-E\n;;<<'E'<<-E${{E\nE\n\n", True),
    ("cat <<E\n${x:-a\nE\n}\nz", True), ("cat <<-E\n\t$(a\n\tE\n)\nz", True),
    # closed on their own line, escaped, in a quoted body, or no construct at all
    ("cat <<E\n$(date) ${HOME} `a` $((1+2))\nE\nz", False), ("cat <<'E'\n$(echo\nE\nz", False), ('cat <<E\n"$(a)" "x\nE\nz', False),
    ("cat <<E\n\\$(a\nE\nz", False), ("cat <<E\nprice $5 and $\nE\nz", False), ("cat <<E\nplain\nE\nz", False),
])
def test_an_unquoted_here_document_body_that_opens_a_construct_past_its_line_is_unknown(text, is_unknown):
    assert unknown(text) == is_unknown


@pytest.mark.parametrize("text,is_unknown", [
    ('cat <<-E"\n"E\n\tE\n<echo }\nz', True), ("cat <<'E\nx'\nbody\nE\nz", True), ('cat <<E"a b"\nbody\nEa b\nz', False),
    ("cat <<'E'\nbody\nE\nz", False), ('cat <<"E"\nbody\nE\nz', False), ("cat <<E'a'\nbody\nEa\nz", False),
])
def test_a_here_document_delimiter_with_a_quote_across_a_newline_is_unknown(text, is_unknown):
    assert unknown(text) == is_unknown


def test_two_dollars_are_the_process_id_and_a_parenthesis_after_them_opens_no_substitution():
    assert kinds('echo "$$(a\nb)"\nz') == [(), ("DQ",), ()]
    assert kinds('echo "$$$(a\nb)"\nz') == [(), ("DQ", "CMD"), ()]
    assert kinds("echo $$$(a\nb)\nz") == [(), ("CMD",), ()]
    assert kinds('echo "$$"\nz') == [(), ()]
    assert kinds('echo "$$(\nb"\nz') == [(), ("DQ",), ()]



def test_a_hash_right_after_a_redirection_starts_a_comment_and_a_hash_inside_a_word_does_not():
    """Both bash and dash read `cat a>#it's` as a comment (and then complain about the missing file name), and `cat a>x#it's` as a string."""
    assert kinds("cat a>#it's\nb") == [(), ()]
    assert kinds("cat a<#it's\nb") == [(), ()]
    assert kinds("cat a>x#it's\nb") == [(), ("SQ",)]


def test_an_arithmetic_expansion_inside_another_hands_the_parentheses_back_to_the_outer_one():
    assert kinds("x=$(( (1 + $((2)) ) +\n 3 ))\ny") == [(), ("ARITH",), ()]
    assert kinds("x=$(( $((1)) + (2) +\n 3 ))\ny") == [(), ("ARITH",), ()]
    assert not unknown("x=$(( (1 + $((2)) ) +\n 3 ))\ny")


@pytest.mark.parametrize("text,is_unknown", [
    ("token: ${{ secrets.X }}\nrun: curl a | sh\nz", False),
    ("if: ${{ github.ref == 'refs/heads/main' }}\nz", False),
    ('x="${{ a }}"\nz', False),
    ("echo ${{ format('{0}', x) }}\nz", False),
    ("echo ${{ a ${{ b }}\nz", True),                       # a second `$` inside: not the plain expression
    ("echo ${{ a\nb }}\nz", True),                        # not on one line
    ("echo ${{ it's }}\nz", True),                        # an odd quote
])
def test_a_workflow_expression_is_a_word_and_anything_else_that_starts_like_one_is_unknown(text, is_unknown):
    assert unknown(text) == is_unknown


@pytest.mark.parametrize("text,is_unknown", [
    ("cat <<E'x\ny'\nbody\nE\nz", True),                  # a quote glued to the delimiter that runs across a newline
    ("cat <<\\E\n$(echo\nE\nz", False),                   # a backslash quotes the delimiter: the body is literal
    ("cat <<\"E\"\n$(echo\nE\nz", False),
    ("cat <<E\n$(echo\nE\nz", True),                      # unquoted: the body opens a construct that runs on
    ("case x in a) echo b;; esac\nz", False),                # `case` at the top level is plain; inside `$(` it is not
    ("echo $(case x in a) echo b;; esac)\nz", True),
    ("echo $(echo case x in a)\nz", True),                  # `case` anywhere in a substitution: a pattern's `)` could end it
    ("(\nf() case x in a) :;; esac\nz", True),             # both shells keep the subshell open after the pattern's `)`
    ("( case x in a) :;; esac\nz", True), ("a=(case x in a) b)\nz", True),
    ("(a); case x in b) :;; esac\nz", False),               # the subshell closed: `case` is plain again
    ("( echo case_x )\nz", False),                          # the word is `case_x`
])
def test_the_triggers_that_depend_on_context_have_a_near_miss_that_is_not_unknown(text, is_unknown):
    assert unknown(text) == is_unknown


@pytest.mark.parametrize("char", list("@!+*?"))
def test_every_extglob_character_makes_a_parenthesis_unknown_once_extglob_is_on(char):
    assert unknown(f"shopt -s extglob\nls {char}(a\nb)\nz")
    assert unknown(f"ls {char}(a\nb)\nz")
    assert unknown(f"ls {char}(a b) x\nz") is False and unknown(f"shopt -s extglob\nls {char}(a b) x\nz")


def test_the_command_that_holds_an_opener_is_the_same_after_a_construct_inside_a_backtick_substitution_closes():
    text = "Run `ssh h $(a) 'x\nbody\n` done"
    opener = line_states(text)[1].openers[-1]
    assert (opener.kind, text[opener.command_at:opener.offset + 1]) == ("SQ", "ssh h $(a) '")
    text = "Run `ssh h <(b) $((1)) 'x\nbody\n` done"
    opener = line_states(text)[1].openers[-1]
    assert text[opener.command_at:opener.offset + 1] == "ssh h <(b) $((1)) '"


def _holder(text: str, line: int = -1) -> str:
    """What the command that holds the innermost opener where line `line` begins says, up to and including the opener."""
    opener = line_states(text)[line].openers[-1]
    return text[opener.command_at:opener.offset + 1]


@pytest.mark.parametrize("middle", ["2>&1", ">&2", "<&0", ">&-", "3>&1", "1>&2", "&>out", "&>>out", ">|out"])
def test_a_redirection_with_an_ampersand_or_a_pipe_does_not_start_a_new_command(middle):
    text = f"ssh evil.example {middle} 'x\nbody"
    assert _holder(text) == f"ssh evil.example {middle} '"


@pytest.mark.parametrize("separator", ["&&", "||", ";", "|", "|&", "&"])
def test_a_separator_starts_a_new_command(separator):
    text = f"ssh evil.example {separator} echo 'x\nbody"
    assert _holder(text) == "echo '"


def test_the_separators_inside_a_parameter_expansion_start_nothing_and_the_command_is_the_same_after_it_closes():
    for inside in (";", "|", "&", "a;b", "#|", ":-&"):
        text = f"ssh evil.example ${{x{inside}}} 'x\nbody"
        assert _holder(text) == f"ssh evil.example ${{x{inside}}} '", inside


@pytest.mark.parametrize("text", [
    "echo ${x:-<<E }\nssh evil.example 'x\nE\nz",             # a word in a parameter expansion, not a here-document
    "echo ${x%<<E }\nssh evil.example 'x\nE\nz",
    'echo "${x:-<<E }"\nssh evil.example \'x\nE\nz',
])
def test_a_here_document_operator_inside_a_parameter_expansion_is_a_word(text):
    assert line_states(text)[-1].openers[-1].kind == "SQ"


def test_a_process_substitution_inside_a_parameter_expansion_is_still_one_after_a_here_string_operator():
    assert kinds('echo "${x:-<<<(}"\nz')[-1] == ("DQ", "PARAM", "PROC", "DQ")


@pytest.mark.parametrize("text,is_unknown", [
    ("ssh evil.example $( { case x in a) :;; esac; }\nz\n)", True),     # `case` anywhere in a substitution: a pattern's `)` could end it
    ("ssh evil.example $(! case x in a) :;; esac)\nz", True),
    ("ssh evil.example $(time case x in a) :;; esac)\nz", True),
    ("echo $[ ) ]\nz", True), ('echo "$[ ) ]"\nz', True),
    ("((x<<E))\nz", True), ("for ((i=1<<E ;;)) do :; done\nz", True), ("echo $((1<<3))\nz", False), ("echo ( (a) )\nz", False),
    ("echo $(cat <<E)\nz", True), ("echo <(cat <<E)\nz", True), ("echo $(cat <<E\nbody\nE\n)\nz", False),
])
def test_what_the_two_shells_do_not_agree_on_inside_a_substitution_is_unknown(text, is_unknown):
    assert unknown(text) == is_unknown


def test_unknown_goes_into_the_lines_of_a_backtick_body():
    states = line_states("ssh evil.example $'\\''\necho `\nbody\n`\n'")
    assert [s.unknown for s in states] == [False, True, True, True, True]


@pytest.mark.parametrize("text,is_unknown", [
    ("echo `ssh evil.example \\\\\\'\nbody\n'`\nz", True),         # three backslashes before a quote: the shell halves them first
    ("echo `ssh evil.example \\\\'\nbody\n'`\nz", True),
    ("echo `ssh evil.example \\\\$(a)`\nz", True),
    ("echo `echo \\\\n`\nz", False), ("echo `ssh evil.example \\'x\nbody\n'`\nz", False),
])
def test_a_run_of_backslashes_in_front_of_a_quote_in_a_backtick_body_is_unknown(text, is_unknown):
    assert unknown(text) == is_unknown


def test_a_here_document_with_a_dash_strips_tabs_and_nothing_else():
    assert kinds("cat <<-E\n\tE\nz") == [(), ("HEREDOC",), ()]
    assert kinds("cat <<-E\n  E\nz") == [(), ("HEREDOC",), ("HEREDOC",)]
    assert kinds("cat <<E\n\tE\nz") == [(), ("HEREDOC",), ("HEREDOC",)]


def test_a_tab_is_a_blank_between_words_and_in_front_of_a_here_document_word():
    assert _holder("ssh\tevil.example\t'x\nbody") == "ssh\tevil.example\t'"
    assert kinds("cat <<\tE\nbody\nE\nz") == [(), ("HEREDOC",), ("HEREDOC",), ()]


def test_a_hash_is_a_comment_only_where_a_command_is_read():
    assert kinds("echo ${a:- #'x'}\nz") == [(), ()]
    assert kinds("echo $((1 # ))\nz") == [(), ()]
    assert kinds("echo a #'x\nz") == [(), ()]


@pytest.mark.parametrize("delimiter", ["E#", "E}", "E=", "E-"])
def test_the_characters_that_end_no_here_document_word_are_part_of_it(delimiter):
    assert kinds(f"cat <<{delimiter}\nbody\n{delimiter}\nz") == [(), ("HEREDOC",), ("HEREDOC",), ()]


def test_a_run_of_backslashes_in_a_backtick_body_costs_the_same_per_character():
    """A pattern searched from every start inside a long run is quadratic; this one starts at the beginning of a run."""
    def cost(size: int) -> float:
        text = "`" + "\\" * size + "`x\n"
        started = time.process_time()
        line_states(text)
        return (time.process_time() - started) / len(text)
    small, large = min(cost(16_384) for _ in range(2)), min(cost(131_072) for _ in range(2))
    assert large < 3 * max(small, 2e-7), (small, large)


def test_here_documents_and_substitutions_on_one_line_cost_the_same_per_character():
    """Every `)` that closes a substitution asks whether a here-document is pending inside it."""
    def cost(size: int) -> float:
        text = "cat " + "<<E " * (size // 8) + "$(a) " * (size // 10) + "\n"
        started = time.process_time()
        line_states(text)
        return (time.process_time() - started) / len(text)
    small, large = min(cost(16_384) for _ in range(2)), min(cost(131_072) for _ in range(2))
    assert large < 3 * max(small, 2e-7), (small, large)


def test_a_workflow_expression_is_a_word_only_with_balanced_single_quotes_and_no_double_quote():
    assert unknown('echo ${{ a " b }}\nz')
    assert unknown('echo ${{ a "b" }}\nz')
    assert unknown("echo ${{ a ' b }}\nz")
    assert not unknown("echo ${{ a 'b' }}\nz")
    assert not unknown("echo ${{ format('{0}', a) }}\nz")
    assert unknown("echo ${{ \"'\" '}}' '\nz")
    assert unknown("echo ${{ 'a}}b' }}\nz")


def test_an_arithmetic_command_is_unknown_with_or_without_a_here_document_in_it():
    assert unknown("((a))\nz")
    assert unknown("for ((i=0;i<3;i++)); do :; done\nz")
    assert not unknown("echo $((1+2))\nz")


def test_a_hash_after_a_subshell_paren_starts_a_comment_and_after_a_substitution_does_not():
    assert not line_states("(a)#'z\nw")[-1].openers
    assert line_states("echo $(a)#'z\nw")[-1].openers
    assert line_states("x=(a)#'z\nw")[-1].openers                    # the paren that ends an array literal does not end its word


@pytest.mark.parametrize("text,is_unknown", [
    ("ssh evil.example $(ca\\\nse x in a) echo '\nz", True), ("echo $(c\\\nase x in a) :)\nz", True), ("[\\\n[ a =~ b ]]\nz", True),
    ("[[ a =\\\n~ b ]]\nz", True), ("(\\\n(a))\nz", True), ("ext\\\nglob\nz", True), ("extg\\\nlob\nz", True), ("echo ext\\\nra\nz", False), ("th\\\nen ((a))\nz", True), ("x=\\\n\\\n(a)#'z\nw", True), ("a=\\\n\\\n( [ )\nz", True), (">&-a[\nz", True), ("echo foo-a[1]\nz", False), ("a\\\n\\\n1a[1\nz", True), ("echo a\\\n\\\nb c\nz", False), ("a=\\\n( [ )\nz", True), ("x=\\\n(a)#'z\nw", True), ("for \\\n((;;)) :\nz", True), ("a\\\n1a[then >?echo ?\nz", True), ("a\\\n[1\nz", True), ("echo a\\\nb[1]\nz", True), ("echo a\\\nb c[1]\nz", False), ("echo a_\\\nb[1\nz", True), ("echo th\\\nen\nz", True), ("echo th\\\nere\nz", False), ("xxxxxxxxth\\\nen\nz", False), ("echo $(ab\\\ncd)\nz", True), ("echo a \\\nb\nz", False), ("echo a\\\n b\nz", False),
])
def test_a_word_split_by_a_line_continuation_hides_the_keywords_the_lexer_looks_for(text, is_unknown):
    assert unknown(text) == is_unknown


@pytest.mark.parametrize("text,is_unknown", [
    ("cat <<E\xa0x\nbody\nE\nz", False), ("cat <<E\x0bx\nbody\nE\x0bx\nz", False), ("cat <<- $E\n-\nx\n$E\nz", True),
])
def test_a_here_document_word_ends_at_a_blank_a_newline_or_an_operator_and_at_nothing_else(text, is_unknown):
    assert unknown(text) == is_unknown


def test_a_here_document_word_that_a_continuation_splits_is_read_whole_and_is_not_quoted():
    assert kinds("cat 3<<E\\\nF 2>&1\nx\\\nEF\nz")[-1] == ()
    assert unknown("cat <<E\\\nF\n$(echo\nEF\nz")


def test_the_text_of_an_unquoted_here_document_is_read_as_dash_reads_it_a_quote_is_a_character_only_at_its_top():
    assert not unknown('cat <<E\nsay "hi"\nE\nz')
    assert unknown('cat <<E\n$(echo ")\nE\nz')
    assert unknown('cat <<E\n${x:-"}\nE\nz')
    assert not unknown("cat <<'E'\n$(echo \")\nE\nz")


@pytest.mark.parametrize("text,is_unknown", [
    ("echo $(( ${x:-(} ))\nz", True), ("echo $(( ${x:-)} ))\nz", True), ("echo ${x:-(}\nz", False), ("echo $(( 1 <('(') ))\nz", True),
    ("echo $(( 1 <(${x:-(}) ))\nz", True), ("echo $(( $(echo \"a\") ))\nz", True), ("echo $(( (1) ))\nz", False),
])
def test_what_is_open_in_an_arithmetic_expansion_counts_below_the_innermost_construct_too(text, is_unknown):
    assert unknown(text) == is_unknown


@pytest.mark.parametrize("text,is_unknown", [
    ("a=( [1]=x )\nz", False), ("a=( [ )\nz", True), ("echo $(a[)\nz", True), ("a[1]=x\nz", False), ("2>&1 a[\nz", True), (">&2 a[1\nz", True), ("a=( x y )\nz", False), ("[ -f x ]\nz", False),
    ("echo [ x\nz", False), ("echo <((#'\n))\nz", True), ("echo <(a)\nz", False),
])
def test_an_assignment_subscript_that_a_bracket_leaves_open_and_a_double_paren_after_a_process_substitution_are_unknown(text, is_unknown):
    assert unknown(text) == is_unknown


@pytest.mark.parametrize("text,is_unknown", [
    ("( a[a[] )\nE\nz", True), ("a[a[1]]=x\nz", False), ("a[1]=x\nz", False), ("a=( [1]=x [2]=y )\nz", False), ("a=( [1 )\nz", True),
    ("echo a[\nz", True), ("[ -f x ]\nz", False),
])
def test_an_assignment_subscript_ends_at_its_matching_bracket(text, is_unknown):
    assert unknown(text) == is_unknown


@pytest.mark.parametrize("text,is_unknown", [
    ("echo $(a) case x in a) :;; esac\nz", False),              # `case` after the substitution closed is plain
    ("echo $(echo `case x in a) :;; esac`)\nz", True),         # a backtick body inside `$(` inherits the open substitution
    ("echo `\\\\'x`\nz", True),                                 # two backslashes at the very start of a backtick body
    ("[[ -f x ]]\nz", False), ("[[ a\n=~ b ]]\nz", True), ("extglob\n@(a\nb)\nz", True),
])
def test_the_flags_that_count_open_substitutions_and_words_read_start_at_the_right_place(text, is_unknown):
    assert unknown(text) == is_unknown


def test_the_command_in_a_substitution_in_double_quotes_begins_at_its_first_word_and_a_dollar_bracket_goes_on():
    assert _holder("echo \"$( ssh h 'x\nb") == "ssh h '"
    assert kinds('echo "$[ 1 ]"\nz') == [(), ()]
    assert unknown('echo "$[ 1 ]"\nz')


@pytest.mark.parametrize("text,is_unknown", [
    ('slugify(frontmatter["name"])\nz', False), ("see `x[i]` and y[0] here\nz", False), ("use arr[1\nz", True), ("x[\n1]=y\nz", True),
    ("`frontmatter[\"name\"]`\nz", False), ("[[ $(a[)) ]]\nz", True), ("a[1 + 2]=x\nz", False), ("a[$i]=x\nz", False), ("a[$(x)]=x\nz", True),
    ("a[${i}]=x\nz", True), ("a[x;y]\nz", True), ("a[(1+2)*3]=x\nz", True), ("a[it's]\nz", True), ("a[b[0]]=x\nz", False), ("a[b[c[0]]]=x\nz", True), ("a=( [1]=x [2]=y )\nz", False),
    ("a=( [1 )\nz", True), ("a=( [)] )\nz", True),
])
def test_a_subscript_that_closes_on_its_line_is_prose_and_one_that_runs_on_is_unknown(text, is_unknown):
    assert unknown(text) == is_unknown



@pytest.mark.parametrize("text,is_unknown", [
    ("((x<<E))\nz", True), ("a; ((x))\nz", True), ("a && ((x))\nz", True), ("if ((x)); then y; fi\nz", True), ("! ((x))\nz", True),
    ("f() ((x))\nz", True), ("a=((x))\nz", True), ("a=( (x))\nz", False), ("CHECK ((outcome = 'x'))\nz", False), ("see ((a) and (b))\nz", False),
    ("echo ((a))\nz", False), ("for ((i=0;i<3;i++)); do :; done\nz", True), ("for  ((i=0;;))\nz", True), ("x; for ((;;))\nz", True),
    ("xfor ((a))\nz", False), ("echo for ((a))\nz", True),
])
def test_a_double_paren_is_unknown_where_a_command_can_begin_and_prose_after_a_word_is_not(text, is_unknown):
    assert unknown(text) == is_unknown


@pytest.mark.parametrize("text,openers", [
    ("- [Digests](#digests)\nz", ()), ("slugify(frontmatter[\"name\"])\nz", ()), ("echo a(b\nz", ()), ("f() { :; }\nz", ()), ("f ( ) { :; }\nz", ()),
    ("case x in (a) :;; esac\nz", ()), ("echo (a\nz", ()), ("(a\nz", ("SUB",)), ("a; (b\nz", ("SUB",)), ("echo $(a(b\nz", ("CMD",)), ("a=(b\nz", ("ARRAY",)),
    ("coproc x (echo a)\nz", ()), ("coproc x (echo 'a\nz", ("SUB", "SQ")), ("$(coproc x (a)\nz", ("CMD",)), ("function f (echo a)\nz", ()),
    ("function f (echo $(a\nz", ("SUB", "CMD")), ("x function (a\nz", ()),
    ("echo a(it's\nz", ("SQ",)), ("a(\\\n", ("SUB",)), ("a(\\\n)\nz", ()), ("a( \\\nz", ("SUB",)), ("a(\nz", ()), ("(coproc x (a))\nz", ()), ("$(coproc }x (a)\nz", ("CMD",)), ("=$(coproc x (a)\nz", ("CMD",)), (":-$(function f (a)\nz", ("CMD",)), ("xcoproc x (a)\nz", ()), ("a_function f (a\nz", ()), ("coproc " + "n" * 30 + " (a\nz", ("SUB",)), ("coproc " + "n" * 20 + " (a\nz", ("SUB",)), ("$(function f (a)\nz", ("CMD",)), ("$(coproc \\\nx (a)\nz", ("CMD",)), ("coproc x\\\ny (a\nz", ("SUB",)), ("function\\\n f (a\nz", ("SUB",)),
])
def test_a_paren_that_follows_a_word_opens_nothing_and_one_that_begins_a_command_does(text, openers):
    assert tuple(o.kind for o in line_states(text)[-1].openers) == openers


def test_a_table_of_contents_does_not_pile_up_subshells():
    toc = "\n".join(f"- [Item {k}](#item-{k})" for k in range(100)) + "\nz"
    assert not unknown(toc) and not line_states(toc)[-1].openers


@pytest.mark.parametrize("text,is_unknown,openers", [
    ("echo ${a:'x'}\nz", True, ()), ("echo ${a:\"x\"}\nz", True, ()), ("echo ${a:1:2}\nz", False, ()), ("echo ${a:-'x'}\nz", False, ()),
    ("echo ${a: -1}\nz", False, ()), ("echo \"${a:'x'}\"\nz", True, ()),
    ("echo $(( 1 <($ {x:-(}) ))\nz", True, ()), ("echo $(( 1 <(2) ))\nz", False, ()), ("echo $(( $(cat <(a)) ))\nz", False, ()),
    ("echo $(( 1 >(2) ))\nz", False, ()), ("echo <(a\nz", False, ("PROC",)),
    ("if: ${{ github.ref <(== >'refs/heads/main' }}\nz", True, ("PARAM", "PROC")), ("if: ${{ github.run_number > 3 && a <= b }}\nz", False, ()),
    ("if: ${{ github.ref >(x }}\nz", True, ("PARAM", "PROC")),
])
def test_arithmetic_substring_offsets_process_substitution_in_arithmetic_and_workflow_expressions(text, is_unknown, openers):
    state = line_states(text)[-1]
    assert (state.unknown, tuple(o.kind for o in state.openers)) == (is_unknown, openers)


# ── pins for the lexer's newer rules (each is a mutation the other tests let survive) ─────────────────────────────

def _kinds(text, **kw):
    return [tuple(o.kind for o in s.openers) for s in line_states(text, **kw)]


def _command(text):
    """What the command that holds the innermost construct open at the end of `text` reads, up to the opener."""
    o = line_states(text)[-1].openers[-1]
    return o.kind, text[o.command_at:o.offset + 1]


@pytest.mark.parametrize("text,last", [
    ("case x in (a\nz", ("SUB",)), ("a" * 30 + " n (b\nz", ()), ("x" * 30 + "(a\nz", ()), ("a_coproc x (b\nz", ()), ("a(\\x\nz", ()),
    ("a( \\\n)\nz", ()), ("echo a>|f#'z\nw", ("SQ",)), ("echo a>&2#'z\nw", ("SQ",)), ("echo a 2>&1 #'z\nw", ()), ("cat <<<#'z\nw", ("SQ",)),
    ("cat <<<a#'z\nw", ("SQ",)), ("cat <<E#'z\nE\nw", ("SQ",)), ("echo ${x%%(#'z}\nw", ("PARAM", "SQ")), ("echo $((1<<2))#'z\nw", ("SQ",)),
])
def test_where_a_paren_follows_a_word_and_where_a_hash_begins_a_comment(text, last):
    assert _kinds(text)[-1] == last


@pytest.mark.parametrize("text,is_unknown", [
    ("é\\\na[1]\nz", False), ("\\\nb[1]\nz", False), ("t\\\nhen ((a))\nz", True), ("the\\\nn ((a))\nz", True), ("extglo\\\nb\nz", True),
    ("e\\\nxtglob\nz", True), ("echo [\\\n[ a ]]\nz", True), ("echo =\\\n~ b\nz", True), ("echo \"$\\\n(a)\"\nz", True), ("echo \"$(\\\na)\"\nz", True),
    ("echo \"$\\\nx\"\nz", True), ("echo $\\\n(a)\nz", True), ("echo $(\\\na)\nz", True),
])
def test_a_line_continuation_that_joins_the_halves_of_a_word_the_lexer_reads_is_unknown(text, is_unknown):
    assert line_states(text)[-1].unknown is is_unknown


def test_the_command_that_holds_a_construct_begins_at_its_first_word_after_each_kind_of_opener():
    assert _command("echo $(ssh h '\nz") == ("SQ", "ssh h '")
    assert _command("echo <(ssh h '\nz") == ("SQ", "ssh h '")
    assert _command("case x in a) ssh h '\nz") == ("SQ", "ssh h '")
    assert _command("{ ssh h '\nz") == ("SQ", "ssh h '")
    assert _command("f() { ssh h '\nz") == ("SQ", "ssh h '")
    assert _command("ssh evil.example { '\nz") == ("SQ", "ssh evil.example { '")          # a brace in argument position is a word
    assert _command("docker run x sh{ -c '\nz") == ("SQ", "docker run x sh{ -c '")


def test_a_pending_here_document_before_a_substitution_does_not_hide_one_opened_inside_it():
    assert line_states("cat <<A $(cat <<B)\nz")[-1].unknown
    assert line_states("case x in a) :;; esac)\nz", start=(Opener("CMD", 0, 0),))[-1].unknown


def test_the_lines_on_which_constructs_closed_are_recorded_for_the_caller():
    assert [(line, o.kind) for line, o in line_states("cat <<E\nx\nE\ny").closed] == [(2, "HEREDOC")]
    assert [(line, o.kind) for line, o in line_states("a'\nb", start=(Opener("SQ", 0, 0),)).closed] == [(0, "SQ")]


def test_a_workflow_expression_ends_where_its_double_braces_close_and_not_at_a_double_quote():
    from diff_sentry.shelllex import _expression_end
    assert _expression_end("${{ a }}", 0) == 8
    assert _expression_end('${{ "x" }}', 0) == -1
    assert _expression_end("x ${{ a }} y", 2) == 10


@pytest.mark.parametrize("text,unknown_flags,open_at_end,closed", [
    # texts on which a one-character change to one of the lexer's rules was seen: the unknown flag at the start of each line (T or F), the
    # constructs open at the end as (kind, offset, where their command began), and the constructs that closed as (line, kind, offset, where their
    # command began)
    ('a=\\\na[\n', 'FFT', (), []),
    ('extglob\\\n@(a\nb)\nz\n', 'FFTTT', (), [(2, 'SUB', 10, 0)]),
    ('\\\nextglob\n@(a\n]b)\nz\n', 'FFFTTT', (), [(3, 'SUB', 11, 10)]),
    ('echo "${a:"x"}\nz\n', 'FTT', (('DQ', 5, 0),), []),
    ('2><<E&1`\n', 'FF', (('BQ', 7, 6), ('HEREDOC', 2, 0)), []),
    ('<<[[ `E \n', 'FF', (('BQ', 5, 0), ('HEREDOC', 0, 0)), []),
    ('(a()\nz\n', 'FFF', (('SUB', 0, 0),), []),
    ('echoa_\\\n[1\nz\n', 'FTTT', (), []),
    ('$( (\n', 'FF', (('CMD', 0, 0), ('SUB', 3, 3)), []),
    ('$(\t(\n', 'FF', (('CMD', 0, 0), ('SUB', 3, 3)), []),
    ('<<Ecoproc a (\n', 'FF', (('HEREDOC', 0, 0),), []),
    ('?xcoproc x (a\n)z\n', 'FFF', (), []),
    ('>&#-a[\nz\n', 'FTT', (), []),
    ('echo 1"$[" ) ]"\nz\n', 'FTT', (('DQ', 14, 13),), []),
    ("cat a<<#i's\nb\n", 'FTT', (('SQ', 9, 0),), []),
    ('a$[(\n', 'FT', (('SUB', 3, 0),), []),
    ("<( '\n", 'FF', (('PROC', 0, 0), ('SQ', 3, 3)), []),
    ('<(E\\\nE\n', 'FTT', (('PROC', 0, 0),), []),
    ('$(E\\\nE\n', 'FTT', (('CMD', 0, 0),), []),
    ('<<\n', 'FT', (), []),
    ("<<'\n", 'FT', (('SQ', 2, 0),), []),
    ("echo $( ssh h '\nz", 'FF', (('CMD', 5, 0), ('SQ', 14, 8)), []),
    ("echo <( ssh h '\nz", 'FF', (('PROC', 5, 0), ('SQ', 14, 8)), []),
    ('shopt -s \\\nextglob\n@(a\nb)\nc\n', 'FFFTTT', (), [(3, 'SUB', 20, 19)]),
    ('echo x; cat <<E\nbody\nE', 'FFF', (('HEREDOC', 12, 8),), [(2, 'HEREDOC', 12, 8)]),
    ("()a#'z\nw\n", 'FFF', (('SQ', 4, 0),), []),
    ("()x=#'z\nw\n", 'FFF', (('SQ', 5, 0),), []),
    (' ( ) <<E{ :; }\nz\n', 'FFF', (('HEREDOC', 5, 1),), []),
    ('ffunction\\\n f (a\nz\n', 'FFFF', (), []),                                   # `ffunction` is no keyword: the word is read whole
    ('coproc"$( a (\n', 'FT', (('DQ', 6, 6), ('CMD', 7, 6)), []),
    ("for 'ssh' h '\n", 'FF', (('SQ', 12, 10),), []),
    ('(()x<<E))z\n\n', 'FTT', (('HEREDOC', 4, 1),), []),
    ('(()x<<E))\nz\n', 'FTT', (('HEREDOC', 4, 1),), []),
    ('() { :a=(; }\nz\n', 'FFF', (('ARRAY', 8, 5),), []),
    ('() { a=(a; }\nz\n', 'FFF', (('ARRAY', 7, 5),), []),
    ('((x<<`E(())\nz\n', 'FTT', (('SUB', 0, 0), ('SUB', 1, 1), ('BQ', 5, 2)), []),
    ("ech`o $a() h 'x\n", 'FF', (('BQ', 3, 0), ('SQ', 13, 11)), []),
    ('a\\\n(\n', 'FFF', (), []),
    ('a\\\n (\n', 'FFF', (), []),
    ('in (\n', 'FF', (('SUB', 3, 0),), []),
    ('in (a\n\n', 'FFF', (('SUB', 3, 0),), []),
    ('-- [I"tem \n', 'FF', (('DQ', 5, 0),), []),
    ('-- [Item<<-E \n', 'FF', (('HEREDOC', 8, 0),), []),
    ('aa coproc x (\n', 'FF', (('SUB', 12, 0),), []),
    ('in coproc a (\n', 'FF', (('SUB', 12, 0),), []),
    ('for (\n', 'FF', (), []),
    ('for( (\n', 'FF', (('SUB', 5, 0),), []),
    ('=a\\\n(\n', 'FFF', (), []),
    ("Run `ssh h $?(a) 'x\nbody\n` done\n", 'FFFF', (), [(2, 'BQ', 4, 0)]),
    ("Run `ssh h @(a) <(b) $((1)) 'x\nbody\n`done\n", 'FFFF', (), [(2, 'BQ', 4, 0)]),
    ("?()a#'z\nw\n", 'FFF', (('SQ', 5, 3),), []),
    ('f() ((x)\nz\n', 'FTT', (('SUB', 4, 4),), []),
    ('=\\\n(\n', 'FTT', (('SUB', 3, 0),), []),
    ('<\\\n(\n', 'FTT', (('SUB', 3, 0),), []),
    ("ssh h $@(a) '\n", 'FF', (('SQ', 12, 0),), []),
    ("ssh h$ ?(a) '\n", 'FF', (('SQ', 12, 0),), []),
    # the states of the shortest texts on which a mutant of one of the lexer's tables, sets or classes (a set element, a character of a regular expression or of a
    # string) read differently
    ('$\\\n(\n', 'FTT', (('SUB', 3, 0),), []),
    ('>\\\n(\n', 'FTT', (('SUB', 3, 0),), []),
    ('$($${(a', 'F', (), []),
    ('>&(\n', 'FF', (('SUB', 2, 0),), []),
    ('()((', 'F', (), []),
    ('<()""(<', 'F', (), []),
    ('\nfor((', 'FF', (), []),
    ('>(`<<E\nE)', 'FF', (('PROC', 0, 0), ('BQ', 2, 2), ('HEREDOC', 3, 3)), []),
    ('[[~', 'F', (), []),
    ('<<"`"', 'T', (('HEREDOC', 0, 0),), []),
    ("<<'''", 'F', (), []),
    ('<<t', 'F', (('HEREDOC', 0, 0),), []),
    ('<<;', 'F', (), []),
    ('<<|', 'F', (), []),
    ('<<EOF<\nEOF\n', 'FFF', (), [(1, 'HEREDOC', 0, 0)]),
    ('<<(', 'F', (), []),
    ('<<>', 'F', (), []),
    ('1a[', 'F', (), []),
    ('${x:+"', 'F', (), []),
    ("''${x: \\", 'F', (), []),
    ('${x:\n`', 'FF', (('PARAM', 0, 0),), []),
    ('${x: }"', 'F', (), []),
    ('${x:sh evil.example 2>&1 `', 'F', (), []),
    ('${x#', 'F', (), []),
    ('${x%', 'F', (), []),
    ('${A_}', 'F', (), []),
    ('${!=', 'F', (), []),
    ('${x+', 'F', (), []),
    ('${#-', 'F', (), []),
    ('${#?', 'F', (), []),
    ('${${{}}}\n', 'FT', (), []),
    ('(in(\n', 'FF', (('SUB', 0, 0), ('SUB', 3, 1)), []),
    ('function\tf\tp(\n', 'FF', (), []),
    ('coproc\tx\tc(\n', 'FF', (), []),
    ('<<"\\`"\n`\n', 'FTT', (), [(1, 'HEREDOC', 0, 0)]),
    ('<<\'E"OF\'\nEOF\n', 'FFF', (('HEREDOC', 0, 0),), []),
    ("<<''\\\n\n\n", 'FFFF', (), [(2, 'HEREDOC', 0, 0)]),
    ('<<"\\"\n"\n', 'FTT', (), [(1, 'HEREDOC', 0, 0)]),
    ('<<"EOF\'"\nEOF\n', 'FFF', (('HEREDOC', 0, 0),), []),
    ("<<E'a'\nEa\n", 'FFF', (), [(1, 'HEREDOC', 0, 0)]),
    ('<<"EO\\F"\nEOF\n', 'FTT', (('HEREDOC', 0, 0),), []),
])
def test_the_state_at_the_end_of_texts_a_small_change_to_a_rule_would_read_differently(text, unknown_flags, open_at_end, closed):
    lexed = line_states(text)
    assert ("".join("T" if s.unknown else "F" for s in lexed), tuple((o.kind, o.offset, o.command_at) for o in lexed[-1].openers),
            [(line, o.kind, o.offset, o.command_at) for line, o in lexed.closed]) == (unknown_flags, open_at_end, closed)


@pytest.mark.parametrize("text", [
    # a `(` that begins a command after `time -p`, the NAME of function/coproc/for/select, or the empty `()` of a function: the substitution stays open
    "echo $(for x do (true)\n", "echo $(select x do (true); done\n", "echo $(time -p (true)\n", "echo $(time -- (true)\n",
    "echo $(function x while (true); do :; done\n", "echo $(coproc x if (true); then :; fi\n", "echo $(f() while (true); do break; done\n",
    "echo $(f() if (true); then :; fi\n",
])
def test_a_paren_after_the_name_of_a_compound_command_or_the_options_of_time_begins_a_command(text):
    assert tuple(o.kind for o in line_states(text)[-1].openers) == ("CMD",), text


@pytest.mark.parametrize("text", ["function f$@ ((#'x\n))\nz", "function f# ((#'x\n))\nz", "function f$a ((#'x\n))\nz", "coproc x$y ((#'x\n))\nz", "function } ((#'x\n))\nz", "function $x ((#'x\n))\nz", "select \"a\" do ((#'x\nz",
                                  "for x$y do ((#'x\nz", "time -- ((#'x\n1) ))\nz", "for x do ((#'x\nz", "select x do ((#'x\nz", "function f ((#'x\n))\nz", "time -p ((#'x\nz"])
def test_a_double_paren_after_the_same_words_is_an_arithmetic_command(text):
    assert line_states(text)[-1].unknown, text


@pytest.mark.parametrize("bullet", [
    "- Fix `thing` (#@@)", "- **bold** (#@@)", "- *em* (#@@)", '- "q" (#@@)', "- 'q' (#@@)", "- {x} (#@@)", "- x? (#@@)", "- x% (#@@)",
    "- x~ (#@@)", "- \u2728 (#@@)", "- [a](#a) (#@@)", "- x} (#@@)",
])
def test_a_paren_after_anything_but_an_operator_or_an_opener_opens_nothing(bullet):
    text = "\n".join(bullet.replace("@@", str(i)) for i in range(30)) + "\nz"
    assert not line_states(text)[-1].unknown and not line_states(text)[-1].openers, bullet


@pytest.mark.parametrize("text,unknown", [
    ("echo $(a (b)\nz", True), ("echo `a (b)`\nz", False), ("a (b)\nz", False), ("echo \"$(a (b)\"\nz", True),
])
def test_a_stray_paren_inside_a_substitution_fails_closed(text, unknown):
    assert line_states(text)[-1].unknown is unknown


@pytest.mark.parametrize("name", ["1", "12", "@", "*", "#", "?", "$", "!", "-", "a"])
def test_a_quote_after_the_colon_of_any_parameter_is_unknown(name):
    assert line_states("echo ${" + name + ":'x'}\nz")[-1].unknown
    assert not line_states("echo ${" + name + ":-'x'}\nz")[-1].unknown


def test_a_hash_is_an_ordinary_character_where_the_shell_reads_no_comments():
    text = "docker run evil/img sh -c # '\nz\n"
    assert not line_states(text)[-1].openers
    assert [o.kind for o in line_states(text, comments=False)[-1].openers] == ["SQ"]
    inner = "echo `a # '`\nz\n"                                         # the body of a backtick substitution follows the option
    assert not line_states(inner)[-1].openers


@pytest.mark.parametrize("keyword", ["do", "else", "elif", "while", "until", "time", "coproc", "if", "then", "!"])
def test_a_double_paren_after_a_word_that_a_command_follows_is_an_arithmetic_command(keyword):
    assert line_states(f"{keyword} ((1))\nz")[-1].unknown, keyword
    assert not line_states("fi ((1))\nz")[-1].unknown


@pytest.mark.parametrize("text,is_unknown", [
    ("ARR[$(x)]=1\nz", True), ("FOO[1\nz", True), ("a1[1\nz", True), ("A1[x]=1\nz", False), ("ab[1]=1\nz", False),
    ("a[x|y]=1\nz", True), ("a[x&y]=1\nz", True), ("a[x<y]=1\nz", True), ("a[x>y]=1\nz", True), ("a[x`y`]=1\nz", True), ("a[x\\y]=1\nz", True),
    ("a[x#y]=1\nz", True), ("a[x(y]=1\nz", True), ("a[x;y]=1\nz", True),
    ("echo ${a:}1\nz", True), ("echo ${1:}\nz", True), ("echo ${a:-}1\nz", False), ("time -- {((#'x\n1) )\nz", True), ("{(true); }\nz", False),
    ("{ ((1)); }\nz", True),
    ("time -- {\\\n((#'x\n1) )\nz", True), ("echo ${{ x }<<-E}}\nz", True), ("echo ${{ a <= b }}\nz", False), ("echo ${{ x }<<<y}}\nz", True),
    ("echo ${1:-'x'}\nz", False), ("echo ${VAR:'x'}\nz", True), ("echo ${!a:'x'}\nz", True), ("echo ${A9:\"x\"}\nz", True), ("echo ${a:1}\nz", False),
    ("echo \"${{ x }}\"\nz", False), ("echo ${{ x }}\nz", False),
    ("x \u65e5th\\\nen y\nz", True), ("x my_th\\\nen y\nz", False), ("x 9th\\\nen y\nz", False),
    ("echo <(case x in a) :;; esac)\nz", True),
])
def test_the_unknown_flag_of_the_subscript_expression_substring_and_split_word_rules(text, is_unknown):
    assert line_states(text)[-1].unknown is is_unknown, text


@pytest.mark.parametrize("text,openers", [
    ("a.(b\nz", ()), ("key:(v\nz", ()), ("a,(b\nz", ()), ("a_(b\nz", ()), ("a-(b\nz", ()), ("a/(b\nz", ()), ("a](b\nz", ()), ("a1(b\nz", ()),
    ("coproc x;y(cmd\nz", ()), ("coproc\tx\t(cmd\nz", ("SUB",)), ("coproc x\t(cmd\nz", ("SUB",)), ("function\tf\t(cmd\nz", ("SUB",)),
    ("coprocx (cmd\nz", ()), ("a=(b c)\nz", ()), ("echo <(a\nz", ("PROC",)),
])
def test_what_a_paren_after_each_kind_of_word_opens(text, openers):
    assert tuple(o.kind for o in line_states(text)[-1].openers) == openers, text


def test_an_array_literal_is_open_until_its_paren_closes():
    assert [tuple(o.kind for o in s.openers) for s in line_states("a=(b\nc)\nz")] == [(), ("ARRAY",), ()]


@pytest.mark.parametrize("text,openers", [
    ("Run `ssh h $?(a) 'x\nbody\n` done\n", [("BQ", 4, 0), ("SQ", 17, 5)]),
    ("Run `ssh h @(a) <(b) $((1)) 'x\nbody\n`done\n", [("BQ", 4, 0), ("SQ", 28, 5)]),
    ("echo `f() (true) ssh h 'x\nbody\n` done\n", [("BQ", 5, 0), ("SQ", 23, 10)]),
])
def test_the_command_that_holds_a_string_in_a_backtick_body_is_counted_from_the_start_of_the_text(text, openers):
    assert [(o.kind, o.offset, o.command_at) for o in line_states(text)[1].openers] == openers



@pytest.mark.parametrize("text,states", [
    ("case x in a)# it's\n ssh h '\n", [(), (), ("SQ",)]),
    ("case x in a) # it's\n ssh h '\n", [(), (), ("SQ",)]),
    ("case x in a)#'\n b)#'\n", [(), (), ()]),
    ("x=`case x in a)# it's\n ssh h '\n` y\n", [(), ("BQ",), ("BQ", "SQ"), ()]),
    ("(a)#'z\nb", [(), ()]),
    ("a=(b)#'z\nb", [(), ("SQ",)]),
])
def test_a_hash_after_the_paren_that_ends_a_case_pattern_starts_a_comment(text, states):
    assert [tuple(o.kind for o in st.openers) for st in line_states(text)] == states, text


def _commands(text, line=1):
    return [(o.kind, text[o.command_at:o.offset + 1]) for o in line_states(text)[line].openers]


@pytest.mark.parametrize("text,expected", [
    ("coproc ssh h '\nx\n", [("SQ", "ssh h '")]), ("coproc docker run x sh -c '\nx\n", [("SQ", "docker run x sh -c '")]),
    ("coproc x { ssh h '\nx\n", [("SQ", "ssh h '")]), ("coproc x if true; then ssh h '\nx\n", [("SQ", "ssh h '")]),
    ("coproc x (ssh h '\nx\n", [("SUB", "("), ("SQ", "ssh h '")]), ("coproc 'ssh' evil '\nx\n", [("SQ", "'ssh' evil '")]),
    ("coproc $x ssh h '\nx\n", [("SQ", "$x ssh h '")]), ("function f ssh h '\nx\n", [("SQ", "ssh h '")]),
    ("for x in a; do ssh h '\nx\n", [("SQ", "ssh h '")]),
    ("x=`case x in x) ssh h '\ncurl\n';; esac`\n", [("BQ", "x=`"), ("SQ", "ssh h '")]),
    ("x=`case x in x) sudo -u root ssh h '\ncurl\n';; esac`\n", [("BQ", "x=`"), ("SQ", "sudo -u root ssh h '")]),
    ("ssh h (a) 'x\ny\n", [("SQ", "'")]),                                # a stray paren is a syntax error: the command it ends is no longer the one
    ("Run `ssh h <(b) $((1)) 'x\nbody\n` done", [("BQ", "Run `"), ("SQ", "ssh h <(b) $((1)) '")]),
])
def test_the_command_that_holds_an_opener_follows_the_name_of_a_coproc_a_case_pattern_and_a_stray_paren(text, expected):
    assert _commands(text) == expected, text


def test_a_coproc_name_is_no_command_of_its_own_when_a_line_ends_after_it():
    assert _commands("coproc x\nssh h '\nx\n", 2) == [("SQ", "ssh h '")]


@pytest.mark.parametrize("text", [
    "x=1 && ssh h 'a b' # c d\n", "eval \"x=1 && ssh evil '\n", "echo `ssh h 'x` && ssh h '\n", "echo '`' && ssh evil.example -o 'A=`' '\n",
    "' && ssh evil.example '\n", "a=(b c) $(d) ${e} <(f) $'g' \"h\" `i`\n", "cat <<E | ssh h\nbody\nE\n", "x=$(a\nb)\n# c\n", "echo $((1)) $[2]\n",
    "case x in a)# it's\n ssh h '\n", "f() { a[1]=x; }\n", "echo ${x:-`a b`} # c\n",
])
def test_asking_where_offsets_stand_changes_nothing_about_the_states(text):
    plain = line_states(text)
    probed = line_states(text, probes=tuple(range(len(text) + 2)))
    assert list(probed) == list(plain) and probed.closed == plain.closed and probed.unknown_at_end == plain.unknown_at_end
    assert set(probed.probed) == set(range(len(text) + 2))


def test_a_probe_says_what_is_open_where_the_simple_command_began_and_whether_a_comment_holds_the_offset():
    text = "x=1 && ssh h 'a b' # c d\n"
    got = line_states(text, probes=(text.index("&&"), text.index("ssh"), text.index("a b"), text.index("c d"))).probed
    assert got[text.index("ssh")] == Probe((), text.index("ssh"), -1, False)
    assert got[text.index("a b")] == Probe((Opener("SQ", text.index("'"), text.index("ssh")),), text.index("ssh"), -1, False)
    assert got[text.index("c d")] == Probe((), text.index("ssh"), text.index("#"), False)
    assert got[text.index("&&")].command_at == 0


def test_a_probe_inside_a_backtick_body_sees_the_body_and_the_opener_of_the_substitution():
    text = "echo `ssh h 'x` && ssh h '\n"
    got = line_states(text, probes=(text.index("ssh"), text.rindex("ssh"))).probed
    assert [(o.kind, o.offset) for o in got[text.index("ssh")].openers] == [("BQ", 5)]
    assert got[text.index("ssh")].command_at == text.index("ssh")
    assert got[text.rindex("ssh")].openers == () and got[text.rindex("ssh")].command_at == text.rindex("ssh")


def test_a_probe_in_a_string_sees_the_string_and_one_after_the_string_does_not():
    text = "eval \"x=1 && ssh evil '\"\n"
    got = line_states(text, probes=(text.index("x=1"), text.index("ssh"), len(text) - 1)).probed
    assert [o.kind for o in got[text.index("ssh")].openers] == ["DQ"] and [o.kind for o in got[text.index("x=1")].openers] == ["DQ"]
    assert got[len(text) - 1].openers == ()


def test_a_probe_remembers_that_something_undecided_was_read_before_it():
    text = "echo ${a:'x'} ssh\n"
    assert line_states(text, probes=(text.index("ssh"), 0)).probed[text.index("ssh")].unknown is True
    assert line_states(text, probes=(0,)).probed[0].unknown is False


@pytest.mark.parametrize("text,flags", [
    ("The type is `list[str | Enum]` here.\nz", [False, False]), ("Use `${ cmd; }` for it.\nz", [False, False]), ("`a[1; b` x\nz\n", [False, False, False]),
    ("`a[1\nb` x\nz\n", [False, True, False, False]),                                   # its own lines are undecided; the text after it is not
    ("`a[1\nb\nz", [False, True, True]),                                          # never closed: the rest of the text is the body
    ("`echo $'a\\'b'` x\nz", [False, True]), ('`a["k"` x\nz', [False, True]),           # a quote in the body: where the shells cut it is not counted here
    ("echo \"`a[1; b`\"\nz", [False, True]), ("echo $(`a[1; b`)\nz", [False, True]),     # inside another construct the flag travels
    ("`a\\`b[1` x\nz", [False, True]),                                            # a nested substitution: another level of backslash quoting
])
def test_what_a_closed_backtick_body_leaves_undecided_is_undecided_for_its_own_lines_when_nothing_else_is_open_or_quoted(text, flags):
    assert [state.unknown for state in line_states(text)] == flags, text


@pytest.mark.parametrize("text", [
    'cat <<E "$(a\nE\n)"\nz', 'cat <<E "x$(a\nE\n)y"\nz', 'cat <<E $"$(a\nE\n)"\nz', 'cat <<E | "$(a\nE\n)" b\nz', 'ssh h <<E "$(a\nE\n)"\nz',
    'cat <<-E >f "$(a\nE\n)"\nz', 'f() { cat <<E "$(a\nE\n)"\nz', "cat <<'E' \"$(a\nE\n)\"\nz",
])
def test_a_substitution_in_double_quotes_on_the_line_of_a_here_document_leaves_the_text_undecided(text):
    """bash reads the body after the whole command, dash and bash both feed the lines to its stdin: the substitution may swallow the delimiter."""
    assert line_states(text)[-1].unknown, text


@pytest.mark.parametrize("text", [
    "echo ${ab:}\nz", "echo ${a1:}\nz", "echo ${_:}\nz", "echo ${A_B:}\nz", "echo ${name:'x'}\nz", "echo ${x:'-a'}\nz", "echo ${a:\\x}\nz", "echo ${a:`b`}\nz",
    "echo ${9:'x'}\nz", "echo ${@:'x'}\nz", "echo ${#a:}\nz", "echo ${!a:}\nz",
])
def test_the_substring_offset_that_dash_reads_as_a_string_is_undecided_whatever_the_name(text):
    assert line_states(text)[-1].unknown, text


@pytest.mark.parametrize("text", ["echo ${a:1}\nz", "echo ${a:-}\nz", "echo ${ab:1:2}\nz", "echo ${a:-'x'}\nz", "echo ${_:-x}\nz"])
def test_a_substring_offset_without_a_quote_and_a_default_value_are_decided(text):
    assert not line_states(text)[-1].unknown, text


@pytest.mark.parametrize("text", ["A_B[&\nz", "_[\nz", "MY_VAR[1\nz", "a_b[1\nz", "a1[1\nz", "_a[1\nz", "x=1 a_b[1\nz", "A9_[x\nz"])
def test_the_name_of_an_assignment_subscript_may_hold_underscores_and_digits(text):
    assert line_states(text)[-1].unknown, text


@pytest.mark.parametrize("text,kinds", [
    ("echo ${{ a`b }}\nz", ["PARAM", "BQ"]), ("echo ${{ 'a'b' }}\nz", ["PARAM", "SQ"]), ("echo ${{ a }}\nz", []), ("echo ${{ 'a' }}\nz", []),
    ("echo ${{ a == 'b' }}\nz", []), ("echo ${{ a <(b }}\nz", ["PARAM", "PROC"]),
])
def test_a_workflow_expression_is_a_word_only_when_nothing_in_it_opens_a_construct(text, kinds):
    assert [o.kind for o in line_states(text)[-1].openers] == kinds, text


@pytest.mark.parametrize("text,kinds", [
    ("cat <<-\\\n E\nx\nE\nz\n", [(), (), ("HEREDOC",), ("HEREDOC",), (), ()]),                     # a continuation and a blank in front of the delimiter are skipped
    ("cat <<-  \\\n  \\\n 'E'\nx\nE\nz", [(), (), (), ("HEREDOC",), ("HEREDOC",), ()]),
    ("cat <<-E\\\nF\nx\nEF\nz", [(), (), ("HEREDOC",), ("HEREDOC",), ()]),                         # one inside the delimiter joins its halves
])
def test_a_line_continuation_in_front_of_or_inside_the_word_of_a_here_document_joins_what_it_cuts(text, kinds):
    assert [tuple(o.kind for o in s.openers) for s in line_states(text)] == kinds


@pytest.mark.parametrize("text", ["cat <<-\\\n $E-\n\nx\n$E\nz\n", "cat <<\\\n\nx\n", "cat <<-\\\n\n"])
def test_a_delimiter_that_a_continuation_leads_to_and_that_expands_is_undecided(text):
    assert line_states(text)[-1].unknown, text


@pytest.mark.parametrize("text,last", [
    ("f(\\\n) until (\n", ("SUB",)), ("f(\\\n)\n(\n", ("SUB",)), ("[[ a == @\\\n(b|c\n", ("SUB",)), ("[[ a == !\\\n(b|c\n", ("SUB",)), ("[[ a == @(b|c) ]]\nz\n", ()),
])
def test_the_empty_parens_of_a_function_and_the_paren_of_an_extended_glob_join_across_a_continuation(text, last):
    assert tuple(o.kind for o in line_states(text)[-1].openers) == last, text


@pytest.mark.parametrize("text", [
    "x=$(cat <<E\nbody\nE); echo hi\nmore\nE\n)\nz", "x=$(<f<< \\E\nb\nE); do(\nx\nE\n)\n", "echo >(cat <<-E\n\tb\n\tE) x\nE\nz", "x=$(cat <<E\nb\nE)\nz",
    "x=$(cat <<E\nEO))F\nE1\nE\n])\nz\n", "x=$(cat <<E\nbody\nEE); echo hi\nmore\nE\n)\nz\n", "x=$(cat <<E\nE1)\nE\n)\nz\n",
])
def test_a_line_that_begins_with_the_delimiter_inside_a_substitution_is_undecided(text):
    """bash takes `E)` for the delimiter and the end of the substitution; dash reads the body on."""
    assert line_states(text).unknown_at_end, text


@pytest.mark.parametrize("text", [
    "x=$(cat <<E\nbody\nE\n)\nz", "x=$(cat <<-E\n\tbody\n\tE\n)\nz", "x=$(cat <<E\nEOF\nE1\nE\n)\nz", "cat <<E\nE)\nE\nz", "x=$(cat <<E\nEx\nE\n)\nz", "x=$(cat <<E\nb))\nE\n)\nz", "x=$(cat <<E\nb\nE `a`\nE\n)\nz", "x=$(cat <<E\nb\nE x\nE\n)\nz", "x=$(cat <<E\nb\nE;\nE\n)\nz", "x=$(cat <<E\na) b\nE\n)\nz", "x=$(cat <<E\n)\nE\n)\nz",
])
def test_a_body_line_that_only_looks_like_the_delimiter_decides_nothing(text):
    assert not line_states(text).unknown_at_end, text


@pytest.mark.parametrize("text", ["for \\\n f do (x\n", "for \\\n f\tdo (x\n", "for \\\n f\tdo \\\n (functio\\\n", "select \\\n f do (x\n", "function \\\n f (x\n", "coproc \\\n f (x\n"])
def test_a_line_continuation_between_a_keyword_and_its_name_is_no_name(text):
    assert [o.kind for o in line_states(text)[-1].openers] == ["SUB"], text


def test_the_lines_that_begin_in_the_same_state_share_one_state_object():
    states = line_states("a\nb\nc\n")
    assert states[0] is states[1] is states[2] is states[3]


def _at(text, start=(), *offsets):
    got = line_states(text, start=tuple(Opener(kind, 0, 0) for kind in start), probes=offsets).probed
    return {p: ([o.kind for o in got[p].openers], got[p].command_at, got[p].comment_at, got[p].unknown) for p in offsets}


@pytest.mark.parametrize("text,start,expected", [
    # the command before the first command word of a text, of a line and of a run of blanks begins at the offset the text begins at
    ("\nbody\n", (), {0: ([], 0, -1, False), 1: ([], 1, -1, False), 5: ([], 1, -1, False)}),
    ("  ssh h 'x", (), {0: ([], 0, -1, False), 1: ([], 0, -1, False), 2: ([], 2, -1, False), 8: ([], 2, -1, False), 9: (["SQ"], 2, -1, False)}),
    # a string stays open up to its closing quote and is closed right after it
    ("$'a' b", (), {2: (["ANSI"], 0, -1, False), 3: (["ANSI"], 0, -1, False), 4: ([], 0, -1, False)}),
    ('"E\\"F"', (), {4: (["DQ"], 0, -1, False), 5: (["DQ"], 0, -1, False), 6: ([], 0, -1, False)}),
    ("  ssh h 'x", ("SQ",), {7: (["SQ"], 0, -1, False), 8: (["SQ"], 0, -1, False), 9: ([], 9, -1, False)}),
    ("' && ssh evil.example '\n", ("SQ",), {0: (["SQ"], 0, -1, False), 1: ([], 0, -1, False), 5: ([], 5, -1, False), 23: (["SQ"], 5, -1, False)}),
    # a comment holds the offsets from its `#` up to the newline that ends it, and the newline is no part of it
    (" #'z\nw", (), {1: ([], 1, 1, False), 3: ([], 1, 1, False), 4: ([], 1, -1, False), 5: ([], 5, -1, False)}),
    ('- "q" (#@@)', (), {6: ([], 0, -1, False), 7: ([], 0, 7, False), 10: ([], 0, 7, False)}),
    # a line continuation inside `$(` is undecided from its backslash on, and a word is judged before the continuation that follows it
    ("$(E\\\nE\n", (), {2: (["CMD"], 2, -1, False), 3: (["CMD"], 2, -1, True)}),
    ("$(\\\n(1\nz", (), {2: (["CMD"], 2, -1, True), 4: (["CMD"], 4, -1, True), 5: (["CMD", "SUB"], 5, -1, True)}),
    # the body of a here-document is where the command that owns it began, and the command after it begins after the body
    ("a <<E <<F\n1\nE\n2\nF\nz", (), {10: ([], 0, -1, False), 17: ([], 0, -1, False), 18: ([], 18, -1, False)}),
    # the NAME of a coproc is followed by a command, which a reserved word does not hide; the word after `if` is a command
    ("coproc x if true; then ssh h '\nx\n", (), {7: ([], 7, -1, False), 12: ([], 12, -1, False), 23: ([], 23, -1, False), 30: (["SQ"], 23, -1, False)}),
    # inside a plain word the answer is the one after the whole word: what the word makes undecided is undecided where it begins
    ("a\\1a[then >?echo ?\nz", (), {2: ([], 0, -1, False), 3: ([], 0, -1, True)}),
    ("`echo $'a\\'b'`\nz", (), {10: (["BQ", "ANSI"], 1, -1, False), 11: (["BQ", "ANSI"], 1, -1, True), 13: ([], 0, -1, True)}),
    # the offsets of texts on which a mutant of a set or a class that tells a construct's kind read differently
    ('\nx\nE\n', ('ARRAY',), {0: (['ARRAY'], 0, -1, False), 1: (['ARRAY'], 1, -1, False), 2: (['ARRAY'], 1, -1, False), 3: (['ARRAY'], 3, -1, False), 4: (['ARRAY'], 3, -1, False), 5: (['ARRAY'], 3, -1, False)}),
    ('f|() { #a[\nE\n', (), {0: ([], 0, -1, False), 1: ([], 0, -1, False), 2: ([], 2, -1, False), 3: (['SUB'], 3, -1, False), 4: ([], 2, -1, False), 5: ([], 2, -1, False), 6: ([], 2, -1, False), 7: ([], 7, 7, False), 8: ([], 7, 7, False), 9: ([], 7, 7, False), 10: ([], 7, -1, False), 11: ([], 11, -1, False), 12: ([], 11, -1, False), 13: ([], 11, -1, False)}),
    ('echo >&2 !()2>&1 \n`\n', (), {0: ([], 0, -1, False), 1: ([], 0, -1, False), 2: ([], 0, -1, False), 3: ([], 0, -1, False), 4: ([], 0, -1, False), 5: ([], 0, -1, False), 6: ([], 0, -1, False), 7: ([], 0, -1, False), 8: ([], 0, -1, False), 9: ([], 0, -1, False), 10: ([], 0, -1, False), 11: (['SUB'], 11, -1, False), 12: ([], 0, -1, False), 13: ([], 0, -1, False), 14: ([], 0, -1, False), 15: ([], 0, -1, False), 16: ([], 0, -1, False), 17: ([], 0, -1, False), 18: ([], 18, -1, False), 19: (['BQ'], 19, -1, False), 20: (['BQ'], 18, -1, False)}),
    ('{ for E)\n\n', (), {0: ([], 0, -1, False), 1: ([], 0, -1, False), 2: ([], 2, -1, False), 3: ([], 2, -1, False), 4: ([], 2, -1, False), 5: ([], 2, -1, False), 6: ([], 2, -1, False), 7: ([], 7, -1, False), 8: ([], 7, -1, False), 9: ([], 7, -1, False), 10: ([], 7, -1, False)}),
    ('echo $( { for 2>&1 \nEOF\n', (), {0: ([], 0, -1, False), 1: ([], 0, -1, False), 2: ([], 0, -1, False), 3: ([], 0, -1, False), 4: ([], 0, -1, False), 5: ([], 0, -1, False), 6: (['CMD'], 7, -1, False), 7: (['CMD'], 7, -1, False), 8: (['CMD'], 8, -1, False), 9: (['CMD'], 8, -1, False), 10: (['CMD'], 10, -1, False), 11: (['CMD'], 10, -1, False), 12: (['CMD'], 10, -1, False), 13: (['CMD'], 10, -1, False), 14: (['CMD'], 10, -1, False), 15: (['CMD'], 15, -1, False), 16: (['CMD'], 15, -1, False), 17: (['CMD'], 15, -1, False), 18: (['CMD'], 15, -1, False), 19: (['CMD'], 15, -1, False), 20: (['CMD'], 20, -1, False), 21: (['CMD'], 20, -1, False), 22: (['CMD'], 20, -1, False), 23: (['CMD'], 20, -1, False), 24: (['CMD'], 20, -1, False)}),
    ('${#x} \'?\n\' "\\"\n${x#*}" $(select(1+(3))) # {a"\n# %*\n# ?\\)a"\nssh h <<E\n`\nx $x\n$(\n', (), {0: ([], 0, -1, False), 1: (['PARAM'], 0, -1, False), 2: (['PARAM'], 0, -1, False), 3: (['PARAM'], 0, -1, False), 4: (['PARAM'], 0, -1, False), 5: ([], 0, -1, False), 6: ([], 0, -1, False), 7: (['SQ'], 0, -1, False), 8: (['SQ'], 0, -1, False), 9: (['SQ'], 0, -1, False), 10: ([], 0, -1, False), 11: ([], 0, -1, False), 12: (['DQ'], 0, -1, False), 13: (['DQ'], 0, -1, False), 14: (['DQ'], 0, -1, False), 15: (['DQ'], 0, -1, False), 16: (['DQ', 'PARAM'], 0, -1, False), 17: (['DQ', 'PARAM'], 0, -1, False), 18: (['DQ', 'PARAM'], 0, -1, False), 19: (['DQ', 'PARAM'], 0, -1, False), 20: (['DQ', 'PARAM'], 0, -1, False), 21: (['DQ'], 0, -1, False), 22: ([], 0, -1, False), 23: ([], 0, -1, False), 24: (['CMD'], 25, -1, False), 25: (['CMD'], 25, -1, False), 26: (['CMD'], 25, -1, False), 27: (['CMD'], 25, -1, False), 28: (['CMD'], 25, -1, False), 29: (['CMD'], 25, -1, False), 30: (['CMD'], 25, -1, False), 31: (['CMD'], 25, -1, False), 32: (['CMD'], 25, -1, True), 33: (['CMD'], 25, -1, True), 34: (['CMD'], 34, -1, True), 35: (['CMD', 'SUB'], 35, -1, True), 36: (['CMD', 'SUB'], 35, -1, True), 37: (['CMD'], 34, -1, True), 38: ([], 0, -1, True), 39: ([], 0, -1, True), 40: ([], 40, 40, True), 41: ([], 40, 40, True), 42: ([], 40, 40, True), 43: ([], 40, 40, True), 44: ([], 40, 40, True), 45: ([], 40, -1, True), 46: ([], 46, 46, True), 47: ([], 46, 46, True), 48: ([], 46, 46, True), 49: ([], 46, 46, True), 50: ([], 46, -1, True), 51: ([], 51, 51, True), 52: ([], 51, 51, True), 53: ([], 51, 51, True), 54: ([], 51, 51, True), 55: ([], 51, 51, True), 56: ([], 51, 51, True), 57: ([], 51, 51, True), 58: ([], 51, -1, True), 59: ([], 59, -1, True), 60: ([], 59, -1, True), 61: ([], 59, -1, True), 62: ([], 59, -1, True), 63: ([], 59, -1, True), 64: ([], 59, -1, True), 65: ([], 59, -1, True), 66: ([], 59, -1, True), 67: ([], 59, -1, True), 68: ([], 59, -1, True), 69: ([], 59, -1, True), 70: ([], 59, -1, True), 71: ([], 59, -1, True), 72: ([], 59, -1, True), 73: ([], 59, -1, True), 74: ([], 59, -1, True), 75: ([], 59, -1, True), 76: ([], 59, -1, True), 77: ([], 59, -1, True), 78: ([], 59, -1, True), 79: ([], 59, -1, True)}),
    ("(( select x for ;; ))\n'\n", (), {0: ([], 0, -1, False), 1: (['SUB'], 1, -1, True), 2: (['SUB', 'SUB'], 1, -1, True), 3: (['SUB', 'SUB'], 3, -1, True), 4: (['SUB', 'SUB'], 3, -1, True), 5: (['SUB', 'SUB'], 3, -1, True), 6: (['SUB', 'SUB'], 3, -1, True), 7: (['SUB', 'SUB'], 3, -1, True), 8: (['SUB', 'SUB'], 3, -1, True), 9: (['SUB', 'SUB'], 3, -1, True), 10: (['SUB', 'SUB'], 3, -1, True), 11: (['SUB', 'SUB'], 3, -1, True), 12: (['SUB', 'SUB'], 12, -1, True), 13: (['SUB', 'SUB'], 12, -1, True), 14: (['SUB', 'SUB'], 12, -1, True), 15: (['SUB', 'SUB'], 12, -1, True), 16: (['SUB', 'SUB'], 12, -1, True), 17: (['SUB', 'SUB'], 17, -1, True), 18: (['SUB', 'SUB'], 17, -1, True), 19: (['SUB', 'SUB'], 19, -1, True), 20: (['SUB'], 1, -1, True), 21: ([], 0, -1, True), 22: ([], 22, -1, True), 23: (['SQ'], 22, -1, True), 24: (['SQ'], 22, -1, True)}),
    ('coproc\n"$( a (\n', (), {0: ([], 0, -1, False), 1: ([], 0, -1, False), 2: ([], 0, -1, False), 3: ([], 0, -1, False), 4: ([], 0, -1, False), 5: ([], 0, -1, False), 6: ([], 0, -1, False), 7: ([], 7, -1, False), 8: (['DQ'], 7, -1, False), 9: (['DQ', 'CMD'], 10, -1, False), 10: (['DQ', 'CMD'], 10, -1, False), 11: (['DQ', 'CMD'], 11, -1, False), 12: (['DQ', 'CMD'], 11, -1, False), 13: (['DQ', 'CMD'], 11, -1, False), 14: (['DQ', 'CMD'], 11, -1, True), 15: (['DQ', 'CMD'], 11, -1, True)}),
    ('echo $(`until {)\n\n', (), {0: ([], 0, -1, False), 1: ([], 0, -1, False), 2: ([], 0, -1, False), 3: ([], 0, -1, False), 4: ([], 0, -1, False), 5: ([], 0, -1, False), 6: (['CMD'], 7, -1, False), 7: (['CMD'], 7, -1, False), 8: (['CMD', 'BQ'], 8, -1, False), 9: (['CMD', 'BQ'], 8, -1, False), 10: (['CMD', 'BQ'], 8, -1, False), 11: (['CMD', 'BQ'], 8, -1, False), 12: (['CMD', 'BQ'], 8, -1, False), 13: (['CMD', 'BQ'], 8, -1, False), 14: (['CMD', 'BQ'], 14, -1, False), 15: (['CMD', 'BQ'], 15, -1, False), 16: (['CMD', 'BQ'], 15, -1, False), 17: (['CMD', 'BQ'], 15, -1, False), 18: (['CMD', 'BQ'], 7, -1, False)}),
    ('echo $( { {; } )\n\n', (), {0: ([], 0, -1, False), 1: ([], 0, -1, False), 2: ([], 0, -1, False), 3: ([], 0, -1, False), 4: ([], 0, -1, False), 5: ([], 0, -1, False), 6: (['CMD'], 7, -1, False), 7: (['CMD'], 7, -1, False), 8: (['CMD'], 8, -1, False), 9: (['CMD'], 8, -1, False), 10: (['CMD'], 10, -1, False), 11: (['CMD'], 11, -1, False), 12: (['CMD'], 11, -1, False), 13: (['CMD'], 13, -1, False), 14: (['CMD'], 13, -1, False), 15: (['CMD'], 13, -1, False), 16: ([], 0, -1, False), 17: ([], 0, -1, False), 18: ([], 0, -1, False)}),
    ('echo $(case x in a) $({|\nE\n', (), {0: ([], 0, -1, False), 1: ([], 0, -1, False), 2: ([], 0, -1, False), 3: ([], 0, -1, False), 4: ([], 0, -1, False), 5: ([], 0, -1, False), 6: (['CMD'], 7, -1, True), 7: (['CMD'], 7, -1, True), 8: (['CMD'], 7, -1, True), 9: (['CMD'], 7, -1, True), 10: (['CMD'], 7, -1, True), 11: (['CMD'], 7, -1, True), 12: (['CMD'], 7, -1, True), 13: (['CMD'], 7, -1, True), 14: (['CMD'], 7, -1, True), 15: (['CMD'], 7, -1, True), 16: (['CMD'], 7, -1, True), 17: (['CMD'], 7, -1, True), 18: (['CMD'], 7, -1, True), 19: ([], 0, -1, True), 20: ([], 0, -1, True), 21: (['CMD'], 22, -1, True), 22: (['CMD'], 22, -1, True), 23: (['CMD'], 23, -1, True), 24: (['CMD'], 23, -1, True), 25: (['CMD'], 25, -1, True), 26: (['CMD'], 25, -1, True), 27: (['CMD'], 25, -1, True)}),
    ('x=${y:-$({>&2 do \n', (), {0: ([], 0, -1, False), 1: ([], 0, -1, False), 2: ([], 0, -1, False), 3: (['PARAM'], 0, -1, False), 4: (['PARAM'], 0, -1, False), 5: (['PARAM'], 0, -1, False), 6: (['PARAM'], 0, -1, False), 7: (['PARAM'], 0, -1, False), 8: (['PARAM', 'CMD'], 9, -1, False), 9: (['PARAM', 'CMD'], 9, -1, False), 10: (['PARAM', 'CMD'], 10, -1, False), 11: (['PARAM', 'CMD'], 10, -1, False), 12: (['PARAM', 'CMD'], 10, -1, False), 13: (['PARAM', 'CMD'], 10, -1, False), 14: (['PARAM', 'CMD'], 10, -1, False), 15: (['PARAM', 'CMD'], 10, -1, False), 16: (['PARAM', 'CMD'], 10, -1, False), 17: (['PARAM', 'CMD'], 10, -1, False), 18: (['PARAM', 'CMD'], 10, -1, False)}),
    ('[[ $a == b && $c =~ ^x ]]\nz', (), {0: ([], 0, -1, False), 1: ([], 0, -1, False), 2: ([], 0, -1, False), 3: ([], 0, -1, False), 4: ([], 0, -1, False), 5: ([], 0, -1, False), 6: ([], 0, -1, False), 7: ([], 0, -1, False), 8: ([], 0, -1, False), 9: ([], 0, -1, False), 10: ([], 0, -1, False), 11: ([], 0, -1, False), 12: ([], 12, -1, False), 13: ([], 12, -1, False), 14: ([], 14, -1, False), 15: ([], 14, -1, False), 16: ([], 14, -1, False), 17: ([], 14, -1, True), 18: ([], 14, -1, True), 19: ([], 14, -1, True), 20: ([], 14, -1, True), 21: ([], 14, -1, True), 22: ([], 14, -1, True), 23: ([], 14, -1, True), 24: ([], 14, -1, True), 25: ([], 14, -1, True), 26: ([], 26, -1, True), 27: ([], 26, -1, True)}),
    ('x=${y:-$({&2 do \n', (), {0: ([], 0, -1, False), 1: ([], 0, -1, False), 2: ([], 0, -1, False), 3: (['PARAM'], 0, -1, False), 4: (['PARAM'], 0, -1, False), 5: (['PARAM'], 0, -1, False), 6: (['PARAM'], 0, -1, False), 7: (['PARAM'], 0, -1, False), 8: (['PARAM', 'CMD'], 9, -1, False), 9: (['PARAM', 'CMD'], 9, -1, False), 10: (['PARAM', 'CMD'], 10, -1, False), 11: (['PARAM', 'CMD'], 11, -1, False), 12: (['PARAM', 'CMD'], 11, -1, False), 13: (['PARAM', 'CMD'], 11, -1, False), 14: (['PARAM', 'CMD'], 11, -1, False), 15: (['PARAM', 'CMD'], 11, -1, False), 16: (['PARAM', 'CMD'], 11, -1, False), 17: (['PARAM', 'CMD'], 11, -1, False)}),
    ("coproc x { ssh h '\nx\n", (), {0: ([], 0, -1, False), 1: ([], 0, -1, False), 2: ([], 0, -1, False), 3: ([], 0, -1, False), 4: ([], 0, -1, False), 5: ([], 0, -1, False), 6: ([], 0, -1, False), 7: ([], 7, -1, False), 8: ([], 7, -1, False), 9: ([], 9, -1, False), 10: ([], 9, -1, False), 11: ([], 11, -1, False), 12: ([], 11, -1, False), 13: ([], 11, -1, False), 14: ([], 11, -1, False), 15: ([], 11, -1, False), 16: ([], 11, -1, False), 17: ([], 11, -1, False), 18: (['SQ'], 11, -1, False), 19: (['SQ'], 11, -1, False), 20: (['SQ'], 11, -1, False), 21: (['SQ'], 11, -1, False)}),
    ('x=$((1)\\\n)\nz', (), {0: ([], 0, -1, False), 1: ([], 0, -1, False), 2: ([], 0, -1, False), 3: (['ARITH'], 0, -1, False), 4: (['ARITH'], 0, -1, False), 5: (['ARITH'], 0, -1, False), 6: (['ARITH'], 0, -1, True), 7: ([], 0, -1, True), 8: ([], 0, -1, True), 9: ([], 0, -1, True), 10: ([], 0, -1, True), 11: ([], 11, -1, True), 12: ([], 11, -1, True)}),
    ('$(( <(', (), {0: ([], 0, -1, False), 1: (['ARITH'], 0, -1, False), 2: (['ARITH'], 0, -1, False), 3: (['ARITH'], 0, -1, False), 4: (['ARITH'], 0, -1, False), 5: (['ARITH'], 0, -1, False), 6: (['ARITH'], 0, -1, False)}),
    ('f ( ) { :; }\nz', (), {0: ([], 0, -1, False), 1: ([], 0, -1, False), 2: ([], 0, -1, False), 3: (['SUB'], 0, -1, False), 4: (['SUB'], 4, -1, False), 5: ([], 0, -1, False), 6: ([], 6, -1, False), 7: ([], 6, -1, False), 8: ([], 8, -1, False), 9: ([], 8, -1, False), 10: ([], 8, -1, False), 11: ([], 11, -1, False), 12: ([], 11, -1, False), 13: ([], 13, -1, False), 14: ([], 13, -1, False)}),
    ('echo ${a1:${x:}\nz', (), {0: ([], 0, -1, False), 1: ([], 0, -1, False), 2: ([], 0, -1, False), 3: ([], 0, -1, False), 4: ([], 0, -1, False), 5: ([], 0, -1, False), 6: (['PARAM'], 0, -1, False), 7: (['PARAM'], 0, -1, False), 8: (['PARAM'], 0, -1, False), 9: (['PARAM'], 0, -1, False), 10: (['PARAM'], 0, -1, False), 11: (['PARAM', 'PARAM'], 0, -1, True), 12: (['PARAM', 'PARAM'], 0, -1, True), 13: (['PARAM', 'PARAM'], 0, -1, True), 14: (['PARAM', 'PARAM'], 0, -1, True), 15: (['PARAM'], 0, -1, True), 16: (['PARAM'], 0, -1, True), 17: (['PARAM'], 0, -1, True)}),
])
def test_a_probe_pins_what_is_open_where_the_command_began_and_whether_a_comment_holds_it(text, start, expected):
    assert _at(text, start, *expected) == expected


@pytest.mark.parametrize("text,start,openers,flag", [
    ("a) n (b\nz", ("CMD",), [(), ()], False),                       # after the substitution a paren behind a word is a syntax error: nothing opens
    (" ))'x\nbody", ("ARITH",), [("SQ",), ("SQ",)], False),            # the quote after the `))` that closed an arithmetic expansion is no quote in one
    ("()x<<E))\nz\n", ("CMD",), [(), ("HEREDOC",)], True),                # the here-document of a command in a substitution that the `)` closes: its body is not decided
    ("coproc \\\\\n\n f (x\n", (), [(), (), (), ()], False),            # a backslash is the whole NAME, a newline ends it, and `f (x` is a stray paren
    ("a\\\nfunction f  (\n", (), [(), (), ("SUB",)], False),           # a function keyword after a line continuation still names a compound command
    ("ca\\\nse x in\n", (), [(), ()], True),                              # a line continuation cuts `case`: the shells differ in what they say of the unfinished command
    ("do\\\nne\n", (), [(), ()], True), ("a\\\nb c in\n", (), [(), ()], False),
    ("c\\\na\\\nse x in\n", (), [(), ()], True), ("d\\\no\\\nn\\\ne\n", (), [(), ()], True), ("a\\\n1\\\na[1]=x\n", (), [(), ()], True),     # a word cut more than once
    ("c\\\nx\\\nse y\n", (), [(), ()], False),
    ("x; es\\\nac y\n", (), [(), ()], True), ("x; i\\\nn y\n", (), [(), ()], True), ("x; f\\\ni y\n", (), [(), ()], True),     # every word of the grammar a continuation may cut
    ("time -\\\np y\n", (), [(), ()], True), ("time -\\\n- y\n", (), [(), ()], True),   # `done` cut in two; a word that is no keyword stays decided
    ('`"$[`', (), [()], True),                                          # a double-quoted `$[` is undecided, though the body holds no single quote
    # texts that begin inside a construct, or whose end is undecided, on which a mutant of a table, a set or a class read differently
    (')(<<E', ('ARRAY',), [('SUB', 'HEREDOC')], False),
    ('for\t((', (), [()], True),
    ('[C[', (), [()], True),
    ('${!/', (), [()], False),
    ('${a.', (), [()], False),
])
def test_the_states_of_texts_that_begin_inside_a_construct_or_hold_a_name_slot(text, start, openers, flag):
    got = line_states(text, start=tuple(Opener(kind, 0, 0) for kind in start))
    assert [tuple(o.kind for o in s.openers) for s in got][-1:] == [openers[-1]] and got.unknown_at_end is flag


_PROBED_TEXTS = [
 "x=1 && ssh h 'a b' # c d\nz\n", "eval \"x=1 && ssh evil '\nz\n", "echo `ssh h 'x` && ssh h '\n", "echo '`' && ssh evil.example -o 'A=`' '\n", "' && ssh evil.example '\n",
 "cat <<E | ssh h\nbody\nE\nz\n", "x=$(a\nb)\n# c\n", "echo $((1)) ${x:-y} $'a\\nb' \"q $x\" `c`\n", "a=(b c) $(d) ${e} <(f) $'g' \"h\" `i`\n", "case x in a)# it's\n ssh h '\n",
 "f() { a[1]=x; }\n", "echo hi \\\n there \\\n  'x\ny'\n", "for x in a; do ssh h '\ncurl\n'; done\n", "coproc x { ssh h '\nz\n", "x=\"a\n  $(b 'c\nd') e\"\n", "echo \"a\\\"b\" 'c'\n",
 "ssh h \"$(echo 'a\nb')\"\n", "echo a # b 'c\nd 'e\n", "time -p ssh h '\n", "if x; then\n  echo 'a\nb'\nfi\n", "echo ${a:-b c} \"${d:-'e'}\"\n", "cat <<'E'\n$x `y`\nE\nz\n",
 "echo $'a\\'b'\nz\n", "((1+2)); echo $((3))\nz\n", "echo a;echo 'b\n' c\n", "a=`b\nc` d\n",
]


@pytest.mark.parametrize("text", _PROBED_TEXTS)
def test_a_probe_at_an_offset_is_the_state_that_lexing_the_text_up_to_it_ends_in(text):
    """Between two tokens, and inside a string, the constructs open before a character are the ones open at the end of the text that stops there (a probe
    at a closing backtick, or in a here-document body, is not asked for; neither is one inside a two-character token)."""
    offsets = tuple(range(len(text) + 1))
    probed = line_states(text, probes=offsets).probed
    multi = {"$(", "<<", "<(", ">(", "${", "$'", "$[", "\\\n", "((", "))", "$((", "=(", "[[", "=~", "]]", "f("}
    for p in offsets:
        if any(token in text[max(0, p - 2):p + 2] for token in multi) or text[p - 1:p] == "\\" or text[p:p + 1] == "`" or "<<" in text:
            continue
        expected = [o.kind for o in line_states(text[:p] + "\n")[-1].openers]
        assert [o.kind for o in probed[p].openers] == expected, (text, p)


@pytest.mark.parametrize("text", ['cat <<"\\"\n"\nz', 'cat <<"\\`"\n`\nz', 'cat <<"$("\n$(\nz', 'cat <<"a\\b"\nz', 'cat <<"$x"\nz'])
def test_a_double_quoted_here_document_delimiter_with_an_escape_or_an_expansion_is_undecided(text):
    assert unknown(text)


@pytest.mark.parametrize("text", ['cat <<"E"\nx\nE\nz', "cat <<'E'\nx\nE\nz", 'cat <<"E F"\nx\nE F\nz', "cat <<E\nx\nE\nz"])
def test_a_plain_here_document_delimiter_is_decided(text):
    assert not unknown(text)


def test_an_extglob_group_is_decided_only_when_it_holds_plain_pattern_characters_and_closes_on_its_line():
    for body in ("a|b", "a b", "~x", "a.b,c", "x=1+2", "a:b", "a/b", "a-b", "a_1", "a\tb"):
        assert not unknown(f"ls @({body}) x\nz"), body
    for body in ("#", "a(b)", "'q'", '"q"', "`q`", "$x", "a\\b", "a;b", "a&b", "a<b"):
        assert unknown(f"ls @({body}) x\nz"), body
    assert unknown("ls @(a)#x\nz") and unknown("ls @(a\nb)\nz")


def test_a_group_longer_than_the_bound_is_undecided_and_a_run_of_openers_costs_a_constant_each():
    assert not unknown("ls @(" + "a" * 190 + ") x\nz")
    assert unknown("ls @(" + "a" * 210 + ") x\nz")
    assert unknown("ls +(" * 3 + "a" * 300 + "\nz")


@pytest.mark.parametrize("char", list("\\$`"))
def test_a_double_quoted_here_document_delimiter_with_a_character_the_shells_read_differently_is_unknown(char):
    assert unknown(f'cat <<"E{char}"\nbody\nE{char}\nz')
    assert not unknown('cat <<"E"\nbody\nE\nz')


@pytest.mark.parametrize("text,kinds_and_commands", [
    ("ssh h $(a) { x '\nz", [("SQ", "ssh h $(a) { x '")]),                  # a `{` after the `)` of a substitution is a word, not the reserved word
    ("ssh h <(a) { x '\nz", [("SQ", "ssh h <(a) { x '")]),
    ("ssh h $((1)) { '\nz", [("SQ", "ssh h $((1)) { '")]),
    ("f() { ssh h '\nz", [("SQ", "ssh h '")]),                              # after the parens of a function it is the reserved word
    ("f( ) {\nssh h '\nz", [("SQ", "ssh h '")]),
    ("coproc $(ssh h '\nz", [("CMD", "$"), ("SQ", "ssh h '")]),              # the NAME slot of a coproc is not the slot of the commands inside its substitution
    ('coproc x="$(ssh h \'\nz', [("DQ", 'x="'), ("CMD", 'x="$'), ("SQ", "ssh h '")]),
    ('coproc (x="$(ssh h \'\nz', [("SUB", "("), ("DQ", 'x="'), ("CMD", 'x="$'), ("SQ", "ssh h '")]),
    ("coproc <(ssh h '\nz", [("PROC", "<"), ("SQ", "ssh h '")]),
    ("coproc x=$(a b) y=1 ssh h '\nz", [("SQ", "x=$(a b) y=1 ssh h '")]),
])
def test_the_command_that_holds_a_string_open_is_the_one_the_shells_run(text, kinds_and_commands):
    openers = line_states(text)[-1].openers
    assert [(o.kind, text[o.command_at:o.offset + 1]) for o in openers] == kinds_and_commands


@pytest.mark.parametrize("text,is_unknown", [
    ("ssh h &\\\n>f '\nz", True), ("ssh h &\\\n>>f '\nz", True), ("ssh h &\\\n\\\n>f '\nz", True),    # bash joins `&` and `>` into `&>`, dash does not
    ("a &&\\\nb\nz", False), ("a &\\\nb\nz", False), ("a &\\\n >f\nz", False),
])
def test_a_line_continuation_between_an_ampersand_and_a_redirect_is_unknown(text, is_unknown):
    assert unknown(text) == is_unknown


def _snapshot(text, start):
    """Everything the lexer says of a text: the unknown flag at the start of each line, the constructs open at the end (kind, offset, where their command began),
    whether the end is undecided, the constructs that closed (line, kind, offset, command), and a probe at every offset."""
    lexed = line_states(text, start=tuple(Opener(kind, 0, 0) for kind in start), probes=tuple(range(len(text) + 1)))
    return ("".join("T" if s.unknown else "F" for s in lexed), tuple((o.kind, o.offset, o.command_at) for o in lexed[-1].openers), lexed.unknown_at_end,
            tuple((line, o.kind, o.offset, o.command_at) for line, o in lexed.closed),
            tuple((p, tuple(o.kind for o in lexed.probed[p].openers), lexed.probed[p].command_at, lexed.probed[p].comment_at, lexed.probed[p].unknown) for p in sorted(lexed.probed)))


@pytest.mark.parametrize("text,start,expected", [
    # texts on which a mutant of a table, a set, a character class, a string or a bound of the lexer read differently (the answers at every offset)
    ('x1n<<\\', (), ('F', (), True, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, True), (5, (), 0, -1, True), (6, (), 0, -1, True)))),
    ('\t>()9EOF[[*', (), ('F', (), False, (), ((0, (), 0, -1, False), (1, (), 1, -1, False), (2, ('PROC',), 3, -1, False), (3, ('PROC',), 3, -1, False), (4, (), 1, -1, False), (5, (), 1, -1, False), (6, (), 1, -1, False), (7, (), 1, -1, False), (8, (), 1, -1, False), (9, (), 1, -1, False), (10, (), 1, -1, False), (11, (), 1, -1, False)))),
    ('9select[[', (), ('F', (), False, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False), (5, (), 0, -1, False), (6, (), 0, -1, False), (7, (), 0, -1, False), (8, (), 0, -1, False), (9, (), 0, -1, False)))),
    ('&${x}${n^', (), ('F', (), False, (), ((0, (), 0, -1, False), (1, (), 1, -1, False), (2, ('PARAM',), 1, -1, False), (3, ('PARAM',), 1, -1, False), (4, ('PARAM',), 1, -1, False), (5, (), 1, -1, False), (6, ('PARAM',), 1, -1, False), (7, ('PARAM',), 1, -1, False), (8, ('PARAM',), 1, -1, False), (9, ('PARAM',), 1, -1, False)))),
    ("foo|${if,$'^ix1", (), ('F', (), True, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 4, -1, False), (5, ('PARAM',), 4, -1, False), (6, ('PARAM',), 4, -1, False), (7, ('PARAM',), 4, -1, False), (8, ('PARAM',), 4, -1, False), (9, ('PARAM',), 4, -1, False), (10, ('PARAM', 'ANSI'), 4, -1, True), (11, ('PARAM', 'ANSI'), 4, -1, True), (12, ('PARAM', 'ANSI'), 4, -1, True), (13, ('PARAM', 'ANSI'), 4, -1, True), (14, ('PARAM', 'ANSI'), 4, -1, True), (15, ('PARAM', 'ANSI'), 4, -1, True)))),
    ('_|in(=A_b&&', (), ('F', (), False, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 2, -1, False), (3, (), 2, -1, False), (4, (), 2, -1, False), (5, ('SUB',), 5, -1, False), (6, ('SUB',), 5, -1, False), (7, ('SUB',), 5, -1, False), (8, ('SUB',), 5, -1, False), (9, ('SUB',), 5, -1, False), (10, ('SUB',), 10, -1, False), (11, ('SUB',), 10, -1, False)))),
    ('(?(:)$`a[(', (), ('F', (), True, (), ((0, (), 0, -1, False), (1, ('SUB',), 1, -1, False), (2, ('SUB',), 1, -1, False), (3, ('SUB', 'SUB'), 3, -1, False), (4, ('SUB', 'SUB'), 3, -1, False), (5, ('SUB',), 1, -1, False), (6, ('SUB',), 1, -1, False), (7, ('SUB', 'BQ'), 7, -1, True), (8, ('SUB', 'BQ'), 7, -1, True), (9, ('SUB', 'BQ'), 7, -1, True), (10, ('SUB', 'BQ'), 1, -1, True)))),
    ('?/*(\t))?A_b${x}', (), ('F', (), False, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, ('SUB',), 0, -1, False), (5, ('SUB',), 5, -1, False), (6, (), 6, -1, False), (7, (), 7, -1, False), (8, (), 7, -1, False), (9, (), 7, -1, False), (10, (), 7, -1, False), (11, (), 7, -1, False), (12, ('PARAM',), 7, -1, False), (13, ('PARAM',), 7, -1, False), (14, ('PARAM',), 7, -1, False), (15, (), 7, -1, False)))),
    ('${x}!(-p)]]', (), ('F', (), False, (), ((0, (), 0, -1, False), (1, ('PARAM',), 0, -1, False), (2, ('PARAM',), 0, -1, False), (3, ('PARAM',), 0, -1, False), (4, (), 0, -1, False), (5, (), 0, -1, False), (6, ('SUB',), 6, -1, False), (7, ('SUB',), 6, -1, False), (8, ('SUB',), 6, -1, False), (9, (), 0, -1, False), (10, (), 0, -1, False), (11, (), 0, -1, False)))),
    (']in(\t', (), ('F', (), False, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, ('SUB',), 0, -1, False), (5, ('SUB',), 0, -1, False)))),
    ('[=))for((.', (), ('F', (), True, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 3, -1, False), (4, (), 4, -1, False), (5, (), 4, -1, False), (6, (), 4, -1, False), (7, (), 4, -1, False), (8, ('SUB',), 8, -1, True), (9, ('SUB', 'SUB'), 9, -1, True), (10, ('SUB', 'SUB'), 9, -1, True)))),
    ('$(for${{&>\n esac', (), ('FT', (('CMD', 0, 0), ('PARAM', 5, 2)), True, (), ((0, (), 0, -1, False), (1, ('CMD',), 2, -1, False), (2, ('CMD',), 2, -1, False), (3, ('CMD',), 2, -1, False), (4, ('CMD',), 2, -1, False), (5, ('CMD',), 2, -1, False), (6, ('CMD', 'PARAM'), 2, -1, True), (7, ('CMD', 'PARAM'), 2, -1, True), (8, ('CMD', 'PARAM'), 8, -1, True), (9, ('CMD', 'PARAM'), 8, -1, True), (10, ('CMD', 'PARAM'), 8, -1, True), (11, ('CMD', 'PARAM'), 8, -1, True), (12, ('CMD', 'PARAM'), 8, -1, True), (13, ('CMD', 'PARAM'), 8, -1, True), (14, ('CMD', 'PARAM'), 8, -1, True), (15, ('CMD', 'PARAM'), 8, -1, True), (16, ('CMD', 'PARAM'), 8, -1, True)))),
    ('$(((|||function${[[|', (), ('F', (), True, (), ((0, (), 0, -1, False), (1, ('ARITH',), 0, -1, False), (2, ('ARITH',), 0, -1, False), (3, ('ARITH',), 0, -1, False), (4, ('ARITH',), 0, -1, False), (5, ('ARITH',), 5, -1, False), (6, ('ARITH',), 6, -1, False), (7, ('ARITH',), 7, -1, False), (8, ('ARITH',), 7, -1, False), (9, ('ARITH',), 7, -1, False), (10, ('ARITH',), 7, -1, False), (11, ('ARITH',), 7, -1, False), (12, ('ARITH',), 7, -1, False), (13, ('ARITH',), 7, -1, False), (14, ('ARITH',), 7, -1, False), (15, ('ARITH',), 7, -1, False), (16, ('ARITH', 'PARAM'), 7, -1, True), (17, ('ARITH', 'PARAM'), 7, -1, True), (18, ('ARITH', 'PARAM'), 7, -1, True), (19, ('ARITH', 'PARAM'), 19, -1, True), (20, ('ARITH', 'PARAM'), 19, -1, True)))),
    ('$(for&>', (), ('F', (), False, (), ((0, (), 0, -1, False), (1, ('CMD',), 2, -1, False), (2, ('CMD',), 2, -1, False), (3, ('CMD',), 2, -1, False), (4, ('CMD',), 2, -1, False), (5, ('CMD',), 2, -1, False), (6, ('CMD',), 2, -1, False), (7, ('CMD',), 2, -1, False)))),
    (']+@(coproc;curl x', (), ('F', (), True, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, ('SUB',), 4, -1, True), (5, ('SUB',), 4, -1, True), (6, ('SUB',), 4, -1, True), (7, ('SUB',), 4, -1, True), (8, ('SUB',), 4, -1, True), (9, ('SUB',), 4, -1, True), (10, ('SUB',), 10, -1, True), (11, ('SUB',), 11, -1, True), (12, ('SUB',), 11, -1, True), (13, ('SUB',), 11, -1, True), (14, ('SUB',), 11, -1, True), (15, ('SUB',), 11, -1, True), (16, ('SUB',), 11, -1, True), (17, ('SUB',), 11, -1, True)))),
    ('((&&?$($(coproc>(:-EOF', (), ('F', (), True, (), ((0, (), 0, -1, False), (1, ('SUB',), 1, -1, True), (2, ('SUB', 'SUB'), 2, -1, True), (3, ('SUB', 'SUB'), 3, -1, True), (4, ('SUB', 'SUB'), 4, -1, True), (5, ('SUB', 'SUB'), 4, -1, True), (6, ('SUB', 'SUB', 'CMD'), 7, -1, True), (7, ('SUB', 'SUB', 'CMD'), 7, -1, True), (8, ('SUB', 'SUB', 'CMD', 'CMD'), 9, -1, True), (9, ('SUB', 'SUB', 'CMD', 'CMD'), 9, -1, True), (10, ('SUB', 'SUB', 'CMD', 'CMD'), 9, -1, True), (11, ('SUB', 'SUB', 'CMD', 'CMD'), 9, -1, True), (12, ('SUB', 'SUB', 'CMD', 'CMD'), 9, -1, True), (13, ('SUB', 'SUB', 'CMD', 'CMD'), 9, -1, True), (14, ('SUB', 'SUB', 'CMD', 'CMD'), 9, -1, True), (15, ('SUB', 'SUB', 'CMD', 'CMD'), 15, -1, True), (16, ('SUB', 'SUB', 'CMD', 'CMD', 'PROC'), 17, -1, True), (17, ('SUB', 'SUB', 'CMD', 'CMD', 'PROC'), 17, -1, True), (18, ('SUB', 'SUB', 'CMD', 'CMD', 'PROC'), 17, -1, True), (19, ('SUB', 'SUB', 'CMD', 'CMD', 'PROC'), 17, -1, True), (20, ('SUB', 'SUB', 'CMD', 'CMD', 'PROC'), 17, -1, True), (21, ('SUB', 'SUB', 'CMD', 'CMD', 'PROC'), 17, -1, True), (22, ('SUB', 'SUB', 'CMD', 'CMD', 'PROC'), 17, -1, True)))),
    ('for||[[=~<', (), ('F', (), True, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 4, -1, False), (5, (), 5, -1, True), (6, (), 5, -1, True), (7, (), 5, -1, True), (8, (), 5, -1, True), (9, (), 9, -1, True), (10, (), 9, -1, True)))),
    ('{\t{', (), ('F', (), False, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 2, -1, False), (3, (), 2, -1, False)))),
    ('!~${{\n;a%%-', ('DQ',), ('FT', (('DQ', 0, 0), ('PARAM', 2, 0)), True, (), ((0, ('DQ',), 0, -1, False), (1, ('DQ',), 0, -1, False), (2, ('DQ',), 0, -1, False), (3, ('DQ', 'PARAM'), 4, -1, True), (4, ('DQ', 'PARAM'), 4, -1, True), (5, ('DQ', 'PARAM'), 4, -1, True), (6, ('DQ', 'PARAM'), 6, -1, True), (7, ('DQ', 'PARAM'), 6, -1, True), (8, ('DQ', 'PARAM'), 6, -1, True), (9, ('DQ', 'PARAM'), 6, -1, True), (10, ('DQ', 'PARAM'), 6, -1, True), (11, ('DQ', 'PARAM'), 6, -1, True)))),
    ('`\\\\"`\n', (), ('FT', (), True, (), ((0, (), 0, -1, False), (1, ('BQ',), 1, -1, True), (2, ('BQ',), 1, -1, True), (3, ('BQ',), 1, -1, True), (4, (), 0, -1, True), (5, (), 0, -1, True), (6, (), 0, -1, True)))),
    ('0_A[', (), ('F', (), False, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False)))),
    ("${A@:'}\n", (), ('FF', (('PARAM', 0, 0), ('SQ', 5, 0)), False, (), ((0, (), 0, -1, False), (1, ('PARAM',), 0, -1, False), (2, ('PARAM',), 0, -1, False), (3, ('PARAM',), 0, -1, False), (4, ('PARAM',), 0, -1, False), (5, ('PARAM',), 0, -1, False), (6, ('PARAM', 'SQ'), 0, -1, False), (7, ('PARAM', 'SQ'), 0, -1, False), (8, ('PARAM', 'SQ'), 0, -1, False)))),
    ('${-:="}\n', (), ('FF', (('PARAM', 0, 0), ('DQ', 5, 0)), False, (), ((0, (), 0, -1, False), (1, ('PARAM',), 0, -1, False), (2, ('PARAM',), 0, -1, False), (3, ('PARAM',), 0, -1, False), (4, ('PARAM',), 0, -1, False), (5, ('PARAM',), 0, -1, False), (6, ('PARAM', 'DQ'), 0, -1, False), (7, ('PARAM', 'DQ'), 0, -1, False), (8, ('PARAM', 'DQ'), 0, -1, False)))),
    ('${@:?"}\n', (), ('FF', (('PARAM', 0, 0), ('DQ', 5, 0)), False, (), ((0, (), 0, -1, False), (1, ('PARAM',), 0, -1, False), (2, ('PARAM',), 0, -1, False), (3, ('PARAM',), 0, -1, False), (4, ('PARAM',), 0, -1, False), (5, ('PARAM',), 0, -1, False), (6, ('PARAM', 'DQ'), 0, -1, False), (7, ('PARAM', 'DQ'), 0, -1, False), (8, ('PARAM', 'DQ'), 0, -1, False)))),
    ('${4[h:L`}\n', (), ('FF', (('PARAM', 0, 0), ('BQ', 7, 0)), False, (), ((0, (), 0, -1, False), (1, ('PARAM',), 0, -1, False), (2, ('PARAM',), 0, -1, False), (3, ('PARAM',), 0, -1, False), (4, ('PARAM',), 0, -1, False), (5, ('PARAM',), 0, -1, False), (6, ('PARAM',), 0, -1, False), (7, ('PARAM',), 0, -1, False), (8, ('PARAM', 'BQ'), 8, -1, False), (9, ('PARAM', 'BQ'), 8, -1, False), (10, ('PARAM', 'BQ'), 0, -1, False)))),
    ('xtglob\nls @(a|b) x\nz\n', (), ('FFFF', (), False, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False), (5, (), 0, -1, False), (6, (), 0, -1, False), (7, (), 7, -1, False), (8, (), 7, -1, False), (9, (), 7, -1, False), (10, (), 7, -1, False), (11, (), 7, -1, False), (12, ('SUB',), 12, -1, False), (13, ('SUB',), 12, -1, False), (14, ('SUB',), 14, -1, False), (15, ('SUB',), 14, -1, False), (16, (), 7, -1, False), (17, (), 7, -1, False), (18, (), 7, -1, False), (19, (), 19, -1, False), (20, (), 19, -1, False), (21, (), 19, -1, False)))),
    ('extglo\nls @(a|b) x\nz\n', (), ('FFFF', (), False, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False), (5, (), 0, -1, False), (6, (), 0, -1, False), (7, (), 7, -1, False), (8, (), 7, -1, False), (9, (), 7, -1, False), (10, (), 7, -1, False), (11, (), 7, -1, False), (12, ('SUB',), 12, -1, False), (13, ('SUB',), 12, -1, False), (14, ('SUB',), 14, -1, False), (15, ('SUB',), 14, -1, False), (16, (), 7, -1, False), (17, (), 7, -1, False), (18, (), 7, -1, False), (19, (), 19, -1, False), (20, (), 19, -1, False), (21, (), 19, -1, False)))),
    ('shopt -s extglob\nls @(a|b) x\nz\n', (), ('FFTT', (), True, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False), (5, (), 0, -1, False), (6, (), 0, -1, False), (7, (), 0, -1, False), (8, (), 0, -1, False), (9, (), 0, -1, False), (10, (), 0, -1, False), (11, (), 0, -1, False), (12, (), 0, -1, False), (13, (), 0, -1, False), (14, (), 0, -1, False), (15, (), 0, -1, False), (16, (), 0, -1, False), (17, (), 17, -1, False), (18, (), 17, -1, False), (19, (), 17, -1, False), (20, (), 17, -1, False), (21, (), 17, -1, False), (22, ('SUB',), 22, -1, True), (23, ('SUB',), 22, -1, True), (24, ('SUB',), 24, -1, True), (25, ('SUB',), 24, -1, True), (26, (), 17, -1, True), (27, (), 17, -1, True), (28, (), 17, -1, True), (29, (), 29, -1, True), (30, (), 29, -1, True), (31, (), 29, -1, True)))),
    ("cat <<E\n${x:-'}'}\nE\nz\n", (), ('FFFTT', (), True, ((2, 'HEREDOC', 4, 0),), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False), (5, (), 0, -1, False), (6, (), 0, -1, False), (7, (), 0, -1, False), (8, (), 0, -1, True), (9, (), 0, -1, True), (10, (), 0, -1, True), (11, (), 0, -1, True), (12, (), 0, -1, True), (13, (), 0, -1, True), (14, (), 0, -1, True), (15, (), 0, -1, True), (16, (), 0, -1, True), (17, (), 0, -1, True), (18, (), 0, -1, True), (19, (), 0, -1, True), (20, (), 20, -1, True), (21, (), 20, -1, True), (22, (), 20, -1, True)))),
    ('cat <<E\n${x:-"}"}\nE\nz\n', (), ('FFFFF', (), False, ((2, 'HEREDOC', 4, 0),), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False), (5, (), 0, -1, False), (6, (), 0, -1, False), (7, (), 0, -1, False), (8, (), 0, -1, False), (9, (), 0, -1, False), (10, (), 0, -1, False), (11, (), 0, -1, False), (12, (), 0, -1, False), (13, (), 0, -1, False), (14, (), 0, -1, False), (15, (), 0, -1, False), (16, (), 0, -1, False), (17, (), 0, -1, False), (18, (), 0, -1, False), (19, (), 0, -1, False), (20, (), 20, -1, False), (21, (), 20, -1, False), (22, (), 20, -1, False)))),
    ('cat <<E\n${x:-a}\nE\nz\n', (), ('FFFFF', (), False, ((2, 'HEREDOC', 4, 0),), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False), (5, (), 0, -1, False), (6, (), 0, -1, False), (7, (), 0, -1, False), (8, (), 0, -1, False), (9, (), 0, -1, False), (10, (), 0, -1, False), (11, (), 0, -1, False), (12, (), 0, -1, False), (13, (), 0, -1, False), (14, (), 0, -1, False), (15, (), 0, -1, False), (16, (), 0, -1, False), (17, (), 0, -1, False), (18, (), 18, -1, False), (19, (), 18, -1, False), (20, (), 18, -1, False)))),
    ("f(\t) ssh h '\nz\n", (), ('FFF', (('SQ', 11, 5),), False, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, ('SUB',), 0, -1, False), (3, ('SUB',), 3, -1, False), (4, (), 0, -1, False), (5, (), 5, -1, False), (6, (), 5, -1, False), (7, (), 5, -1, False), (8, (), 5, -1, False), (9, (), 5, -1, False), (10, (), 5, -1, False), (11, (), 5, -1, False), (12, ('SQ',), 5, -1, False), (13, ('SQ',), 5, -1, False), (14, ('SQ',), 5, -1, False), (15, ('SQ',), 5, -1, False)))),
    ("f( ) ssh h '\nz\n", (), ('FFF', (('SQ', 11, 5),), False, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, ('SUB',), 0, -1, False), (3, ('SUB',), 3, -1, False), (4, (), 0, -1, False), (5, (), 5, -1, False), (6, (), 5, -1, False), (7, (), 5, -1, False), (8, (), 5, -1, False), (9, (), 5, -1, False), (10, (), 5, -1, False), (11, (), 5, -1, False), (12, ('SQ',), 5, -1, False), (13, ('SQ',), 5, -1, False), (14, ('SQ',), 5, -1, False), (15, ('SQ',), 5, -1, False)))),
    ('echo (', (), ('F', (), False, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False), (5, (), 0, -1, False), (6, ('SUB',), 0, -1, False)))),
    ('a (', (), ('F', (), False, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, ('SUB',), 0, -1, False)))),
    ('a (\\', (), ('F', (), False, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, ('SUB',), 3, -1, False), (4, ('SUB',), 3, -1, False)))),
    ('a (\\\n', (), ('FF', (('SUB', 2, 0),), False, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, ('SUB',), 0, -1, False), (4, ('SUB',), 0, -1, False), (5, ('SUB',), 0, -1, False)))),
    ('x;for((i=0;i<3;i++)); do :; done\nz\n', (), ('FTT', (), True, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 2, -1, False), (3, (), 2, -1, False), (4, (), 2, -1, False), (5, (), 2, -1, False), (6, ('SUB',), 6, -1, True), (7, ('SUB', 'SUB'), 7, -1, True), (8, ('SUB', 'SUB'), 7, -1, True), (9, ('SUB', 'SUB'), 7, -1, True), (10, ('SUB', 'SUB'), 7, -1, True), (11, ('SUB', 'SUB'), 11, -1, True), (12, ('SUB', 'SUB'), 11, -1, True), (13, ('SUB', 'SUB'), 11, -1, True), (14, ('SUB', 'SUB'), 11, -1, True), (15, ('SUB', 'SUB'), 15, -1, True), (16, ('SUB', 'SUB'), 15, -1, True), (17, ('SUB', 'SUB'), 15, -1, True), (18, ('SUB', 'SUB'), 15, -1, True), (19, ('SUB',), 6, -1, True), (20, (), 2, -1, True), (21, (), 2, -1, True), (22, (), 22, -1, True), (23, (), 22, -1, True), (24, (), 22, -1, True), (25, (), 25, -1, True), (26, (), 25, -1, True), (27, (), 25, -1, True), (28, (), 28, -1, True), (29, (), 28, -1, True), (30, (), 28, -1, True), (31, (), 28, -1, True), (32, (), 28, -1, True), (33, (), 33, -1, True), (34, (), 33, -1, True), (35, (), 33, -1, True)))),
    ('x&for((i=0;i<3;i++)); do :; done\nz\n', (), ('FTT', (), True, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 2, -1, False), (3, (), 2, -1, False), (4, (), 2, -1, False), (5, (), 2, -1, False), (6, ('SUB',), 6, -1, True), (7, ('SUB', 'SUB'), 7, -1, True), (8, ('SUB', 'SUB'), 7, -1, True), (9, ('SUB', 'SUB'), 7, -1, True), (10, ('SUB', 'SUB'), 7, -1, True), (11, ('SUB', 'SUB'), 11, -1, True), (12, ('SUB', 'SUB'), 11, -1, True), (13, ('SUB', 'SUB'), 11, -1, True), (14, ('SUB', 'SUB'), 11, -1, True), (15, ('SUB', 'SUB'), 15, -1, True), (16, ('SUB', 'SUB'), 15, -1, True), (17, ('SUB', 'SUB'), 15, -1, True), (18, ('SUB', 'SUB'), 15, -1, True), (19, ('SUB',), 6, -1, True), (20, (), 2, -1, True), (21, (), 2, -1, True), (22, (), 22, -1, True), (23, (), 22, -1, True), (24, (), 22, -1, True), (25, (), 25, -1, True), (26, (), 25, -1, True), (27, (), 25, -1, True), (28, (), 28, -1, True), (29, (), 28, -1, True), (30, (), 28, -1, True), (31, (), 28, -1, True), (32, (), 28, -1, True), (33, (), 33, -1, True), (34, (), 33, -1, True), (35, (), 33, -1, True)))),
    ('x|for((i=0;i<3;i++)); do :; done\nz\n', (), ('FTT', (), True, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 2, -1, False), (3, (), 2, -1, False), (4, (), 2, -1, False), (5, (), 2, -1, False), (6, ('SUB',), 6, -1, True), (7, ('SUB', 'SUB'), 7, -1, True), (8, ('SUB', 'SUB'), 7, -1, True), (9, ('SUB', 'SUB'), 7, -1, True), (10, ('SUB', 'SUB'), 7, -1, True), (11, ('SUB', 'SUB'), 11, -1, True), (12, ('SUB', 'SUB'), 11, -1, True), (13, ('SUB', 'SUB'), 11, -1, True), (14, ('SUB', 'SUB'), 11, -1, True), (15, ('SUB', 'SUB'), 15, -1, True), (16, ('SUB', 'SUB'), 15, -1, True), (17, ('SUB', 'SUB'), 15, -1, True), (18, ('SUB', 'SUB'), 15, -1, True), (19, ('SUB',), 6, -1, True), (20, (), 2, -1, True), (21, (), 2, -1, True), (22, (), 22, -1, True), (23, (), 22, -1, True), (24, (), 22, -1, True), (25, (), 25, -1, True), (26, (), 25, -1, True), (27, (), 25, -1, True), (28, (), 28, -1, True), (29, (), 28, -1, True), (30, (), 28, -1, True), (31, (), 28, -1, True), (32, (), 28, -1, True), (33, (), 33, -1, True), (34, (), 33, -1, True), (35, (), 33, -1, True)))),
    ('x(for((i=0;i<3;i++)); do :; done\nz\n', (), ('FTT', (), True, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False), (5, (), 0, -1, False), (6, ('SUB',), 6, -1, True), (7, ('SUB', 'SUB'), 7, -1, True), (8, ('SUB', 'SUB'), 7, -1, True), (9, ('SUB', 'SUB'), 7, -1, True), (10, ('SUB', 'SUB'), 7, -1, True), (11, ('SUB', 'SUB'), 11, -1, True), (12, ('SUB', 'SUB'), 11, -1, True), (13, ('SUB', 'SUB'), 11, -1, True), (14, ('SUB', 'SUB'), 11, -1, True), (15, ('SUB', 'SUB'), 15, -1, True), (16, ('SUB', 'SUB'), 15, -1, True), (17, ('SUB', 'SUB'), 15, -1, True), (18, ('SUB', 'SUB'), 15, -1, True), (19, ('SUB',), 6, -1, True), (20, (), 0, -1, True), (21, (), 0, -1, True), (22, (), 22, -1, True), (23, (), 22, -1, True), (24, (), 22, -1, True), (25, (), 25, -1, True), (26, (), 25, -1, True), (27, (), 25, -1, True), (28, (), 28, -1, True), (29, (), 28, -1, True), (30, (), 28, -1, True), (31, (), 28, -1, True), (32, (), 28, -1, True), (33, (), 33, -1, True), (34, (), 33, -1, True), (35, (), 33, -1, True)))),
    ('x)for((i=0;i<3;i++)); do :; done\nz\n', (), ('FTT', (), True, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 2, -1, False), (3, (), 2, -1, False), (4, (), 2, -1, False), (5, (), 2, -1, False), (6, ('SUB',), 6, -1, True), (7, ('SUB', 'SUB'), 7, -1, True), (8, ('SUB', 'SUB'), 7, -1, True), (9, ('SUB', 'SUB'), 7, -1, True), (10, ('SUB', 'SUB'), 7, -1, True), (11, ('SUB', 'SUB'), 11, -1, True), (12, ('SUB', 'SUB'), 11, -1, True), (13, ('SUB', 'SUB'), 11, -1, True), (14, ('SUB', 'SUB'), 11, -1, True), (15, ('SUB', 'SUB'), 15, -1, True), (16, ('SUB', 'SUB'), 15, -1, True), (17, ('SUB', 'SUB'), 15, -1, True), (18, ('SUB', 'SUB'), 15, -1, True), (19, ('SUB',), 6, -1, True), (20, (), 2, -1, True), (21, (), 2, -1, True), (22, (), 22, -1, True), (23, (), 22, -1, True), (24, (), 22, -1, True), (25, (), 25, -1, True), (26, (), 25, -1, True), (27, (), 25, -1, True), (28, (), 28, -1, True), (29, (), 28, -1, True), (30, (), 28, -1, True), (31, (), 28, -1, True), (32, (), 28, -1, True), (33, (), 33, -1, True), (34, (), 33, -1, True), (35, (), 33, -1, True)))),
    ('x{for((i=0;i<3;i++)); do :; done\nz\n', (), ('FTT', (), True, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False), (5, (), 0, -1, False), (6, ('SUB',), 6, -1, True), (7, ('SUB', 'SUB'), 7, -1, True), (8, ('SUB', 'SUB'), 7, -1, True), (9, ('SUB', 'SUB'), 7, -1, True), (10, ('SUB', 'SUB'), 7, -1, True), (11, ('SUB', 'SUB'), 11, -1, True), (12, ('SUB', 'SUB'), 11, -1, True), (13, ('SUB', 'SUB'), 11, -1, True), (14, ('SUB', 'SUB'), 11, -1, True), (15, ('SUB', 'SUB'), 15, -1, True), (16, ('SUB', 'SUB'), 15, -1, True), (17, ('SUB', 'SUB'), 15, -1, True), (18, ('SUB', 'SUB'), 15, -1, True), (19, ('SUB',), 6, -1, True), (20, (), 0, -1, True), (21, (), 0, -1, True), (22, (), 22, -1, True), (23, (), 22, -1, True), (24, (), 22, -1, True), (25, (), 25, -1, True), (26, (), 25, -1, True), (27, (), 25, -1, True), (28, (), 28, -1, True), (29, (), 28, -1, True), (30, (), 28, -1, True), (31, (), 28, -1, True), (32, (), 28, -1, True), (33, (), 33, -1, True), (34, (), 33, -1, True), (35, (), 33, -1, True)))),
    ('x}for((i=0;i<3;i++)); do :; done\nz\n', (), ('FTT', (), True, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False), (5, (), 0, -1, False), (6, ('SUB',), 6, -1, True), (7, ('SUB', 'SUB'), 7, -1, True), (8, ('SUB', 'SUB'), 7, -1, True), (9, ('SUB', 'SUB'), 7, -1, True), (10, ('SUB', 'SUB'), 7, -1, True), (11, ('SUB', 'SUB'), 11, -1, True), (12, ('SUB', 'SUB'), 11, -1, True), (13, ('SUB', 'SUB'), 11, -1, True), (14, ('SUB', 'SUB'), 11, -1, True), (15, ('SUB', 'SUB'), 15, -1, True), (16, ('SUB', 'SUB'), 15, -1, True), (17, ('SUB', 'SUB'), 15, -1, True), (18, ('SUB', 'SUB'), 15, -1, True), (19, ('SUB',), 6, -1, True), (20, (), 0, -1, True), (21, (), 0, -1, True), (22, (), 22, -1, True), (23, (), 22, -1, True), (24, (), 22, -1, True), (25, (), 25, -1, True), (26, (), 25, -1, True), (27, (), 25, -1, True), (28, (), 28, -1, True), (29, (), 28, -1, True), (30, (), 28, -1, True), (31, (), 28, -1, True), (32, (), 28, -1, True), (33, (), 33, -1, True), (34, (), 33, -1, True), (35, (), 33, -1, True)))),
    ('x\tfor((i=0;i<3;i++)); do :; done\nz\n', (), ('FTT', (), True, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False), (5, (), 0, -1, False), (6, ('SUB',), 6, -1, True), (7, ('SUB', 'SUB'), 7, -1, True), (8, ('SUB', 'SUB'), 7, -1, True), (9, ('SUB', 'SUB'), 7, -1, True), (10, ('SUB', 'SUB'), 7, -1, True), (11, ('SUB', 'SUB'), 11, -1, True), (12, ('SUB', 'SUB'), 11, -1, True), (13, ('SUB', 'SUB'), 11, -1, True), (14, ('SUB', 'SUB'), 11, -1, True), (15, ('SUB', 'SUB'), 15, -1, True), (16, ('SUB', 'SUB'), 15, -1, True), (17, ('SUB', 'SUB'), 15, -1, True), (18, ('SUB', 'SUB'), 15, -1, True), (19, ('SUB',), 6, -1, True), (20, (), 0, -1, True), (21, (), 0, -1, True), (22, (), 22, -1, True), (23, (), 22, -1, True), (24, (), 22, -1, True), (25, (), 25, -1, True), (26, (), 25, -1, True), (27, (), 25, -1, True), (28, (), 28, -1, True), (29, (), 28, -1, True), (30, (), 28, -1, True), (31, (), 28, -1, True), (32, (), 28, -1, True), (33, (), 33, -1, True), (34, (), 33, -1, True), (35, (), 33, -1, True)))),
    ('x\nfor((i=0;i<3;i++)); do :; done\nz\n', (), ('FFTT', (), True, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 2, -1, False), (3, (), 2, -1, False), (4, (), 2, -1, False), (5, (), 2, -1, False), (6, ('SUB',), 6, -1, True), (7, ('SUB', 'SUB'), 7, -1, True), (8, ('SUB', 'SUB'), 7, -1, True), (9, ('SUB', 'SUB'), 7, -1, True), (10, ('SUB', 'SUB'), 7, -1, True), (11, ('SUB', 'SUB'), 11, -1, True), (12, ('SUB', 'SUB'), 11, -1, True), (13, ('SUB', 'SUB'), 11, -1, True), (14, ('SUB', 'SUB'), 11, -1, True), (15, ('SUB', 'SUB'), 15, -1, True), (16, ('SUB', 'SUB'), 15, -1, True), (17, ('SUB', 'SUB'), 15, -1, True), (18, ('SUB', 'SUB'), 15, -1, True), (19, ('SUB',), 6, -1, True), (20, (), 2, -1, True), (21, (), 2, -1, True), (22, (), 22, -1, True), (23, (), 22, -1, True), (24, (), 22, -1, True), (25, (), 25, -1, True), (26, (), 25, -1, True), (27, (), 25, -1, True), (28, (), 28, -1, True), (29, (), 28, -1, True), (30, (), 28, -1, True), (31, (), 28, -1, True), (32, (), 28, -1, True), (33, (), 33, -1, True), (34, (), 33, -1, True), (35, (), 33, -1, True)))),
    ('x for((i=0;i<3;i++)); do :; done\nz\n', (), ('FTT', (), True, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False), (5, (), 0, -1, False), (6, ('SUB',), 6, -1, True), (7, ('SUB', 'SUB'), 7, -1, True), (8, ('SUB', 'SUB'), 7, -1, True), (9, ('SUB', 'SUB'), 7, -1, True), (10, ('SUB', 'SUB'), 7, -1, True), (11, ('SUB', 'SUB'), 11, -1, True), (12, ('SUB', 'SUB'), 11, -1, True), (13, ('SUB', 'SUB'), 11, -1, True), (14, ('SUB', 'SUB'), 11, -1, True), (15, ('SUB', 'SUB'), 15, -1, True), (16, ('SUB', 'SUB'), 15, -1, True), (17, ('SUB', 'SUB'), 15, -1, True), (18, ('SUB', 'SUB'), 15, -1, True), (19, ('SUB',), 6, -1, True), (20, (), 0, -1, True), (21, (), 0, -1, True), (22, (), 22, -1, True), (23, (), 22, -1, True), (24, (), 22, -1, True), (25, (), 25, -1, True), (26, (), 25, -1, True), (27, (), 25, -1, True), (28, (), 28, -1, True), (29, (), 28, -1, True), (30, (), 28, -1, True), (31, (), 28, -1, True), (32, (), 28, -1, True), (33, (), 33, -1, True), (34, (), 33, -1, True), (35, (), 33, -1, True)))),
    ('$${(a', (), ('F', (), True, (), ((0, (), 0, -1, False), (1, (), 0, -1, True), (2, (), 0, -1, True), (3, (), 0, -1, True), (4, ('SUB',), 4, -1, True), (5, ('SUB',), 4, -1, True)))),
    ('()((', (), ('F', (), True, (), ((0, (), 0, -1, False), (1, ('SUB',), 1, -1, False), (2, (), 0, -1, False), (3, ('SUB',), 3, -1, True), (4, ('SUB', 'SUB'), 3, -1, True)))),
    ('<()""(<', (), ('F', (), False, (), ((0, (), 0, -1, False), (1, ('PROC',), 2, -1, False), (2, ('PROC',), 2, -1, False), (3, (), 0, -1, False), (4, ('DQ',), 0, -1, False), (5, (), 0, -1, False), (6, (), 0, -1, False), (7, (), 0, -1, False)))),
    ('>(`<<E\nE)', (), ('FF', (('PROC', 0, 0), ('BQ', 2, 2), ('HEREDOC', 3, 3)), True, (), ((0, (), 0, -1, False), (1, ('PROC',), 2, -1, False), (2, ('PROC',), 2, -1, False), (3, ('PROC', 'BQ'), 3, -1, False), (4, ('PROC', 'BQ'), 3, -1, False), (5, ('PROC', 'BQ'), 3, -1, False), (6, ('PROC', 'BQ'), 3, -1, False), (7, ('PROC', 'BQ'), 3, -1, True), (8, ('PROC', 'BQ'), 3, -1, True), (9, ('PROC', 'BQ'), 2, -1, True)))),
    ('for< `', (), ('F', (), False, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False), (5, (), 0, -1, False), (6, ('BQ',), 0, -1, False)))),
    ('{<', (), ('F', (), False, (), ((0, (), 0, -1, False), (1, (), 1, -1, False), (2, (), 1, -1, False)))),
    ('[[~', (), ('F', (), False, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False)))),
    ('1a[', (), ('F', (), False, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False)))),
    ('${x:+"', (), ('F', (), False, (), ((0, (), 0, -1, False), (1, ('PARAM',), 0, -1, False), (2, ('PARAM',), 0, -1, False), (3, ('PARAM',), 0, -1, False), (4, ('PARAM',), 0, -1, False), (5, ('PARAM',), 0, -1, False), (6, ('PARAM', 'DQ'), 0, -1, False)))),
    ('${x: }"', (), ('F', (), False, (), ((0, (), 0, -1, False), (1, ('PARAM',), 0, -1, False), (2, ('PARAM',), 0, -1, False), (3, ('PARAM',), 0, -1, False), (4, ('PARAM',), 0, -1, False), (5, ('PARAM',), 0, -1, False), (6, (), 0, -1, False), (7, ('DQ',), 0, -1, False)))),
    ('${x: `', (), ('F', (), True, (), ((0, (), 0, -1, False), (1, ('PARAM',), 0, -1, True), (2, ('PARAM',), 0, -1, True), (3, ('PARAM',), 0, -1, True), (4, ('PARAM',), 0, -1, True), (5, ('PARAM',), 0, -1, True), (6, ('PARAM', 'BQ'), 0, -1, True)))),
    ('${x:sh evil.example 2>&1 `', (), ('F', (), True, (), ((0, (), 0, -1, False), (1, ('PARAM',), 0, -1, True), (2, ('PARAM',), 0, -1, True), (3, ('PARAM',), 0, -1, True), (4, ('PARAM',), 0, -1, True), (5, ('PARAM',), 0, -1, True), (6, ('PARAM',), 0, -1, True), (7, ('PARAM',), 0, -1, True), (8, ('PARAM',), 0, -1, True), (9, ('PARAM',), 0, -1, True), (10, ('PARAM',), 0, -1, True), (11, ('PARAM',), 0, -1, True), (12, ('PARAM',), 0, -1, True), (13, ('PARAM',), 0, -1, True), (14, ('PARAM',), 0, -1, True), (15, ('PARAM',), 0, -1, True), (16, ('PARAM',), 0, -1, True), (17, ('PARAM',), 0, -1, True), (18, ('PARAM',), 0, -1, True), (19, ('PARAM',), 0, -1, True), (20, ('PARAM',), 0, -1, True), (21, ('PARAM',), 0, -1, True), (22, ('PARAM',), 0, -1, True), (23, ('PARAM',), 0, -1, True), (24, ('PARAM',), 0, -1, True), (25, ('PARAM',), 0, -1, True), (26, ('PARAM', 'BQ'), 0, -1, True)))),
    ('${A_}', (), ('F', (), False, (), ((0, (), 0, -1, False), (1, ('PARAM',), 0, -1, False), (2, ('PARAM',), 0, -1, False), (3, ('PARAM',), 0, -1, False), (4, ('PARAM',), 0, -1, False), (5, (), 0, -1, False)))),
    ('${x%', (), ('F', (), False, (), ((0, (), 0, -1, False), (1, ('PARAM',), 0, -1, False), (2, ('PARAM',), 0, -1, False), (3, ('PARAM',), 0, -1, False), (4, ('PARAM',), 0, -1, False)))),
    ('${!=', (), ('F', (), False, (), ((0, (), 0, -1, False), (1, ('PARAM',), 0, -1, False), (2, ('PARAM',), 0, -1, False), (3, ('PARAM',), 0, -1, False), (4, ('PARAM',), 0, -1, False)))),
    ('${x+', (), ('F', (), False, (), ((0, (), 0, -1, False), (1, ('PARAM',), 0, -1, False), (2, ('PARAM',), 0, -1, False), (3, ('PARAM',), 0, -1, False), (4, ('PARAM',), 0, -1, False)))),
    ('${#?', (), ('F', (), False, (), ((0, (), 0, -1, False), (1, ('PARAM',), 0, -1, False), (2, ('PARAM',), 0, -1, False), (3, ('PARAM',), 0, -1, False), (4, ('PARAM',), 0, -1, False)))),
    ('${#-', (), ('F', (), False, (), ((0, (), 0, -1, False), (1, ('PARAM',), 0, -1, False), (2, ('PARAM',), 0, -1, False), (3, ('PARAM',), 0, -1, False), (4, ('PARAM',), 0, -1, False)))),
    ('${{}<}}', (), ('F', (), False, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False), (5, (), 0, -1, False), (6, (), 0, -1, False), (7, (), 0, -1, False)))),
    ('bin(\n', (), ('FF', (), False, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False), (5, (), 0, -1, False)))),
    ('$function f(f', (), ('F', (), False, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False), (5, (), 0, -1, False), (6, (), 0, -1, False), (7, (), 0, -1, False), (8, (), 0, -1, False), (9, (), 0, -1, False), (10, (), 0, -1, False), (11, (), 0, -1, False), (12, ('SUB',), 12, -1, False), (13, ('SUB',), 12, -1, False)))),
    ('a coproc nx(\n', (), ('FF', (('SUB', 11, 0),), False, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False), (5, (), 0, -1, False), (6, (), 0, -1, False), (7, (), 0, -1, False), (8, (), 0, -1, False), (9, (), 0, -1, False), (10, (), 0, -1, False), (11, (), 0, -1, False), (12, ('SUB',), 0, -1, False), (13, ('SUB',), 0, -1, False)))),
    ("a=( ) { ssh h '\nz\n", (), ('FFF', (('SQ', 14, 0),), False, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, ('ARRAY',), 0, -1, False), (4, ('ARRAY',), 4, -1, False), (5, (), 0, -1, False), (6, (), 0, -1, False), (7, (), 0, -1, False), (8, (), 0, -1, False), (9, (), 0, -1, False), (10, (), 0, -1, False), (11, (), 0, -1, False), (12, (), 0, -1, False), (13, (), 0, -1, False), (14, (), 0, -1, False), (15, ('SQ',), 0, -1, False), (16, ('SQ',), 0, -1, False), (17, ('SQ',), 0, -1, False), (18, ('SQ',), 0, -1, False)))),
    ("echo hi; x=$(ssh h '\nz\n", (), ('FFF', (('CMD', 11, 9), ('SQ', 19, 13)), False, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False), (5, (), 0, -1, False), (6, (), 0, -1, False), (7, (), 0, -1, False), (8, (), 0, -1, False), (9, (), 9, -1, False), (10, (), 9, -1, False), (11, (), 9, -1, False), (12, ('CMD',), 13, -1, False), (13, ('CMD',), 13, -1, False), (14, ('CMD',), 13, -1, False), (15, ('CMD',), 13, -1, False), (16, ('CMD',), 13, -1, False), (17, ('CMD',), 13, -1, False), (18, ('CMD',), 13, -1, False), (19, ('CMD',), 13, -1, False), (20, ('CMD', 'SQ'), 13, -1, False), (21, ('CMD', 'SQ'), 13, -1, False), (22, ('CMD', 'SQ'), 13, -1, False), (23, ('CMD', 'SQ'), 13, -1, False)))),
    ('a &\\\n<f\nz\n', (), ('FFFF', (), False, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False), (5, (), 5, -1, False), (6, (), 5, -1, False), (7, (), 5, -1, False), (8, (), 8, -1, False), (9, (), 8, -1, False), (10, (), 8, -1, False)))),
    ('ls @(aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa) x\nz\n', (), ('FFF', (), False, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False), (5, ('SUB',), 5, -1, False), (6, ('SUB',), 5, -1, False), (7, ('SUB',), 5, -1, False), (8, ('SUB',), 5, -1, False), (9, ('SUB',), 5, -1, False), (10, ('SUB',), 5, -1, False), (11, ('SUB',), 5, -1, False), (12, ('SUB',), 5, -1, False), (13, ('SUB',), 5, -1, False), (14, ('SUB',), 5, -1, False), (15, ('SUB',), 5, -1, False), (16, ('SUB',), 5, -1, False), (17, ('SUB',), 5, -1, False), (18, ('SUB',), 5, -1, False), (19, ('SUB',), 5, -1, False), (20, ('SUB',), 5, -1, False), (21, ('SUB',), 5, -1, False), (22, ('SUB',), 5, -1, False), (23, ('SUB',), 5, -1, False), (24, ('SUB',), 5, -1, False), (25, ('SUB',), 5, -1, False), (26, ('SUB',), 5, -1, False), (27, ('SUB',), 5, -1, False), (28, ('SUB',), 5, -1, False), (29, ('SUB',), 5, -1, False), (30, ('SUB',), 5, -1, False), (31, ('SUB',), 5, -1, False), (32, ('SUB',), 5, -1, False), (33, ('SUB',), 5, -1, False), (34, ('SUB',), 5, -1, False), (35, ('SUB',), 5, -1, False), (36, ('SUB',), 5, -1, False), (37, ('SUB',), 5, -1, False), (38, ('SUB',), 5, -1, False), (39, ('SUB',), 5, -1, False), (40, ('SUB',), 5, -1, False), (41, ('SUB',), 5, -1, False), (42, ('SUB',), 5, -1, False), (43, ('SUB',), 5, -1, False), (44, ('SUB',), 5, -1, False), (45, ('SUB',), 5, -1, False), (46, ('SUB',), 5, -1, False), (47, ('SUB',), 5, -1, False), (48, ('SUB',), 5, -1, False), (49, ('SUB',), 5, -1, False), (50, ('SUB',), 5, -1, False), (51, ('SUB',), 5, -1, False), (52, ('SUB',), 5, -1, False), (53, ('SUB',), 5, -1, False), (54, ('SUB',), 5, -1, False), (55, ('SUB',), 5, -1, False), (56, ('SUB',), 5, -1, False), (57, ('SUB',), 5, -1, False), (58, ('SUB',), 5, -1, False), (59, ('SUB',), 5, -1, False), (60, ('SUB',), 5, -1, False), (61, ('SUB',), 5, -1, False), (62, ('SUB',), 5, -1, False), (63, ('SUB',), 5, -1, False), (64, ('SUB',), 5, -1, False), (65, ('SUB',), 5, -1, False), (66, ('SUB',), 5, -1, False), (67, ('SUB',), 5, -1, False), (68, ('SUB',), 5, -1, False), (69, ('SUB',), 5, -1, False), (70, ('SUB',), 5, -1, False), (71, ('SUB',), 5, -1, False), (72, ('SUB',), 5, -1, False), (73, ('SUB',), 5, -1, False), (74, ('SUB',), 5, -1, False), (75, ('SUB',), 5, -1, False), (76, ('SUB',), 5, -1, False), (77, ('SUB',), 5, -1, False), (78, ('SUB',), 5, -1, False), (79, ('SUB',), 5, -1, False), (80, ('SUB',), 5, -1, False), (81, ('SUB',), 5, -1, False), (82, ('SUB',), 5, -1, False), (83, ('SUB',), 5, -1, False), (84, ('SUB',), 5, -1, False), (85, ('SUB',), 5, -1, False), (86, ('SUB',), 5, -1, False), (87, ('SUB',), 5, -1, False), (88, ('SUB',), 5, -1, False), (89, ('SUB',), 5, -1, False), (90, ('SUB',), 5, -1, False), (91, ('SUB',), 5, -1, False), (92, ('SUB',), 5, -1, False), (93, ('SUB',), 5, -1, False), (94, ('SUB',), 5, -1, False), (95, ('SUB',), 5, -1, False), (96, ('SUB',), 5, -1, False), (97, ('SUB',), 5, -1, False), (98, ('SUB',), 5, -1, False), (99, ('SUB',), 5, -1, False), (100, ('SUB',), 5, -1, False), (101, ('SUB',), 5, -1, False), (102, ('SUB',), 5, -1, False), (103, ('SUB',), 5, -1, False), (104, ('SUB',), 5, -1, False), (105, ('SUB',), 5, -1, False), (106, ('SUB',), 5, -1, False), (107, ('SUB',), 5, -1, False), (108, ('SUB',), 5, -1, False), (109, ('SUB',), 5, -1, False), (110, ('SUB',), 5, -1, False), (111, ('SUB',), 5, -1, False), (112, ('SUB',), 5, -1, False), (113, ('SUB',), 5, -1, False), (114, ('SUB',), 5, -1, False), (115, ('SUB',), 5, -1, False), (116, ('SUB',), 5, -1, False), (117, ('SUB',), 5, -1, False), (118, ('SUB',), 5, -1, False), (119, ('SUB',), 5, -1, False), (120, ('SUB',), 5, -1, False), (121, ('SUB',), 5, -1, False), (122, ('SUB',), 5, -1, False), (123, ('SUB',), 5, -1, False), (124, ('SUB',), 5, -1, False), (125, ('SUB',), 5, -1, False), (126, ('SUB',), 5, -1, False), (127, ('SUB',), 5, -1, False), (128, ('SUB',), 5, -1, False), (129, ('SUB',), 5, -1, False), (130, ('SUB',), 5, -1, False), (131, ('SUB',), 5, -1, False), (132, ('SUB',), 5, -1, False), (133, ('SUB',), 5, -1, False), (134, ('SUB',), 5, -1, False), (135, ('SUB',), 5, -1, False), (136, ('SUB',), 5, -1, False), (137, ('SUB',), 5, -1, False), (138, ('SUB',), 5, -1, False), (139, ('SUB',), 5, -1, False), (140, ('SUB',), 5, -1, False), (141, ('SUB',), 5, -1, False), (142, ('SUB',), 5, -1, False), (143, ('SUB',), 5, -1, False), (144, ('SUB',), 5, -1, False), (145, ('SUB',), 5, -1, False), (146, ('SUB',), 5, -1, False), (147, ('SUB',), 5, -1, False), (148, ('SUB',), 5, -1, False), (149, ('SUB',), 5, -1, False), (150, ('SUB',), 5, -1, False), (151, ('SUB',), 5, -1, False), (152, ('SUB',), 5, -1, False), (153, ('SUB',), 5, -1, False), (154, ('SUB',), 5, -1, False), (155, ('SUB',), 5, -1, False), (156, ('SUB',), 5, -1, False), (157, ('SUB',), 5, -1, False), (158, ('SUB',), 5, -1, False), (159, ('SUB',), 5, -1, False), (160, ('SUB',), 5, -1, False), (161, ('SUB',), 5, -1, False), (162, ('SUB',), 5, -1, False), (163, ('SUB',), 5, -1, False), (164, ('SUB',), 5, -1, False), (165, ('SUB',), 5, -1, False), (166, ('SUB',), 5, -1, False), (167, ('SUB',), 5, -1, False), (168, ('SUB',), 5, -1, False), (169, ('SUB',), 5, -1, False), (170, ('SUB',), 5, -1, False), (171, ('SUB',), 5, -1, False), (172, ('SUB',), 5, -1, False), (173, ('SUB',), 5, -1, False), (174, ('SUB',), 5, -1, False), (175, ('SUB',), 5, -1, False), (176, ('SUB',), 5, -1, False), (177, ('SUB',), 5, -1, False), (178, ('SUB',), 5, -1, False), (179, ('SUB',), 5, -1, False), (180, ('SUB',), 5, -1, False), (181, ('SUB',), 5, -1, False), (182, ('SUB',), 5, -1, False), (183, ('SUB',), 5, -1, False), (184, ('SUB',), 5, -1, False), (185, ('SUB',), 5, -1, False), (186, ('SUB',), 5, -1, False), (187, ('SUB',), 5, -1, False), (188, ('SUB',), 5, -1, False), (189, ('SUB',), 5, -1, False), (190, ('SUB',), 5, -1, False), (191, ('SUB',), 5, -1, False), (192, ('SUB',), 5, -1, False), (193, ('SUB',), 5, -1, False), (194, ('SUB',), 5, -1, False), (195, ('SUB',), 5, -1, False), (196, ('SUB',), 5, -1, False), (197, ('SUB',), 5, -1, False), (198, ('SUB',), 5, -1, False), (199, ('SUB',), 5, -1, False), (200, ('SUB',), 5, -1, False), (201, ('SUB',), 5, -1, False), (202, ('SUB',), 5, -1, False), (203, ('SUB',), 5, -1, False), (204, (), 0, -1, False), (205, (), 0, -1, False), (206, (), 0, -1, False), (207, (), 207, -1, False), (208, (), 207, -1, False), (209, (), 207, -1, False)))),
    ('ls @(aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa) x\nz\n', (), ('FTT', (), True, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False), (5, ('SUB',), 5, -1, True), (6, ('SUB',), 5, -1, True), (7, ('SUB',), 5, -1, True), (8, ('SUB',), 5, -1, True), (9, ('SUB',), 5, -1, True), (10, ('SUB',), 5, -1, True), (11, ('SUB',), 5, -1, True), (12, ('SUB',), 5, -1, True), (13, ('SUB',), 5, -1, True), (14, ('SUB',), 5, -1, True), (15, ('SUB',), 5, -1, True), (16, ('SUB',), 5, -1, True), (17, ('SUB',), 5, -1, True), (18, ('SUB',), 5, -1, True), (19, ('SUB',), 5, -1, True), (20, ('SUB',), 5, -1, True), (21, ('SUB',), 5, -1, True), (22, ('SUB',), 5, -1, True), (23, ('SUB',), 5, -1, True), (24, ('SUB',), 5, -1, True), (25, ('SUB',), 5, -1, True), (26, ('SUB',), 5, -1, True), (27, ('SUB',), 5, -1, True), (28, ('SUB',), 5, -1, True), (29, ('SUB',), 5, -1, True), (30, ('SUB',), 5, -1, True), (31, ('SUB',), 5, -1, True), (32, ('SUB',), 5, -1, True), (33, ('SUB',), 5, -1, True), (34, ('SUB',), 5, -1, True), (35, ('SUB',), 5, -1, True), (36, ('SUB',), 5, -1, True), (37, ('SUB',), 5, -1, True), (38, ('SUB',), 5, -1, True), (39, ('SUB',), 5, -1, True), (40, ('SUB',), 5, -1, True), (41, ('SUB',), 5, -1, True), (42, ('SUB',), 5, -1, True), (43, ('SUB',), 5, -1, True), (44, ('SUB',), 5, -1, True), (45, ('SUB',), 5, -1, True), (46, ('SUB',), 5, -1, True), (47, ('SUB',), 5, -1, True), (48, ('SUB',), 5, -1, True), (49, ('SUB',), 5, -1, True), (50, ('SUB',), 5, -1, True), (51, ('SUB',), 5, -1, True), (52, ('SUB',), 5, -1, True), (53, ('SUB',), 5, -1, True), (54, ('SUB',), 5, -1, True), (55, ('SUB',), 5, -1, True), (56, ('SUB',), 5, -1, True), (57, ('SUB',), 5, -1, True), (58, ('SUB',), 5, -1, True), (59, ('SUB',), 5, -1, True), (60, ('SUB',), 5, -1, True), (61, ('SUB',), 5, -1, True), (62, ('SUB',), 5, -1, True), (63, ('SUB',), 5, -1, True), (64, ('SUB',), 5, -1, True), (65, ('SUB',), 5, -1, True), (66, ('SUB',), 5, -1, True), (67, ('SUB',), 5, -1, True), (68, ('SUB',), 5, -1, True), (69, ('SUB',), 5, -1, True), (70, ('SUB',), 5, -1, True), (71, ('SUB',), 5, -1, True), (72, ('SUB',), 5, -1, True), (73, ('SUB',), 5, -1, True), (74, ('SUB',), 5, -1, True), (75, ('SUB',), 5, -1, True), (76, ('SUB',), 5, -1, True), (77, ('SUB',), 5, -1, True), (78, ('SUB',), 5, -1, True), (79, ('SUB',), 5, -1, True), (80, ('SUB',), 5, -1, True), (81, ('SUB',), 5, -1, True), (82, ('SUB',), 5, -1, True), (83, ('SUB',), 5, -1, True), (84, ('SUB',), 5, -1, True), (85, ('SUB',), 5, -1, True), (86, ('SUB',), 5, -1, True), (87, ('SUB',), 5, -1, True), (88, ('SUB',), 5, -1, True), (89, ('SUB',), 5, -1, True), (90, ('SUB',), 5, -1, True), (91, ('SUB',), 5, -1, True), (92, ('SUB',), 5, -1, True), (93, ('SUB',), 5, -1, True), (94, ('SUB',), 5, -1, True), (95, ('SUB',), 5, -1, True), (96, ('SUB',), 5, -1, True), (97, ('SUB',), 5, -1, True), (98, ('SUB',), 5, -1, True), (99, ('SUB',), 5, -1, True), (100, ('SUB',), 5, -1, True), (101, ('SUB',), 5, -1, True), (102, ('SUB',), 5, -1, True), (103, ('SUB',), 5, -1, True), (104, ('SUB',), 5, -1, True), (105, ('SUB',), 5, -1, True), (106, ('SUB',), 5, -1, True), (107, ('SUB',), 5, -1, True), (108, ('SUB',), 5, -1, True), (109, ('SUB',), 5, -1, True), (110, ('SUB',), 5, -1, True), (111, ('SUB',), 5, -1, True), (112, ('SUB',), 5, -1, True), (113, ('SUB',), 5, -1, True), (114, ('SUB',), 5, -1, True), (115, ('SUB',), 5, -1, True), (116, ('SUB',), 5, -1, True), (117, ('SUB',), 5, -1, True), (118, ('SUB',), 5, -1, True), (119, ('SUB',), 5, -1, True), (120, ('SUB',), 5, -1, True), (121, ('SUB',), 5, -1, True), (122, ('SUB',), 5, -1, True), (123, ('SUB',), 5, -1, True), (124, ('SUB',), 5, -1, True), (125, ('SUB',), 5, -1, True), (126, ('SUB',), 5, -1, True), (127, ('SUB',), 5, -1, True), (128, ('SUB',), 5, -1, True), (129, ('SUB',), 5, -1, True), (130, ('SUB',), 5, -1, True), (131, ('SUB',), 5, -1, True), (132, ('SUB',), 5, -1, True), (133, ('SUB',), 5, -1, True), (134, ('SUB',), 5, -1, True), (135, ('SUB',), 5, -1, True), (136, ('SUB',), 5, -1, True), (137, ('SUB',), 5, -1, True), (138, ('SUB',), 5, -1, True), (139, ('SUB',), 5, -1, True), (140, ('SUB',), 5, -1, True), (141, ('SUB',), 5, -1, True), (142, ('SUB',), 5, -1, True), (143, ('SUB',), 5, -1, True), (144, ('SUB',), 5, -1, True), (145, ('SUB',), 5, -1, True), (146, ('SUB',), 5, -1, True), (147, ('SUB',), 5, -1, True), (148, ('SUB',), 5, -1, True), (149, ('SUB',), 5, -1, True), (150, ('SUB',), 5, -1, True), (151, ('SUB',), 5, -1, True), (152, ('SUB',), 5, -1, True), (153, ('SUB',), 5, -1, True), (154, ('SUB',), 5, -1, True), (155, ('SUB',), 5, -1, True), (156, ('SUB',), 5, -1, True), (157, ('SUB',), 5, -1, True), (158, ('SUB',), 5, -1, True), (159, ('SUB',), 5, -1, True), (160, ('SUB',), 5, -1, True), (161, ('SUB',), 5, -1, True), (162, ('SUB',), 5, -1, True), (163, ('SUB',), 5, -1, True), (164, ('SUB',), 5, -1, True), (165, ('SUB',), 5, -1, True), (166, ('SUB',), 5, -1, True), (167, ('SUB',), 5, -1, True), (168, ('SUB',), 5, -1, True), (169, ('SUB',), 5, -1, True), (170, ('SUB',), 5, -1, True), (171, ('SUB',), 5, -1, True), (172, ('SUB',), 5, -1, True), (173, ('SUB',), 5, -1, True), (174, ('SUB',), 5, -1, True), (175, ('SUB',), 5, -1, True), (176, ('SUB',), 5, -1, True), (177, ('SUB',), 5, -1, True), (178, ('SUB',), 5, -1, True), (179, ('SUB',), 5, -1, True), (180, ('SUB',), 5, -1, True), (181, ('SUB',), 5, -1, True), (182, ('SUB',), 5, -1, True), (183, ('SUB',), 5, -1, True), (184, ('SUB',), 5, -1, True), (185, ('SUB',), 5, -1, True), (186, ('SUB',), 5, -1, True), (187, ('SUB',), 5, -1, True), (188, ('SUB',), 5, -1, True), (189, ('SUB',), 5, -1, True), (190, ('SUB',), 5, -1, True), (191, ('SUB',), 5, -1, True), (192, ('SUB',), 5, -1, True), (193, ('SUB',), 5, -1, True), (194, ('SUB',), 5, -1, True), (195, ('SUB',), 5, -1, True), (196, ('SUB',), 5, -1, True), (197, ('SUB',), 5, -1, True), (198, ('SUB',), 5, -1, True), (199, ('SUB',), 5, -1, True), (200, ('SUB',), 5, -1, True), (201, ('SUB',), 5, -1, True), (202, ('SUB',), 5, -1, True), (203, ('SUB',), 5, -1, True), (204, ('SUB',), 5, -1, True), (205, (), 0, -1, True), (206, (), 0, -1, True), (207, (), 0, -1, True), (208, (), 208, -1, True), (209, (), 208, -1, True), (210, (), 208, -1, True)))),
    ('select<(e)\nz\n', (), ('FFF', (), False, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False), (5, (), 0, -1, False), (6, (), 0, -1, False), (7, ('PROC',), 8, -1, False), (8, ('PROC',), 8, -1, False), (9, ('PROC',), 8, -1, False), (10, (), 0, -1, False), (11, (), 11, -1, False), (12, (), 11, -1, False), (13, (), 11, -1, False)))),
    ('for((i)\nz\n', (), ('FTT', (('SUB', 3, 0),), True, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, ('SUB',), 4, -1, True), (5, ('SUB', 'SUB'), 5, -1, True), (6, ('SUB', 'SUB'), 5, -1, True), (7, ('SUB',), 4, -1, True), (8, ('SUB',), 8, -1, True), (9, ('SUB',), 8, -1, True), (10, ('SUB',), 8, -1, True)))),
    ('$function f(\nz\n', (), ('FFF', (('SUB', 11, 0),), False, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False), (5, (), 0, -1, False), (6, (), 0, -1, False), (7, (), 0, -1, False), (8, (), 0, -1, False), (9, (), 0, -1, False), (10, (), 0, -1, False), (11, (), 0, -1, False), (12, ('SUB',), 0, -1, False), (13, ('SUB',), 13, -1, False), (14, ('SUB',), 13, -1, False), (15, ('SUB',), 13, -1, False)))),
    ("for<<E '\nz\n", (), ('FFF', (('SQ', 7, 0), ('HEREDOC', 3, 0)), False, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False), (5, (), 0, -1, False), (6, (), 0, -1, False), (7, (), 0, -1, False), (8, ('SQ',), 0, -1, False), (9, ('SQ',), 0, -1, False), (10, ('SQ',), 0, -1, False), (11, ('SQ',), 0, -1, False)))),
    ('{<<E\nz\n', (), ('FFF', (('HEREDOC', 1, 1),), False, (), ((0, (), 0, -1, False), (1, (), 1, -1, False), (2, (), 1, -1, False), (3, (), 1, -1, False), (4, (), 1, -1, False), (5, (), 1, -1, False), (6, (), 1, -1, False), (7, (), 1, -1, False)))),
    ('\n()}', (), ('FF', (), False, (), ((0, (), 0, -1, False), (1, (), 1, -1, False), (2, ('SUB',), 2, -1, False), (3, (), 1, -1, False), (4, (), 1, -1, False)))),
    ('for((0)', (), ('F', (), True, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, ('SUB',), 4, -1, True), (5, ('SUB', 'SUB'), 5, -1, True), (6, ('SUB', 'SUB'), 5, -1, True), (7, ('SUB',), 4, -1, True)))),
    ('}coproc\\\nx(z', (), ('FF', (), False, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False), (5, (), 0, -1, False), (6, (), 0, -1, False), (7, (), 0, -1, False), (8, (), 0, -1, False), (9, (), 0, -1, False), (10, (), 0, -1, False), (11, ('SUB',), 11, -1, False), (12, ('SUB',), 11, -1, False)))),
    ('["]', ('ARRAY',), ('F', (('ARRAY', 0, 0),), True, (), ((0, ('ARRAY',), 0, -1, True), (1, ('ARRAY',), 0, -1, True), (2, ('ARRAY', 'DQ'), 0, -1, True), (3, ('ARRAY', 'DQ'), 0, -1, True)))),
    ('<<"""', (), ('F', (), True, (), ((0, (), 0, -1, False), (1, (), 0, -1, True), (2, (), 0, -1, True), (3, ('DQ',), 0, -1, True), (4, (), 0, -1, True), (5, ('DQ',), 0, -1, True)))),
    ('<<E\t\nE', (), ('FF', (('HEREDOC', 0, 0),), False, ((1, 'HEREDOC', 0, 0),), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False), (5, (), 0, -1, False), (6, (), 0, -1, False)))),
    ('in-(n', (), ('F', (), False, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False), (5, (), 0, -1, False)))),
    ('a\\\n1\\\n[', (), ('FTT', (), True, (), ((0, (), 0, -1, False), (1, (), 0, -1, True), (2, (), 0, -1, True), (3, (), 0, -1, True), (4, (), 0, -1, True), (5, (), 0, -1, True), (6, (), 0, -1, True), (7, (), 0, -1, True)))),
    ('\\\nth\\\nen', (), ('FFT', (), True, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 2, -1, False), (3, (), 2, -1, False), (4, (), 2, -1, True), (5, (), 2, -1, True), (6, (), 2, -1, True), (7, (), 2, -1, True), (8, (), 2, -1, True)))),
    ('c\\\na\\\n\\\nse', (), ('FTTT', (), True, (), ((0, (), 0, -1, False), (1, (), 0, -1, True), (2, (), 0, -1, True), (3, (), 0, -1, True), (4, (), 0, -1, True), (5, (), 0, -1, True), (6, (), 0, -1, True), (7, (), 0, -1, True), (8, (), 0, -1, True), (9, (), 0, -1, True), (10, (), 0, -1, True)))),
    (')case', ('ARRAY',), ('F', (('ARRAY', 0, 0),), False, ((0, 'ARRAY', 0, 0),), ((0, ('ARRAY',), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False), (5, (), 0, -1, False)))),
    ('=~[[', (), ('F', (), True, (), ((0, (), 0, -1, True), (1, (), 0, -1, True), (2, (), 0, -1, True), (3, (), 0, -1, True), (4, (), 0, -1, True)))),
    ('-$(#', (), ('F', (), False, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, ('CMD',), 3, 3, False), (3, ('CMD',), 3, 3, False), (4, ('CMD',), 3, 3, False)))),
    ("<<#'", (), ('F', (), True, (), ((0, (), 0, -1, False), (1, (), 0, -1, True), (2, (), 0, -1, True), (3, (), 0, -1, True), (4, ('SQ',), 0, -1, True)))),
    # survivors with a differing input of the sweeps of the lexer (string, set and class mutants; AST, bound and slice mutants)
    ('f=( ( ) { :; }\nz', (), ('FF', (('ARRAY', 2, 0),), False, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, ('ARRAY',), 0, -1, False), (4, ('ARRAY',), 4, -1, False), (5, ('ARRAY', 'SUB'), 4, -1, False), (6, ('ARRAY', 'SUB'), 6, -1, False), (7, ('ARRAY',), 4, -1, False), (8, ('ARRAY',), 4, -1, False), (9, ('ARRAY',), 4, -1, False), (10, ('ARRAY',), 10, -1, False), (11, ('ARRAY',), 10, -1, False), (12, ('ARRAY',), 10, -1, False), (13, ('ARRAY',), 13, -1, False), (14, ('ARRAY',), 13, -1, False), (15, ('ARRAY',), 15, -1, False), (16, ('ARRAY',), 15, -1, False)))),
    ("echo ${{ 'a$' }}\nz", (), ('FT', (), True, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False), (5, (), 0, -1, False), (6, ('PARAM',), 0, -1, True), (7, ('PARAM',), 0, -1, True), (8, ('PARAM',), 0, -1, True), (9, ('PARAM',), 0, -1, True), (10, ('PARAM', 'SQ'), 0, -1, True), (11, ('PARAM', 'SQ'), 0, -1, True), (12, ('PARAM', 'SQ'), 0, -1, True), (13, ('PARAM',), 0, -1, True), (14, ('PARAM',), 0, -1, True), (15, (), 0, -1, True), (16, (), 0, -1, True), (17, (), 17, -1, True), (18, (), 17, -1, True)))),
    ('in coproc\\\n a (\n', (), ('FTT', (('SUB', 14, 0),), True, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False), (5, (), 0, -1, False), (6, (), 0, -1, False), (7, (), 0, -1, False), (8, (), 0, -1, False), (9, (), 0, -1, True), (10, (), 0, -1, True), (11, (), 0, -1, True), (12, (), 0, -1, True), (13, (), 0, -1, True), (14, (), 0, -1, True), (15, ('SUB',), 0, -1, True), (16, ('SUB',), 0, -1, True)))),
    ("cat <<'\\E'\n;{\nE\n\n", (), ('FFFFF', (('HEREDOC', 4, 0),), False, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False), (5, (), 0, -1, False), (6, (), 0, -1, False), (7, (), 0, -1, False), (8, (), 0, -1, False), (9, (), 0, -1, False), (10, (), 0, -1, False), (11, (), 0, -1, False), (12, (), 0, -1, False), (13, (), 0, -1, False), (14, (), 0, -1, False), (15, (), 0, -1, False), (16, (), 0, -1, False), (17, (), 0, -1, False)))),
    ("coproc\nssh h '", (), ('FF', (), False, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False), (5, (), 0, -1, False), (6, (), 0, -1, False), (7, (), 7, -1, False), (8, (), 7, -1, False), (9, (), 7, -1, False), (10, (), 7, -1, False), (11, (), 7, -1, False), (12, (), 7, -1, False), (13, (), 7, -1, False), (14, ('SQ',), 7, -1, False)))),
    ("x=$(coproc\nssh h '", (), ('FF', (('CMD', 2, 0),), False, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, ('CMD',), 4, -1, False), (4, ('CMD',), 4, -1, False), (5, ('CMD',), 4, -1, False), (6, ('CMD',), 4, -1, False), (7, ('CMD',), 4, -1, False), (8, ('CMD',), 4, -1, False), (9, ('CMD',), 4, -1, False), (10, ('CMD',), 4, -1, False), (11, ('CMD',), 11, -1, False), (12, ('CMD',), 11, -1, False), (13, ('CMD',), 11, -1, False), (14, ('CMD',), 11, -1, False), (15, ('CMD',), 11, -1, False), (16, ('CMD',), 11, -1, False), (17, ('CMD',), 11, -1, False), (18, ('CMD', 'SQ'), 11, -1, False)))),
    ('echo `acopro x a[\n)\n`', (), ('FTT', (('BQ', 5, 0),), False, ((2, 'BQ', 5, 0),), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False), (5, (), 0, -1, False), (6, ('BQ',), 6, -1, False), (7, ('BQ',), 6, -1, False), (8, ('BQ',), 6, -1, False), (9, ('BQ',), 6, -1, False), (10, ('BQ',), 6, -1, False), (11, ('BQ',), 6, -1, False), (12, ('BQ',), 6, -1, False), (13, ('BQ',), 6, -1, False), (14, ('BQ',), 6, -1, False), (15, ('BQ',), 6, -1, True), (16, ('BQ',), 6, -1, True), (17, ('BQ',), 6, -1, True), (18, ('BQ',), 18, -1, True), (19, ('BQ',), 18, -1, True), (20, (), 0, -1, False), (21, (), 0, -1, False)))),
    ('echo `acopro x a[\n)\n', (), ('FTT', (('BQ', 5, 0),), True, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False), (5, (), 0, -1, False), (6, ('BQ',), 6, -1, False), (7, ('BQ',), 6, -1, False), (8, ('BQ',), 6, -1, False), (9, ('BQ',), 6, -1, False), (10, ('BQ',), 6, -1, False), (11, ('BQ',), 6, -1, False), (12, ('BQ',), 6, -1, False), (13, ('BQ',), 6, -1, False), (14, ('BQ',), 6, -1, False), (15, ('BQ',), 6, -1, True), (16, ('BQ',), 6, -1, True), (17, ('BQ',), 6, -1, True), (18, ('BQ',), 18, -1, True), (19, ('BQ',), 18, -1, True), (20, ('BQ',), 0, -1, True)))),
    ('echo ${a1:$${x:}\nz\n', (), ('FTT', (), True, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False), (5, (), 0, -1, False), (6, ('PARAM',), 0, -1, False), (7, ('PARAM',), 0, -1, False), (8, ('PARAM',), 0, -1, False), (9, ('PARAM',), 0, -1, False), (10, ('PARAM',), 0, -1, False), (11, ('PARAM',), 0, -1, True), (12, ('PARAM',), 0, -1, True), (13, ('PARAM',), 0, -1, True), (14, ('PARAM',), 0, -1, True), (15, ('PARAM',), 0, -1, True), (16, (), 0, -1, True), (17, (), 17, -1, True), (18, (), 17, -1, True), (19, (), 17, -1, True)))),
    ('echo ${a:$${x}\nz\n', (), ('FTT', (), True, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False), (5, (), 0, -1, False), (6, ('PARAM',), 0, -1, False), (7, ('PARAM',), 0, -1, False), (8, ('PARAM',), 0, -1, False), (9, ('PARAM',), 0, -1, False), (10, ('PARAM',), 0, -1, True), (11, ('PARAM',), 0, -1, True), (12, ('PARAM',), 0, -1, True), (13, ('PARAM',), 0, -1, True), (14, (), 0, -1, True), (15, (), 15, -1, True), (16, (), 15, -1, True), (17, (), 15, -1, True)))),
    ('echo $${x}\n', (), ('FT', (), True, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False), (5, (), 0, -1, False), (6, (), 0, -1, True), (7, (), 0, -1, True), (8, (), 0, -1, True), (9, (), 0, -1, True), (10, (), 0, -1, True), (11, (), 0, -1, True)))),
    ('echo ${a:$$((x}\nz\n', (), ('FTT', (), True, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False), (5, (), 0, -1, False), (6, ('PARAM',), 0, -1, False), (7, ('PARAM',), 0, -1, False), (8, ('PARAM',), 0, -1, False), (9, ('PARAM',), 0, -1, False), (10, ('PARAM',), 0, -1, True), (11, ('PARAM',), 0, -1, True), (12, ('PARAM',), 0, -1, True), (13, ('PARAM',), 0, -1, True), (14, ('PARAM',), 0, -1, True), (15, (), 0, -1, True), (16, (), 16, -1, True), (17, (), 16, -1, True), (18, (), 16, -1, True)))),
    ('echo ${a:$$(x}\nz\n', (), ('FTT', (), True, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False), (5, (), 0, -1, False), (6, ('PARAM',), 0, -1, False), (7, ('PARAM',), 0, -1, False), (8, ('PARAM',), 0, -1, False), (9, ('PARAM',), 0, -1, False), (10, ('PARAM',), 0, -1, True), (11, ('PARAM',), 0, -1, True), (12, ('PARAM',), 0, -1, True), (13, ('PARAM',), 0, -1, True), (14, (), 0, -1, True), (15, (), 15, -1, True), (16, (), 15, -1, True), (17, (), 15, -1, True)))),
    ('echo ${a:$$((1)}\nz\n', (), ('FTT', (), True, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False), (5, (), 0, -1, False), (6, ('PARAM',), 0, -1, False), (7, ('PARAM',), 0, -1, False), (8, ('PARAM',), 0, -1, False), (9, ('PARAM',), 0, -1, False), (10, ('PARAM',), 0, -1, True), (11, ('PARAM',), 0, -1, True), (12, ('PARAM',), 0, -1, True), (13, ('PARAM',), 0, -1, True), (14, ('PARAM',), 0, -1, True), (15, ('PARAM',), 0, -1, True), (16, (), 0, -1, True), (17, (), 17, -1, True), (18, (), 17, -1, True), (19, (), 17, -1, True)))),
    ('echo ${a:$$(( )}\nz\n', (), ('FTT', (), True, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False), (5, (), 0, -1, False), (6, ('PARAM',), 0, -1, False), (7, ('PARAM',), 0, -1, False), (8, ('PARAM',), 0, -1, False), (9, ('PARAM',), 0, -1, False), (10, ('PARAM',), 0, -1, True), (11, ('PARAM',), 0, -1, True), (12, ('PARAM',), 0, -1, True), (13, ('PARAM',), 0, -1, True), (14, ('PARAM',), 0, -1, True), (15, ('PARAM',), 0, -1, True), (16, (), 0, -1, True), (17, (), 17, -1, True), (18, (), 17, -1, True), (19, (), 17, -1, True)))),
    ('echo ${1:$$((}\nz\n', (), ('FTT', (), True, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False), (5, (), 0, -1, False), (6, ('PARAM',), 0, -1, False), (7, ('PARAM',), 0, -1, False), (8, ('PARAM',), 0, -1, False), (9, ('PARAM',), 0, -1, False), (10, ('PARAM',), 0, -1, True), (11, ('PARAM',), 0, -1, True), (12, ('PARAM',), 0, -1, True), (13, ('PARAM',), 0, -1, True), (14, (), 0, -1, True), (15, (), 15, -1, True), (16, (), 15, -1, True), (17, (), 15, -1, True)))),
    ('echo $$(date)\nz\n', (), ('FFF', (), False, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False), (5, (), 0, -1, False), (6, (), 0, -1, False), (7, (), 0, -1, False), (8, ('SUB',), 8, -1, False), (9, ('SUB',), 8, -1, False), (10, ('SUB',), 8, -1, False), (11, ('SUB',), 8, -1, False), (12, ('SUB',), 8, -1, False), (13, (), 0, -1, False), (14, (), 14, -1, False), (15, (), 14, -1, False), (16, (), 14, -1, False)))),
    ('echo ${a:$$ (x}\nz\n', (), ('FFF', (), False, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False), (5, (), 0, -1, False), (6, ('PARAM',), 0, -1, False), (7, ('PARAM',), 0, -1, False), (8, ('PARAM',), 0, -1, False), (9, ('PARAM',), 0, -1, False), (10, ('PARAM',), 0, -1, False), (11, ('PARAM',), 0, -1, False), (12, ('PARAM',), 0, -1, False), (13, ('PARAM',), 0, -1, False), (14, ('PARAM',), 0, -1, False), (15, (), 0, -1, False), (16, (), 16, -1, False), (17, (), 16, -1, False), (18, (), 16, -1, False)))),
    ('echo $$x $$ $$$\n', (), ('FF', (), False, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False), (5, (), 0, -1, False), (6, (), 0, -1, False), (7, (), 0, -1, False), (8, (), 0, -1, False), (9, (), 0, -1, False), (10, (), 0, -1, False), (11, (), 0, -1, False), (12, (), 0, -1, False), (13, (), 0, -1, False), (14, (), 0, -1, False), (15, (), 0, -1, False), (16, (), 0, -1, False)))),
    ('<<""\n"\n', (), ('FFF', (('HEREDOC', 0, 0),), False, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False), (5, (), 0, -1, False), (6, (), 0, -1, False), (7, (), 0, -1, False)))),
    ("coproc x if true; then ssh h '\nx\n", (), ('FFF', (('SQ', 29, 23),), False, (), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False), (5, (), 0, -1, False), (6, (), 0, -1, False), (7, (), 7, -1, False), (8, (), 7, -1, False), (9, (), 9, -1, False), (10, (), 9, -1, False), (11, (), 9, -1, False), (12, (), 12, -1, False), (13, (), 12, -1, False), (14, (), 12, -1, False), (15, (), 12, -1, False), (16, (), 12, -1, False), (17, (), 12, -1, False), (18, (), 18, -1, False), (19, (), 18, -1, False), (20, (), 18, -1, False), (21, (), 18, -1, False), (22, (), 18, -1, False), (23, (), 23, -1, False), (24, (), 23, -1, False), (25, (), 23, -1, False), (26, (), 23, -1, False), (27, (), 23, -1, False), (28, (), 23, -1, False), (29, (), 23, -1, False), (30, ('SQ',), 23, -1, False), (31, ('SQ',), 23, -1, False), (32, ('SQ',), 23, -1, False), (33, ('SQ',), 23, -1, False)))),
    ('ssh evil.example ${x:-a[\n}\n', (), ('FTT', (), True, ((1, 'PARAM', 17, 0),), ((0, (), 0, -1, False), (1, (), 0, -1, False), (2, (), 0, -1, False), (3, (), 0, -1, False), (4, (), 0, -1, False), (5, (), 0, -1, False), (6, (), 0, -1, False), (7, (), 0, -1, False), (8, (), 0, -1, False), (9, (), 0, -1, False), (10, (), 0, -1, False), (11, (), 0, -1, False), (12, (), 0, -1, False), (13, (), 0, -1, False), (14, (), 0, -1, False), (15, (), 0, -1, False), (16, (), 0, -1, False), (17, (), 0, -1, False), (18, ('PARAM',), 0, -1, True), (19, ('PARAM',), 0, -1, True), (20, ('PARAM',), 0, -1, True), (21, ('PARAM',), 0, -1, True), (22, ('PARAM',), 0, -1, True), (23, ('PARAM',), 0, -1, True), (24, ('PARAM',), 0, -1, True), (25, ('PARAM',), 0, -1, True), (26, (), 0, -1, True), (27, (), 0, -1, True)))),
])
def test_the_whole_answer_for_texts_a_mutant_of_a_table_a_set_or_a_class_read_differently(text, start, expected):
    assert _snapshot(text, start) == expected


def test_probes_given_in_any_order_and_twice_are_each_answered_with_the_state_before_their_character():
    lexed = line_states("ssh h 'x\nz", probes=(9, 1, 9, 4))
    assert sorted(lexed.probed) == [1, 4, 9]
    assert [o.kind for o in lexed.probed[1].openers] == [] and [o.kind for o in lexed.probed[9].openers] == ["SQ"]
    assert lexed.probed[4].command_at == 0


def test_a_probe_in_a_here_document_body_stands_where_the_line_that_opened_it_left_off():
    text = "cat <<E\nfoo 'x\nE\nssh h '"
    for needle in ("foo", "x\n", "E\nssh"):
        probe = line_states(text, probes=(text.index(needle),)).probed[text.index(needle)]
        assert probe.openers == () and probe.command_at == 0
