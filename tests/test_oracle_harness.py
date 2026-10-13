"""How the oracle reads what `bash -n` and `dash -n` print: the lexer is held to it, so a message read wrong makes the oracle blind. No Docker."""

from __future__ import annotations

import pytest

from tests.oracle.harness import read_diagnostics, read_probe


@pytest.mark.parametrize("shell,message,expected", [
    ("bash", "", False),
    ("bash", "s.sh: line 2: unexpected EOF while looking for matching `''", True),
    ("bash", "s.sh: line 3: warning: here-document at line 1 delimited by end-of-file (wanted `E')", True),
    ("bash", "s.sh: line 1: syntax error near unexpected token `;;'\ns.sh: line 1: `x=(;;>))'", None),
    ("bash", "s.sh: line 1: syntax error near unexpected token `;;'\ns.sh: line 3: unexpected EOF while looking for matching `''", None),
    ("bash", "s.sh: line 1: unexpected EOF while looking for matching `)'\ns.sh: line 2: syntax error: unexpected end of file", True),
    ("dash", "", False),
    ("dash", "s.sh: 2: Syntax error: Unterminated quoted string", True),
    ("dash", "s.sh: 2: Syntax error: Missing '}'", True),
    ("dash", "s.sh: 2: Syntax error: Missing '))'", True),
    ("dash", "s.sh: 2: Syntax error: end of file unexpected (expecting \")\")", True),
    ("dash", "s.sh: 2: Syntax error: end of file unexpected (expecting \"esac\")", None),
    ("dash", "s.sh: 1: Syntax error: \"(\" unexpected", None),
    ("dash", "timeout", None),
    ("bash", "timeout", None),
])
def test_what_a_shell_printed_is_read_as_open_closed_or_nothing(shell, message, expected):
    assert read_diagnostics(shell, message) is expected


@pytest.mark.parametrize("shell,quote,message,expected", [
    ("bash", "'", "s.sh: line 2: unexpected EOF while looking for matching `''", False),                 # the probe quote was read as a quote
    ("bash", "\"", "s.sh: line 2: unexpected EOF while looking for matching `\"'", False),
    ("bash", "'", "", True),                                                                           # nothing was said: the probe was swallowed
    ("bash", "'", "s.sh: line 4: warning: here-document at line 1 delimited by end-of-file (wanted `E')", True),
    ("bash", "'", "s.sh: line 1: syntax error near unexpected token `;;'\ns.sh: line 3: unexpected EOF while looking for matching `''", None),
    ("dash", "'", "s.sh: 2: Syntax error: Unterminated quoted string", False),
    ("dash", "\"", "s.sh: 2: Syntax error: Unterminated quoted string", False),
    ("dash", "'", "", True),
    ("dash", "'", "s.sh: 1: Syntax error: \"(\" unexpected", None),
    ("dash", "'", "timeout", None),
])
def test_a_probe_quote_is_swallowed_when_the_shell_does_not_call_it_unterminated(shell, quote, message, expected):
    assert read_probe(shell, quote, message) is expected

