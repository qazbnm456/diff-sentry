"""Shell-like programs from a small grammar, cut short: the texts the lexer is held to bash and dash on.

A program is a few lines of words (plain, single and double quoted, `$'…'`, parameter expansions, command and process substitutions, backticks), pipelines, comments, line continuations and here-documents (quoted or not, with bodies that open constructs). Every prefix that ends at a newline, and a few that end anywhere, is a text a document can start in the middle of."""
from __future__ import annotations

import random

_TEXT = ["a", "ls", "-x", "foo=bar", "it", "x y", "(", ")", "}", "{", ";", "#", "&", "\\", "$", "=", "*", "?", "%", "!", "@", "a", "b", " "]
_BODY = ["plain", "x $x", "${x}", "$(a)", "`a`", "it's", "\"q", "$(", "${", "`", "\\", "$((1"]


def _text(rng: random.Random) -> str:
    return "".join(rng.choice(_TEXT) for _ in range(rng.randint(0, 4)))


def _single(rng: random.Random) -> str:
    return "'" + _text(rng).replace("'", "") + rng.choice(["", "\n", "\\"]) + "'"


def _double(rng: random.Random, depth: int) -> str:
    parts = [_text(rng).replace('"', "").replace("\\", ""), _param(rng, depth), _substitution(rng, depth), "`" + _simple(rng) + "`", "\n", '\\"', "\\$", "$"]
    return '"' + "".join(rng.choice(parts) for _ in range(rng.randint(0, 3))) + '"'


def _param(rng: random.Random, depth: int) -> str:
    if depth <= 0:
        return "$x"
    return rng.choice(["$x", "${x}", "${x:-" + _word(rng, depth - 1) + "}", "${#x}", "${x%%" + _text(rng).replace("}", "") + "}", "${x#*}", "${1}",
                       "${@}", "${!x}", "${x:+" + _double(rng, depth - 1) + "}", "$((1+" + rng.choice(["2", "(3)", "x"]) + "))"])


def _substitution(rng: random.Random, depth: int) -> str:
    if depth <= 0:
        return "$(a)"
    return "$(" + rng.choice(["", " "]) + _command(rng, depth - 1, multi=rng.random() < 0.5) + ")"


def _simple(rng: random.Random) -> str:
    return rng.choice(["a", "echo x", "echo $x", "ls -l"])


def _word(rng: random.Random, depth: int) -> str:
    k = rng.random()
    if k < 0.25:
        return rng.choice(["a", "ls", "-x", "foo", "x=1", "/bin/sh"])
    if k < 0.40:
        return _single(rng)
    if k < 0.58:
        return _double(rng, depth)
    if k < 0.74:
        return _param(rng, depth)
    if k < 0.86:
        return _substitution(rng, depth)
    if k < 0.92:
        return "`" + _simple(rng) + "`"
    if k < 0.96:
        return "$'" + _text(rng).replace("'", "").replace("\\", "") + rng.choice(["", "\\n", "\\'"]) + "'"
    return "<(" + _simple(rng) + ")"


def _heredoc(rng: random.Random) -> tuple[str, str]:
    tag = rng.choice(["E", "EOF", "X"])
    op = rng.choice(["<<", "<<-"])
    quote = rng.choice(["'", '"', ""]) if rng.random() < 0.4 else ""
    body = "\n".join(rng.choice(_BODY + [_text(rng)]) for _ in range(rng.randint(0, 3)))
    tabs = "\t" if op == "<<-" and rng.random() < 0.5 else ""
    return f"{rng.choice(['cat', 'sh', 'ssh h'])} {op}{quote}{tag}{quote}", f"{body}\n{tabs}{tag}" if body else f"{tabs}{tag}"


def _command(rng: random.Random, depth: int, multi: bool = False) -> str:
    out = " ".join(_word(rng, depth) for _ in range(rng.randint(1, 4)))
    if rng.random() < 0.25:
        out += rng.choice([" | ", " && ", " ; ", " || "]) + " ".join(_word(rng, depth) for _ in range(rng.randint(1, 2)))
    if rng.random() < 0.2:
        out += " \\\n " + _word(rng, depth)
    if rng.random() < 0.15:
        out += " # " + _text(rng) + rng.choice(["", "'", '"', "`", "$("])
    if multi and rng.random() < 0.5:
        head, body = _heredoc(rng)
        out = head + "\n" + body + "\n"
    return out


def _program(rng: random.Random) -> str:
    lines = []
    for _ in range(rng.randint(2, 7)):
        if rng.random() < 0.1:
            lines.append("# " + _text(rng) + rng.choice(["", "'", '"']))
        elif rng.random() < 0.2:
            head, body = _heredoc(rng)
            lines.append(head + "\n" + body)
        else:
            lines.append(_command(rng, rng.randint(1, 3), multi=True))
    return "\n".join(lines) + "\n"


def prefixes(rng: random.Random, count: int) -> list[str]:
    """The distinct texts that `count` programs cut short at every newline and at six places, each ending in a newline."""
    texts: set[str] = set()
    for _ in range(count):
        program = _program(rng)
        cuts = [k + 1 for k, ch in enumerate(program) if ch == "\n"] + [rng.randrange(1, len(program)) for _ in range(6)]
        for cut in cuts:
            text = program[:cut]
            texts.add(text if text.endswith("\n") else text + "\n")
    return sorted(texts)


# (what comes before, what closes it): the places a construct can be open in, with a few tokens put inside each
_CONTEXTS = [
    ("", ""), ("echo ", ""), ("echo $(", ")"), ('echo "$(', ')"'), ("echo ${x:-", "}"), ('echo "${x:-', '}"'), ("echo `", "`"), ("(( ", " ))"),
    ("echo $(( ", " ))"), ("cat <(", ")"), ("( ", " )"), ("{ ", "; }"), ("if x; then ", "; fi"), ("case x in a) ", ";; esac"), ("[[ ", " ]]"),
    ("a=( ", " )"), ("for x in ", "; do :; done"), ("f() { ", "; }"), ("while ", "; do :; done"), ("echo $( { ", "; } )"), ("x=${y:-$(", ")}"),
    ("echo '", "'"), ('echo "', '"'), ("echo $'", "'"), ("cat <<E\n", "\nE"), ("cat <<'E'\n", "\nE"), ("cat <<E ", ""), ("echo $(case x in a) ", ";; esac)"),
    ("echo ${x:-$(", ")}"), ("ssh evil.example ", ""), ("ssh evil.example 2>&1 ", ""), ("echo $[ ", " ]"),
]
_TOKENS = ["a", " ", ";", "|", "&", "<<E ", "<<-E ", "<<E \"$(", "E)\n", "x=$(cat <<E\n", "#", "'", '"', "`", "\\", "\\\n", "\n", ")", "}", "(", "{", "$(", "${", "$((", "))", "]]", "]", ";;",
           "esac", "fi", "<<<", "<(", "$'", "=~", "E\n", "x=", "$", ">&2 ", "2>&1 ", "<<E)", "${x:-", "$[ ", "\0", "ca\\\nse ", "((", "a[", "a=( ", "coproc x ", "function f ", "th\\\nen ", "for ", "in ", "time -p ", "do ", "done ", "if ", "while ", "until ", "select x ", "f() "]
_TAILS = ["", "E\n", "EOF\n", "\n", ")\n", "}\n", "`\n", "'\n"]


def contexts(rng: random.Random, count: int) -> list[str]:
    """Texts that put up to three tokens inside each place a construct can be open in (and cut them off there), then end in one of a few tails. Random atoms rarely build a `$(` that holds a here-document operator and closes on its line; this does."""
    texts: set[str] = set()
    for _ in range(count):
        before, after = rng.choice(_CONTEXTS)
        body = "".join(rng.choice(_TOKENS) for _ in range(rng.randint(0, 3)))
        text = before + body + (after if after and rng.random() < 0.6 else "")
        texts.add(text + "\n" + rng.choice(_TAILS))
    return sorted(texts)

