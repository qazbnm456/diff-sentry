"""A conservative, linear-time lexer for shell quoting: what is still open where each line of a text begins?

A download piped into a shell, written in a document, is only a documented installer when no shell construct opened EARLIER swallows it as data: the quoted argument of a wrapper (`ssh evil.example '` with the download on the next line, `docker run x sh -c '…`), a here-document, a command or process substitution, `${…}`, backticks. Whether one is open is a question about the shell's lexer, which depends on the context it is in (Régis-Gianas, Jeannerod and Treinen, "Morbig: A Static Parser for POSIX Shell", SLE 2018) and so cannot be answered by counting quotes per line or by a regular expression. This module runs one pass with an explicit stack of the open constructs and a queue of pending here-documents (the two ideas Morbig and mvdan/sh share), jumping over plain text with precompiled character classes, so the work is linear in the text.

`line_states` gives, for every line, a `State(openers, unknown)`:

* `openers`: the constructs open where the line begins, outermost first. Each knows where it began and where the simple command that holds it began, so the caller can ask whether that command is a wrapper (`ssh`, `docker run`, `sh -c`). (The command of `coproc ssh h '` begins at `ssh`: the NAME of a coproc is the program of a simple command, or a name before a compound command, and the command may begin at either.)
* `unknown`: the text before the line holds something this lexer does not decide, because bash and dash (or two readings of it) disagree or because deciding needs a parser: `$'…\\'…'`; a quote in `$((…))`, or in `${…}` inside double quotes; `${name:` (the name may be digits or a special parameter) followed by `}` or by a quote, a backtick or a backslash (a substring offset is arithmetic to bash, and dash reads a quote there as a string and the `}` of `${a:}` as its operator); `$'…'` in `$((…))` or `${…}`; a `${` that no parameter name follows (`${'a'}`, `${\\a}`, `${#'a'}`; a workflow expression `${{ x }}` is a word); a `(` or `)` in a `${…}` inside `$((…))`; `$[ … ]`; `$${`, and `$$(` in a `${a:…}` (dash reads a `$` and the expansion `${` or the parenthesis where bash reads the process id and a brace or a parenthesis, in some contexts: undecided in all); a `((` where a command can begin (after a separator, a reserved word, `time -p`, the NAME of `function`/`coproc`/`for`/`select`, `=`, `)` or `for`), and `<((`; a line continuation inside a two-character token (`$` and `(`, `<` and `<`, `)` and `)`), or inside a word in `$(` or `<(` (`ca\\⏎se`), or one that cuts a keyword of the grammar (`th\\⏎en`, `ca\\⏎se`, `do\\⏎ne`, `time -\\⏎-`) or a name that a `[` follows, or sits in `extglob`, `[[`, `=~`, `((`, `=(`; an assignment subscript (`a[`, `a=( [1`) that is not a plain `[…]` on its line (quotes and `$name` are plain; `)`, `;` and `$(` are not); `$((echo a); (echo b))`; `case` anywhere inside `(`, `$(`, `<(` or `name=(`; `[[ … =~ … ]]`; an extended glob once `extglob` has been read; a `(` that follows a word inside a substitution (outside one it is a syntax error to every shell but bash inside `[[ … ]]`, where it groups a test, and opens nothing here, so `[a](#b)` and ``Fix `x` (#1)`` lines pile up no subshells; the `)` of such a paren ends no case pattern); a here-document whose line also holds `$(`, `<(` or `(` (in double quotes too: `<<E "$(a`), that a substitution closes on its own line, whose delimiter it cannot read (or has a quote across a newline), or whose unquoted body continues a line with a backslash or opens a construct past its line; a nested backtick substitution, or a backtick body with two backslashes in front of a quote or a `$`; nesting deeper than `MAX_DEPTH`. It stays set to the end of the text, except for what a backtick body that closes and holds no quote leaves undecided when nothing is open around it (an inline code span such as `list[str | Enum]`): that is undecided for the lines of the body only. A caller that counts it (`indicators._enclosing_lines`) does so on the lines after the first line, at or after the one that raised it, on which a command may begin like a wrapper's: it may only make a verdict more severe. `comments=False` reads a `#` as an ordinary character, as a zsh does in a terminal. A `#` after the `)` that ends a case pattern begins a comment.

`line_states(text, probes=offsets)` also answers where each offset stands (`Lexed.probed`: a `Probe` with the constructs open before that character, where its simple command began, the `#` of the comment it is in, and whether something undecided came before it); the caller asks about the words of a single line.

A text starts at the top level unless the caller says it starts inside a construct. `tests/test_oracle.py` (opt-in) checks the lexer against `bash -n` and `dash -n`.
"""
from __future__ import annotations

import re
from bisect import bisect_left, bisect_right
from dataclasses import dataclass

MAX_DEPTH = 16

# What ends a run of plain text in each context. Everything else is skipped in one step.
_DQ_SPECIAL = re.compile(r'[\\"`$]')
_ANSI_SPECIAL = re.compile(r"[\\']")
_BQ_SPECIAL = re.compile(r"[\\`]")
_CMD_SPECIAL = re.compile(r"[\\'\"`$#<>(){}\n;&| \t]")
_HEREDOC_WORD = re.compile(r"<<(?:(-)|(?!-))(?:[ \t]|\\\n)*+((?:\\[\s\S]|'[^'\n]*'|\"[^\"\n]*\"|[^ \t\n;&|<>()'\"\\`$])+)")     # one shell word, quoted or not
_BQ_BACKSLASHES = re.compile(r"(?<!\\)\\{2,}['\"$]")         # from the start of a run, or every position of a long run would scan the rest of it
_BLANKS = " \t"
_CONTINUATION = "\\\n"
_EXTGLOB = "@!+*?"
# What may follow `${`: a parameter name or a special parameter, with `#` (length) or `!` (indirection) in front, and then `}`, an operator or a dot (`${var.ami}`, `${project.version}`: Terraform, Maven and JavaScript spell it so; the shells close it at the `}`).
# Anything else (a quote, a backslash, `$(`, a blank, a second `$`) is read differently by bash and dash.
_SUBSCRIPT = re.compile(r"(?<![A-Za-z0-9_])[A-Za-z_][A-Za-z0-9_]*\[")         # `a[`: bash reads on to the matching `]`, through newlines
_SUBSCRIPT_PIECE = r"""[^\[\]();|&<>`$\\#\n'"]|\$(?=[A-Za-z_])|'[^'\n]*'|"[^"\n$`\\]*\""""
_PLAIN_SUBSCRIPT = re.compile(rf"\[(?:{_SUBSCRIPT_PIECE}|\[(?:{_SUBSCRIPT_PIECE})*\])*\]")        # `[1]`, `["name"]`, `[$i]`, `[b[0]]`
_SUBSTRING_RISK = re.compile(r"[#!]?(?:(?<![A-Za-z0-9_])(?:[A-Za-z_][A-Za-z0-9_]*|[0-9]+)|[@*?$!#-]):(?:\}|(?![-=?+])[^}\n]{0,200}['\"`\\])")       # `${a:'x'}`: a substring offset is arithmetic to bash, and dash reads a quote there as a string; `${a:}`: dash takes the `}` for its operator
_PARAM_START = re.compile(r"[#!]?(?:(?<![A-Za-z0-9_])(?:[A-Za-z_][A-Za-z0-9_]*|[0-9]+)|[@*?$!#-])(?=[}:#%/^,@\[=+?*.-])")
# `${{ secrets.X }}`, `${{ github.ref == 'refs/heads/main' }}`: a workflow expression, read as a word when it ends on its line, holds no double quote and no `}}` inside a single-quoted string (bash closes the parameter at the first `}`, dash calls it a bad substitution; neither leaves anything open).
_EXPRESSION = re.compile(r"\$\{\{(?:(?![<>]\(|<<)[^'\"}\n\\`$]|\}(?!\})|'(?:[^'\"}\n\\`$]|\}(?!\}))*')*\}\}")


def _expression_end(text: str, at: int) -> int:
    """Where the workflow expression that begins at `at` (a `$` followed by `{{`) ends, or -1."""
    m = _EXPRESSION.match(text, at)
    return m.end() if m else -1
_NAMED = frozenset({"function", "coproc", "for", "select"})
_PAREN_KINDS = frozenset({"CMD", "SUB", "ARRAY", "PROC"})      # the constructs that a `)` ends
_NOT_A_WORD_END = frozenset(";&|<>({=$\n)[!")         # in front of a `(`: an operator or an opener, not the end of a word
_RESERVED = frozenset({"then", "do", "else", "elif", "if", "while", "until", "!", "time", "coproc"})      # words after which a command begins


def _joins_a_redirect(text: str, i: int) -> bool:
    """Whether the line continuations at `i` are followed by `>`: `&\\⏎>f` is bash's `&>f` and, to dash, a `&` and a `>f`."""
    while text.startswith(_CONTINUATION, i):
        i += 2
    return text[i:i + 1] == ">"


def _blank_back(text: str, i: int) -> int:
    """`i` moved back over blanks and line continuations (`\\⏎`), which the shell does not see."""
    while i > 0 and (text[i - 1] in " \t" or text[i - 2:i] == "\\\n"):
        i -= 2 if text[i - 1] == "\n" else 1
    return i


_IN_RE = re.compile(r"(?<![^\s;&|(){}])i(?:\\\n)?n\Z")


def _follows_in(text: str, k: int) -> bool:
    """Whether the word that ends at `k` is `in` (a line continuation may cut it): `case x in (a)` opens a pattern, not a command."""
    return _IN_RE.search(text, max(0, k - 8), k) is not None                     # the lookbehind sees the character in front of the window


def _arithmetic_command_may_begin(text: str, i: int) -> bool:
    """Whether a `((` at `i` that is not at a command position is still one: after `=` (`a=((1))`), `)` (`f() ((1))`) or `for`."""
    i = _blank_back(text, i)
    return text[i - 1:i] in ("=", ")") or (text[i - 3:i] == "for" and text[i - 4:i - 3] in ("", " ", "\t", "\n", ";", "&", "|", "(", ")", "{", "}"))


_COMPOUND_NAME_RE = re.compile(r"(?:\A|(?<=[\s;&|(){}`$]))(?:coproc|function)(?:[ \t]|\\\n)+(?:[^\s;&|\\]|\\\n)*\Z")


def _names_a_compound(text: str, k: int) -> bool:
    """Whether the word that ends at `k` is the NAME of `coproc` or `function` (`coproc NAME (cmd)`, `function NAME (cmd)`: a compound command follows)."""
    window = text[max(0, k - 200):k]
    return ("coproc" in window or "function" in window) and _COMPOUND_NAME_RE.search(window) is not None


def _stray_paren(text: str, i: int) -> bool:
    """Whether the `(` at `i`, which is not where a command begins, follows a word (`f(x)`, `[a](#b)`, `foo (bar)`): a syntax error to every shell (bash alone groups a test so in `[[ ( a == b ) ]]`, where the pair holds no quote state either way), which ends the command there. A function body (`f()`, `f ( )`), a case pattern (`case x in (a)`) and the compound command that follows the NAME of a coproc or a function are no such paren, and neither is the paren of an extended glob group."""
    k = _blank_back(text, i)
    if not text[k - 1:k] or text[k - 1:k] in _NOT_A_WORD_END or (text[k - 1:k] in _EXTGLOB and not text[k:i].replace(_CONTINUATION, "")):
        return False                                # an operator or an opener in front of the paren: a command (or an extglob group) may begin
    after = i + 1
    while after < len(text) and text[after] in " \t":
        after += 1
    if text[after:after + 1] in (")", "") or (text[after] == "\\" and text[after + 1:after + 2] in ("\n", "")):
        return False                                # a function body, or a paren whose next word the shells read after a line continuation or the end
    return not (_follows_in(text, k) or _names_a_compound(text, k))


_EXTGLOB_PLAIN_BODY = re.compile(r"[\w.,|:/ \t~=+-]*")
_EXTGLOB_GROUP_MAX = 200       # a longer group is undecided


def _extglob_group_may_differ(text: str, i: int) -> bool:
    """Whether the `(` at `i`, glued to one of `@!+*?`, is read differently by a bash that has `extglob` on (the group is a pattern then, and the word goes on after its `)`) in a way that moves a quote: the group holds more than plain pattern characters (a newline is none), is not closed within `_EXTGLOB_GROUP_MAX` characters (the search is bounded, so a run of `+(` costs a constant each), or a `#` follows it.
    The option is the shell's, not the text's (`shopt -s extglob` may be in another block, spelled with quotes, or set by a startup file)."""
    close = text.find(")", i, i + _EXTGLOB_GROUP_MAX)
    return close == -1 or text[close + 1:close + 2] == "#" or _EXTGLOB_PLAIN_BODY.fullmatch(text, i + 1, close) is None


def _function_parens(text: str, i: int) -> bool:
    """Whether the empty `()` that opens at `i` follows a word: `f() if (cmd)`, the body of a function is a compound command, so one begins after it."""
    k = _blank_back(text, i)
    return k > 0 and text[k - 1:k] not in _NOT_A_WORD_END


_KEYWORDS = _RESERVED | _NAMED | {"-p", "--"}           # the words after which the lexer takes a command to begin (`time -p (cmd)`, `function f (cmd)`)
_CUT_KEYWORDS = _KEYWORDS | {"case", "esac", "in", "done", "fi"}     # the words of the grammar a line continuation may cut: the shells read the whole (and differ in what they say of an unfinished one)


def _is_word_char(ch: str) -> bool:
    return ch.isascii() and (ch.isalnum() or ch in "_-")


def _splits_a_word(text: str, i: int, after: int) -> bool:
    """Whether the run of line continuations that begins at `i` and ends at `after` cuts a word whose whole is read differently from its halves: a keyword (`th\\⏎en`, `fu\\⏎nction`, `time -\\⏎-`: the word after it is at a command position; `ca\\⏎se`, `do\\⏎ne`, and a word cut more than once, `c\\⏎a\\⏎se`) or an identifier that a `[` follows (`a\\⏎1a[`, `a\\⏎[1`: the joined name opens an assignment subscript)."""
    if not (i and _is_word_char(text[i - 1])):
        return False
    start, steps = i, 0
    while start > 0 and steps < 16:
        if _is_word_char(text[start - 1]):
            start -= 1
        elif text[start - 2:start] == _CONTINUATION:
            start -= 2
        else:
            break
        steps += 1
    end, steps = after, 0
    while end < len(text) and steps < 16:
        if _is_word_char(text[end]):
            end += 1
        elif text.startswith(_CONTINUATION, end):
            end += 2
        else:
            break
        steps += 1
    return text[end:end + 1] == "[" or (text[start:i] + text[after:end]).replace(_CONTINUATION, "") in _CUT_KEYWORDS


_COMMANDS = ("TOP", "CMD", "PROC", "SUB", "ARRAY", "BQ")        # the contexts in which commands are read


@dataclass(frozen=True, slots=True)
class Opener:
    """An open construct. `kind` is SQ, DQ, ANSI, BQ, CMD, PROC, SUB, ARRAY (`a=(`), ARITH, PARAM, HEREDOC or BODY (the text of an unquoted here-document, which dash reads as if in double quotes); `offset` is where it began; `command_at` is where the simple command that holds it began."""
    kind: str
    offset: int
    command_at: int


@dataclass(frozen=True, slots=True)
class State:
    openers: tuple[Opener, ...]
    unknown: bool


@dataclass(frozen=True, slots=True)
class Probe:
    """Where an offset of the text stands, as the shell reads it up to that character: the constructs open there (outermost first), where the simple command that holds it began, the offset of the `#` that begins the comment it is in (-1: it is in none), and whether something undecided was seen before it."""
    openers: tuple[Opener, ...]
    command_at: int
    comment_at: int
    unknown: bool


class Lexed(list):
    """The states, one per line, and `closed`: the constructs that began on one line and ended on a later one, each with the line it ended on. (A string a wrapper opened and the shell closed again is no longer open, but the text is a script that ran the wrapper, and a caller may want to know.) `probed` answers the offsets that `line_states` was asked about."""

    closed: list[tuple[int, Opener]]
    unknown_at_end: bool        # `unknown` after the last character: it may have been set on the last line, which no state shows
    probed: dict[int, Probe]


def line_states(text: str, start: tuple[Opener, ...] = (), base: int = 0, unknown_before: bool = False, comments: bool = True,
                probes: tuple[int, ...] = ()) -> Lexed:
    """The state where each line begins: one entry per line, so `text.count("\\n") + 1` of them. `base` is where `text` begins in the text it was cut from (the body of a backtick substitution is read as a text of its own, and inherits `unknown`). `comments=False` reads a `#` as an ordinary character, as a zsh does in a terminal (its `interactive_comments` is off by default). `probes` are offsets (of `text`, in any order) whose `Probe` is wanted in `Lexed.probed`: the state before that character is read, or inside the comment it is part of. A probe inside a here-document body gets the state of the line that opened it (the body's own `HEREDOC` is in the states of its lines, not in a probe); one inside the body of a backtick substitution gets the exact state there, the substitution's opener below the constructs that the body opens (the caller probes single lines)."""
    stack: list[Opener] = list(start)
    arith: list[int] = [0] * sum(1 for o in stack if o.kind == "ARITH")     # open inner parentheses of each ARITH
    pending: list[tuple[str, bool, int, int, bool]] = []    # here-documents whose body follows: delimiter, <<-, offset, command, quoted
    unknown = unknown_before
    substitutions = sum(1 for o in stack if o.kind in ("CMD", "PROC"))      # how many `$(` and `<(` are open
    parens = sum(1 for o in stack if o.kind in _PAREN_KINDS)                # how many constructs a `)` ends are open
    extglob = False                     # the word `extglob` has been read: extended patterns are on
    dbracket = False                    # a `[[` has been read: `=~` may be the regular expression operator
    n = len(text)
    i = 0
    word_start = True                   # the previous character ends a word (or there is none)
    command_at = 0                      # where the simple command being read began
    fresh = True                        # the next non-blank character starts a command
    prev_keyword = ""                   # the reserved word the last command-position word was (`time` keeps the command position through its options)
    name_slot = False                   # the next word is the NAME of `function`, `coproc`, `for` or `select`: a command follows it
    slot_coproc = False                 # ... and the keyword was `coproc`, whose NAME is the program of a simple command (`coproc ssh h '`)
    pinned = -1                         # where the NAME of a `coproc` began: the simple command that follows it may be the NAME and its arguments
    fn_close = -2                       # where the `)` of an empty `( )` (the parens of a function definition) is: a `{` right after it is the reserved word
    in_name = False                     # a NAME is being read (it may hold `$`, `#`, quotes): the blank or operator that ends it starts a command
    interned: dict[tuple, State] = {}   # the States handed out so far by stack and flag: a line whose stack was seen before shares its State
    states = Lexed()
    states.closed = []
    probed: dict[int, Probe] = {}
    states.probed = probed
    wanted = tuple(sorted(set(probes)))      # the offsets whose Probe is asked for, once each and in order
    npr = len(wanted)
    nxt = 0                             # the first of them not answered yet
    opened_on = [-1] * len(stack)       # the line each open construct began on (-1: before the text)

    def give(upto: int, comment_at: int = -1) -> None:
        """Answer the probes that lie before `upto` with the state as it is now."""
        nonlocal nxt
        while nxt < npr and wanted[nxt] < upto:
            probed[wanted[nxt]] = Probe(tuple(stack), base + command_at, base + comment_at if comment_at >= 0 else -1, unknown)
            nxt += 1

    def snap(extra: tuple[Opener, ...] = ()) -> State:
        key = (tuple(stack) + extra, unknown)
        got = interned.get(key)
        if got is None:
            if len(interned) >= 1024:
                interned.clear()
            got = interned[key] = State(*key)
        return got

    def skipped(frm: int, upto: int) -> None:
        """The lines that begin inside text[frm:upto], which a jump over plain text does not visit: all in the current state."""
        k = text.count("\n", frm, upto)
        if k:
            states.extend([snap()] * k)

    def push(kind: str, at: int) -> None:
        nonlocal unknown, substitutions, parens, in_name, pinned, name_slot
        if len(stack) >= MAX_DEPTH:
            unknown = True
        else:
            stack.append(Opener(kind, base + at, base + command_at))
            opened_on.append(len(states) - 1)
            if kind in ("CMD", "PROC", "SUB"):
                in_name, pinned, name_slot = False, -1, False       # the commands inside have a NAME slot of their own: `coproc $(ssh h '`, `coproc (x="$(ssh h '`
            if kind in ("CMD", "PROC"):
                substitutions += 1
            if kind in _PAREN_KINDS:
                parens += 1

    def close() -> Opener:
        """The innermost construct ends here; if it began on an earlier line, it is recorded as closed."""
        nonlocal substitutions, parens
        opener = stack.pop()
        if opener.kind in ("CMD", "PROC"):
            substitutions -= 1
        if opener.kind in _PAREN_KINDS:
            parens -= 1
        began = opened_on.pop()
        if len(states) - 1 > began:
            states.closed.append((len(states) - 1, opener))
        return opener

    def backtick(at: int) -> int:
        """Read the substitution whose backtick is at `at`: the shell cuts its body at the first backtick that is not escaped and then reads the body as commands, so the lines inside it begin in whatever the body has open. Returns where to go on."""
        nonlocal unknown, nxt
        j = at + 1
        while True:
            m = _BQ_SPECIAL.search(text, j)
            if m is None:
                end = n
                break
            if text[m.start()] == "\\":
                if text[m.start() + 1:m.start() + 2] == "`":
                    unknown = True              # a nested substitution: another level of backslash quoting
                j = m.start() + 2
                continue
            end = m.start()
            break
        opener = Opener("BQ", base + at, base + command_at)
        here = len(states) - 1
        if _BQ_BACKSLASHES.search(text, at + 1, end):
            unknown = True                      # the shell halves `\\` before it reads the body: whether the quote after them is live is not counted here
        inside = ()
        if nxt < npr:
            lo = bisect_right(wanted, at, nxt)
            inside = tuple(p - at - 1 for p in wanted[lo:bisect_left(wanted, end, lo)])
        inner = line_states(text[at + 1:end], (*stack, opener), base + at + 1, unknown, comments, inside)
        if inside:
            for p, answer in inner.probed.items():
                probed[p + at + 1] = answer
            while nxt < npr and wanted[nxt] < end:
                nxt += 1
        states.extend(inner[1:])
        states.closed.extend((here + line, o) for line, o in inner.closed)
        if end >= n or stack or "'" in text[at + 1:end] or '"' in text[at + 1:end]:
            unknown = unknown or inner.unknown_at_end
        # (otherwise the body is read apart from the text around it, and cut at its closing backtick: with no quote in it and nothing open around it, what it leaves undecided (`a[1`, `${ x; }`) is undecided for its own lines and for no other)
        if end < n:
            if len(states) - 1 > here:
                states.closed.append((len(states) - 1, opener))
            return end + 1
        stack.append(opener)                    # never closed
        opened_on.append(here)
        return n

    states.append(snap())
    while i < n:
        top = stack[-1].kind if stack else "TOP"
        # ---- quoting contexts: only a few characters matter -----------------------------------------------------------------
        if top == "SQ":
            j = text.find("'", i)
            if nxt < npr:
                give(n + 1 if j < 0 else j + 1)
            skipped(i, n if j < 0 else j)
            if j < 0:
                i = n
            else:
                close()
                i = j + 1
            continue
        if top == "ANSI":
            m = _ANSI_SPECIAL.search(text, i)
            j = n if m is None else m.start()
            if nxt < npr:
                give(n + 1 if m is None else j + (2 if text[j] == "\\" else 1))
            skipped(i, j)
            if m is None:
                i = n
            elif text[j] == "\\":
                if text[j + 1:j + 2] == "'":
                    unknown = True              # `$'\''` is one string in bash and an error in dash
                if text[j + 1:j + 2] == "\n":
                    states.append(snap())
                i = j + 2
            else:
                close()
                i = j + 1
            continue
        if top in ("DQ", "BODY"):
            m = _DQ_SPECIAL.search(text, i)
            j = n if m is None else m.start()
            skipped(i, j)
            if m is None:
                if nxt < npr:
                    give(n + 1)
                i = n
                continue
            c, nx = text[j], text[j + 1:j + 2]
            if nxt < npr:
                give(j + (2 if c == "\\" else 1))
            if c == "$" and (text.startswith(_CONTINUATION, j + 1) or (nx == "(" and text.startswith(_CONTINUATION, j + 2))):
                unknown = True                  # a line continuation inside `$(` or `$((` joins its halves: not decided here
            if c == "\\":
                if nx == "\n":
                    states.append(snap())
                i = j + 2
            elif c == '"':
                if top == "DQ":
                    close()
                i = j + 1                       # in the text of a here-document a lone `"` is a character
            elif c == "`":
                i = backtick(j)
            elif c == "$" and nx == "(":
                if text[j + 2:j + 3] == "(":
                    push("ARITH", j)
                    arith.append(0)
                    i = j + 3
                else:
                    unknown = unknown or bool(pending)      # `<<E "$(…`: the body of the here-document may begin inside the substitution
                    push("CMD", j)
                    command_at = i = j + 2
                    fresh = True
                    word_start = True
            elif c == "$" and nx == "[":
                unknown = True                  # `$[ … ]` is the old spelling of `$(( … ))`, and a `)` in it is not the end of anything
                i = j + 2
            elif c == "$" and nx == "{" and text[j + 2:j + 3] == "{" and _expression_end(text, j) >= 0:
                i = _expression_end(text, j)
            elif c == "$" and nx == "{":
                push("PARAM", j)
                unknown = unknown or _PARAM_START.match(text, j + 2) is None or _SUBSTRING_RISK.match(text, j + 2) is not None
                i = j + 2
            else:
                i = j + 2 if c == "$" and nx == "$" else j + 1      # `$$` is the process id: a `(` after it opens nothing
            continue
        # ---- command-like contexts: TOP, CMD, PROC, SUB, ARITH, PARAM -------------------------------------------------------
        m = _CMD_SPECIAL.search(text, i)
        j = n if m is None else m.start()
        if j > i:                                # plain text: part of a word (it holds no newline)
            named, name_slot = name_slot, False
            named_coproc = named and slot_coproc
            if fresh:
                command_at = pinned if pinned >= 0 and text[i:j] not in _RESERVED else i
                pinned = -1
                if prev_keyword == "time" and text[i:j] in ("-p", "--"):
                    fresh = True                     # `time -p (cmd)`: the options keep the command position
                else:
                    fresh = text[i:j] in _RESERVED       # a command follows `then`, `do`, `!` and the like
                    prev_keyword = text[i:j] if fresh else ""
                name_slot = text[i:j] in _NAMED
                slot_coproc = text[i:j] == "coproc"
            if named:
                in_name = True                       # `function f (cmd)`, `coproc x if …`, `for x do …`: a command follows the NAME
                if named_coproc:
                    pinned = command_at
            if parens and text[i:j] == "case":
                unknown = True                   # `case x in a) …` inside `(`, `$(`, `<(` or `a=(`: its `)` is not the end of that construct
            if "[" in text[i:j]:
                word = text[i:j]
                if top == "ARRAY" and word[0] == "[" and _PLAIN_SUBSCRIPT.match(text, i) is None:
                    unknown = True               # `a=( [1`: an array element's subscript runs on to its `]`, through newlines and parens
                elif any(_PLAIN_SUBSCRIPT.match(text, i + m.end() - 1) is None for m in _SUBSCRIPT.finditer(word)):
                    unknown = True               # `a[1`, `a[)`, `>&-a[`: so does an assignment's, wherever the name begins in the word
            if not dbracket and text.find("[[", i, j) >= 0:
                dbracket = True
            if dbracket and text.find("=~", i, j) >= 0:
                unknown = True                   # a regular expression in `[[ … =~ … ]]` follows its own quoting rules
            if not extglob and text.find("extglob", i, j) >= 0:
                extglob = True                   # `shopt -s extglob`: from here on `@(a|b)` is a pattern
            word_start = False
            if nxt < npr:
                give(j)
            i = j
            if m is None:
                break
        c, nx = text[i], text[i + 1:i + 2]
        pin_here = False
        if in_name and (c in _BLANKS or c in "\n;&|()<>"):
            fresh, in_name = True, False
        elif name_slot and c not in _BLANKS and c not in "\n;&|()<>" and not (c == "\\" and nx == "\n"):
            name_slot, in_name = False, True                 # the NAME begins with a character that is no plain text (`function } (cmd)`, `function $x (cmd)`)
            pin_here = slot_coproc
        if (text.startswith(_CONTINUATION, i + 1) and (c in "$<>" or (c == ")" and top == "ARITH") or (c == "&" and _joins_a_redirect(text, i + 1)))) or (
                text.startswith(_CONTINUATION, i + 2) and ((c == "<" and nx == "<") or (c == "$" and nx == "("))):
            unknown = True                      # a line continuation inside `$(`, `$((`, `<<`, `<<<` or `))` joins its halves: not decided here
        if c in _BLANKS:
            if nxt < npr:
                give(i + 1)
            word_start = True
            i += 1
            continue
        if c == "\n":
            if nxt < npr:
                give(i + 1)
            i += 1
            word_start = True
            pinned = -1
            if top in _COMMANDS:
                fresh = True
                if pending:
                    i, bad, more = _bodies(text, i, pending, snap, states, base, bool(substitutions))
                    unknown = unknown or bad
                    pending.clear()
                    if nxt < npr:
                        give(i)
                    if more:
                        states.append(snap())       # the line after the last delimiter
                    continue
            states.append(snap())
            continue
        if c == "\\" and nx == "\n":                  # a line continuation: nothing happens, and the next line goes on
            if text[i - 2:i] != _CONTINUATION:           # the run of continuations that begins here is judged once, by its first
                after = i + 2
                while text.startswith(_CONTINUATION, after):
                    after += 2
                if (substitutions and text[i - 1:i].isalnum() and text[after:after + 1].isalnum()) or _splits_a_word(text, i, after) \
                        or text[i - 1:i] + text[after:after + 1] in ("[[", "=~", "((", "=(") or "extglob" in text[max(0, i - 6):i] + text[after:after + 6]:
                    unknown = True              # in the middle of a word: `ca\⏎se`, `ext\⏎glob`, `[\⏎[` are the words the tests below look for
            if nxt < npr:
                give(i + 2)
            states.append(snap())
            i += 2
            continue
        at_command = fresh
        if fresh:
            command_at = pinned if pinned >= 0 and c not in "{(" else i
            pinned = -1
            fresh = False
        if pin_here:
            pinned = command_at
        if c == "{" and (nx in ("", " ", "\t", "\n", "(", ")", ";", "&", "|", "<", ">") or text.startswith(_CONTINUATION, i + 1)) and (at_command or fn_close == _blank_back(text, i) - 1):
            fresh = True                        # a command follows the reserved word `{` (`f() { a[1]=x; }`); an argument `{` (`ssh h { '`) is a word
        is_comment = c == "#" and word_start and top in _COMMANDS and comments
        if nxt < npr and not is_comment:
            give(i + (2 if c == "\\" else 1))
        if c == "\\":
            i += 2
            word_start = False
        elif is_comment:
            k = text.find("\n", i)
            if nxt < npr:
                give(n + 1 if k < 0 else k, i)
            i = n if k < 0 else k
        elif c == "'":
            if (top == "PARAM" and any(o.kind in ("DQ", "BODY") for o in stack)) or arith:
                unknown = True                  # `"${x:-'}'}"` and `$(('a'))` are read differently by bash and dash
            push("SQ", i)
            i += 1
            word_start = False
        elif c == '"':
            if arith:
                unknown = True                  # `$(("a"))`
            push("DQ", i)
            i += 1
            word_start = False
        elif c == "`":
            i = backtick(i)
            word_start = False
        elif c == "$":
            if nx == "'":
                if arith or top == "PARAM":
                    unknown = True              # `$((…$'a'…))`, `${$'a'}`: bash and dash read them differently
                push("ANSI", i)
                i += 2
            elif nx == "(":
                if text[i + 2:i + 3] == "(":
                    push("ARITH", i)
                    arith.append(0)
                    i += 3
                else:
                    unknown = unknown or bool(pending)      # `<<E $(…)`: the body of the here-document may begin inside the substitution
                    push("CMD", i)
                    command_at = i = i + 2
                    fresh = True
                word_start = True
                continue
            elif nx == "[":
                unknown = True                  # `$[ … ]` is the old spelling of `$(( … ))`, and a `)` in it is not the end of anything
                i += 2
            elif nx == "{" and text[i + 2:i + 3] == "{" and _expression_end(text, i) >= 0:
                i = _expression_end(text, i)
            elif nx == "{":
                push("PARAM", i)
                unknown = unknown or _PARAM_START.match(text, i + 2) is None or _SUBSTRING_RISK.match(text, i + 2) is not None
                i += 2
            else:
                if nx == "$" and (text[i + 2:i + 3] == "{" or (top == "PARAM" and text[i + 2:i + 3] == "(")):
                    unknown = True              # `$${x}`, and `$$(` in a `${a:…}`: in some contexts dash reads a `$` and the expansion or the parenthesis where bash reads the process id
                i += 2 if nx == "$" else 1      # `$$` is the process id
            word_start = False
        elif c in "<>" and nx == "(" and top != "ARITH":          # in `$(( 1 <(2) ))` they are an operator and a parenthesis
            unknown = unknown or bool(pending) or text[i + 2:i + 3] == "("       # `<((`: the second paren is an arithmetic command to bash
            push("PROC", i)
            command_at = i = i + 2
            fresh = True
            word_start = True
        elif c == "<" and nx == "<" and top != "PARAM":          # in `${x:-<<E}` it is a word
            if text[i + 2:i + 3] == "<" or top == "ARITH":
                i += 3 if text[i + 2:i + 3] == "<" else 2      # a here-string (a syntax error in dash) or a shift
                word_start = False
                continue
            hw = _HEREDOC_WORD.match(text, i)
            if hw is None or text[hw.end():hw.end() + 1] in ("`", "$", "'", '"'):
                unknown = True                  # a delimiter that expands, or one this lexer cannot read as a word (a quote across a newline)
                i += 2
            else:
                states.extend([snap()] * text.count("\n", i, hw.end()))      # a backslash-newline before or in the word ends a line
                word = hw.group(2)
                if '"' in word and any(ch in word for ch in "\\$`"):
                    unknown = True              # `<<"\""`: a double-quoted delimiter with an escape or an expansion is not read by the regex as the shells read it
                pending.append((_unquote(word), hw.group(1) == "-", i, command_at, any(ch in word.replace("\\\n", "") for ch in "\\'\"")))
                i = hw.end()
            word_start = False
        elif c == "(" and top == "PARAM":
            unknown = unknown or bool(arith)    # `$(( ${x:-(} ))`: bash counts the paren in arithmetic
            i += 1                              # `${x%% (*}`: a pattern character
            word_start = False
        elif c == "(":
            if top == "ARITH":
                arith[-1] += 1
            elif nx != "(" and top in _COMMANDS and not at_command and _stray_paren(text, i):
                unknown = unknown or bool(substitutions)        # a paren taken for a syntax error may open a compound command this module does not model
                # `[a](#b)` opens nothing: the shell stops at the paren, and a TOC of such links must not pile up subshells
            else:
                if nx == "(" and (at_command or _arithmetic_command_may_begin(text, i)):
                    unknown = True              # `((x<<E))`: an arithmetic command to bash and two subshells to dash; after a word it is a syntax error to both
                if (text[i - 1] in _EXTGLOB and (extglob or _extglob_group_may_differ(text, i))) or pending:
                    unknown = True              # extglob `@(a|b)` (bash only, and only with `extglob` on: the option is not known, see above); a `(` on the line of a `<<`
                push("ARRAY" if text[i - 1:i] == "=" else "SUB", i)
                fresh = True
            i += 1
            word_start = True
        elif c == ")":
            if top in ("CMD", "SUB", "ARRAY", "PROC"):
                closed = close()
                command_at = closed.command_at - base
                fresh = closed.kind == "SUB" and not text[closed.offset - base + 1:i].replace(_CONTINUATION, "").strip(" \t") and _function_parens(text, closed.offset - base)
                if closed.kind == "SUB" and not text[closed.offset - base + 1:i].replace(_CONTINUATION, "").strip(" \t\n"):
                    fn_close = i                # `f( ) {`: not `$(a) {`, whose `{` is a word
                if pending and base + pending[-1][2] > closed.offset:       # the offsets of the pending here-documents only grow
                    unknown = True              # `$(cat <<E)`: bash reads the lines after it as the body, dash ends the here-document with the `)`
            elif top in ("TOP", "BQ"):
                fresh = True                    # the `)` that ends a case pattern: a command follows (after a stray one, a syntax error ends the command)
            elif top == "PARAM" and arith:
                unknown = True                  # `$(( ${x:-)} ))`
            elif top == "ARITH":
                if arith[-1] > 0:
                    arith[-1] -= 1
                else:
                    if nx != ")":
                        unknown = True          # `$((echo a); (echo b))`: bash falls back to a substitution, dash reports an error
                    else:
                        i += 1
                    command_at = close().command_at - base
                    arith.pop()
            i += 1
            word_start = top in ("SUB", "TOP", "BQ")      # the paren of a subshell or of a case pattern ends its word: `(a)#b` and `a)# c` have a comment, `a=(b)#c` has none
        elif c == "}" and top == "PARAM":
            close()
            i += 1
            word_start = False
        elif c in ";&|" and top != "PARAM":
            if (c == "&" and (text[i - 1:i] in ("<", ">") or nx == ">")) or (c == "|" and text[i - 1:i] == ">"):
                word_start = False              # a redirection (`2>&1`, `&>f`, `>|f`) is not the end of a command
            else:
                word_start = True
                fresh = True
                pinned = -1
            i += 1
        else:
            i += 1
            word_start = c in "<>"
    if nxt < npr:
        give(n + 2)
    if pending:                                  # `cat <<E \⏎` at the end of the text: the next line would be the body
        states[-1] = snap((Opener("HEREDOC", base + pending[0][2], base + pending[0][3]),))
    states.unknown_at_end = unknown
    return states


def _bodies(text: str, i: int, pending: list, snap, states: list, base: int, in_substitution: bool) -> tuple[int, bool, bool]:
    """Read the bodies of the here-documents whose `<<` came on the line that just ended, each line up to its delimiter.
    Every line of a body begins in the enclosing state plus a HEREDOC opener (the delimiter line is one: it ends the body). Returns the offset after the last body, whether something undecidable was seen (an unquoted body joins lines through a backslash-newline, or opens a construct that runs past the line, and bash and dash differ) and whether a line follows the last delimiter, which the caller records."""
    n = len(text)
    unknown = False
    for delim, strip, at, cmd, quoted in pending:
        inside = snap((Opener("HEREDOC", base + at, base + cmd),))
        while True:
            states.append(inside)                # the line that begins at `i`
            if i >= n:
                return n, unknown, False         # the text ends inside the body
            eol = text.find("\n", i)
            line = text[i:] if eol < 0 else text[i:eol]
            i = n if eol < 0 else eol + 1
            said = line.lstrip("\t") if strip else line
            if in_substitution and said != delim and said.startswith(delim) and ")" in said[len(delim):]:
                unknown = True                   # `$(cat <<E⏎…⏎E)`, `EE)`: bash takes a line that begins with the delimiter and holds a `)` for the end of the substitution
            if said == delim:
                states.closed.append((len(states) - 1, Opener("HEREDOC", base + at, base + cmd)))
                if eol < 0:
                    return n, unknown, False     # the delimiter is the last line
                break
            if not quoted and (line.endswith("\\") or (("$" in line or "`" in line) and _opens_across_lines(line))):
                unknown = True
            if eol < 0:
                return n, unknown, False
    return i, unknown, True


def _opens_across_lines(line: str) -> bool:
    """Whether a line of an unquoted here-document body starts a `$(`, `${` or backtick that it does not close. dash reads such a body as if it were in double quotes, at parse time, so the construct runs on past a line that bash takes for the delimiter."""
    lexed = line_states(line + "\n", (Opener("BODY", -1, -1),))
    return lexed.unknown_at_end or len(lexed[1].openers) != 1


_DQ_ESCAPE = re.compile(r"\\([$`\"\\\n])")
_QUOTED_PIECE = re.compile(r"\\([\s\S])|'([^']*)'|\"((?:[^\"\\]|\\[\s\S])*)\"|([^\\'\"]+)")


def _unquote(word: str) -> str:
    """The word after quote removal: `E\\\\` is `E\\`, `'E'x` is `Ex`, and a backslash-newline is no part of it."""
    out = []
    for m in _QUOTED_PIECE.finditer(word):
        if m.group(1) is not None:
            out.append("" if m.group(1) == "\n" else m.group(1))
        elif m.group(2) is not None:
            out.append(m.group(2))
        elif m.group(3) is not None:
            out.append(_DQ_ESCAPE.sub(lambda e: "" if e.group(1) == "\n" else e.group(1), m.group(3)))
        else:
            out.append(m.group(4))
    return "".join(out)
