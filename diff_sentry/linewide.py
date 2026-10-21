"""The coarse, line-wide reading of the text in front of an installer, kept as a floor under the shell lexer.

A line opens something when it holds an odd number of apostrophes (one between two letters is not counted), an odd number of double quotes or a here-document operator and ANY word of it could be a program that runs what follows (`wrapped`: a wrapper, an interpreter, a path, a name glued to the command). The sixty lines after it are enclosed. `wrapped` is also asked of the text in front of the command on its own line. The shell lexer (`shelllex`) reads quoting exactly in the text as written, and the text is often not what a shell is handed: a YAML scalar, a string literal, a template, a `printf`, a variable that holds a quote, Markdown that renders a link or a code span away. This reading counts the quote characters that the text spells and takes any word that could run what follows, whatever they mean, so the installer stays `critical` whenever either reading says it is enclosed or led by a program.
It is the line-wide rule that preceded the lexer; its words, patterns and functions are fixed as written, so a text it rates `critical` through that rule is never softened, except for the removed lines, hunk headers (not their section heading) and `\\ No newline` notes of a patch in its rendered view (which is of the new file) and a NUL in the text (it is read without the NUL, as the shells read it). Pure Python, no dspy, linear in the text: it reads the last 300 characters of each line.
"""

from __future__ import annotations

import bisect
import re

# Programs that run `curl` somewhere else or in its place. Interpreters and shells are also English words in a sentence ("install python and curl"), so they count only with an argument that is not a word (`python3 evil.py`).
_WRAPPERS = frozenset({"docker", "podman", "nerdctl", "kubectl", "oc", "lxc", "lxd", "limactl", "colima", "wsl", "adb",
                       "bwrap", "firejail", "unshare", "nsenter", "chroot", "ssh", "sshpass", "su", "runuser", "sg",
                       "poetry", "uv", "npm", "yarn", "pnpm", "pipenv", "conda", "mise", "asdf", "direnv", "nix", "flatpak",
                       "snap", "bundle", "watch", "pyenv", "rbenv", "setpriv", "fakeroot",
                       "torsocks", "tsocks", "proxychains", "proxychains4", "nix-shell", "toolbox", "distrobox",
                       "vagrant", "multipass", "npx", "pnpx", "bunx", "uvx", "pipx", "strace", "ltrace", "gdb",
                       "systemd-run"})

# ... and the wrappers that are never a word of a sentence: they run whatever follows.
_ALWAYS_WRAPPERS = frozenset({"su", "sg", "runuser", "setpriv", "npx", "pnpx", "bunx", "uvx", "pipx", "strace", "ltrace", "torsocks", "tsocks", "proxychains",
                              "proxychains4", "sshpass", "nix-shell", "bwrap", "firejail", "unshare", "nsenter",
                              "systemd-run", "docker-compose", "podman-compose", "nerdctl", "kubectl", "limactl", "colima", "distrobox", "toolbox", "multipass",
                              "vagrant", "lxc", "lxd", "podman"})

_INTERPRETERS = frozenset({"python", "python3", "perl", "ruby", "node", "nodejs", "deno", "bun", "php",
                           "sh", "bash", "zsh", "dash", "ksh", "fish", "busybox"})

# The word after a wrapper that says it is being used as one: a flag, a host, an image, a path, an address, or the verb.
_WRAPPER_ARG_RE = re.compile(r"\A-|[./:@=\d]|\A(?:run|exec|shell|ssh|attach|start|create|compose|sudo)\Z")

_MARKUP_RE = re.compile(r"<!--[^>]{0,60}-->|</?[A-Za-z][A-Za-z0-9]{0,10}(?:[ \t](?:\"[^\"\n]{0,400}\"|'[^'\n]{0,400}'|[^<>\"'\n]){0,600})?/?>")

_PATH_WORD_RE = re.compile(r"\.{1,2}/|/|~(?:/|\Z)")                    # `./evil`, `/tmp/x`, `~/bin/x`; not `.bashrc` or `~=3.9`

_ADDRESS_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")                  # an IPv4 address is a host, not a version

_VERSION_RE = re.compile(r"[<>=~!]+|[<>=~!]*v?\d[\d.x*+]*")

_EDGE_CHARS = frozenset("([{<!@\"'`*\\)]}>_")

def _edge(c: str) -> bool:
    """Markup or punctuation that can be glued to a word without changing the word: ASCII brackets, quotes and emphasis, and any non-ASCII symbol (typographic quotes and brackets, bullets, arrows, zero-width characters)."""
    return c in _EDGE_CHARS or (not c.isascii() and not c.isalnum())

_NON_ASCII_RE = re.compile(r"[^\x00-\x7f]+")

# `Run:ssh`, `Run:__ssh`, `Run:./evil`, not `host:22`, `user@host:22` or `http://x`
_LABEL_WORD_RE = re.compile(r"[A-Za-z][\w-]{0,29}:([^\sA-Za-z0-9/]{0,6}[A-Za-z][\w./-]{0,100}|(?:\.{1,2}/|~/|/(?!/))[\w./-]{1,100})")

# the closing tag of an element stands in front of a word without a blank (`</b>ssh`)
_CLOSING_TAG_RE = re.compile(r"</[A-Za-z][A-Za-z0-9]{0,10}>")

# ... and so does the OPENING tag of a block-level element (`<br>`, `<li>`, `<td>`, `<p>`, `<dd>`, `<hr>`)
_BLOCK_OPEN_RE = re.compile(r"<(?:br|hr|p|li|td|th|tr|dd|dt|div|ul|ol|dl|table|h[1-8]|summary|details|blockquote|center|section|caption|"
                            r"figure|figcaption|pre)(?![A-Za-z0-9:-])(?:[ \t](?:\"[^\"\n]{0,400}\"|'[^'\n]{0,400}'|[^<>\"'\n]){0,600})?/?>",
                            re.IGNORECASE)

_LONE_OPERATOR_RE = re.compile(r"(?<=\s)\d{0,3}[<>]+&?\d{0,3}(?=\s)")

# what a list marker or a sentence's punctuation leaves glued to the word after it: `1)docker`, `(1)docker`, `1:docker`, `:docker`
_LEAD_PUNCT_WORD_RE = re.compile(
    r"(?:\(?\d{1,3}[.):]|\([A-Za-z]{1,3}\)|[A-Za-z]{1,3}\)|[A-Za-z][.]|\[[A-Za-z0-9]{1,3}\]|={1,3}>|-{1,3}>|[:,.;)\]}])+([A-Za-z./~][\w./-]{0,100})")

def _command_words(before: str, mask: int = -1) -> tuple[list[str], list[str]]:
    """`(raw, words)` for what stands in front of the command: markup is gone, a redirect is not a word (`ssh >f host`, `ssh > f host`, `docker<x run`: the operator, its target, and anything glued to the word after it), and a label or a list marker glued to a word with no space (CJK prose has none, `Run:ssh`, `1)docker`) is not part of it. A bracket that OPENS the first word (`<docker run`) is punctuation, not a redirect, and `>=3.9` is a version. A lone `>` is a redirect OR a breadcrumb (`Terminal > docker run`): bit j of `mask` says whether the j-th lone operator takes the next word as its target, and the caller asks every combination. `raw` keeps each word as written, for the clause test."""
    raw, words, skip, seen = [], [], False, 0
    tokens = _MARKUP_RE.sub(" ", _CLOSING_TAG_RE.sub(": ", _BLOCK_OPEN_RE.sub(": ", before))).split()
    for k, w in enumerate(tokens):
        if skip:                                       # the target of a bare redirect operator (`> f`)
            skip = False
            continue
        i = 0
        while i < len(w) and w[i].isdigit():
            i += 1
        if i < len(w) and w[i] in "<>" and k and w[i + 1:i + 2] != "=":
            if w.strip("<>&0123456789") == "":          # `>` alone: the next word is its target (or a breadcrumb's text); `>f` carries its own
                if seen < 3:
                    skip = bool(mask >> seen & 1)
                    if not skip:
                        raw.clear(), words.clear()          # a breadcrumb: the command starts after it
                else:                                   # past the combinations tried: a program after it is a breadcrumb's text
                    head = _bare(re.split(r"[<>]", tokens[k + 1], maxsplit=1)[0]) if k + 1 < len(tokens) else ""
                    nxt = head.rsplit("/", 1)[-1]
                    skip = not (nxt in _WRAPPERS or nxt in _ALWAYS_WRAPPERS or nxt in _INTERPRETERS or "/" in head
                                or _PATH_WORD_RE.match(head))
                    if not skip:
                        raw.clear(), words.clear()
                seen += 1
            continue
        cut = next((j for j in range(1, len(w)) if w[j] in "<>" and w[j - 1] not in "=-"), -1)      # (`=>`, `->` are arrows)
        if cut > 0:                                    # an operator glued after the word: `ssh<x`, `docker>f`
            w = w[:cut]
        if not w:
            continue
        if w.strip(":,.;!?)") == "":                    # a lone `:` after `</b>` ends the clause of the word before it
            if raw:
                raw[-1] += w
            continue
        raw.append(w)
        label = _LABEL_WORD_RE.fullmatch(w)               # `安裝：docker`, `Run:ssh`: a label glued to the word
        tail = label.group(1) if label else _NON_ASCII_RE.split(w)[-1]
        lead = _LEAD_PUNCT_WORD_RE.fullmatch(tail)
        words.append(_bare(lead.group(1) if lead else tail) or _bare(w))
    return raw, words

def _bare(word: str) -> str:
    i, j = 0, len(word)
    while i < j and _edge(word[i]):
        i += 1
    while j > i and _edge(word[j - 1]):
        j -= 1
    return word[i:j].removeprefix("~~").removesuffix("~~")

def wrapped(before: str) -> bool:
    """Whether what stands in front of `curl` on its line is a program that runs it somewhere else or in its place: `docker run evil curl`, `python3 evil.py curl`, `./evil curl`, a name glued to it (`evil-curl`). Every word counts, since a prose word or a bracket in front of the wrapper changes nothing about what runs; a word that ends a label or a clause ("Install docker:") is prose, and so is a wrapper's name with no argument that makes it a command ("docker users can run …")."""
    if before and before[-1] not in " \t`\"'([{>*" and not (not before[-1].isascii() and not before[-1].isalnum()) \
            and not (before[-1] == "_" and not (len(before) > 1 and before[-2].isalnum())) and not before.endswith("~~"):
        return True               # a name glued to it (`evil-curl`); a typographic quote, `_x_` emphasis or `~~x~~` is not a name
    # markup glued to a word hides it: `<code>ssh`, `<!-- x -->docker`, `__docker`, `~~docker`, `“ssh`, `«docker`
    lone = len(_LONE_OPERATOR_RE.findall(before))
    return any(_wrapped_words(*_command_words(before, mask)) for mask in range(1 << min(lone, 3)))


def _wrapped_words(raw: list[str], words: list[str]) -> bool:
    for k, word in enumerate(words):
        # a word that ended a clause is prose, judged before its punctuation is stripped
        if not word or raw[k][-1] in ":,.!?)":
            continue
        if _PATH_WORD_RE.match(word) or (k == 0 and "/" in word):
            return True
        name = re.sub(r"\A(python\d?)\.\d+\Z", r"\1", word.rsplit("/", 1)[-1])       # python3.11 is python3
        if name in _ALWAYS_WRAPPERS:
            return True
        if name in ("powershell", "pwsh"):
            # `powershell -c "irm …"` is how the installers are documented; a script file or an encoded command is not
            if any(w.lower().strip("\"'") in ("-file", "-f", "-encodedcommand", "-enc", "-e") or w.lower().endswith(".ps1")
                   for w in words[k + 1:]):
                return True
            continue
        if name in _WRAPPERS or name in _INTERPRETERS:
            nxt = (words[k + 1] if k + 1 < len(words) else "").strip("\"'`").rstrip(":,.;!?)")
            after = words[k + 2].strip("\"'`") if k + 2 < len(words) else ""
            versioned = ((name in _INTERPRETERS or name == "docker") and _VERSION_RE.fullmatch(nxt)
                         and not _ADDRESS_RE.fullmatch(nxt))
            if not nxt or (_WRAPPER_ARG_RE.search(nxt) and not versioned) \
                    or (name in _WRAPPERS and nxt in ("curl", "wget")) \
                    or (nxt == "container" and after in ("run", "exec", "start", "create")):
                return True
    return False

_LEAD_MARKUP_RE = re.compile(r"^(?:[\s>#*+\-`'\"]|\$(?=[ \t]))*")           # `$ curl`, not `$(./evil) curl` or `$R curl`


_APOSTROPHE_RE = re.compile(r"(?<![A-Za-z])'|'(?![A-Za-z])")           # a single quote that is not an apostrophe inside a word
WINDOW = 60                                                             # the lines after an opening line that are enclosed


def opening_lines(lines: list[str]) -> list[int]:
    """The indexes of the lines that may open a quote or a here-document that a wrapper holds: an odd number of apostrophes or of double quotes, or a `<<`, in the last 300 characters of the line (without the markers a quote, a list or a prompt puts in front of it), and a word in it that could run what follows."""
    found = []
    for i, line in enumerate(lines):
        tail = _LEAD_MARKUP_RE.sub("", line[-300:])
        if tail.strip() and (len(_APOSTROPHE_RE.findall(tail)) % 2 or tail.count('"') % 2 or "<<" in tail) and wrapped(tail + " "):
            found.append(i)
    return found


def encloses(openers: list[int], line: int) -> bool:
    """Whether an opening line is among the sixty lines above `line`."""
    j = bisect.bisect_left(openers, line)
    return j > 0 and line - openers[j - 1] <= WINDOW
