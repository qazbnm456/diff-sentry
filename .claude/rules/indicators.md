---
paths:
  - "diff_sentry/indicators.py"
  - "diff_sentry/normalize.py"
  - "tests/corpus/**"
  - "tests/test_indicators.py"
  - "diff_sentry/hosts.py"
  - "tests/oracle/**"
  - "tests/test_oracle.py"
  - "tests/test_oracle_harness.py"
  - "diff_sentry/shelllex.py"
  - "diff_sentry/linewide.py"
  - "tests/test_shelllex.py"
  - "tests/test_enclosure.py"
  - "tests/test_linewide.py"
  - "tests/test_gate_edges.py"
  - "tests/test_metadata_rules.py"
  - "tests/test_adversarial_input.py"
  - "tests/test_detection_quality.py"
  - "tests/test_incident_*.py"
---

# Indicator rules

## Rules that hold for every indicator

- **Deterministic, pure Python, no subprocess.** A subprocess spawned inside the live dspy.RLM/asyncio process
  hangs; a heavier scanner belongs host-side, after the run. `mint_id` is a sha1 over rule and evidence (no time,
  no randomness), so a baseline hit and an in-loop re-scan of the same content dedupe to one union member.
  Evidence is a bounded snippet (`_MAX_EVIDENCE`), never the whole diff.
- **Severities are tuned, not paranoid.** A plain workflow-file edit is `medium`, below the signal floor on
  purpose: a benign workflow PR must not force a SIEM signal, and a real payload inside the workflow fires the
  high/critical shell and obfuscation rules itself. A CODEOWNERS reassignment is `high`. A bare
  `pull_request_target` (the ordinary label-bot shape) is `medium`; the same trigger checking out the PR head is
  `pwn-request` / `critical`. `dev-tunnel-endpoint`, `content-addressed-host` (IPFS) and `dynamic-code-eval` are
  sub-floor corroborators; pairs with no innocent reading (`child_process` + `detached`, network-fetch +
  file-write) are `high`. Requiring both halves is how a common primitive becomes evidence without becoming noise.
- **Every rule ships with its negative case**, and `tests/corpus/` pins the suite's hit/miss behavior.
- **`pwn-request` has three checkout forms, each requiring the privileged trigger:** the head expression on a
  `ref:` (directly or one binding hop away), a hand-rolled `git fetch` / `gh pr checkout`, and
  `allow-unsafe-pr-checkout: true` (the actions/checkout v5.1+ opt-in; the line states the intent, so no dataflow
  is needed). Each form has its own title. A privileged trigger is recognised in the common YAML spellings (map
  key, `on: name`, flow list or map, block-list item, quotes, anchor, trailing comment). `issue_comment` counts
  beside `pull_request_target` and `workflow_run` (it runs with the base repository's secrets), but that trigger
  alone is not a finding; `pull_request_review` and `pull_request_review_comment` are not privileged.
- **A paired rule only pairs within one file.** `scan_diff` splits a unified diff on its file headers and
  `scan_content` does the same for an event. `normalize.content_segments` is the single definition both
  `raw_content` and the baseline build on. Per-file scoping stops two halves from different files composing into a
  `critical` no file contains, and keeps a hit id byte-stable between a whole-diff and a single-file scan, which is
  what lets the baseline and an in-loop scan dedupe. Non-diff input falls through to a whole-text scan.
- **The in-loop tool registers as exactly `scan_indicators`.** dspy registers a tool under its `__name__` and the
  prompt calls `scan_indicators(region)`; the inner callable is renamed on purpose (`make_indicator_tool`).
- **Hits are capped at 25 per (rule, place, title)** (`_MAX_HITS_PER_RULE`), most severe first, so decoys cannot
  evict the critical that follows them. The title is part of the key because `curl-pipe-shell` has three forms. The
  SIEM payload lists the 100 most severe and says how many there were (`indicator_count`).
- **A detector that raises is a finding, not a silence.** `scan_indicators` runs each detector in `_DETECTORS`
  under a guard; one that raises records a `high` `scanner-error` hit and the rest still run.
  `tests/test_metadata_rules.py` feeds thousands of random hostile strings through the scanners and requires that
  none raises. The prose softening and the rendered view run under the same kind of guard (`_or_closed`): a crash
  keeps the installer as strict as the detector found it and adds a `scanner-error` hit.
- **Every regex is linear on hostile input.** The watcher runs these rules on any user's text (up to 65,536
  characters in a body) on one poller thread, and a regex that backtracks does not return. Habits: `[ \t]*` after a
  line anchor, never `\s*`; no two adjacent quantifiers that can take the same character; alternatives disjoint
  on their first character; every unbounded `[^\n]*` in front of another pattern gets a `{0,N}` window; host
  patterns anchored and label-bounded. `tests/test_adversarial_input.py` times named vectors and, in a subprocess,
  runs 65,536-character inputs built from the literals of every module-level regex in the package. A regex written
  inside a function is not picked up: compile it at module level.
- **The change text is scanned once per change in the poller.** `cli._baseline_indicators(event, content_hits=...)`
  and `cli.screen(..., baseline=...)` take the result of the one `scan_change`.
- **Command words are bounded by ASCII alphanumerics, never `\b` or `\w`**, which know Unicode: `__curl ... | sh__`
  (Markdown emphasis) and `執行curl ...` (CJK prose has no spaces) must still be found.
- **`invisible-unicode`** covers bidi overrides, embeddings and isolates; the word joiner and invisible math
  operators; the Hangul fillers; a ZWSP anywhere but right after `@` (Dependabot renders `@​user`); a BOM
  anywhere but the start of a line; Unicode tag characters (except the three subdivision flags); the
  variation-selector supplement; and three or more plain variation selectors in a row.
- **`branch-name-injection` is `high` unless the author is an OWNER, MEMBER or COLLABORATOR** (then `medium`): a
  maintainer can name a branch `fix/handle_${HOME}_expansion`.

## `curl-pipe-shell`

A download piped into a shell or an interpreter is `critical`. It has three forms that are judged separately: the
pipe, the command substitution and PowerShell's. In prose (a `title`, `body` or `comment`, or a documentation file:
`.md .mdx .markdown .rst .adoc .ipynb .html .htm`) a documented installer is `medium`. Code files (`.sh`, `.go`,
`.yml`, a Dockerfile, `requirements.txt`) and branches are never softened. The segment kind decides, never a label.
The planner's `scan_indicators` applies the same softening to the region it is given.

### What it matches

- **The pipe form.** The shell is `sh bash zsh dash ksh ash fish csh tcsh` by name or path (quotes or backslashes
  threaded through the letters are fine), `$SHELL`, or one of them behind `env`, `busybox`, `command`, `exec`,
  `nohup`, `nice`, `timeout`, `stdbuf`, `sudo`, `doas`, `pkexec` or `su -c`. An interpreter that reads its program from the pipe
  (`python3 -`, `perl`, `ruby`, `node`, `php`) counts too, but not `python -m`, a script file or `-c` / `-e`. The first
  pipe into a shell is the sink; up to three stages in between; the download word may itself be quoted or split by a
  backslash-newline; up to 300 characters of arguments sit between it and the pipe, after the padding that would
  push a real command out of that window has been folded. The window reads quoted strings (which may run over a line),
  `$'...'` as an ANSI-C string, and a backslash outside a string as bash does (`\'`, `\|` and `\$` are characters of a word,
  `curl -H 'a<newline>b' URL \' | sh`). A second window reads `$` as a plain character (after `\$` or `$$`, and in dash,
  `$'` starts no ANSI-C string), and a third ignores quotes altogether (it finds a Markdown table cell's `\|`). A match of
  any of the three counts.
- **The command substitution form:** `bash -c "$(curl ...)"`, `bash <(curl ...)`, `source <(curl ...)`,
  `eval "$(curl ...)"`, `python3 <(curl ...)`, here-strings, with the usual prefixes.
- **The PowerShell form:** `iwr ... | iex` (`curl` and `wget` are aliases of `iwr` there), `iex (irm ...)`,
  `iex ((New-Object Net.WebClient).DownloadString(...))`, `[scriptblock]::Create(...)`.
- A backslash-continued command and a pipe at the end of a line are joined before matching (`_join_lines`), in the
  scan and in the softening alike. A line that looks like a table row but is not one keeps its lines, and its
  pipeline is appended at the end of the text; the appended lines are matched as a text of their own (`_matches`). Prose and HTML files are also scanned as rendered (`_rendered`, below), and the
  hits only that view has are added.

### When prose makes it `medium`

Every download of the form in the segment must meet all of these; one failure keeps the whole form `critical`.
The form is part of the hit id, and two hits that share an id keep the more severe one (`keep_worse`).

1. **Known installers only** (`hosts.KNOWN_INSTALLERS`: exact hosts, and exact path patterns for shared hosts such
   as `raw.githubusercontent.com/nvm-sh/nvm/...`). `hosts.installer_only` is strict: every flag is on an allowlist
   (`-sSfL`, `-o-`, `--proto '=https'`, `--retry N`; `--proxy`, `--config`, `--next` and the like fail), every
   argument is a clean URL, and a stand-in (`...`, `<url>`) names no download. `powershell_installer_only` applies the same
   test to PowerShell. Never add a whole platform (github.com, raw.githubusercontent.com) to the list.
2. **A plain shell side** (pipe form). A bare shell name or one under `/bin`, `/usr/bin`, `/usr/local/bin`, plain
   flags, no `-c`, no script operand (`sh ./evil.sh`), no `=` or URL; only decode or copy filters between the
   download and the shell (`base64 gunzip gzip zcat xz tee cat`); an interpreter only for a known installer and only
   with the switches it documents.
3. **It stands on its own logical line.** Nothing on the line feeds it (`|`, `=`, `&`, `;`, `$`, `xargs`, `-exec`;
   only `NONINTERACTIVE=`, `CI=` and `DEBIAN_FRONTEND=` may precede it), and no program runs it elsewhere or in its
   place (`_wrapped` reads every word in front of the command, after markup, labels, list markers and redirects are
   dropped). The command starts within `_MAX_PROSE_LEAD` characters of its line or inside an inline code span, and
   the rest of the line is prose.
4. **Nothing earlier in the segment changes what runs** (`_HIJACK_RE`): a curl config, an alias or function named
   `curl` or a shell, an assignment to `PATH`, `HOME`, `LD_*`, `BASH_ENV`, `SSL_CERT_*`, a URL assigned to any
   variable, a proxy variable, a write to `/etc/hosts`, PowerShell's `Set-Alias`. This is a brake on false positives,
   not a proof: what defeats it is still recorded at `medium` and handed to the planner as evidence.
5. **The installer is not enclosed** by anything a wrapper opened above it, and the text has no shape the
   softening does not read (both below).

### Is the installer enclosed?

`ssh evil.example 'NEWLINE curl ... | sh NEWLINE '` runs the installer inside ssh's argument, so a documented installer
stays `critical` when something above it opens a wrapper's quote, here-document or substitution. `enclosed` in
`_soften_prose` asks two readings of the folded join; **either one** keeps the installer `critical`.

- **The line-wide floor (`linewide.py`)** is the line-wide rule that preceded the lexer, kept unchanged. A line
  opens something when its last 300 characters (minus quote, list and prompt markers) hold an odd number of
  apostrophes (one between two letters does not count), an odd number of double quotes or a `<<`, and a word in it
  could run what follows (`linewide.wrapped`: a wrapper, an interpreter, a path, a name glued to the command). The
  60 lines after an opening line are enclosed. The floor also asks `wrapped` of the text in front of the command on
  its own line. It counts the quotes the text spells, so it sees the ones a YAML scalar, a string literal, `printf`, a
  variable or Markdown rendering turns into the quote a shell is handed, which the lexer cannot. It knows no fence,
  removed line, closed string or syntax error. A text with a NUL is read with and without it.
  - **Guarantee:** what the line-wide rule rates `critical` through its opening-line rule or lead check is never
    softened. Exceptions: the removed lines, hunk headers (not the section heading after the second `@@`, which is a line of the
    new file) and `\ No newline` notes of a patch (the rendered view is of the new file, so a line break it makes
    carries the marker of its line), and a NUL anywhere in the text (it is read without the NUL, as the shells read it).
  - **Do not narrow the floor or relax the lexer's answer on top of it.** Test the lexer's relaxations through
    quote-free openers (`ssh evil.example $(`).
- **The lexer (`shelllex.py`)** is a one-pass quoting lexer with a stack of open constructs (quotes, `$'...'`,
  backticks, `$(...)`, `<(...)`, `(...)`, `$((...))`, `${...}`) and a queue of pending here-documents, held to
  `bash -n` and `dash -n` by the oracle. What the two shells read differently, or what needs a parser, is `unknown`
  (the docstring lists them) and counts as enclosed on the lines after the first one on which a command may begin like
  a wrapper's. A construct counts only when the command that holds it is a wrapper and does not read as prose
  (`_begins_with_wrapper`, `_wrapped`): `ssh evil.example '`, `docker run x sh -c "`, `ssh evil.example <<'EOF'`. A
  capitalised first word, an apostrophe, a URL, or a word such as `the a an is it to of use run` makes prose, and a
  plain-word host (`ssh host '`) reads as prose.
  - The diff's `+` and a blockquote's `>` are removed, and the text is read in each stretch between code fences. A
    fence is a line of three or more backticks or tildes, at most three blanks in, with nothing in front of it. A
    fence behind a quote or list marker cuts nothing. The lines of an HTML block are text. A string opened in one
    block is not open in the next. CommonMark's container rules are not modelled further.
  - Every reading is also tried from each wrapper word as a fresh start, because prose or a table cell can sit in
    front of a command (`Run:ssh`, `| docker |`). The 60 lines after it are read as a script of its own.
  - `eval` runs the script its first string holds, and a string piped into a shell or an interpreter is a script
    too; both are read as such to a depth of three.
  - A wrapper-led line whose comment holds a quote is read a second time as a zsh in a terminal reads it, where `#` is no comment.
  - The enclosure reads are held to a budget of 12 units per character plus 2,000, and a command of more than 600
    characters is judged from its head and tail. The budget fails closed.

### Shapes the softening does not read, and the rendered view

- **The gate (`_unread_shape`)** is fail-closed: a text with a shape that the softening does not read is not softened
  at all, and the extras of its rendered view are not either. The shapes are a lone CR, a diff block in a
  document (a line of the new file that starts with `+` and a non-blank), a notebook array, the strings of a list that
  hold a download and a program, a multi-line array assignment, a YAML single-quoted scalar that goes on, and a
  template placeholder that spells a quote. A crash of the check is a shape.
- **The rendered view (`_rendered`)** reads a text as a reader copies it: entities decoded, comments and tags
  gone, a block tag a line break, links reduced to their text, emphasis markers removed, a word in backticks reduced to the
  word, a code span of a quote read as that quote. Its stricter hit stands (stricter wins). `_shield_html_fences` blanks
  fence markers inside HTML blocks first. A second view without those last two readings is read as well, because a
  backtick they erase still counts in front of a command (`ssh host <code> ' </code> curl ... | sh`). `.rst`, `.adoc`,
  `.html`, `.htm` and `.ipynb` are not Markdown, so no fence or HTML block cuts there.

### Accepted over-alerts and known gaps

The first four bullets are over-alerts, not misses: for the examples they give, the installer stays `critical`.

- A letter-apostrophe-letter (`change's`) after a path-like first word makes the rest of that stretch of prose
  enclosed (`/format the change's notes`, `bin/evil doesn't work.`). Markup hides a relative path from the raw
  reading, but an absolute path (`/usr/bin/x`, `./x`, `~/x`) or a typographic quote hides nothing, and the rendered
  view reads a code span or emphasis away, so `` `src/main.py` doesn't read the config. `` before an installer is
  `critical`. A shell would read the apostrophe as an unterminated string.
- A line led by a wrapper that runs what follows whose comment holds a quote (`uv run pytest  # run the project's tests`;
  not `npm test` or a plain-word host), and prose with an unmatched quote or backtick next to a bare path or a wrapper head.
- A table row with a quote, a closer or a stray `$(` or backtick opener followed by a paragraph joins that paragraph; a cell
  after a command written as plain text or `<code>` is a stage of its pipeline; a `+` row inside a fenced `diff` block reads
  as shell text.
- A tilde fence (the rendered view erases `~~~`), and any text with a gate shape.
- Known gaps: a hunk or text that starts inside a construct opened above what is visible; indented code read as
  prose; commands that are not known wrappers (`awk`, `parallel`, `aws ssm`, `csh`, `lua -e`);
  a patch whose removed lines or hunk headers sit between `curl U |` and `sh`; single-line sink forms such as
  `| >/dev/null sh`, `| { sh; }`, `| setsid sh`, `| xargs -0 sh -c`; a comment word followed by a backslash; a
  here-document on a multi-line compound command; a redirect after a here-document delimiter; more than about 300
  characters of distinct words between `curl` and the pipe; a quoted-space argument (`' '`) that the padding fold turns into
  a lone quote (`" "` and a string that ends in a blank are folded the same way), together with a quoted argument that runs
  over a line; an argument that is a multi-line `$(...)`, backtick span, `${...}` or `<(...)` in front of the pipe; a quoted
  `|#` among the arguments (the rest of the line reads as a comment); a `$'` that is an ANSI-C string in one place and `$$` followed by a quote in another. The quote-aware window reads a
  backslash as a shell does and must keep doing so: reading `\'` as a plain character would catch some of these by
  accident, but it closes strings a shell never opens, and the window built that way backtracked exponentially on
  `$'a'` chains and cost hundreds of microseconds per character on `\"` chains.
- A table cell spells its pipe `\|`, and that is read as a pipe only in a table row that starts with a pipe; elsewhere `\|`
  is an argument of the command (`curl \| URL | sh` is `critical`). So an installer written with `\|` in a table without
  leading pipes, in a paragraph or in an HTML cell is `critical` too, although Markdown renders the `\|` as a pipe there. A
  line that starts with a pipe inside a multi-line quoted argument is read as a table row, and its `\|` as a cell's pipe.
- A lone CR is a character of a word to a shell. The shell rules read the text once more with each lone CR as a letter
  (`curl URL<CR>| sh` runs; `\<CR>` is an escaped CR), also for the planner tool and `diff_sentry scan`, which read a
  file or stdin with the CR kept.

### Measured

- **Over-alert rate.** The uv installer inserted as its own paragraph into 2,400 real Markdown documents (7,200
  insertions): about 2.5% read `critical` where the line-wide rule alone said `medium`, and none read `medium` where it
  said `critical`. About a quarter of those come from a gate shape (under 1% of documents hold one). Without the
  floor, about 3% of the insertions would have been softened that the line-wide rule kept `critical`. An installer
  whose own line carries a quote (the rustup one) over-alerts more, roughly one insertion in eight on a similar corpus,
  because a plain apostrophe in the prose above pairs with that quote.
- **Cost is linear.** The worst shape (`curl(` repeated) costs about 10 µs per character per channel (0.7 s for a 65 KB body,
  about 20 s for a 2 MB patch); the hostile enclosure and gate shapes cost 2 to 17 µs per character; plain prose is
  about 2 µs and a README 8 to 14. Tests hold the cost per character flat from 16 KiB to 128 KiB.
- **The lexer agrees with real shells.** The oracle (`DS_ORACLE=1`) has found no case of the lexer calling a construct closed
  that `bash -n` or `dash -n` reports open since the last fix.

### How it is verified

- **The oracle** (`tests/test_oracle.py`, opt-in, Docker): seeded candidates run under the container's real `bash`
  and `dash` with stub `curl`/`wget` and stub programs that only log, no network, no capabilities, a read-only root,
  and a canary download before and after each batch. Four properties: recall in code files, recall in prose
  (whatever a shell really runs stays `critical`), the lexer against `bash -n` / `dash -n`, and soundness of the
  softening (whatever is reduced to `medium` fetches nothing but a known installer and calls nothing else). A new
  spelling goes into `tests/oracle/grammar.py` first. The oracle sees under-detection and unsafe softening, never extra
  alerts, and does not cover PowerShell, zsh, or effects only the real installer would show; guards that only add
  alerts are pinned by unit tests instead.
- **Unit pins.** `tests/test_linewide.py` pins the floor against its source rule; `tests/test_gate_edges.py` pins the
  gate, rendered view and shield patterns by the shortest texts on which a mutant of each differs;
  `tests/test_enclosure.py`, `tests/test_shelllex.py` and `tests/test_metadata_rules.py` pin the rest end to end.
  A mutant that no text tells from the code is an equivalent one (an alternative another covers, a possessive
  quantifier, a class member under `re.IGNORECASE`, a cost bound).

## Other prose softening

All in `indicators._soften_prose`; a code file and a branch are never softened.

- **`prompt-injection`** whose only trigger is the bare phrase "system prompt" is `medium`: ordinary in a thread
  about an LLM product. It is `high` when:
  - a real override phrase is present (`ignore previous instructions`, `your system prompt`, `print the system
    prompt`, `new instructions:`, and the previous / prior / earlier / the above family), which must name what is
    dropped (instructions, rules, guidance, context) or ask for an action (approve, merge, lgtm, reply, print,
    reveal, send, exfiltrate, grant, delete, execute). "Ignore all previous commits" and a bare "ignore the above"
    are ordinary sentences;
  - an imperative starts a sentence aimed at the phrase (`Ignore the system prompt ...`, `New system prompt: ...`):
    the verb follows the start of the text or a line, punctuation, a quote, a markdown or diff marker, a table pipe,
    a bullet, a vocative, or `could you` / `can you` / `you need to` / `you will`; never a hyphen, an apostrophe or a
    word;
  - it is addressed to a reviewer or a model: `please`, `you must/should`, or a name (`agents`, `Claude`, `the AI`,
    `reviewers`) with a directive modal, then the verb. A name without a modal describes them. Not through a negation.

  It stays `medium` when the verb starts a library title with a subordinate clause (`Ignore system prompt when
  counting tokens`), when the phrase starts a longer name (`system prompt caching`) or is a whole table cell, and
  when negated, except that a clause about the review itself (`when reviewing this PR`, `and merge`) makes it an
  instruction. A variable (`SYSTEM_PROMPT`), a flag or a path is not the phrase.
- **`pwn-request`** is `medium`: a workflow shown in a body, a comment or a documentation file is not one that runs.
  The same text in a workflow file stays `critical`.
- **`diff-viewport-evasion`** is `medium` in a comment only (a padded markdown table). In a file, including a
  markdown file, it stays `high`.
- A planner re-scan of text that is not byte-identical to the baseline's window mints another id (a title is scanned
  with the author appended by the baseline), and the stricter baseline hit for a code file always stays in the union.
