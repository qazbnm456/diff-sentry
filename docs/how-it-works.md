# How it works

diff-sentry has two tiers. The deterministic rules are pure Python, need no model, and are all the GitHub Action runs. The full pipeline adds a reasoning model that reads a PR, issue or push inside a sandbox, and still takes its alert decision from the rules' evidence.

## Severities are tuned against noise

A plain workflow-file edit is `medium`, below the Action's failure threshold, on purpose: a benign workflow PR must not break your build. A `pull_request_target` on its own is `medium` too, because that is the ordinary label-bot shape. It becomes `critical` only when the same workflow also checks out the PR head. Rules that would be noisy alone require two halves to fire: `child_process` is everywhere and `detached` alone means nothing, but a process deliberately outliving its parent is a loader.

A diff carries deleted code as well as added code, so the scan skips `-` lines by default. Removing a payload does not flag the change that removes it.

## Evidence a model cannot suppress

An LLM reviewer that reads a diff can be argued out of its conclusion by that same diff. diff-sentry is built so that the diff cannot argue the evidence away.

The deterministic rules run host-side, before any model takes a turn, and their hits are recorded as facts. When a verdict is assembled, the evidence is re-sourced as the union of every recorded hit, and the alert decision is derived from that union rather than from the model's self-report. A successful prompt injection can skew the *verdict*; it cannot remove a single piece of *evidence*. In the Action, that is the whole product: no model runs at all.

## The full pipeline

```
GitHub PR/issue/push  →  normalize (metadata head+tail)  →  classify (diff held in a sandboxed REPL)
                      →  judgement-only verdict  →  UNION deterministic indicators on read  →  SIEM signal
                      →  reward-free trajectory export
```

**Deep classification.** The full pipeline hands the change to a reasoning model that explores it inside a sandboxed Python REPL: decode a base64 filename, inspect the raw file list, re-scan a decoded region. The change is a variable under analysis, never text spliced into instructions, and nothing in it is run. The model submits a judgement only. It has no field in which to write, hide, or invent evidence.

**The studio console.** A local web console that streams a run as it happens: each iteration, each tool call, the indicators as they fire, and the assembled verdict with its evidence. Useful when you are tuning rules or explaining a call to someone who has to act on it. See [`studio/README.md`](../studio/README.md).

**Trajectories for training.** Every run records a full trace, and `export` turns a directory of traces into a reward-free dataset: the planner's actions, the classifier's calls, and objective labels read back from the assembled verdict. The intended use is fine-tuning a smaller model for the planner role (`DS_ROOT_LM`) on your own traffic, so the deep tier gets cheaper the longer you run it. Scoring and credit assignment deliberately live outside this repo; what ships here is the rollout source.

**A reward-free scorecard.** The [`eval/`](../eval/README.md) workspace member scores a recorded run's assembled verdict with an independent LLM judge across four categories, means only, no composite and no threshold. It reads the trace contract one-way and never feeds training.

## Running it locally

```bash
uv sync --group dev
uv run diff-sentry scan changes.diff            # the deterministic layer alone (what the Action runs)
uv run diff-sentry pr acme/widgets 7            # full classification (needs DS_* creds, deno, gh)
uv run diff-sentry issue acme/widgets 12
uv run diff-sentry classify event.json          # a payload you already hold
uv run diff-sentry render output/traces/pr-7.jsonl pr-7      # re-derive a response, offline
uv run diff-sentry export "output/traces/*.jsonl" ds.json    # reward-free dataset, offline
uv run diff-sentry watch --repos acme/widgets                # monitor a watchlist, see watch.md
```

Models are roles, set by environment: `DS_ROOT_LM` (planner), `DS_SUB_LM` (analyst), `DS_CLASSIFIER_LM` (second-stage classifier, defaults to the analyst). Point them at any OpenAI-compatible endpoint; see [`.env.example`](../.env.example). The planner and analyst can also run on a **Claude Pro/Max subscription** by giving either role a `claude-agent-sdk/<model>` value with the `subscription` extra installed. The classifier always needs its own endpoint.

None of this is required to use the Action, and none of it sends your code anywhere you did not configure yourself.

## Grounded in real incidents

Two incidents are reconstructed offline and pinned by tests, so a rule change that breaks coverage fails the build.

**`hackerbot-claw`** (Datadog's [BewAIre writeup](https://www.datadoghq.com/blog/engineering/stopping-hackerbot-claw-with-bewaire/)). The original artifacts are gone and the attacker account was deleted, so `tests/corpus/hackerbot_claw_incident.json` reconstructs all three events: a `${IFS}`/base64 payload hidden in a *filename* under `documentation/rules/` that de-obfuscates to a published pipe-to-shell IOC, a prompt injection telling a triage LLM to bulk-label and exfiltrate, and a prompt injection appending a fake owner to CODEOWNERS. Each is asserted under a neutral benign verdict, so the alert is evidence-driven: a false-benign self-report could not have suppressed any of them.

**AsyncAPI "Miasma"**. The attack was Node end to end, and `tests/test_indicators.py` reconstructs its stages: the `pull_request_target` workflow that checks out the PR head, the payload pushed off the diff viewport by a whitespace run, the IPFS fetch-to-disk dropper, and the `_0x` obfuscation injected into a source file. Each rule ships with its negative case, so the tuning is pinned as tightly as the detection.
