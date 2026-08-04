"""Deterministic indicator detectors — pure-Python, in-loop-safe, NO subprocess.

`scan_indicators(text)` runs a suite of pattern detectors over a change (or a decoded region) and
returns structured `IndicatorHit`s — FACTS, never a model opinion. It is used TWO ways:

1. **Host-side BASELINE** at ingest (`cli`/`normalize`), stashed in the run_start meta, so the
   deterministic evidence is in the trace even if the planner never scans — the planner cannot suppress
   a hit by omission (assemble unions baseline ∪ tool hits).
2. **An RLM TOOL** (`make_indicator_tool`) the planner calls on a specific region it decoded or wants
   double-checked; each call records a `tool_call` carrying the FULL structured hits.

Why pure-Python and no subprocess: a subprocess spawned from inside the live dspy.RLM/asyncio process
reliably hangs (a hard-won rlm-kit-consumer lesson). Any heavier external scanner belongs host-side,
post-run — never as an in-loop tool.

No dspy import; the tool wrapper imports only `rlm_kit.trace.record_tool_call`.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import math
import re
from collections.abc import Callable

from .schema import IndicatorHit

_MAX_EVIDENCE = 240  # bounded snippet — never leak the whole diff into a hit


def _snip(text: str, start: int, end: int, *, pad: int = 40) -> str:
    """A bounded, whitespace-collapsed window around [start, end) for an IndicatorHit's evidence."""
    lo = max(0, start - pad)
    hi = min(len(text), end + pad)
    window = re.sub(r"\s+", " ", text[lo:hi]).strip()
    return window[:_MAX_EVIDENCE]


def mint_id(rule: str, evidence: str) -> str:
    """A DETERMINISTIC hit id — stable across the host-side baseline scan and an in-loop tool scan of
    the same content, so the two de-duplicate to one union member. No Date/random (both unavailable and
    would break replay determinism)."""
    digest = hashlib.sha1(f"{rule}\x00{evidence}".encode("utf-8", "replace")).hexdigest()[:8]
    return f"ind-{rule}-{digest}"


def _hit(rule: str, severity: str, title: str, evidence: str, *, location: str = "",
         decoded: str | None = None) -> IndicatorHit:
    return IndicatorHit(id=mint_id(rule, evidence), rule=rule, severity=severity, title=title,
                        evidence=evidence[:_MAX_EVIDENCE], location=location, decoded=decoded)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# ── individual detectors: each takes the text and yields IndicatorHit(s) ──────────────────────────

_IFS_RE = re.compile(r"\$\{?IFS\}?")
_CMD_SUBST_RE = re.compile(r"\$\([^)]{1,200}\)|`[^`]{1,200}`")
_CURL_PIPE_RE = re.compile(r"\b(?:curl|wget)\b[^\n|]{0,300}\|\s*(?:ba)?sh\b", re.IGNORECASE)
_CHMOD_EXEC_RE = re.compile(r"chmod\s+\+x[^\n]{0,120}", re.IGNORECASE)
_B64_RE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
# Exfiltration: environment/secret READS and a secret NAME piped to a network sink. Deliberately NOT the
# bare token name alone (a legit workflow uses `${{ secrets.GITHUB_TOKEN }}`) and NOT `export X=$Y`
# (`export PATH=$PATH:…` is a normal idiom) — the secret must actually reach an exfil verb to fire.
# `/proc/<pid>/mem` (and maps) reading ANOTHER process is the runner-memory-dump technique from the
# tj-actions supply-chain incident; the secret-name alternation covers the CI token families that class of
# attack harvests. `self/maps` is deliberately EXCLUDED — parsing your own memory map is textbook legit
# native tooling (crash reporters, profilers, sanitizers); the cross-process (`\d+`) reads are the tell.
_EXFIL_RE = re.compile(
    r"printenv|env\s*\||/proc/(?:self/(?:environ|mem)|\d+/(?:environ|mem|maps))|~/\.aws/credentials|"
    r"(?:AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|NPM_TOKEN|NODE_AUTH_TOKEN|PYPI_TOKEN|ACTIONS_RUNTIME_TOKEN|"
    r"ACTIONS_ID_TOKEN_REQUEST_TOKEN|CARGO_REGISTRY_TOKEN|TWINE_PASSWORD|NUGET_API_KEY)\b"
    r"[^\n]{0,80}?(?:curl|wget|nc\b|https?://|\|\s*(?:ba)?sh)",
    re.IGNORECASE)
_CI_PATH_RE = re.compile(r"(?:^|[\s\"'/])(\.github/workflows/[^\s\"']+|CODEOWNERS)\b")
_RAW_IP_URL_RE = re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?/\S*")

# Exfil sinks come in TWO precision tiers. The enrichment-fetch allowlist (MF2) owns "org-owned vs
# external"; THIS is the detection side — a NAMED list, not "any external host".
# Tier 1 — OAST / interaction / request-bin services whose ONLY purpose is receiving out-of-band callbacks
# (the tj-actions gist/webhook-callback shape). A committed reference has NO legitimate use → `high`.
_OAST_DOMAINS = (
    "webhook.site", "requestbin.com", "requestbin.net", "burpcollaborator.net",
    "oast.pro", "oast.live", "oast.site", "oast.online", "oast.fun", "oast.me",
    "interactsh.com", "dnslog.cn", "hookbin.com",
)
_OAST_DOMAIN_RE = re.compile(r"\b(?:" + "|".join(re.escape(d) for d in _OAST_DOMAINS) + r")\b", re.IGNORECASE)
# Tier 2 — dev tunnels / API-mock services. Heavily ABUSED as exfil sinks, BUT with mainstream legitimate
# use (smee.io is GitHub's own Probot webhook proxy; ngrok/beeceptor appear in ordinary dev READMEs). So a
# corroborating `medium` — BELOW the signal floor — never a standalone signal (the FP-safe tier).
_TUNNEL_DOMAINS = (
    "ngrok.io", "ngrok-free.app", "ngrok.app", "ngrok.dev", "smee.io",
    "beeceptor.com", "pipedream.net", "trycloudflare.com", "serveo.net",
)
_TUNNEL_DOMAIN_RE = re.compile(r"\b(?:" + "|".join(re.escape(d) for d in _TUNNEL_DOMAINS) + r")\b", re.IGNORECASE)

# CI-bypass markers: a commit/PR that skips the CI checks a malicious change would otherwise trip. Legit
# uses exist (a docs-only commit), so `medium` — BELOW the signal floor: a corroborating tell, never a
# standalone smoking gun (mirrors `workflow-tamper`'s tuning; a real payload fires its own high rule).
# GitHub honors [skip ci]/[ci skip]/[no ci]/[skip actions]/[actions skip] and the skip-checks trailer.
_CI_BYPASS_RE = re.compile(
    r"\[\s*(?:skip[\s_-]*ci|ci[\s_-]*skip|no[\s_-]*ci|skip[\s_-]*actions|actions[\s_-]*skip)\s*\]"
    r"|skip-checks\s*:\s*true", re.IGNORECASE)

# Workflow permission escalation: an over-broad `permissions: write-all` grant — the "permission model
# change" the malicious-PR research flags. Rare and high-signal, like a CODEOWNERS reassignment → `high`.
# LINE-ANCHORED (MULTILINE) on the YAML shorthand and NOT on a diff `-` deletion line, so REMOVING a
# write-all (the recommended hardening after tj-actions) and prose mentions do NOT fire.
_WRITE_ALL_RE = re.compile(r"^[+ ]?\s*permissions\s*:\s*write-all\b", re.IGNORECASE | re.MULTILINE)

# ── Workflow-CONFIGURATION escalation (distinct from `workflow-tamper`, which only asks "was a workflow
# file touched?"). This asks what the workflow BECOMES. `pull_request_target`/`workflow_run` run a fork
# PR's workflow with the BASE repo's token and secrets; on their own that is a legitimate pattern (label
# or comment bots that never touch the PR's code), so alone they are a sub-floor `medium`, consistent
# with `workflow-tamper`'s tuning. The lethal pairing is that trigger PLUS an explicit checkout of the PR
# HEAD — attacker-authored code executing inside the privileged context. That is the ROOT CAUSE of the
# AsyncAPI "Miasma" supply-chain compromise (a fork PR harvested the org-admin token out of the runner),
# and it has no safe reading → `critical`.
_PRIV_TRIGGER_RE = re.compile(r"^[+ ]?\s*(?:pull_request_target|workflow_run)\s*:", re.MULTILINE)
_PR_HEAD_REF_RE = re.compile(
    r"github\.event\.pull_request\.head\.(?:sha|ref)|github\.event\.workflow_run\.head_(?:sha|branch)|"
    r"refs/pull/[^\s\"']*/(?:head|merge)", re.IGNORECASE)

# Diff-PRESENTATION evasion — attacks aimed at the human reading the diff, not at the runtime. Miasma
# prepended ~700 spaces to shove its payload off the right edge of a standard diff viewer. No source
# formatter indents past ~60 columns, so a 200-space run before real content is unambiguous.
# NOT anchored to the line start. Miasma PREPENDED its ~700 spaces, but a run of that size sitting
# mid-line shoves the tail of the line off the viewport just as effectively, and the concealment is the
# thing being detected — not where it happens to sit. No formatter indents or aligns past ~60 columns.
_WS_SHOVE_RE = re.compile(r"[ \t]{200,}(?=\S)")
# Trojan Source: bidi overrides/isolates reorder rendered text away from what the compiler sees; ZWSP
# hides content outright. Deliberately EXCLUDES U+200E/U+200F (LRM/RLM) and U+200C/U+200D (ZWNJ/ZWJ),
# named here as CODEPOINTS rather than pasted literally — those carry real linguistic and emoji-
# sequence use and would fire on ordinary prose, and a comment full of invisible characters is the
# very thing this rule exists to catch (ruff PLE2502 rejects it, correctly).
# those carry real linguistic and emoji-sequence use, and would fire on ordinary prose.
_INVISIBLE_RE = re.compile("[\u202a-\u202e\u2066-\u2069\u200b]")  # escaped on purpose: literal
# invisible characters in this file would be unreadable, un-reviewable, and would trip this very rule.

# Node/npm execution primitives. Miasma's payload was JS end-to-end and our suite was shell/YAML-shaped,
# so every stage of it ran silently past the deterministic floor. Tuned rather than uniformly paranoid:
# `child_process` and `eval` appear in legitimate tooling constantly, so only the DETACHED spawn (a
# process deliberately outliving the parent — the stage-1 loader shape) and inline `node -e` execution
# reach the floor; a bare dynamic eval is a sub-floor corroborator.
_JS_CHILD_PROC_RE = re.compile(
    r"child_process|\b(?:execSync|spawnSync|execFileSync|execFile|spawn|fork)\s*\(", re.IGNORECASE)
_JS_DETACHED_RE = re.compile(r"detached\s*:\s*true|\.unref\s*\(\s*\)")
_NODE_INLINE_EXEC_RE = re.compile(
    r"\bnode\s+-e\b|process\.execPath[^\n]{0,120}['\"]-e['\"]|['\"]-e['\"][^\n]{0,120}process\.execPath")
_DYNAMIC_EVAL_RE = re.compile(r"\beval\s*\(|new\s+Function\s*\(")
# The dropper shape: pull bytes off the network AND commit them to disk. Either half alone is ordinary
# (every HTTP client fetches; every build writes files); together in one change they are a stage-2 loader.
_JS_NET_FETCH_RE = re.compile(
    r"\bfetch\s*\(|\baxios\b|require\s*\(\s*['\"]https?['\"]\s*\)|\bhttps?\.(?:get|request)\s*\(",
    re.IGNORECASE)
_FILE_WRITE_RE = re.compile(r"writeFileSync|createWriteStream|\bfs\.write", re.IGNORECASE)

# Tier 3 — content-addressed / permaweb gateways. Miasma staged its second-stage binary on IPFS. Same
# FP-safe reasoning as the dev tunnels: these have real mainstream use (web3 apps, NFT metadata), so a
# reference alone is a sub-floor `medium`. When the change actually FETCHES from one and writes the
# result to disk, `remote-fetch-to-disk` fires on its own and carries the signal.
_CONTENT_HOST_DOMAINS = (
    "ipfs.io", "dweb.link", "cloudflare-ipfs.com", "gateway.pinata.cloud", "ipfs.infura.io",
    "nftstorage.link", "w3s.link", "arweave.net", "ipfs.dweb.link",
)
_CONTENT_HOST_RE = re.compile(
    r"\b(?:" + "|".join(re.escape(d) for d in _CONTENT_HOST_DOMAINS) + r")\b", re.IGNORECASE)

# javascript-obfuscator's signature identifier mangling (`_0x1dd48b`). Terser/uglify emit SHORT names
# (`a`, `t`), never this form, so it is a strong obfuscation tell that base64 detection cannot see —
# Miasma's 15k-char `validator.js` payload used exactly this and fired nothing in our suite.
_HEX_IDENT_RE = re.compile(r"_0x[0-9a-fA-F]{4,}")

# Prompt-injection phrases — the class of payload hackerbot-claw aimed at a claude-code-action workflow.
_INJECTION_PHRASES = (
    "ignore previous instructions", "ignore all previous", "disregard the above",
    "disregard previous", "system prompt", "you are now", "new instructions:",
    "override your instructions", "bulk-label", "label all issues", "as an ai",
    "do not follow your instructions", "forget your instructions",
)
_INJECTION_RE = re.compile("|".join(re.escape(p) for p in _INJECTION_PHRASES), re.IGNORECASE)


def _scan_shell(text: str) -> list[IndicatorHit]:
    hits: list[IndicatorHit] = []
    for m in _IFS_RE.finditer(text):
        hits.append(_hit("ci-shell-injection", "high",
                         "`${IFS}` shell field-separator trick (space-evasion in a command)",
                         _snip(text, m.start(), m.end())))
    for m in _CURL_PIPE_RE.finditer(text):
        hits.append(_hit("curl-pipe-shell", "critical",
                         "pipe-to-shell download-and-execute (`curl … | bash`)",
                         _snip(text, m.start(), m.end())))
    for m in _CHMOD_EXEC_RE.finditer(text):
        hits.append(_hit("make-executable", "medium", "makes a file executable (`chmod +x`)",
                         _snip(text, m.start(), m.end())))
    subs = list(_CMD_SUBST_RE.finditer(text))
    for m in subs[:8]:  # cap: a diff can have many; the first few are enough to flag
        hits.append(_hit("command-substitution", "medium", "shell command substitution (`$(…)` / backticks)",
                         _snip(text, m.start(), m.end())))
    return hits


def _scan_obfuscation(text: str) -> list[IndicatorHit]:
    """Decode base64 blobs and RE-SCAN the decoded bytes for shell/exfil payloads (de-obfuscation)."""
    hits: list[IndicatorHit] = []
    seen: set[str] = set()
    for m in _B64_RE.finditer(text):
        blob = m.group(0)
        if blob in seen:
            continue
        seen.add(blob)
        try:
            decoded = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True).decode("utf-8", "replace")
        except (binascii.Error, ValueError):
            continue
        if not decoded.isprintable() and "\n" not in decoded:
            continue
        # Only flag base64 that DECODES to something suspicious — a plain data blob isn't an indicator.
        # (Rescan shell/exfil/URL/callback-domain payloads; CI-skip and permission markers aren't usefully
        # base64-wrapped, so they're not in the inner set.)
        inner = (_scan_shell(decoded) + _scan_urls(decoded) + _scan_exfil(decoded)
                 + _scan_exfil_domains(decoded) + _scan_js_exec(decoded))
        if inner:
            worst = max((h.severity for h in inner), key=lambda s: _sev_rank(s))
            hits.append(_hit("obfuscated-payload", worst,
                             "base64 blob decodes to a shell/exfil payload",
                             _snip(text, m.start(), m.end()), decoded=decoded[:_MAX_EVIDENCE]))
    return hits


def _scan_exfil(text: str) -> list[IndicatorHit]:
    return [_hit("data-exfiltration", "high", "reads secrets/credentials/environment",
                 _snip(text, m.start(), m.end()))
            for m in _EXFIL_RE.finditer(text)]


def _scan_urls(text: str) -> list[IndicatorHit]:
    return [_hit("raw-ip-url", "medium", "hardcoded raw-IP URL (possible C2 / non-standard host)",
                 _snip(text, m.start(), m.end()))
            for m in _RAW_IP_URL_RE.finditer(text)]


def _scan_exfil_domains(text: str) -> list[IndicatorHit]:
    hits = [_hit("exfil-infrastructure", "high",
                 "references a known exfil / OAST callback service (no legitimate use in a change)",
                 _snip(text, m.start(), m.end()))
            for m in _OAST_DOMAIN_RE.finditer(text)]
    hits += [_hit("dev-tunnel-endpoint", "medium",
                  "references a dev-tunnel / API-mock service (abused as an exfil sink)",
                  _snip(text, m.start(), m.end()))
             for m in _TUNNEL_DOMAIN_RE.finditer(text)]
    hits += [_hit("content-addressed-host", "medium",
                  "references an IPFS / permaweb gateway (abused to host a stage-2 payload)",
                  _snip(text, m.start(), m.end()))
             for m in _CONTENT_HOST_RE.finditer(text)]
    return hits


def _scan_ci_bypass(text: str) -> list[IndicatorHit]:
    return [_hit("ci-bypass", "medium",
                 "CI-skip marker (evades the checks a malicious change would trip)",
                 _snip(text, m.start(), m.end()))
            for m in _CI_BYPASS_RE.finditer(text)]


def _scan_workflow_perms(text: str) -> list[IndicatorHit]:
    return [_hit("workflow-permission-escalation", "high",
                 "over-broad workflow permission grant (`write-all`)",
                 _snip(text, m.start(), m.end()))
            for m in _WRITE_ALL_RE.finditer(text)]


def _scan_workflow_config(text: str) -> list[IndicatorHit]:
    """What a workflow BECOMES, not merely that one was touched (`workflow-tamper`'s job)."""
    trigger = _PRIV_TRIGGER_RE.search(text)
    if not trigger:
        return []
    head = _PR_HEAD_REF_RE.search(text)
    if head:
        return [_hit("pwn-request", "critical",
                     "privileged fork trigger checks out the PR HEAD — untrusted code with the base "
                     "repo's token/secrets",
                     _snip(text, head.start(), head.end()))]
    return [_hit("privileged-fork-trigger", "medium",
                 "`pull_request_target`/`workflow_run` — a fork PR runs in a privileged context",
                 _snip(text, trigger.start(), trigger.end()))]


def _scan_diff_evasion(text: str) -> list[IndicatorHit]:
    """Payloads aimed at the human READING the diff rather than at the runtime."""
    hits: list[IndicatorHit] = []
    m = _WS_SHOVE_RE.search(text)
    if m:
        hits.append(_hit("diff-viewport-evasion", "high",
                         "content shoved past the diff viewport by a long whitespace run",
                         f"{m.end() - m.start()} leading whitespace chars before content: "
                         f"{_snip(text, m.end(), m.end(), pad=80)}"))
    inv = _INVISIBLE_RE.search(text)
    if inv:
        hits.append(_hit("invisible-unicode", "high",
                         "bidi-override / zero-width characters (rendered text differs from real code)",
                         f"U+{ord(inv.group(0)):04X} at offset {inv.start()}: "
                         f"{_snip(text, inv.start(), inv.end())}"))
    return hits


def _scan_js_exec(text: str) -> list[IndicatorHit]:
    """Node/npm execution primitives — the ecosystem our shell/YAML-shaped rules were blind to."""
    hits: list[IndicatorHit] = []
    detached = _JS_DETACHED_RE.search(text)
    if detached and _JS_CHILD_PROC_RE.search(text):
        hits.append(_hit("detached-process-spawn", "high",
                         "spawns a DETACHED child process (outlives the parent — stage-1 loader shape)",
                         _snip(text, detached.start(), detached.end())))
    for m in _NODE_INLINE_EXEC_RE.finditer(text):
        hits.append(_hit("inline-code-exec", "high",
                         "executes code passed inline to node (`node -e`)",
                         _snip(text, m.start(), m.end())))
        break
    fetch = _JS_NET_FETCH_RE.search(text)
    write = _FILE_WRITE_RE.search(text)
    if fetch and write:
        hits.append(_hit("remote-fetch-to-disk", "high",
                         "fetches from the network AND writes the result to disk (dropper shape)",
                         _snip(text, fetch.start(), fetch.end())))
    ev = _DYNAMIC_EVAL_RE.search(text)
    if ev:
        hits.append(_hit("dynamic-code-eval", "medium",
                         "dynamic code evaluation (`eval` / `new Function`)",
                         _snip(text, ev.start(), ev.end())))
    return hits


def _scan_hex_identifiers(text: str) -> list[IndicatorHit]:
    """javascript-obfuscator's `_0x…` mangling — obfuscation that base64 detection cannot see."""
    found = _HEX_IDENT_RE.findall(text)
    if len(set(found)) >= 3 and len(found) >= 8:
        return [_hit("obfuscated-identifiers", "high",
                     "hex-mangled identifiers (`_0x…`) — machine-obfuscated JavaScript",
                     f"{len(set(found))} distinct over {len(found)} uses: "
                     f"{', '.join(sorted(set(found))[:6])}")]
    return []


def _scan_ci_paths(text: str) -> list[IndicatorHit]:
    hits: list[IndicatorHit] = []
    for m in _CI_PATH_RE.finditer(text):
        path = m.group(1)
        is_co = path == "CODEOWNERS"
        # CODEOWNERS reassignment is a rare, high-signal governance takeover (exactly hackerbot-claw's
        # move) → `high`. A plain workflow-file EDIT is common and legitimate → `medium` (below the
        # signal floor), so a benign workflow PR does not force a SIEM signal; a real payload inside the
        # workflow still fires the high/critical shell/obfuscation rules and forces the signal itself.
        rule = "codeowners-tamper" if is_co else "workflow-tamper"
        sev = "high" if is_co else "medium"
        title = ("reassigns code ownership (`CODEOWNERS`)" if is_co
                 else f"edits a CI workflow file (`{path}`)")
        hits.append(_hit(rule, sev, title, _snip(text, m.start(), m.end()), location=path))
    return hits


def _scan_injection(text: str) -> list[IndicatorHit]:
    return [_hit("prompt-injection", "high",
                 "prompt-injection phrasing aimed at an LLM reviewer/workflow",
                 _snip(text, m.start(), m.end()))
            for m in _INJECTION_RE.finditer(text)]


def _scan_entropy(text: str) -> list[IndicatorHit]:
    """A single flag for a very-high-entropy long token (packed/encrypted blob), capped to one hit."""
    for tok in re.findall(r"\S{60,}", text):
        if _shannon_entropy(tok) >= 4.5:
            return [_hit("high-entropy-blob", "low", "very high-entropy long token (packed/encoded data)",
                         tok[:_MAX_EVIDENCE])]
    return []


def _sev_rank(sev: str) -> int:
    from .schema import severity_rank
    return severity_rank(sev)


def scan_indicators(text: str, *, location: str = "") -> list[IndicatorHit]:
    """Run every detector over `text` and return the DEDUPED union of hits (by deterministic id).

    `location` labels hits that don't carry their own (a filename/region tag). Deterministic and
    side-effect-free — safe to run host-side (baseline) and in-loop (tool)."""
    text = text or ""
    all_hits = (
        _scan_shell(text) + _scan_obfuscation(text) + _scan_exfil(text) + _scan_urls(text)
        + _scan_exfil_domains(text) + _scan_ci_paths(text) + _scan_ci_bypass(text)
        + _scan_workflow_perms(text) + _scan_injection(text) + _scan_entropy(text)
        + _scan_workflow_config(text) + _scan_diff_evasion(text) + _scan_js_exec(text)
        + _scan_hex_identifiers(text)
    )
    deduped: dict[str, IndicatorHit] = {}
    for h in all_hits:
        if location and not h.location:
            h = h.model_copy(update={"location": location})
        deduped.setdefault(h.id, h)
    return list(deduped.values())


# ── provenance detectors: FACTS from host-side `gh api` ingest enrichment, NOT untrusted text ─────────
# These take the structured `provenance` dict (author type/association, account age, commit signatures)
# ingest.py attaches — the "source/provenance" signals from the malicious-PR research. Host-side ONLY: not
# an RLM tool (there is nothing for the planner to decode), recorded into the run_start baseline so they
# join the evidence union (MF3) and re-derive on read.

# Base names of first-party automation bots. A REAL bot commits as a `Bot`-type account
# (`renovate[bot]`); we scrutinise a `User`-type account wearing a bot identity. github.com forbids `[`/`]`
# in a username, so a `[bot]`-suffixed User login is STRUCTURALLY impossible for a real account → forged.
# A bot-like NAME (exact `renovate`, or a lookalike `renovate-bot`/`dependabot-fix`) is ambiguous: a legit
# HOSTED machine account (Mend's `renovate-bot`, `snyk-bot`) has one too, so it only rises to a signal when
# the account is ALSO an outsider (new / first-time) — an established machine account never trips it.
_BOT_BASES = ("dependabot", "renovate", "github-actions", "mergify", "snyk", "greenkeeper",
              "depfu", "imgbot", "pre-commit-ci", "allcontributors")
# author_association values that mean "not an established contributor to THIS repo".
_OUTSIDER_ASSOCIATIONS = frozenset({"FIRST_TIME_CONTRIBUTOR", "FIRST_TIMER", "NONE", "MANNEQUIN"})
_YOUNG_ACCOUNT_DAYS = 30  # younger than this is a weak newness tell (sub-floor)


def _resembles_bot(login_lower: str) -> bool:
    stripped = login_lower.replace("[bot]", "")
    return any(base in stripped for base in _BOT_BASES)


def scan_provenance(provenance: dict) -> list[IndicatorHit]:
    """Deterministic signals from host-side ingest enrichment (author/commit facts from `gh api`), not
    from the untrusted text. Tuned like the text rules: a new/first-time author and an unsigned commit are
    COMMON → sub-floor `low` corroborators (never force a signal alone). Bot identity: a `[bot]`-suffixed
    User login is a FORGED identity (impossible on real github.com) → `high`; a bot-like NAME only rises to
    a `medium` corroborator when the account is ALSO an outsider, so a legit hosted `renovate-bot` machine
    account never forces a signal. Deterministic + side-effect-free (safe in baseline)."""
    prov = provenance or {}
    hits: list[IndicatorHit] = []

    login = str(prov.get("author_login") or "")
    login_l = login.strip().lower()
    atype = str(prov.get("author_type") or "")
    is_user = bool(atype) and atype.lower() != "bot"   # KNOWN User (unknown/empty type stays silent)

    assoc = str(prov.get("author_association") or "").upper()
    age = prov.get("author_account_age_days")
    young = isinstance(age, (int, float)) and not isinstance(age, bool) and age < _YOUNG_ACCOUNT_DAYS
    outsider = assoc in _OUTSIDER_ASSOCIATIONS or young

    if is_user and login_l.endswith("[bot]"):
        hits.append(_hit("bot-impersonation", "high",
                         "a `[bot]`-suffixed login on a User account — a forged automation identity",
                         f"login={login[:80]} type={atype[:20]}"))
    elif is_user and outsider and _resembles_bot(login_l):
        hits.append(_hit("bot-like-author", "medium",
                         "a new/unestablished User account whose login mimics an automation bot",
                         f"login={login[:80]} type={atype[:20]} association={assoc[:40] or 'n/a'}"))

    # Display-name spoof — a bot-like PROFILE NAME (not login) worn by a new/unestablished User. Same
    # outsider gate as bot-like-author, so an established `renovate-bot` ("Renovate Bot") stays silent.
    display = str(prov.get("author_display_name") or "")
    if is_user and outsider and display and (_resembles_bot(display.lower())
                                             or display.strip().lower().endswith("[bot]")):
        hits.append(_hit("bot-like-display-name", "medium",
                         "a new/unestablished User whose DISPLAY NAME mimics an automation bot",
                         f"name={display[:80]} login={login[:80]}"))

    # Author account does not resolve — a positively-confirmed 404, or GitHub's `ghost` deletion
    # attribution. A real post-incident tell, but benign deletions happen too → medium (sub-floor).
    if prov.get("author_not_found") is True or login_l == "ghost":
        hits.append(_hit("author-unresolvable", "medium",
                         "the author account does not resolve (deleted / not found)",
                         f"login={login[:80] or 'n/a'} "
                         f"resolved={'404' if prov.get('author_not_found') is True else 'ghost-attribution'}"))

    unverified = prov.get("commits_unverified")
    if isinstance(unverified, int) and not isinstance(unverified, bool) and unverified > 0:
        total = prov.get("commits_total")
        ev = f"unverified={unverified}" + (f" of {total}" if isinstance(total, int) else "")
        hits.append(_hit("unsigned-commits", "low", "one or more commits are unsigned / unverified", ev))

    # A signature was attached but does NOT bind to the committer's GitHub identity (bad_email / unknown_key
    # / no_user / unverified_email) — spoofing-shaped, distinct from plain unsigned. Low: misconfigured-but-
    # honest signers produce these constantly, so a corroborator, never a signal driver.
    mismatch = prov.get("commits_sig_identity_mismatch")
    if isinstance(mismatch, int) and not isinstance(mismatch, bool) and mismatch > 0:
        hits.append(_hit("signature-identity-mismatch", "low",
                         "a commit signature does not bind to the committer's GitHub identity",
                         f"identity_mismatch={mismatch}"))

    # A forged bot-like git AUTHOR name on an UNVERIFIED commit (real API-created bot commits VERIFY) — the
    # commit-level spoof shape. Same outsider gate as the login/display rules: an established machine account
    # (self-hosted Renovate without platformCommit, github-actions committing via git) legitimately produces
    # unverified bot-named commits, and a Bot-type author authoring bot-named commits is normal — so this
    # only rises to a corroborator for an OUTSIDER User, and a name matching the author's OWN login (a
    # self-consistent identity) is not a spoof. Medium; the git author string is pure attacker input.
    authors = prov.get("unverified_commit_authors")
    if is_user and outsider and isinstance(authors, list):
        spoofed = next(
            (n for n in authors
             if isinstance(n, str) and n.strip().lower() != login_l
             and (_resembles_bot(n.strip().lower()) or n.strip().lower().endswith("[bot]"))),
            None)
        if spoofed:
            hits.append(_hit("spoofed-commit-author", "medium",
                             "an unsigned commit's git author name mimics an automation bot",
                             f"git_author={spoofed[:80]} login={login[:80]}"))

    reasons: list[str] = []
    if assoc in _OUTSIDER_ASSOCIATIONS:
        reasons.append(f"association={assoc}")
    if young:
        reasons.append("account_age<30d")   # BUCKETED, so re-ingesting a day later keeps the same hit id
    if reasons:
        hits.append(_hit("unknown-contributor", "low",
                         "author is not an established contributor (new / first-time)",
                         "; ".join(reasons)[:_MAX_EVIDENCE]))
    return hits


def make_indicator_tool() -> Callable[[str], str]:
    """Build the sync `scan_indicators` RLM tool. It scans a region the planner passes and RECORDS the
    full structured hits into the trace (so the evidence is a fact, re-sourced on read), then returns a
    compact text summary + the hit ids the planner may cite. Sync — dspy.RLM invokes tools synchronously."""
    from rlm_kit.trace import record_tool_call

    def scan_indicators_tool(region: str) -> str:
        """Scan a snippet of the change (or a value you decoded) for malicious indicators — shell
        injection, obfuscated payloads, secret exfiltration, known exfil/OAST callback services,
        CI/CODEOWNERS tampering, workflow permission escalation, CI-skip bypass, prompt injection. Returns
        the hits found (id, rule, severity, title). Cite an id in your final `indicator_ids`."""
        hits = scan_indicators(region or "")
        record_tool_call("scan_indicators", args={"region": (region or "")[:200]}, ok=True,
                         hits=[h.model_dump() for h in hits], n=len(hits))
        if not hits:
            return "No indicators fired on this region."
        lines = [f"- {h.id} [{h.severity}] {h.rule}: {h.title}" for h in hits]
        return f"{len(hits)} indicator(s):\n" + "\n".join(lines)

    # dspy registers a tool under its __name__ and the planner calls it by that name; the prompt
    # (detect.INSTRUCTIONS) says `scan_indicators(region)`, so the tool MUST register under exactly that
    # name — otherwise the sandbox call is a NameError. The inner def can't literally BE `scan_indicators`
    # without shadowing the module-level detector it calls, so rename the callable here. (The trace
    # `tool_call` already records the "scan_indicators" name via record_tool_call above.)
    scan_indicators_tool.__name__ = "scan_indicators"
    scan_indicators_tool.__qualname__ = "scan_indicators"
    return scan_indicators_tool


def hits_from_events(events: list[dict]) -> list[IndicatorHit]:
    """Re-source the UNION of every deterministic hit from a trace: the run_start meta BASELINE plus
    every `scan_indicators` tool_call's recorded hits, deduped by id. This is the evidence a signal is
    built on — never the planner's self-report (MF3)."""
    deduped: dict[str, IndicatorHit] = {}

    def _absorb(raw_hits) -> None:
        for h in raw_hits or []:
            try:
                hit = IndicatorHit(**h) if isinstance(h, dict) else h
            except (TypeError, ValueError):
                continue
            deduped.setdefault(hit.id, hit)

    for e in events:
        p = e.get("payload", {})
        if e.get("type") == "run_start":
            _absorb((p.get("meta") or {}).get("baseline_indicators"))
        elif e.get("type") == "tool_call" and p.get("tool") == "scan_indicators":
            _absorb(p.get("hits"))
    return list(deduped.values())
