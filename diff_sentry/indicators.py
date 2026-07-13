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
from typing import Callable

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
_EXFIL_RE = re.compile(
    r"printenv|env\s*\||/proc/self/environ|~/\.aws/credentials|"
    r"(?:AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|NPM_TOKEN)\b[^\n]{0,80}?(?:curl|wget|nc\b|https?://|\|\s*(?:ba)?sh)",
    re.IGNORECASE)
_CI_PATH_RE = re.compile(r"(?:^|[\s\"'/])(\.github/workflows/[^\s\"']+|CODEOWNERS)\b")
_RAW_IP_URL_RE = re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?/\S*")

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
        inner = _scan_shell(decoded) + _scan_urls(decoded) + _scan_exfil(decoded)
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
        + _scan_ci_paths(text) + _scan_injection(text) + _scan_entropy(text)
    )
    deduped: dict[str, IndicatorHit] = {}
    for h in all_hits:
        if location and not h.location:
            h = h.model_copy(update={"location": location})
        deduped.setdefault(h.id, h)
    return list(deduped.values())


def make_indicator_tool() -> Callable[[str], str]:
    """Build the sync `scan_indicators` RLM tool. It scans a region the planner passes and RECORDS the
    full structured hits into the trace (so the evidence is a fact, re-sourced on read), then returns a
    compact text summary + the hit ids the planner may cite. Sync — dspy.RLM invokes tools synchronously."""
    from rlm_kit.trace import record_tool_call

    def scan_indicators_tool(region: str) -> str:
        """Scan a snippet of the change (or a value you decoded) for malicious indicators — shell
        injection, obfuscated payloads, exfiltration, CI/CODEOWNERS tampering, prompt injection. Returns
        the hits found (id, rule, severity, title). Cite an id in your final `indicator_ids`."""
        hits = scan_indicators(region or "")
        record_tool_call("scan_indicators", args={"region": (region or "")[:200]}, ok=True,
                         hits=[h.model_dump() for h in hits], n=len(hits))
        if not hits:
            return "No indicators fired on this region."
        lines = [f"- {h.id} [{h.severity}] {h.rule}: {h.title}" for h in hits]
        return f"{len(hits)} indicator(s):\n" + "\n".join(lines)

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
