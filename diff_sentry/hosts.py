"""Payload hosts: which hosts a change's indicators point at, and which of them mean something.

Two consumers share this. `actors` links campaigns by the payload infrastructure their flagged changes reuse, so it needs a token worth linking on; `indicators` needs to know when a download piped into a shell, written in prose, is the ordinary installer everyone quotes (rustup, nvm, Docker) and not a payload.

The lists are curated and short on purpose. A host missing from `COMMON_HOSTS` costs a noisy link; an entry wrongly in `KNOWN_INSTALLERS` hides a download-and-execute, so that list is exact hosts with an exact path pattern for anything shared, never a whole platform. And `installer_only` is STRICT: it accepts a command only when every argument parses cleanly as an installer URL (no userinfo, no dot segments, no encoding tricks, no extra target), and anything it does not understand keeps the hit at full severity. `fetch_targets`, which feeds IOC extraction, is the opposite: permissive, and it reads the host curl would actually connect to.

Pure stdlib; no dspy.
"""

from __future__ import annotations

import ipaddress
import posixpath
import re
from urllib.parse import unquote

# Hosts whose sharing links nothing: package registries, vendor download sites, the platform itself.
COMMON_HOSTS = (
    "github.com", "githubassets.com", "objects.githubusercontent.com", "avatars.githubusercontent.com",
    "user-images.githubusercontent.com", "camo.githubusercontent.com", "npmjs.org", "npmjs.com", "pypi.org",
    "pythonhosted.org", "crates.io", "rubygems.org", "docker.com", "docker.io", "golang.org", "go.dev",
    "rust-lang.org", "rustup.rs", "python.org", "nodejs.org", "brew.sh", "astral.sh", "bun.sh", "deno.land",
    "python-poetry.org", "helm.sh", "sentry.io", "codecov.io", "aka.ms", "microsoft.com", "google.com",
    "www.googleapis.com", "fonts.googleapis.com", "ajax.googleapis.com", "oauth2.googleapis.com",
    "apache.org", "gnu.org", "kernel.org", "llvm.org", "apple.com", "claude.ai", "anthropic.com",
    "ollama.com", "ollama.ai", "discord.com", "discordapp.com", "hooks.slack.com", "slack.com",
    "tailscale.com", "k3s.io", "volta.sh", "sdkman.io", "pyenv.run", "starship.rs", "nodesource.com", "pnpm.io",
    "example.com", "example.org", "example.net", "localhost",
)
# Multi-tenant hosts: the host says nothing, the first path segment (the account or bucket) is the identity.
TENANT_HOSTS = frozenset({
    "raw.githubusercontent.com", "gist.githubusercontent.com", "gist.github.com", "gitlab.com",
    "bitbucket.org", "storage.googleapis.com", "s3.amazonaws.com",
})
# Hosts where a per-account identifier is deeper in the path (a webhook id): (host, pattern with one group).
_SERVICE_IDS = (
    ("discord.com", re.compile(r"^/api/webhooks/(\d+)")), ("discordapp.com", re.compile(r"^/api/webhooks/(\d+)")),
    ("hooks.slack.com", re.compile(r"^/services/([A-Z0-9]+)")),
)
# github.com download URLs carry the account too: `/owner/repo/releases/download/…`.
_GITHUB_DOWNLOAD = re.compile(r"^/([^/]+)/[^/]+/(?:releases/download|raw|archive)/")
# (host, exact pattern the WHOLE normalized path must match, or None for any path on that host).
KNOWN_INSTALLERS: tuple[tuple[str, re.Pattern[str] | None], ...] = (
    ("sh.rustup.rs", None), ("rustup.rs", None), ("get.docker.com", None), ("install.python-poetry.org", None),
    ("astral.sh", re.compile(r"/(?:uv|ruff)/(?:\d+\.\d+\.\d+/)?install\.(?:sh|ps1)")),
    ("bun.sh", re.compile(r"/install(?:\.ps1)?")), ("deno.land", re.compile(r"/install\.(?:sh|ps1)")),
    ("get.pnpm.io", re.compile(r"/install\.(?:sh|ps1)")), ("sentry.io", re.compile(r"/get-cli/?")), ("brew.sh", None),
    ("raw.githubusercontent.com", re.compile(r"/nvm-sh/nvm/(?:v\d+\.\d+\.\d+|master|HEAD)/install\.sh")),
    ("raw.githubusercontent.com", re.compile(r"/Homebrew/install/(?:HEAD|master)/install\.sh")),
    ("claude.ai", re.compile(r"/install\.(?:sh|ps1)")), ("ollama.com", re.compile(r"/install\.sh")),
    ("ollama.ai", re.compile(r"/install\.sh")),
    ("raw.githubusercontent.com", re.compile(r"/ohmyzsh/ohmyzsh/master/tools/install\.sh")),
    ("raw.githubusercontent.com", re.compile(r"/helm/helm/main/scripts/get-helm-3")),
    ("tailscale.com", re.compile(r"/install\.sh")), ("get.k3s.io", None), ("get.volta.sh", None),
    ("get.sdkman.io", None), ("pyenv.run", None), ("starship.rs", re.compile(r"/install\.sh")),
    ("fnm.vercel.app", re.compile(r"/install")),
    ("deb.nodesource.com", re.compile(r"/setup_(?:\d+|lts|current)\.x")),
)

# Anchored and label-bounded: unambiguous, so it is linear even on a 65,000-character "host" an attacker wrote.
_HOST_RE = re.compile(r"\A(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}\Z")
_URL_RE = re.compile(r"https?://([^/\s\"'<>)\]?#\x00-\x1f\x7f]+)(/[^\s\"'<>)\]\x00-\x1f\x7f]*)?", re.IGNORECASE)
_FETCH_RE = re.compile(r"\b(?:curl|wget)\b([^\n|;&]{0,300})", re.IGNORECASE)
_SPACES_RE = re.compile(r"\$\{?IFS\}?|[{},]")
# Extensions that make `name.ext` a file, not a host, when there is no path after it.
_FILE_TLDS = frozenset({"txt", "sh", "json", "zip", "tar", "gz", "tgz", "bz2", "xz", "out", "log", "cfg", "conf",
                        "yml", "yaml", "py", "js", "html", "htm", "bin", "exe", "pem", "key", "crt", "cer", "md",
                        "rs", "go", "rb", "pl", "ps1", "bat", "cmd", "dll", "so", "deb", "rpm", "pkg", "dmg", "iso", "toml",
                        "jsonl", "csv", "pdf", "jar", "whl", "zst", "ini", "lock", "sql", "xml", "svg", "png", "jpg",
                        "gif", "ico", "css", "ts", "tsx", "jsx", "c", "h", "cpp", "hpp", "cs", "java", "kt"})
# The flags `installer_only` accepts. An ALLOWLIST: any other flag may add a target, change where bytes come from (`--proxy`, `--config`, `--input-file`, `--next`), or turn a boolean into a value, so it keeps the hit's severity.
_PLAIN_FLAGS = frozenset({"--fail", "--silent", "--show-error", "--location", "--quiet", "--tlsv1.2", "--tlsv1.3",
                          "--http1.1", "--http2"})
_CLUSTER_FLAG = re.compile(r"-[sSfLq]{1,6}")          # curl -sSfL / -fsSL, wget -q
_STDOUT_FLAG = re.compile(r"-[sSfLq]*[oO]-")          # curl -o- / wget -qO-
# `-m` is curl's max-time but wget's mirror mode (a boolean), so it is not accepted for either: the next token could be a target.
_NUMERIC_FLAGS = frozenset({"--retry", "--retry-delay", "--connect-timeout", "--max-time"})
_DEVNULL = re.compile(r"\d?>/dev/null")
_PLACEHOLDER = re.compile(r"\.{2,}|\u2026|<(?![^<>\s]*://)[^<>\s]{0,30}>|\[[^\[\]\s]{0,30}\]|(?i:url|<?url>?)")
_SHELLISH = re.compile(r"[$`(){}*;&|<>!\s\[\]\\]")


def _authority_host(authority: str) -> str | None:
    """The host curl would connect to for `authority` (`user@host:port`): after the LAST `@`, port stripped. None when it is not a plain DNS name or IPv4 address."""
    host = authority.rsplit("@", 1)[-1]
    if host.count(":") == 1:
        host = host.split(":", 1)[0]
    host = host.lower().rstrip(".")
    if len(host) > 253:                                  # longer than any DNS name: never a host
        return None
    if _HOST_RE.match(host):
        return host
    try:
        if re.fullmatch(r"0x[0-9a-f]+|\d+", host):           # `http://2130706433/` is 127.0.0.1 to curl
            try:
                return str(ipaddress.IPv4Address(int(host, 0)))
            except ValueError:
                return str(ipaddress.IPv4Address(int(host, 10)))
        return host if isinstance(ipaddress.ip_address(host), ipaddress.IPv4Address) else None
    except ValueError:
        return None


def _normal_path(path: str) -> str:
    """The path a server would see once percent-escapes and dot segments are resolved."""
    p = posixpath.normpath(unquote(path.split("?", 1)[0].split("#", 1)[0])) if path else ""
    return "/" + p.lstrip("/") if p and p != "." else ""


def fetch_targets(text: str) -> list[tuple[str, str]]:
    """`(host, path)` for every URL in `text` and every `curl`/`wget` target, in order, unfiltered. The host is the one curl connects to (a URL whose userinfo names an installer still connects to the host after the `@`).
    The shell's field-separator variable and brace lists are how a command is spelled without spaces, so they read as the spaces they stand for. Permissive by design: this feeds IOC extraction, where a wrong guess is a missed link, not a hidden payload."""
    found: dict[tuple[str, str], None] = {}
    for m in _URL_RE.finditer(text or ""):
        host = _authority_host(m.group(1))
        if host:
            found.setdefault((host, m.group(2) or ""), None)
    for m in _FETCH_RE.finditer(text or ""):
        # Every non-flag token is a candidate, whatever flag precedes it: a value flag differs between curl and wget (`-c`, `-m`, `-d`), and guessing wrong would swallow the payload host. A bare `out.txt` is not a host, so file-name look-alikes with no path are dropped instead.
        for tok in _SPACES_RE.sub(" ", m.group(1)).split():
            if tok.startswith("-"):
                continue
            authority, slash, tail = tok.strip("'\"").split("://", 1)[-1].partition("/")
            if "://" not in tok and not slash and re.fullmatch(r"0x[0-9a-f]+|\d+", authority):
                continue                                     # `--retry 16909060` is a count, `16909060/x` is 1.2.3.4
            host = _authority_host(authority)
            if host and (slash or host.rsplit(".", 1)[-1] not in _FILE_TLDS):
                found.setdefault((host, slash + re.split(r"[\x00-\x1f\x7f]", tail)[0]), None)
    return list(found)


def _strict_target(tok: str) -> tuple[str, str] | None:
    """`(host, normalized path)` when `tok` is a clean http(s) target and nothing else, else None. Rejects userinfo, non-default ports, queries and fragments, percent-encoding, backslashes, empty and dot segments, and any non-ASCII: each of those is a way to make a URL read as one host while fetching another."""
    tok = tok.strip("'\"")
    if _SHELLISH.search(tok):                            # `$(id)`, a backtick, a glob, a pipe: not a plain URL
        return None
    scheme, sep, rest = tok.partition("://")
    if sep:
        if scheme.lower() not in ("http", "https"):
            return None
    else:
        rest = tok
    authority, slash, path = rest.partition("/")
    path = slash + path
    if "@" in authority or not authority.isascii() or not path.isascii():
        return None
    if any(c in path for c in ("%", "\\", "?", "#")) or any(ord(c) < 32 or ord(c) == 127 for c in tok):
        return None
    if ":" in authority and authority.rsplit(":", 1)[1] not in ("80", "443"):
        return None
    host = _authority_host(authority)
    if host is None:
        return None
    segments = path.split("/")[1:] if path else []
    if any(s in ("", ".", "..") for s in segments[:-1]) or (segments and segments[-1] in (".", "..")):
        return None
    return host, path


def is_known_installer(host: str, path: str = "") -> bool:
    h = host.lower().rstrip(".")
    norm = _normal_path(path)
    return any(h == kh and (pat is None or pat.fullmatch(norm)) for kh, pat in KNOWN_INSTALLERS)


def _flag_extra(tok: str, nxt: str | None) -> int | None:
    """How many FOLLOWING tokens an allowed flag consumes (0 or 1), or None when the flag is not on the allowlist."""
    t = tok.strip("'\"")
    if _CLUSTER_FLAG.fullmatch(t) or _STDOUT_FLAG.fullmatch(t) or t in _PLAIN_FLAGS:
        return 0
    n = nxt.strip("'\"") if nxt is not None else None
    if (t in ("-o", "-O") or re.fullmatch(r"-[sSfLq]*[oO]", t)) and n == "-":       # `-o -`, `-qO -`
        return 1
    if t in ("--proto", "--proto-redir") and n == "=https":
        return 1
    if t in _NUMERIC_FLAGS and n is not None and n.isdigit():
        return 1
    return None


def _walk(text: str):
    """For each `curl`/`wget` in `text`: `(flags_ok, positional tokens)`. `flags_ok` is False as soon as a flag is not on the allowlist."""
    for m in _FETCH_RE.finditer(text or ""):
        toks = _SPACES_RE.sub(" ", m.group(1)).split()
        positional: list[str] = []
        ok = not (m.end() < len(text) and text[m.end()] not in "\n|;&")      # the capture was cut short: unread arguments
        i = 0
        while i < len(toks):
            tok = toks[i]
            if _DEVNULL.fullmatch(tok):                          # `2>/dev/null` silences errors, it names no target
                i += 1
                continue
            if tok.startswith("-"):
                extra = _flag_extra(tok, toks[i + 1] if i + 1 < len(toks) else None)
                if extra is None:
                    ok = False
                    break
                i += 1 + extra
                continue
            if not _PLACEHOLDER.fullmatch(tok.strip("`'\"")):         # a stand-in for the URL (an ellipsis, `<url>`) is no target
                positional.append(tok)
            i += 1
        yield ok, positional


def installer_only(text: str) -> bool:
    """True when every `curl`/`wget` in `text` names only known installers, and at least one is named.

    STRICT on both counts. Every argument must be a clean installer URL (no userinfo, dot segments, encoding, or shell syntax) and every FLAG must be on the allowlist (`-sSfL`, `-o-`, `--proto '=https'`, `--retry N`, …): `--proxy`, `--config`, `--input-file`, `--next`, or an attached `-xURL` can all change where the bytes come from, so any flag the check does not understand makes the answer False and the hit keeps its severity."""
    targets = 0
    for ok, positional in _walk(text):
        if not ok:
            return False
        for tok in positional:
            parsed = _strict_target(tok)
            if parsed is None or not is_known_installer(*parsed):
                return False
            targets += 1
    return targets > 0


_ANY_URL_RE = re.compile(r"https?://[^\s\"'()<>|,;`]{1,300}", re.IGNORECASE)
_BARE_URL = re.compile(r"(?<![\w./@:-])((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}/[^\s\"'()<>|,;`]{1,300})")
# What a PowerShell download-and-execute may consist of besides its URL: the cmdlets and aliases, the pipe, and the two parameters every installer one-liner uses. `-Proxy`, `-SkipCertificateCheck`, `-Headers` and anything else can change where the bytes come from, so they keep the hit's severity.
_PS_WORDS = frozenset({"iwr", "irm", "invoke-webrequest", "invoke-restmethod", "iex", "invoke-expression", "|",
                       "-uri", "-usebasicparsing", "-useb"})


def powershell_installer_only(text: str) -> bool:
    """True when `text` is a PowerShell download-and-execute whose every URL is a clean, known installer and which says nothing else (no proxy, no certificate switch, no other URL scheme). The counterpart of `installer_only` for the form that has no `curl` to walk."""
    # Spaced out the way it reads, and with the `https://` PowerShell 7 supplies when a URL has none (bun documents its Windows installer that way, with no spaces around the pipe).
    text = _BARE_URL.sub(r"https://\1", re.sub(r"\s*\|\s*", " | ", text or ""))
    found = _ANY_URL_RE.findall(text)
    if not found:
        return False
    for url in found:
        parsed = _strict_target(url)
        if parsed is None or not is_known_installer(*parsed):
            return False
    rest = re.sub(r"[()'\"]", " ", _ANY_URL_RE.sub(" ", text))
    return all(word.lower() in _PS_WORDS for word in rest.split())


def bare_command(text: str) -> bool:
    """True when every `curl`/`wget` in `text` has allowed flags and NO argument at all: a sentence that mentions a pipe into a shell with no download named. An argument the parser cannot read is NOT "no argument"; it stays a target."""
    seen = False
    for ok, positional in _walk(text):
        if not ok or positional:
            return False
        seen = True
    return seen


def _is_common(host: str) -> bool:
    h = host.lower().rstrip(".")
    try:
        ip = ipaddress.ip_address(h)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        pass
    return any(h == d or h.endswith("." + d) for d in COMMON_HOSTS)


def _safe(token: str) -> str:
    return re.sub(r"[^A-Za-z0-9._~-]", "", token)[:80]


def ioc_of(host: str, path: str = "") -> str | None:
    """The token two changes share when they use the same payload infrastructure, or None when the host links nothing (a registry, a vendor, a known installer, a private address). A multi-tenant host contributes its tenant (`raw.githubusercontent.com/attacker`), so a payload hosted on someone's GitHub is still a link. The path is resolved first, so `…/nvm-sh/nvm/../../attacker/x` is the attacker's."""
    h = host.lower().rstrip(".")
    norm = _normal_path(path)
    if is_known_installer(h, path):
        return None
    if h == "github.com":
        m = _GITHUB_DOWNLOAD.match(norm)
        return f"github.com/{_safe(m.group(1).lower())}" if m else None
    for svc_host, pat in _SERVICE_IDS:
        if h == svc_host:
            m = pat.match(norm)
            return f"{h}{norm[:m.end(1)]}" if m else None
    if h in TENANT_HOSTS:
        seg = _safe(norm.lstrip("/").split("/", 1)[0].lower())
        return f"{h}/{seg}" if seg else None
    if h.endswith(".storage.googleapis.com"):
        return h                                              # a bucket subdomain IS the tenant
    return None if _is_common(h) else h
