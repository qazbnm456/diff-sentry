"""The repo scans its own pull requests with its own rules (`self-scan (dogfood)` in ci.yml). Files that carry attack patterns as their job are listed under `report-only-paths`; everything else is GATED, and CI's own rule for a gated file is "describe a payload shape, never quote one". A module added without that discipline turns the job red only after the push, so the package's gated source is held to the same rule here."""

from __future__ import annotations

import fnmatch
import subprocess
from pathlib import Path

import pytest

from diff_sentry.indicators import scan_diff

_ROOT = Path(__file__).resolve().parents[1]


def _report_only_globs() -> list[str]:
    lines = (_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8").splitlines()
    for i, line in enumerate(lines):
        if line.strip().startswith("report-only-paths:"):
            base = len(line) - len(line.lstrip())
            out = []
            for follow in lines[i + 1:]:
                if follow.strip() and len(follow) - len(follow.lstrip()) <= base:
                    break
                if follow.strip():
                    out.append(follow.strip())
            return out
    return []


def _report_only(path: str, globs: list[str]) -> bool:
    return any((g.endswith("/**") and path.startswith(g[:-2])) or fnmatch.fnmatch(path, g)
               or (g == "*.md" and path.endswith(".md")) for g in globs)


def _gated_source() -> list[str]:
    try:
        files = subprocess.run(["git", "ls-files", "-co", "--exclude-standard"], cwd=_ROOT, capture_output=True,
                               text=True, check=True).stdout.split()
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("not a git checkout")
    globs = _report_only_globs()
    return [f for f in files if f.startswith("diff_sentry/") and f.endswith(".py") and not _report_only(f, globs)]


def test_the_report_only_list_is_readable():
    globs = _report_only_globs()
    assert "diff_sentry/indicators.py" in globs and "tests/**" in globs and "*.md" in globs


@pytest.mark.parametrize("path", _gated_source())
def test_a_gated_module_quotes_no_payload(path):
    text = (_ROOT / path).read_text(encoding="utf-8")
    hard = [(h.rule, h.severity, h.evidence[:90]) for h in scan_diff(text, location=path)
            if h.severity in ("high", "critical")]
    assert not hard, f"{path} would fail the self-scan job: {hard}"
