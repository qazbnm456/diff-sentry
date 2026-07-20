"""The one-way dependency fence: diff_sentry NEVER imports diff_sentry_eval; the reverse is the design.

A fresh subprocess interpreter, so no previously-imported module can mask a violation. An eval score with a
path back into the rollout core is the exact violation this prevents (it would bias the very measure the
harness provides).
"""

from __future__ import annotations

import pathlib
import subprocess
import sys


def test_import_diff_sentry_does_not_import_the_eval_harness():
    """The rollout core must stay eval-free: importing diff_sentry may not pull the harness."""
    code = "import sys, diff_sentry; assert 'diff_sentry_eval' not in sys.modules; print('ok')"
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "ok"


def test_import_eval_pulls_diff_sentry_one_way_and_stays_light():
    """The harness reads diff-sentry's contract (the one-way direction) without dragging dspy or openai at
    import time — scoring with the stub judge needs neither."""
    code = ("import sys, diff_sentry_eval; assert 'diff_sentry' in sys.modules; "
            "assert 'dspy' not in sys.modules; assert 'openai' not in sys.modules; print('ok')")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "ok"


def test_diff_sentry_source_never_references_the_harness():
    """Belt and braces: no module in the diff_sentry package may even NAME diff_sentry_eval."""
    import diff_sentry

    package_dir = pathlib.Path(diff_sentry.__file__).resolve().parent
    offenders = [str(p) for p in sorted(package_dir.rglob("*.py"))
                 if "diff_sentry_eval" in p.read_text(encoding="utf-8")]
    assert offenders == []
