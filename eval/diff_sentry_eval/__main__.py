"""`python -m diff_sentry_eval` — the same entry as the `diff-sentry-eval` script."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
