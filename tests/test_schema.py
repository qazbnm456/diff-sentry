"""The judgement-only output model + its healing coercion."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from diff_sentry.schema import ChangeVerdict, decisive_verdict_model, max_severity, severity_rank
from tests.conftest import MALICIOUS_VERDICT


def test_change_verdict_roundtrip():
    v = ChangeVerdict.from_payload(MALICIOUS_VERDICT)
    assert v.verdict == "malicious"
    assert v.confidence == 0.95
    assert "codeowners-tamper" in v.techniques


def test_from_payload_ignores_legacy_keys():
    # a stray planner that tried to author indicators must not break coercion; the extra key is dropped
    payload = {**MALICIOUS_VERDICT, "indicators": [{"id": "x"}], "signal": True}
    v = ChangeVerdict.from_payload(payload)
    assert v.verdict == "malicious"
    assert not hasattr(v, "indicators")


def test_confidence_is_bounded():
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        ChangeVerdict(summary="s", verdict="benign", confidence=1.5, rationale="r")


def test_severity_ordering():
    assert severity_rank("critical") > severity_rank("high") > severity_rank("info")
    assert max_severity(["low", "critical", "medium"]) == "critical"
    assert max_severity([]) == "info"
    assert max_severity(["bogus"]) == "info"


def test_the_decisive_model_is_the_submit_type_with_inconclusive_refused_twice():
    model = decisive_verdict_model("3 files")
    assert model.__name__ == "ChangeVerdict" and issubclass(model, ChangeVerdict)
    assert model.model_json_schema() == ChangeVerdict.model_json_schema()     # the prompt the planner sees is unchanged
    for _ in range(2):
        with pytest.raises(ValidationError, match=r"refused: this change has content to classify \(3 files\)"):
            model(**{**MALICIOUS_VERDICT, "verdict": " Inconclusive"})
    assert model(**{**MALICIOUS_VERDICT, "verdict": "inconclusive"}).verdict == "inconclusive"
    assert model(**MALICIOUS_VERDICT).verdict == "malicious"
    assert decisive_verdict_model("x") is not model                          # each run counts its own refusals


_PR = {"repo": "acme/app", "kind": "pull_request", "number": 9, "author": "a", "title": "Add toast notifications",
       "body": "Shows a toast after save.", "head_ref": "feat/toast",
       "files": [{"filename": "src/lib/Save.svelte", "status": "modified", "additions": 3, "deletions": 1,
                  "patch": "@@ -1,2 +1,4 @@\n-import { save } from './api';\n+import { save } from './api';\n"
                           "+import { toast } from 'svelte-sonner';\n+\ttoast.success(  'Saved' );\n }"},
                 {"filename": "setup.py", "status": "added", "additions": 1, "deletions": 0, "patch": "+rm -rf /"},
                 {"filename": "lib/x.rb", "status": "added", "additions": 2, "deletions": 0, "patch": "+end\n+}"}],
       "comments": [{"author": "b", "association": "MEMBER", "created_at": "2026-01-01T00:00:00Z",
                     "body": "Please pin the sonner version before merging."}]}


def _quoting(event=_PR, **kw):
    from diff_sentry.normalize import quotable

    return decisive_verdict_model(None, quotable=quotable(event), **kw)


def _says(rationale, verdict="malicious"):
    return {**MALICIOUS_VERDICT, "verdict": verdict, "rationale": rationale}


@pytest.mark.parametrize("rationale", [
    "`import { toast } from 'svelte-sonner';` sends nothing anywhere.",          # a patch line, marker dropped
    "Line `+\ttoast.success( 'Saved' );` runs on save.",                         # its marker kept, blanks differ
    "Two lines: `+import { save } from './api';\n+import { toast } from 'svelte-sonner';`",
    "The new file `setup.py` holds `rm -rf /`.",                                  # short, but a path / a whole line
    "The title says `Add toast notifications`.", "The reviewer asked: `pin the sonner version before`.",
    "```js\nimport { toast } from 'svelte-sonner';\n```",                          # a fence, its info string dropped
])
def test_an_accusing_verdict_that_quotes_the_change_stands(rationale):
    for verdict in ("malicious", "suspicious"):
        assert _quoting()(**_says(rationale, verdict)).verdict == verdict


@pytest.mark.parametrize("rationale", [
    ("The sink pass over added lines plus scan_indicators returned 0 high/critical hit(s), including "
     "governance-file regions, which is not explicable as ordinary release churn."),  # r104's, verbatim
    "It imports `requests.post(attacker)`.",                                       # not in the change
    "It calls `toast`.",                                                           # short and not a whole line
    "The block ends in `}`.",                                                      # a whole changed line, no content
    "The file closes with `end`.",                                                 # a whole changed line under 4
    'It runs "import { toast } from \'svelte-sonner\';".',                         # double quotes are paraphrase
    "The repo is `acme/app` with `file_count`.",                                   # the metadata, not the change
    "`import { toast }" + " x" * 50_000,                                           # an unclosed backtick
    "`\ud800 lone surrogate in a quote`",
])
def test_an_accusing_verdict_that_quotes_nothing_is_refused_once(rationale):
    model = _quoting()
    with pytest.raises(ValidationError, match=r"refused: a `malicious` verdict names what in the change"):
        model(**_says(rationale))
    assert model(**_says(rationale)).verdict == "malicious"                       # the second stands


def test_the_quote_rule_never_touches_benign_inconclusive_or_the_extract_fallback():
    from diff_sentry.schema import no_refusal

    model = _quoting()
    assert model(**_says("no quote", "benign")).verdict == "benign"
    assert model(**_says("no quote", "inconclusive")).verdict == "inconclusive"
    with no_refusal():
        assert model(**_says("no quote")).verdict == "malicious"
    with pytest.raises(ValidationError):                                           # its one refusal is still there
        model(**_says("no quote"))


def test_inconclusive_and_quote_refusals_count_apart():
    from diff_sentry.normalize import quotable

    model = decisive_verdict_model("3 files", quotable=quotable(_PR))
    for verdict, match in (("inconclusive", "content to classify"), ("inconclusive", "content to classify"),
                           ("malicious", "quotes nothing")):
        with pytest.raises(ValidationError, match=match):
            model(**_says("no quote", verdict))
    assert model(**_says("no quote")).verdict == "malicious"


def test_the_release_facts_and_actor_history_can_be_quoted():
    from diff_sentry.normalize import quotable

    event = {**_PR, "actor_history": {"sightings": [{"note": "opened 40 typo PRs in one hour"}]},
             "release": {"package": "app", "publishers": ["new-maintainer-2026"]}}
    assert _quoting(event)(**_says("History: `opened 40 typo PRs in one hour`.")).verdict == "malicious"
    assert _quoting(event)(**_says("Published by `new-maintainer-2026`.")).verdict == "malicious"
    text, _ = quotable(event)
    assert "acme/app" not in text and "_diff_sentry_metadata" not in text


def test_a_fault_inside_the_quote_rule_lets_the_verdict_through(monkeypatch):
    from diff_sentry import schema

    monkeypatch.setattr(schema, "quotes_the_change", lambda *a: 1 / 0)
    assert _quoting()(**_says("no quote")).verdict == "malicious"
