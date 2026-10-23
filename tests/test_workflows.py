"""The repository's own workflows weight the slash-command rule: a command no workflow answers steps down, one a workflow matches steps up, and an outsider's PR into a repository that runs fork code under `pull_request_target` is a corroborator. No network: the API is faked."""

from __future__ import annotations

import base64

import pytest

from diff_sentry.indicators import scan_metadata, scan_provenance
from diff_sentry.ingest import GhApiError, repo_workflows

_FORMAT = """name: format
on:
  issue_comment:
    types: [created]
jobs:
  fmt:
    if: contains(github.event.comment.body, '/format')
    runs-on: ubuntu-latest
"""
_ANY_COMMENT = "on: [issue_comment]\njobs:\n  greet:\n    runs-on: ubuntu-latest\n"
_PRT = """on: pull_request_target
jobs:
  test:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
"""
_PUSH = "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
# reads the head to diff it, never checks it out (litellm's cost-map guard)
_PRT_FETCH_ONLY = """on: pull_request_target
jobs:
  guard:
    steps:
      - uses: actions/checkout@v4
      - env:
          HEAD_SHA: ${{ github.event.pull_request.head.sha }}
        run: git fetch --depth=1 origin "$HEAD_SHA"
"""


def _api(files: dict[str, str], *, listing_status: int | None = None, broken: str | None = None):
    calls = []

    def call(path: str):
        calls.append(path)
        if path.endswith("/contents/.github/workflows"):
            if listing_status:
                raise GhApiError(path, status=listing_status)
            return [{"type": "file", "name": n, "path": f".github/workflows/{n}", "size": len(t)} for n, t in files.items()]
        name = path.rsplit("/", 1)[1]
        if name == broken:
            raise RuntimeError("down")
        return {"content": base64.b64encode(files[name].encode()).decode(), "encoding": "base64"}

    call.calls = calls
    return call


def test_the_workflows_are_read_for_their_triggers_and_commands():
    facts = repo_workflows("o/r", _api({"fmt.yml": _FORMAT, "hello.yml": _ANY_COMMENT, "prt.yml": _PRT, "ci.yml": _PUSH}))
    assert facts == {"repo_workflows_read": True, "repo_comment_workflows": 2, "repo_comment_commands": ["format"],
                     "repo_comment_commands_open": ["format"], "repo_comment_workflows_unfiltered": 1,
                     "repo_prt_head_checkout": [".github/workflows/prt.yml"]}


def test_a_gated_command_is_matched_but_not_open_and_a_path_is_not_a_command():
    gated = _FORMAT.replace("    if: contains", "    if: github.event.comment.author_association == 'MEMBER' && contains") + "    steps:\n      - with:\n          path: '/tmp'\n"
    facts = repo_workflows("o/r", _api({"fmt.yml": gated}))
    assert facts["repo_comment_commands"] == ["format"] and facts["repo_comment_commands_open"] == []


def test_more_workflows_than_it_reads_is_no_facts():
    assert repo_workflows("o/r", _api({f"w{i}.yml": _PUSH for i in range(101)})) == {}


@pytest.mark.parametrize(("text", "runs"), [
    (_PRT, True),
    (_PRT_FETCH_ONLY, False),
    ("on: pull_request_target\njobs:\n  t:\n    steps:\n      - run: gh pr checkout ${{ github.event.number }}\n", True),
    ("on: pull_request_target\njobs:\n  t:\n    steps:\n      - run: git checkout ${{ github.event.pull_request.head.sha }}\n", True),
    ("on: pull_request_target\njobs:\n  t:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: refs/pull/${{ github.event.number }}/merge\n", True),
    ("on: pull_request_target\njobs:\n  t:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.merge_commit_sha }}\n", True),
    ("on: pull_request_target\njobs:\n  t:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          repository: ${{ github.event.pull_request.head.repo.full_name }}\n", True),
    ("on: pull_request_target\njobs:\n  t:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ format('refs/pull/{0}/merge', github.event.number) }}\n", True),
    ("on: pull_request_target\njobs:\n  t:\n    steps:\n      - run: git fetch origin pull/${{ github.event.number }}/head && git checkout FETCH_HEAD\n", True),
])
def test_only_a_checkout_of_the_prs_code_counts(text, runs):
    assert bool(repo_workflows("o/r", _api({"w.yml": text}))["repo_prt_head_checkout"]) is runs


def test_no_workflows_directory_is_a_fact_and_an_unread_one_is_none():
    assert repo_workflows("o/r", _api({}, listing_status=404)) == {"repo_workflows_read": True, "repo_comment_workflows": 0}
    assert repo_workflows("o/r", _api({}, listing_status=500)) == {}
    assert repo_workflows("o/r", _api({"fmt.yml": _FORMAT, "ci.yml": _PUSH}, broken="ci.yml")) == {}


def _rule(event: dict) -> str | None:
    return next((h.severity for h in scan_metadata(event) if h.rule == "slash-command-trigger"), None)


def _event(body: str = "/format", at: str = "2026-02-27T05:20:00Z", **prov) -> dict:
    return {"author": "m", "created_at": "2026-02-27T05:14:00Z", "provenance": prov,
            "comments": [{"author": "m", "author_association": "NONE", "body": body, "created_at": at, "author_type": "User"}]}


@pytest.mark.parametrize(("prov", "quick", "slow"), [
    ({}, "medium", "low"),                                                                   # not read: the plain reading
    ({"repo_workflows_read": True, "repo_comment_workflows": 0}, "low", "info"),            # nothing starts on a comment
    ({"repo_workflows_read": True, "repo_comment_workflows": 1, "repo_comment_commands": ["deploy"]}, "low", "info"),
    ({"repo_workflows_read": True, "repo_comment_workflows": 1, "repo_comment_commands": ["format"],
      "repo_comment_commands_open": ["format"]}, "high", "medium"),                         # anyone can run it
    ({"repo_workflows_read": True, "repo_comment_workflows": 1, "repo_comment_commands": ["format"]}, "medium", "low"),   # only some
    ({"repo_workflows_read": True, "repo_comment_workflows": 2, "repo_comment_commands": ["deploy"],
      "repo_comment_workflows_unfiltered": 1}, "medium", "low"),                            # one answers any comment
])
def test_the_slash_command_is_weighted_by_what_the_repository_runs(prov, quick, slow):
    assert _rule(_event(**prov)) == quick
    assert _rule(_event(at="2026-02-27T09:20:00Z", **prov)) == slow


def test_an_outsiders_pr_into_a_repository_running_fork_code_is_a_corroborator():
    prov = {"author_login": "m", "author_type": "User", "author_association": "NONE", "head_sha": "abc",
            "repo_prt_head_checkout": [".github/workflows/prt.yml"]}
    assert {h.rule: h.severity for h in scan_provenance(prov)}.get("prt-runs-fork-code") == "medium"
    assert "prt-runs-fork-code" not in {h.rule for h in scan_provenance({**prov, "author_association": "MEMBER",
                                                                             "author_account_age_days": 900})}
    assert "prt-runs-fork-code" not in {h.rule for h in scan_provenance({k: v for k, v in prov.items() if k != "head_sha"})}


def test_the_watcher_reads_a_repositorys_workflows_once_an_hour(monkeypatch):
    from diff_sentry import watch

    clock = [1000.0]
    monkeypatch.setattr(watch.time, "monotonic", lambda: clock[0])
    w = watch.Watcher.__new__(watch.Watcher)
    w._workflows = {}
    api = _api({"fmt.yml": _FORMAT})
    w._repo_workflows("o/r", api)
    w._repo_workflows("o/r", api)
    assert len(api.calls) == 2                       # the listing and one workflow, once
    clock[0] += 3601
    w._repo_workflows("o/r", api)
    assert len(api.calls) == 4



@pytest.mark.parametrize("gate", ["if: github.actor == 'maintainer'", "if: 'bot' == github.event.comment.user.login",
                                  "run: gh api repos/o/r/collaborators/$USER", "uses: ./.github/workflows/handle.yml",
                                  "uses: org/shared/.github/workflows/gate.yml@v1", "uses: ./.github/actions/check-author"])
def test_a_commenter_check_in_any_common_form_keeps_the_command_from_the_open_set(gate):
    facts = repo_workflows("o/r", _api({"fmt.yml": _FORMAT + f"    {gate}\n"}))
    assert facts["repo_comment_commands"] == ["format"] and facts["repo_comment_commands_open"] == []


def test_a_dispatcher_that_reads_commands_on_other_lines_is_an_open_handler():
    dispatcher = _FORMAT + """    steps:
      - run: |
          CMD=$(jq -r .x "$GITHUB_EVENT_PATH")
          case "$CMD" in "/deploy") ./deploy.sh ;; esac
"""
    facts = repo_workflows("o/r", _api({"fmt.yml": dispatcher}))
    assert facts["repo_comment_workflows_unfiltered"] == 1
    assert _rule(_event("/deploy", **facts)) == "medium"          # the plain reading, never a step down
