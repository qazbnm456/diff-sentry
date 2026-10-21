"""A GitHub owner that imitates the repository's own: litellm 1.107.0's private release workflow was pointed at `Berri-AI/litellm` (the project is `BerriAI`) by a commit pushed past branch protection, and built the release from it. The Action scans a push as well as a pull request, so that commit is a diff it can read."""

from __future__ import annotations

import pytest

from diff_sentry.indicators import lookalike_owner, scan_change, scan_diff


@pytest.mark.parametrize(("candidate", "owner", "how"), [
    ("Berri-AI", "BerriAI", "hyphen"),
    ("open-telemetry", "opentelemetry", "hyphen"),
    ("BerriAl", "BerriAI", "edit"),           # one letter, six or more characters
    ("BerirAI", "BerriAI", "edit"),           # two letters swapped
    ("ipython", "python", "edit"),            # a real sibling organisation: why an edit is only medium
    ("berriai", "BerriAI", None),             # GitHub owners ignore case: the same account
    ("BerriAI", "BerriAI", None),
    ("pypi", "pypa", None),                   # one edit, but too short to read as a lookalike
    ("python", "astral-sh", None),
])
def test_what_reads_as_the_owner(candidate, owner, how):
    assert lookalike_owner(candidate, owner) == how


def _diff(path: str, old: str, new: str) -> str:
    return (f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -1,2 +1,2 @@\n"
            f" name: release\n-{old}\n+{new}\n")


def _rules(hits) -> dict[str, str]:
    return {h.rule: h.severity for h in hits if h.rule in ("lookalike-owner", "foreign-checkout")}


@pytest.mark.parametrize("line", [
    "  source_repo:\n+    default: Berri-AI/litellm",                  # an input's default
    "          repository: Berri-AI/litellm",                          # a checkout
    "      - run: git clone https://github.com/Berri-AI/litellm src",  # a clone
    "      - uses: Berri-AI/setup-release@v1",                          # an action
    "  SOURCE_REPO: Berri-AI/litellm",                                 # a variable
    "      - run: curl -L https://api.github.com/repos/Berri-AI/litellm/tarball/main | tar xz",
    "      - run: gh api repos/Berri-AI/litellm/tarball/main > src.tgz",
    "      - run: git clone https://GITHUB.COM/Berri-AI/litellm",
    "      - run: curl -sSf https://raw.githubusercontent.com/Berri-AI/litellm/main/x.sh -o x.sh",
    "      - run: docker pull ghcr.io/berri-ai/litellm:latest",
    "      - run: gh release download -R Berri-AI/litellm",
])
def test_a_workflow_pointed_at_a_lookalike_owner_is_critical(line):
    diff = _diff(".github/workflows/release.yml", "    default: BerriAI/litellm", line)
    assert _rules(scan_diff(diff, files=True, owner="BerriAI")) == {"lookalike-owner": "critical"}


def test_a_lookalike_outside_a_workflow_is_high():
    diff = _diff("scripts/build.sh", "git clone https://github.com/BerriAI/litellm", "git clone https://github.com/Berri-AI/litellm")
    assert _rules(scan_diff(diff, files=True, owner="BerriAI")) == {"lookalike-owner": "high"}


def test_checking_out_another_owner_is_medium_and_the_own_owner_is_nothing():
    other = _diff(".github/workflows/ci.yml", "x: 1", "          repository: actions/example")
    assert _rules(scan_diff(other, files=True, owner="BerriAI")) == {"foreign-checkout": "medium"}
    own = _diff(".github/workflows/ci.yml", "x: 1", "          repository: berriai/litellm-docs")
    assert _rules(scan_diff(own, files=True, owner="BerriAI")) == {}


def test_a_removed_lookalike_and_an_unknown_owner_raise_nothing():
    removed = _diff(".github/workflows/release.yml", "    default: Berri-AI/litellm", "    default: BerriAI/litellm")
    assert _rules(scan_diff(removed, files=True, owner="BerriAI")) == {}
    added = _diff(".github/workflows/release.yml", "x: 1", "    default: Berri-AI/litellm")
    assert _rules(scan_diff(added, files=True)) == {}          # the scan does not know whose repository it is


def test_a_pull_request_is_judged_against_its_repository():
    event = {"repo": "BerriAI/litellm", "kind": "pull_request", "number": 1, "author": "dev", "title": "ci", "body": "",
             "files": [{"filename": ".github/workflows/release.yml", "status": "modified", "additions": 1, "deletions": 1,
                        "patch": "@@ -1,2 +1,2 @@\n   source_repo:\n-    default: BerriAI/litellm\n+    default: Berri-AI/litellm"}]}
    assert _rules(scan_change(event)) == {"lookalike-owner": "critical"}
    release = {**event, "repo": "pypi/litellm", "kind": "release"}
    assert _rules(scan_change(release)) == {}


def test_the_scan_command_reads_the_owner_from_the_actions_environment(tmp_path, monkeypatch, capsys):
    from diff_sentry import cli

    path = tmp_path / "x.diff"
    path.write_text(_diff(".github/workflows/release.yml", "x: 1", "  source_repo:\n+    default: Berri-AI/litellm"))
    monkeypatch.setenv("GITHUB_REPOSITORY", "BerriAI/litellm")
    assert cli.main(["scan", str(path)]) == 1
    assert "lookalike-owner" in capsys.readouterr().out
    assert cli.main(["scan", "--repo", "acme/widgets", str(path)]) == 0


@pytest.mark.parametrize(("line", "owner"), [
    ("          images: nodered/node-red", "node-red"),           # Docker Hub namespaces drop the hyphen
    ("          tags: openpolicyagent/opa:latest", "open-policy-agent"),
    ("    container: condaforge/linux-anvil-cos7-x86_64", "conda-forge"),
    ("      - run: pylint homeassistant/components/foo", "home-assistant"),   # a package directory
    ("      - run: buf lint opentelemetry/proto", "open-telemetry"),
    ("      - run: node action/dist/index.js", "actions"),
])
def test_an_image_or_a_path_is_no_owner(line, owner):
    diff = _diff(".github/workflows/ci.yml", "x: 1", line)
    assert _rules(scan_diff(diff, files=True, owner=owner)) == {}


def test_a_sibling_organisation_one_edit_away_stays_below_the_floor():
    diff = _diff("docs/links.sh", "x=1", "git clone https://github.com/python/cpython")
    assert _rules(scan_diff(diff, files=True, owner="ipython")) == {"lookalike-owner": "medium"}


def test_padding_cannot_push_the_lookalike_out_of_reach():
    line = "    # " + " ".join(["a/b"] * 2_001) + "\n+  source_repo:\n+    default: Berri-AI/litellm"
    diff = _diff(".github/workflows/release.yml", "x: 1", line)
    assert _rules(scan_diff(diff, files=True, owner="BerriAI")) == {"lookalike-owner": "critical"}


def test_npm_shorthand_and_a_repo_flag_outside_a_workflow():
    npm = _diff("package.json", '  "x": 1', '  "repository": "github:Berri-AI/litellm"')
    assert _rules(scan_diff(npm, files=True, owner="BerriAI")) == {"lookalike-owner": "high"}
    flag = _diff("scripts/b.sh", "x=1", "gh release download -R Berri-AI/litellm")
    assert _rules(scan_diff(flag, files=True, owner="BerriAI")) == {"lookalike-owner": "high"}


@pytest.mark.parametrize("padding", [
    "".join(f"          repository: org{i}/x\n+" for i in range(60)),            # cheap foreign checkouts in front
    "".join(f"  # github.com/Berri{c}AI/x\n+" for c in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"),
])
def test_cheap_hits_in_front_never_crowd_out_the_lookalike(padding):
    diff = _diff(".github/workflows/release.yml", "x: 1",
                 padding + "  source_repo:\n+    description: where to build from\n+    default: Berri-AI/litellm")
    assert _rules(scan_diff(diff, files=True, owner="BerriAI"))["lookalike-owner"] == "critical"


@pytest.mark.parametrize(("path", "lines", "owner"), [
    ("charts/gatekeeper/values.yaml", "image:\n+  repository: openpolicyagent/gatekeeper", "open-policy-agent"),
    ("chart/values.yaml", "image:\n+  repository: nodered/node-red", "node-red"),
    ("scripts/push.sh", "DOCKER_REPO=condaforge/miniforge3", "conda-forge"),
    ("setup.cfg", "source_dir = opentelemetry/proto", "open-telemetry"),
])
def test_an_image_or_a_path_under_a_repository_key_stays_below_the_floor(path, lines, owner):
    from diff_sentry.schema import severity_rank

    hits = [h for h in scan_diff(_diff(path, "x: 1", lines), files=True, owner=owner) if h.rule == "lookalike-owner"]
    assert all(severity_rank(h.severity) < severity_rank("high") for h in hits)


@pytest.mark.parametrize("line", [
    "  SOURCE_REPO2: Berri-AI/litellm",
    '        include: [{"repo": "Berri-AI/litellm"}]',
])
def test_a_key_with_a_digit_and_a_json_key_are_read(line):
    diff = _diff(".github/workflows/release.yml", "x: 1", line)
    assert _rules(scan_diff(diff, files=True, owner="BerriAI")) == {"lookalike-owner": "critical"}


def _workflow(*lines: str, context: tuple[str, ...] = ()) -> str:
    body = "".join(f" {c}\n" for c in context) + "".join(f"+{line}\n" for line in lines)
    n = len(context) + len(lines)
    return f"diff --git a/.github/workflows/r.yml b/.github/workflows/r.yml\n--- a/.github/workflows/r.yml\n+++ b/.github/workflows/r.yml\n@@ -1,{len(context)} +1,{n} @@\n{body}"


@pytest.mark.parametrize("lines", [
    ("env:", "  # image", "  X_REPO: Berri-AI/litellm", "steps:", "  - uses: actions/checkout@v4", "    with:",
     "      repository: Berri-AI/litellm"),
    ("  # image", "  X_REPO: Berri-AI/litellm", "  - run: git clone https://github.com/Berri-AI/litellm"),
])
def test_a_weak_sighting_first_never_hides_a_strong_one_after(lines):
    assert _rules(scan_diff(_workflow(*lines), files=True, owner="BerriAI")) == {"lookalike-owner": "critical"}


@pytest.mark.parametrize(("lines", "context"), [
    (("    # docker", "    with:", "      repository: Berri-AI/litellm"), ()),
    (("  - name: Checkout source for the docker image", "    uses: actions/checkout@v4", "    with:",
      "      repository: Berri-AI/litellm"), ()),
    (("      repository: Berri-AI/litellm",), ("  - name: Build image", "    uses: actions/checkout@v4", "    with:")),
    (("  source_repo:", "    description: Repository to build the docker image from", "    default: Berri-AI/litellm"), ()),
])
def test_words_around_a_reference_never_demote_it(lines, context):
    assert _rules(scan_diff(_workflow(*lines, context=context), files=True, owner="BerriAI")) == {"lookalike-owner": "critical"}


def test_a_flow_mapping_and_a_parent_past_a_hunk_edge():
    flow = _workflow("    with: {path: chart, repository: Berri-AI/litellm}")
    assert _rules(scan_diff(flow, files=True, owner="BerriAI")) == {"lookalike-owner": "critical"}
    crossed = ("diff --git a/.github/workflows/r.yml b/.github/workflows/r.yml\n--- a/.github/workflows/r.yml\n"
               "+++ b/.github/workflows/r.yml\n@@ -1,1 +1,1 @@\n image: x\n@@ -50,1 +50,2 @@\n         with:\n"
               "+          repository: Berri-AI/litellm\n")
    assert _rules(scan_diff(crossed, files=True, owner="BerriAI")) == {"lookalike-owner": "critical"}


@pytest.mark.parametrize(("line", "owner"), [
    ("  IMAGE_REPO: natsio/nats-box", "nats-io"),
    ("  docker_repository: homeassistant/home-assistant", "home-assistant"),
    ("        default: homeassistant/components", "home-assistant"),
    ("    image: {repository: nodered/node-red}", "node-red"),
])
def test_a_hyphen_lookalike_in_a_workflow_is_critical_whatever_the_yaml_around_it(line, owner):
    # an accepted over-alert: no reading of the YAML around a reference decides it, since every such reading had a spelling that moved the checkout's own `repository:` below the floor
    assert _rules(scan_diff(_workflow(line), files=True, owner=owner)) == {"lookalike-owner": "critical"}


@pytest.mark.parametrize("lines", [
    ("    with:", "      repository:", "        Berri-AI/litellm"),               # the value on the next line
    ("      repository: >-", "        Berri-AI/litellm"),                         # a block scalar
    ('      repository: "', '        Berri-AI/litellm"'),                         # a quote opened on the key's line
    ("      repository: !!str Berri-AI/litellm",),                                # a tag
    ("  SRC_REPO: &src Berri-AI/litellm",),                                       # an anchor
    ("      repository: !!str", "        Berri-AI/litellm"),                     # a tag, then the next line
    ("      repository: &a !!str Berri-AI/litellm",),                             # an anchor before a tag
    ("      repository:", "", "        Berri-AI/litellm"),                     # a blank line between
    ("      repository: # src", "        Berri-AI/litellm"),                    # a comment after the key
    ("      repository:", "        # src", "        Berri-AI/litellm"),         # a comment line between
])
def test_a_value_spelled_past_its_key_is_read(lines):
    assert _rules(scan_diff(_workflow(*lines), files=True, owner="BerriAI")) == {"lookalike-owner": "critical"}


def test_the_strong_class_is_bounded_whatever_was_held_before():
    variants = [f"{'BerriAI'[:k]}-{'BerriAI'[k:]}" for k in range(1, 7)]
    variants += [f"{'BerriAI'[:k]}-{'BerriAI'[k:j]}-{'BerriAI'[j:]}" for k in range(1, 6) for j in range(k + 1, 7)]
    weak = [f"IMAGE_REPO: {v}/x" for v in variants]
    strong = [f"git clone https://github.com/{v}/x" for v in variants]
    diff = _diff("scripts/b.sh", "x=1", "\n+".join(weak + strong))
    assert len([h for h in scan_diff(diff, files=True, owner="BerriAI") if h.severity == "high"]) <= 50


@pytest.mark.parametrize("key", ["repository:", "x_repo:", "default="])
def test_a_long_blank_run_after_a_key_stays_linear(key):
    import time

    diff = _diff(".github/workflows/r.yml", "x: 1", key + " " * 65_536 + "!")
    start = time.perf_counter()
    scan_diff(diff, files=True, owner="BerriAI")
    assert time.perf_counter() - start < 2.0          # a lead with adjacent blank runs takes minutes here


def test_a_value_on_the_next_line_joins_only_the_line_truly_after_it():
    unchanged_between = ("diff --git a/.github/workflows/r.yml b/.github/workflows/r.yml\n--- a/.github/workflows/r.yml\n"
                         "+++ b/.github/workflows/r.yml\n@@ -1,1 +1,3 @@\n+    source_repo:\n     description: x\n"
                         "+      homeassistant/script/run.sh\n")
    assert _rules(scan_diff(unchanged_between, files=True, owner="home-assistant")) == {}
    across_hunks = ("diff --git a/.github/workflows/r.yml b/.github/workflows/r.yml\n--- a/.github/workflows/r.yml\n"
                    "+++ b/.github/workflows/r.yml\n@@ -1,0 +1,1 @@\n+  repository:\n@@ -80,0 +81,1 @@\n"
                    "+    Berri-AI/litellm: legacy\n")
    assert _rules(scan_diff(across_hunks, files=True, owner="BerriAI")) == {}
