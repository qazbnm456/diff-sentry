"""The FastAPI surface — verified with `run_live` STUBBED, so it needs no LLM, dspy, gh, or diff_sentry.
Exercises the live endpoint's worker-thread → async-queue → SSE glue and the replay endpoints' file
handling, plus the path-traversal, no-cache, and cited-unknown-augmentation guards."""

import json

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from diff_sentry_studio import app as appmod  # noqa: E402

client = TestClient(appmod.app)


# ---- /v1/config: never raises (unlike DetectConfig.from_env), reads env directly ----

def test_config_exposes_model_roles_from_env(monkeypatch):
    monkeypatch.setenv("DS_ROOT_LM", "planner-m")
    monkeypatch.setenv("DS_SUB_LM", "analyst-m")
    monkeypatch.setenv("DS_CLASSIFIER_LM", "cls-m")
    monkeypatch.setenv("DS_MAX_ITERATIONS", "42")
    cfg = client.get("/v1/config").json()
    assert cfg["models"] == {"planner": "planner-m", "analyst": "analyst-m", "classifier": "cls-m"}
    assert cfg["max_iterations"] == 42


def test_config_none_when_unset_does_not_raise(monkeypatch):
    for k in ("DS_ROOT_LM", "DS_SUB_LM", "DS_CLASSIFIER_LM"):
        monkeypatch.delenv(k, raising=False)
    cfg = client.get("/v1/config").json()   # from_env() would RAISE here; the studio must not
    assert cfg["models"] == {"planner": None, "analyst": None, "classifier": None}


def test_config_classifier_falls_back_to_analyst(monkeypatch):
    monkeypatch.setenv("DS_SUB_LM", "analyst-m")
    monkeypatch.delenv("DS_CLASSIFIER_LM", raising=False)
    assert client.get("/v1/config").json()["models"]["classifier"] == "analyst-m"


def test_config_classifier_never_surfaces_a_subscription_analyst(monkeypatch):
    # the classifier is a make_model_tool endpoint and from_env REJECTS a subscription classifier, so
    # the panel must NOT show a subscription-sentinel analyst as the classifier — a config a run couldn't
    # use. (Regression: classifier = DS_CLASSIFIER_LM or analyst surfaced the subscription analyst.)
    monkeypatch.setenv("DS_SUB_LM", "claude-agent-sdk/claude-fable-5")
    monkeypatch.delenv("DS_CLASSIFIER_LM", raising=False)
    cfg = client.get("/v1/config").json()["models"]
    assert cfg["analyst"] == "claude-agent-sdk/claude-fable-5"   # the analyst role CAN be subscription
    assert cfg["classifier"] is None                            # but the classifier fallback is suppressed
    monkeypatch.setenv("DS_CLASSIFIER_LM", "openai/gpt-4o")      # an explicit non-sub classifier shows through
    assert client.get("/v1/config").json()["models"]["classifier"] == "openai/gpt-4o"


def test_config_exposes_backend_emit_on_and_fetch(monkeypatch):
    monkeypatch.delenv("DS_CLASSIFY_BACKEND", raising=False)
    monkeypatch.setenv("DS_EMIT_ON", "malicious")
    monkeypatch.delenv("DS_ENABLE_FETCH", raising=False)
    cfg = client.get("/v1/config").json()
    assert cfg["classify_backend"] == "self" and cfg["emit_on"] == ["malicious"] and cfg["enable_fetch"] is False


# ---- /v1/runs + /v1/runs/{id} (augmented with the re-derived fabrication tell) ----

def test_list_runs_lists_stored_responses(tmp_path, monkeypatch):
    (tmp_path / "responses").mkdir()
    (tmp_path / "responses" / "acme-x-pr-7.json").write_text("{}")
    (tmp_path / "responses" / "acme-x-issue-3.json").write_text("{}")
    monkeypatch.setattr(appmod, "ARTIFACTS", tmp_path)
    assert client.get("/v1/runs").json()["runs"] == ["acme-x-issue-3", "acme-x-pr-7"]


def test_get_run_augments_cited_unknown_ids_from_the_trace(tmp_path, monkeypatch):
    (tmp_path / "responses").mkdir()
    (tmp_path / "traces").mkdir()
    (tmp_path / "responses" / "r.json").write_text(json.dumps({"id": "r", "status": "classified", "verdict": "benign"}))
    (tmp_path / "traces" / "r.jsonl").write_text(
        json.dumps({"type": "run_start", "step_id": 0, "payload": {"meta": {"baseline_indicators": [{"id": "ind-a"}]}}}) + "\n"
        + json.dumps({"type": "result", "step_id": 1, "payload": {"output": {"indicator_ids": ["ind-a", "ind-ghost"]}}}) + "\n")
    monkeypatch.setattr(appmod, "ARTIFACTS", tmp_path)
    body = client.get("/v1/runs/r").json()
    assert body["status"] == "classified"
    assert body["cited_unknown_ids"] == ["ind-ghost"]     # re-derived; response envelope omits it


def test_get_run_404_when_absent():
    assert client.get("/v1/runs/does-not-exist").status_code == 404
    assert client.get("/v1/runs/does-not-exist/events").status_code == 404
    assert client.get("/v1/runs/does-not-exist/iterations").status_code == 404


def test_run_id_path_is_slug_sanitized_against_traversal(tmp_path, monkeypatch):
    # a run_id embeds user input (a repo string) and becomes a file path. A traversal attempt must fold to
    # a harmless slug that resolves inside ARTIFACTS (→ 404), never escape it.
    monkeypatch.setattr(appmod, "ARTIFACTS", tmp_path)
    assert appmod._slug_id("../../etc/passwd") == "etc-passwd"
    assert appmod._slug_id("..") == "unknown" and "/" not in appmod._slug_id("a/b/c")
    assert client.get("/v1/runs/..%2F..%2Fetc%2Fpasswd").status_code == 404


# ---- replay SSE: always ends with completed (truncated trace guard) ----

def _write_trace(tmp_path, lines):
    (tmp_path / "traces").mkdir(exist_ok=True)
    (tmp_path / "traces" / "r.jsonl").write_text("\n".join(json.dumps(x) for x in lines) + "\n")


def test_replay_streams_mapped_events(tmp_path, monkeypatch):
    # A REAL finished trace holds both `final` (record_main_trajectory) and `run_end` (recorder __exit__),
    # in that order, with `result` between them. The mapper must skip `final` so the terminal event fires
    # exactly ONCE — and after `detection.result.done`, not before it.
    _write_trace(tmp_path, [
        {"type": "run_start", "step_id": 0, "payload": {"meta": {"planner": "P"}}},
        {"type": "tool_call", "step_id": 1, "payload": {"tool": "scan_indicators", "hits": [{"severity": "high"}], "n": 1}},
        {"type": "final", "step_id": 2, "payload": {}},
        {"type": "result", "step_id": 3, "payload": {"output": {}}},
        {"type": "run_end", "step_id": 4, "payload": {}}])
    monkeypatch.setattr(appmod, "ARTIFACTS", tmp_path)
    with client.stream("GET", "/v1/runs/r/events") as resp:
        body = "".join(resp.iter_text())
    assert "event: detection.run.created" in body and "event: detection.scan" in body
    assert body.count("event: detection.run.completed") == 1     # `final` skipped → run_end is the sole terminal
    assert body.index("detection.result.done") < body.index("detection.run.completed")  # terminal is LAST


def test_replay_of_truncated_trace_still_ends_with_completed(tmp_path, monkeypatch):
    # a hard-killed run (SIGKILL) leaves a trace with NO run_end; replay must still emit the terminal
    # `completed` so the client stops "Classifying…" and GETs the stored response instead of hanging.
    _write_trace(tmp_path, [
        {"type": "run_start", "step_id": 0, "payload": {"meta": {"planner": "P"}}},
        {"type": "tool_call", "step_id": 1, "payload": {"tool": "scan_indicators", "hits": [], "n": 0}}])
    monkeypatch.setattr(appmod, "ARTIFACTS", tmp_path)
    with client.stream("GET", "/v1/runs/r/events") as resp:
        body = "".join(resp.iter_text())
    assert body.count("event: detection.run.completed") == 1     # synthesized terminal event
    assert body.rstrip().endswith("data: {}")                    # and it is the LAST event


# ---- /v1/classify: worker-thread → queue → SSE glue (run_live stubbed) ----

def test_classify_streams_live_events_then_completed(tmp_path, monkeypatch):
    def fake_run_live(request, run_id, sink, on_done, *, artifacts_dir=None):
        sink({"event": "detection.scan", "data": {"n": 2, "worst": "critical"}})
        sink({"event": "detection.classify", "data": {"verdict": "malicious"}})
        on_done({"status": "classified", "id": run_id, "verdict": "malicious"})

    monkeypatch.setattr(appmod, "ARTIFACTS", tmp_path)
    monkeypatch.setattr(appmod, "run_live", fake_run_live)
    with client.stream("POST", "/v1/classify",
                       json={"mode": "classify", "payload": {"repo": "acme/x", "number": 9}}) as r:
        body = "".join(r.iter_text())
    assert "event: detection.run.created" in body and "acme-x-9" in body     # run_id derived + slugged
    assert "event: detection.scan" in body and "event: detection.classify" in body
    assert "event: detection.run.completed" in body and '"verdict": "malicious"' in body
    assert body.index("created") < body.index("detection.scan") < body.index("completed")


def test_classify_derives_run_id_per_mode(tmp_path, monkeypatch):
    seen = {}

    def fake_run_live(request, run_id, sink, on_done, *, artifacts_dir=None):
        seen["run_id"], seen["request"] = run_id, request
        on_done({"status": "classified", "id": run_id})

    monkeypatch.setattr(appmod, "ARTIFACTS", tmp_path)
    monkeypatch.setattr(appmod, "run_live", fake_run_live)
    for payload, expect in [
        ({"mode": "pr", "repo": "acme/x", "number": 7}, "acme-x-pr-7"),
        ({"mode": "issue", "repo": "acme/x", "number": 12}, "acme-x-issue-12"),
    ]:
        with client.stream("POST", "/v1/classify", json=payload) as r:
            "".join(r.iter_text())
        assert seen["run_id"] == expect
        assert "run_id" not in seen["request"] and "overwrite" not in seen["request"]


def test_classify_409_when_run_exists_without_overwrite(tmp_path, monkeypatch):
    (tmp_path / "responses").mkdir()
    (tmp_path / "responses" / "acme-x-pr-7.json").write_text("{}")
    monkeypatch.setattr(appmod, "ARTIFACTS", tmp_path)
    started = {"n": 0}
    monkeypatch.setattr(appmod, "run_live", lambda *a, **k: started.__setitem__("n", started["n"] + 1))
    r = client.post("/v1/classify", json={"mode": "pr", "repo": "acme/x", "number": 7})
    assert r.status_code == 409 and "acme-x-pr-7" in r.json()["detail"]
    assert started["n"] == 0                              # guard rejected BEFORE the worker started


def test_classify_overwrites_when_overwrite_true(tmp_path, monkeypatch):
    (tmp_path / "responses").mkdir()
    (tmp_path / "responses" / "acme-x-pr-7.json").write_text("{}")
    monkeypatch.setattr(appmod, "ARTIFACTS", tmp_path)
    monkeypatch.setattr(appmod, "run_live",
                        lambda request, run_id, sink, on_done, **k: on_done({"status": "classified", "id": run_id}))
    with client.stream("POST", "/v1/classify",
                       json={"mode": "pr", "repo": "acme/x", "number": 7, "overwrite": True}) as r:
        body = "".join(r.iter_text())
    assert "event: detection.run.completed" in body and '"status": "classified"' in body


# ---- /v1/runs/{id}/iterations + /v1/fixtures ----

def test_iterations_breakdown_from_trace(tmp_path, monkeypatch):
    _write_trace(tmp_path, [
        {"type": "run_start", "step_id": 0, "ts": 1.0, "payload": {"meta": {"event": "the change", "planner": "P"}}},
        {"type": "main_step", "step_id": 1, "ts": 1.0, "payload": {"turn": 0, "reasoning": "r", "code": "c", "output": "o"}},
        {"type": "tool_call", "step_id": 2, "ts": 3.0, "payload": {"tool": "scan_indicators", "hits": [], "n": 0}},
        {"type": "run_end", "step_id": 3, "ts": 5.0, "payload": {}}])
    monkeypatch.setattr(appmod, "ARTIFACTS", tmp_path)
    d = client.get("/v1/runs/r/iterations").json()
    assert d["initial"]["change"] == "the change" and d["total_s"] == 4.0
    assert len(d["iterations"]) == 1 and d["timeline"][0]["label"] == "scan" and d["timeline"][0]["rel_s"] == 2.0


def test_fixtures_lists_incident_demos_or_empty(tmp_path, monkeypatch):
    # CORPUS is anchored to the repo root INDEPENDENTLY of ARTIFACTS (a DS_ARTIFACTS_DIR override must not
    # empty the demo picker), so the test points CORPUS at a tmp tree, not ARTIFACTS.
    corpus = tmp_path / "corpus"
    monkeypatch.setattr(appmod, "CORPUS", corpus)
    assert client.get("/v1/fixtures").json() == {"fixtures": []}       # no corpus tree → empty, never 500
    corpus.mkdir(parents=True)
    (corpus / "hackerbot_claw_incident.json").write_text(json.dumps({"entries": [
        {"name": "n", "incident_ref": "PR #7", "expected_signal": True, "expected_rules": ["curl-pipe-shell"],
         "event": {"repo": "acme/x", "kind": "pull_request"}}]}))
    fx = client.get("/v1/fixtures").json()["fixtures"]
    assert fx[0]["name"] == "n" and fx[0]["expected_signal"] is True and fx[0]["event"]["repo"] == "acme/x"


# ---- the zero-build frontend is served same-origin, no-cache ----

def test_frontend_shell_and_assets_are_served_and_revalidate():
    root = client.get("/")
    assert root.status_code == 200 and "text/html" in root.headers["content-type"]
    assert "diff-sentry" in root.text and 'src="/static/app.js"' in root.text
    # the pure modules must load BEFORE app.js (which reads their ReplayCore / RunCore globals)
    assert root.text.index('src="/static/replay-core.js"') < root.text.index('src="/static/app.js"')
    assert root.text.index('src="/static/run-core.js"') < root.text.index('src="/static/app.js"')
    assert root.headers.get("cache-control") == "no-cache"
    for asset in ("app.js", "replay-core.js", "run-core.js", "trajectory.js", "style.css",
                  "vendor/fonts/jetbrains-mono-400.woff2"):
        resp = client.get(f"/static/{asset}")
        assert resp.status_code == 200 and resp.headers.get("cache-control") == "no-cache"
    assert client.get("/v1/runs/does-not-exist").status_code == 404   # static mount did not shadow the API
