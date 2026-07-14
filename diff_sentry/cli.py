"""THE entry point: a GitHub change in → a structured malicious-intent verdict out, signal emitted.

    python -m diff_sentry pr owner/repo 7                 # classify a PR (needs gh + DS_* creds + Deno)
    python -m diff_sentry issue owner/repo 12             # classify an issue
    python -m diff_sentry classify event.json             # classify a payload you already hold
    python -m diff_sentry render traces/pr-7.jsonl pr-7   # re-render the response from a trace (offline)
    python -m diff_sentry export "traces/*.jsonl" ds.json # reward-free dataset export (offline)

`run()` is the programmatic entry. It records `traces/{run_id}.jsonl`, writes `responses/{run_id}.json`,
and — host-side, AFTER the run — emits a SIEM signal when the assembled verdict warrants it. A host-side
BASELINE indicator scan runs at ingest and rides in the run_start meta, so the deterministic evidence is
in the trace before the planner takes a turn (MF3). `render`/`export` work offline; `pr`/`issue`/`classify`
need model creds (DS_* env) + a Deno sandbox (`classify` only *ingests* offline).
"""

from __future__ import annotations

import argparse
import asyncio
import glob
import json
import os
from dataclasses import dataclass
from typing import Callable, Optional

from . import __version__
from .config import DetectConfig
from .schema import AssembledVerdict


async def detect_from_event(
    event: dict,
    config: DetectConfig,
    *,
    trace_path: Optional[str] = None,
    run_id: str = "change",
    on_event: Optional[Callable[[dict], None]] = None,
    extra_tools=(),
):
    """Run the classifier on one change event and return the planner's JUDGEMENT (`ChangeVerdict`).
    Call `assemble.assemble_verdict(verdict, events)` to attach the deterministic indicators + signal."""
    import rlm_kit

    from .detect import ClassifyChange, setup
    from .normalize import event_metadata, normalize_event

    setup(config)
    task = ClassifyChange(config=config, extra_tools=extra_tools)
    event_str = normalize_event(event)
    meta_source = event_metadata(event)
    # Host-side BASELINE scan — deterministic evidence in the trace before the planner runs (MF3).
    baseline = _baseline_indicators(event)

    async def _run():
        return await task.arun(event=event_str)

    if trace_path:
        with rlm_kit.TraceRecorder(trace_path, run_id=run_id, on_event=on_event, meta={
            # The run's INITIAL STATE (the untrusted event is a REPL variable, not a chat turn) + prompt.
            "event": event_str,
            "instructions": task.instructions,
            # The change under review — echoed into the response envelope + the SIEM signal.
            "source": {k: meta_source.get(k) for k in ("repo", "kind", "number", "author", "title",
                                                        "file_count", "content_sha256")},
            # The deterministic baseline — assemble unions this with every scan_indicators tool call.
            "baseline_indicators": baseline,
            # The emit threshold THIS run used, so an offline re-render/export re-derives the SAME signal.
            "emit_on": list(config.emit_on),
            # The models actually used this run (roles → concrete names) — self-describing trace.
            "planner": config.main_model,
            "analyst": config.sub_model,
            "classifier": config.classifier_model,
            # The budget THIS run ran under, so an offline reader computes hit_iteration_cap correctly.
            "max_iterations": config.max_iterations,
            "max_llm_calls": config.max_llm_calls,
        }):
            return await _run()
    return await _run()


def _baseline_indicators(event: dict) -> list[dict]:
    """The host-side deterministic evidence recorded in run_start meta BEFORE the planner runs: the text
    detectors over the raw content ∪ the provenance detectors over the ingest facts. Both re-source into the
    evidence union on read (MF3), so a false-benign SUBMIT can skew the verdict but never suppress these."""
    from .indicators import scan_indicators, scan_provenance
    from .normalize import raw_content

    return ([h.model_dump() for h in scan_indicators(raw_content(event))]
            + [h.model_dump() for h in scan_provenance(event.get("provenance") or {})])


def _write(path_parts: tuple[str, str], content: str) -> str:
    d, name = path_parts
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path


def _reset_trace(trace_path: str) -> None:
    """Drop any stale trace for this run_id before the run (TraceRecorder appends; one trace per run)."""
    if os.path.exists(trace_path):
        os.remove(trace_path)


@dataclass
class RunArtifacts:
    assembled: Optional[AssembledVerdict]
    events: list
    run_id: str
    trace_path: str
    response_path: str
    emit: object = None           # an emit.EmitResult when the SIEM emitter ran, else None
    status: str = "classified"


def run(
    event: dict,
    *,
    run_id: str = "change",
    outdir: str = "./output",
    config: Optional[DetectConfig] = None,
    on_event: Optional[Callable[[dict], None]] = None,
    extra_tools=(),
    emit: bool = True,
    poster=None,
) -> RunArtifacts:
    """THE programmatic entry: classify one change, write the response, and (host-side, after the run)
    emit a SIEM signal when warranted. Never raises on a run failure — a failed run still writes an
    informative response and returns result-less RunArtifacts."""
    from rlm_kit.trace import load_events

    from .assemble import assemble_verdict
    from .emit import emit_signal
    from .response import build_failed_response, build_response

    config = config or DetectConfig.from_env()
    trace_path = os.path.join(outdir, "traces", f"{run_id}.jsonl")
    _reset_trace(trace_path)

    try:
        verdict = asyncio.run(detect_from_event(event, config, trace_path=trace_path, run_id=run_id,
                                                on_event=on_event, extra_tools=extra_tools))
    except Exception as exc:  # noqa: BLE001 — a failed run is still self-contained + navigable
        events = load_events(trace_path, run_id) if os.path.exists(trace_path) else []
        resp = build_failed_response(run_id, events, f"{type(exc).__name__}: {exc}")
        response_path = _write((os.path.join(outdir, "responses"), f"{run_id}.json"),
                               resp.model_dump_json(indent=2) + "\n")
        emit_result = emit_signal(resp, config, poster=poster) if emit else None
        return RunArtifacts(None, events, run_id, trace_path, response_path, emit_result, status="failed")

    events = load_events(trace_path, run_id)
    assembled = assemble_verdict(verdict, events, emit_on=config.emit_on)
    resp = build_response(assembled, events, run_id)
    response_path = _write((os.path.join(outdir, "responses"), f"{run_id}.json"),
                           resp.model_dump_json(indent=2) + "\n")
    emit_result = emit_signal(resp, config, poster=poster) if emit else None
    return RunArtifacts(assembled, events, run_id, trace_path, response_path, emit_result, status=resp.status)


# ---- subcommands -------------------------------------------------------------

def _print_run(arts: RunArtifacts) -> None:
    a = arts.assembled
    if a is None:
        print(f"  ✗ {arts.run_id} failed → {arts.response_path}")
        return
    sig = "SIGNAL" if a.signal else "no-signal"
    emitted = ""
    if arts.emit is not None:
        e = arts.emit
        emitted = (f" · emitted→{e.status_code}" if e.emitted
                   else f" · not-emitted({e.skipped_reason or e.error})")
    print(f"  ✔ {arts.run_id} [{a.verdict}/{sig}/sev={a.max_indicator_severity}] "
          f"{len(a.indicators)} indicator(s) → {arts.response_path}{emitted}")


def _cmd_pr(args) -> int:
    from .ingest import pr_event

    config = DetectConfig.from_env()
    event = pr_event(args.repo, args.number)
    arts = run(event, run_id=f"{args.repo.replace('/', '-')}-pr-{args.number}", outdir=args.out,
               config=config, emit=not args.no_emit)
    _print_run(arts)
    return 0 if arts.assembled is not None else 1


def _cmd_issue(args) -> int:
    from .ingest import issue_event

    config = DetectConfig.from_env()
    event = issue_event(args.repo, args.number)
    arts = run(event, run_id=f"{args.repo.replace('/', '-')}-issue-{args.number}", outdir=args.out,
               config=config, emit=not args.no_emit)
    _print_run(arts)
    return 0 if arts.assembled is not None else 1


def _cmd_classify(args) -> int:
    from .ingest import event_from_payload

    config = DetectConfig.from_env()
    with open(args.payload, "r", encoding="utf-8") as fh:
        payload = json.load(fh)
    event = event_from_payload(payload)
    run_id = args.run_id or (payload.get("repo", "change").replace("/", "-") + f"-{payload.get('number', 0)}")
    arts = run(event, run_id=run_id, outdir=args.out, config=config, emit=not args.no_emit)
    _print_run(arts)
    return 0 if arts.assembled is not None else 1


def _cmd_render(args) -> int:
    from rlm_kit.trace import load_events

    from .assemble import verdict_from_events
    from .response import build_failed_response, build_response

    events = load_events(args.trace, args.run_id)
    assembled = verdict_from_events(events)
    resp = (build_response(assembled, events, args.run_id) if assembled is not None
            else build_failed_response(args.run_id, events, "trace has no result event"))
    out = resp.model_dump_json(indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(out + "\n")
        print(f"wrote {args.out}")
    else:
        print(out)
    return 0


def _cmd_export(args) -> int:
    from .rl_export import export_dataset, load_runs

    paths = [p for g in args.trace for p in glob.glob(g)]
    runs = load_runs(*paths)
    bundle = export_dataset(runs)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(bundle, fh, ensure_ascii=False, indent=2, default=str)
    signals = sum(1 for lab in bundle["labels"].values() if lab["signal"])
    print(f"runs={len(runs)} ({signals} signalling) | sft_turns={len(bundle['sft_turns'])} | "
          f"classifier={len(bundle['classifier'])} | reward-free → {args.out}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="diff_sentry", description=__doc__)
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    pr = sub.add_parser("pr", help="classify a GitHub pull request")
    pr.add_argument("repo", help="owner/name")
    pr.add_argument("number", type=int)
    pr.add_argument("--out", default="./output")
    pr.add_argument("--no-emit", action="store_true", help="do not emit a SIEM signal")
    pr.set_defaults(func=_cmd_pr)

    iss = sub.add_parser("issue", help="classify a GitHub issue")
    iss.add_argument("repo", help="owner/name")
    iss.add_argument("number", type=int)
    iss.add_argument("--out", default="./output")
    iss.add_argument("--no-emit", action="store_true", help="do not emit a SIEM signal")
    iss.set_defaults(func=_cmd_issue)

    cl = sub.add_parser("classify", help="classify a change payload you already hold (offline ingest)")
    cl.add_argument("payload", help="path to a JSON payload {repo,kind,number,author,title,body,files}")
    cl.add_argument("--run-id", default=None)
    cl.add_argument("--out", default="./output")
    cl.add_argument("--no-emit", action="store_true", help="do not emit a SIEM signal")
    cl.set_defaults(func=_cmd_classify)

    r = sub.add_parser("render", help="re-render the response from a trace (offline)")
    r.add_argument("trace")
    r.add_argument("run_id")
    r.add_argument("--out", default=None)
    r.set_defaults(func=_cmd_render)

    e = sub.add_parser("export", help="export reward-free SFT/RL datasets from traces (offline)")
    e.add_argument("trace", nargs="+", help="trace file glob(s)")
    e.add_argument("out", help="output json path")
    e.set_defaults(func=_cmd_export)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
