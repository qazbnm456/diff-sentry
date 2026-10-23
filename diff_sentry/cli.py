"""THE entry point: a GitHub change in → a structured malicious-intent verdict out, signal emitted.

    python -m diff_sentry pr owner/repo 7                 # classify a PR (needs gh + DS_* creds + Deno) python -m diff_sentry issue owner/repo 12             # classify an issue python -m diff_sentry classify event.json             # classify a payload you already hold python -m diff_sentry render traces/pr-7.jsonl pr-7   # re-render the response from a trace (offline) python -m diff_sentry export "traces/*.jsonl" ds.json # reward-free dataset export (offline) git diff main...HEAD | python -m diff_sentry scan -   # indicators only, exit 1 at/above the floor python -m diff_sentry watch --repos owner/name        # monitor a watchlist (--screen-only needs no model) python -m diff_sentry actor mallory                   # the dossier of an account the watcher has seen python -m diff_sentry archive verify                  # re-hash the snapshot archive

`run()` is the programmatic entry. It records `traces/{run_id}.jsonl`, writes `responses/{run_id}.json`, and (host-side, AFTER the run) emits a SIEM signal when the assembled verdict warrants it. A host-side BASELINE indicator scan runs at ingest and rides in the run_start meta, so the deterministic evidence is in the trace before the planner takes a turn (MF3). `scan`/`render`/`export` work offline; `pr`/`issue`/`classify` need model creds (DS_* env) + a Deno sandbox (`classify` only *ingests* offline). `scan` exposes that deterministic baseline on its own: the half we can run in our own CI on an untrusted fork PR, where no creds exist and none may be handed over (see `_cmd_scan`).
"""

from __future__ import annotations

import argparse
import asyncio
import glob
import json
import math
import os
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass

from . import __version__
from .config import DetectConfig
from .normalize import event_metadata, normalize_event
from .schema import SEVERITIES, SIGNAL_SEVERITY_FLOOR, AssembledVerdict, IndicatorHit


async def detect_from_event(
    event: dict,
    config: DetectConfig,
    *,
    trace_path: str | None = None,
    run_id: str = "change",
    on_event: Callable[[dict], None] | None = None,
    extra_tools=(),
):
    """Run the classifier on one change event and return the planner's JUDGEMENT (`ChangeVerdict`). Call `assemble.assemble_verdict(verdict, events)` to attach the deterministic indicators + signal."""
    import rlm_harness

    from .detect import ClassifyChange, setup
    from .rubric import default_rubric, rubric_to_meta

    setup(config)
    task = ClassifyChange(config=config, extra_tools=extra_tools, event=event)
    event_str = normalize_event(event)
    # Host-side BASELINE scan: deterministic evidence in the trace before the planner runs (MF3).
    baseline = _baseline_indicators(event)

    async def _run():
        return await task.arun(event=event_str)

    if trace_path:
        with rlm_harness.TraceRecorder(trace_path, run_id=run_id, on_event=on_event, meta={
            # The run's INITIAL STATE (the untrusted event is a REPL variable, not a chat turn) + prompt.
            "event": event_str,
            "instructions": task.instructions,
            # The change under review: echoed into the response envelope + the SIEM signal.
            "source": _source_echo(event),
            # The host-derived facts about the author and the event (account age as of the event, profile, timestamps, fork, commit offsets), so an offline reader sees what the ingest saw.
            **({"provenance": event["provenance"]} if event.get("provenance") else {}),
            # The deterministic baseline: assemble unions this with every scan_indicators tool call.
            "baseline_indicators": baseline,
            # The emit threshold THIS run used, so an offline re-render/export re-derives the SAME signal.
            "emit_on": list(config.emit_on),
            # The models actually used this run (roles → concrete names): self-describing trace.
            "planner": config.main_model,
            "analyst": config.sub_model,
            "classifier": config.classifier_model,
            # The budget THIS run ran under, so an offline reader computes hit_iteration_cap correctly.
            "max_iterations": config.max_iterations,
            "max_llm_calls": config.max_llm_calls,
            # The ATLAS rubric decomposition carried as LABELS (structure only; the trainer scores dᵢ). A FIXED skeleton (default_rubric): diff-sentry's task is constant, so only the per-criterion FACTS vary per run (re-sourced from the trace on read; see rubric.criteria_facts).
            "rubric": rubric_to_meta(default_rubric()),
        }):
            return await _run()
    return await _run()


def _baseline_indicators(event: dict, *, content_hits: list[IndicatorHit] | None = None) -> list[dict]:
    """The host-side deterministic evidence recorded in run_start meta BEFORE the planner runs: the text detectors over the raw content ∪ the provenance detectors over the ingest facts. Both re-source into the evidence union on read (MF3), so a false-benign SUBMIT can skew the verdict but never suppress these."""
    from .images import scan_image
    from .indicators import keep_worse, scan_change, scan_provenance
    from .releases import release_scope, scan_release, scan_release_change

    # `content_hits` lets a caller that already scanned the change (the watcher, once per change) avoid scanning the same text again: the scan is the expensive part.
    release = event.get("kind") == "release"
    scan = scan_release_change if release else scan_change
    hits = (scan(event) if content_hits is None else release_scope(list(content_hits)) if release else list(content_hits)) \
        + scan_provenance(event.get("provenance") or {}) + scan_release(event.get("release") or {}) \
        + scan_image((event.get("release") or {}).get("image") or {})
    # Hits an EARLIER version of this same change raised ride along, so an edit that removes the payload cannot also remove the evidence (the watcher supplies them; a change scanned on its own has none).
    for raw in event.get("prior_indicators") or []:
        if isinstance(raw, IndicatorHit):
            hits.append(raw)
        elif isinstance(raw, dict):
            try:
                hits.append(IndicatorHit(**raw))
            except (TypeError, ValueError):
                continue
    deduped: dict[str, IndicatorHit] = {}
    for h in hits:
        keep_worse(deduped, h)
    return [h.model_dump() for h in deduped.values()]


# The change under review, echoed into the response envelope and the SIEM signal.
_SOURCE_KEYS = ("repo", "kind", "number", "author", "title", "file_count", "content_sha256", "created_at")


def _source_echo(event: dict) -> dict:
    meta_source = event_metadata(event)
    return {k: meta_source.get(k) for k in _SOURCE_KEYS}


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
    assembled: AssembledVerdict | None
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
    config: DetectConfig | None = None,
    on_event: Callable[[dict], None] | None = None,
    extra_tools=(),
    emit: bool = True,
    poster=None,
    emit_failed: bool = True,
) -> RunArtifacts:
    """THE programmatic entry: classify one change, write the response, and (host-side, after the run) emit a SIEM signal when warranted. Never raises on a run failure: a failed run still writes an informative response and returns result-less RunArtifacts."""
    from rlm_harness.trace import load_events

    from .assemble import assemble_verdict
    from .emit import emit_signal
    from .response import build_failed_response, build_response

    config = config or DetectConfig.from_env()
    trace_path = os.path.join(outdir, "traces", f"{run_id}.jsonl")
    _reset_trace(trace_path)

    try:
        verdict = asyncio.run(detect_from_event(event, config, trace_path=trace_path, run_id=run_id,
                                                on_event=on_event, extra_tools=extra_tools))
    except Exception as exc:  # noqa: BLE001 (a failed run is still self-contained + navigable)
        events = load_events(trace_path, run_id) if os.path.exists(trace_path) else []
        resp = build_failed_response(run_id, events, f"{type(exc).__name__}: {exc}")
        response_path = _write((os.path.join(outdir, "responses"), f"{run_id}.json"),
                               resp.model_dump_json(indent=2) + "\n")
        # `emit_failed=False` is for a caller that retries a failed run: the screen already alerted on the evidence, and a `status=failed` signal per attempt would page the SIEM ten times for one change.
        emit_result = emit_signal(resp, config, poster=poster) if emit and emit_failed else None
        return RunArtifacts(None, events, run_id, trace_path, response_path, emit_result, status="failed")

    events = load_events(trace_path, run_id)
    assembled = assemble_verdict(verdict, events, emit_on=config.emit_on)
    resp = build_response(assembled, events, run_id)
    response_path = _write((os.path.join(outdir, "responses"), f"{run_id}.json"),
                           resp.model_dump_json(indent=2) + "\n")
    emit_result = emit_signal(resp, config, poster=poster) if emit else None
    return RunArtifacts(assembled, events, run_id, trace_path, response_path, emit_result, status=resp.status)


def screen(
    event: dict,
    *,
    run_id: str = "change",
    outdir: str = "./output",
    config: DetectConfig | None = None,
    emit: bool = True,
    poster=None,
    baseline: list[dict] | None = None,
):
    """The deterministic SCREEN: baseline indicators only, no model. Writes `<out>/screened/{run_id}.json` (a `not_escalated` response carrying the evidence) and, when the evidence reaches the floor, emits the early `stage=screen` SIEM signal. Never raises on the emit path; needs no model creds or Deno.

    It writes no trace: a screen is not a trajectory, so it must not enter the rollout corpus."""
    from rlm_harness.trace import EVENT_RUN_START

    from .emit import emit_signal
    from .response import build_screened_response

    config = config or DetectConfig.screen_from_env()
    meta = {
        "event": normalize_event(event),
        "source": _source_echo(event),
        "baseline_indicators": baseline if baseline is not None else _baseline_indicators(event),
        "emit_on": list(config.emit_on),
        **({"provenance": event["provenance"]} if event.get("provenance") else {}),
    }
    events = [{"type": EVENT_RUN_START, "payload": {"meta": meta}}]
    resp = build_screened_response(run_id, events)
    path = _write((os.path.join(outdir, "screened"), f"{run_id}.json"),
                  resp.model_dump_json(indent=2) + "\n")
    emit_result = emit_signal(resp, config, poster=poster, stage="screen") if emit else None
    return ScreenArtifacts(resp, path, emit_result)


@dataclass
class ScreenArtifacts:
    response: object              # the DetectionResponse of the screen
    path: str
    emit: object = None           # an emit.EmitResult when the early alert ran, else None


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
    from .history import enabled
    from .ingest import pr_event, repo_workflows

    config = DetectConfig.from_env()
    event = pr_event(args.repo, args.number, history=enabled(args.account_history), workflows=repo_workflows)
    arts = run(event, run_id=f"{args.repo.replace('/', '-')}-pr-{args.number}", outdir=args.out,
               config=config, emit=not args.no_emit)
    _print_run(arts)
    return 0 if arts.assembled is not None else 1


def _cmd_issue(args) -> int:
    from .history import enabled
    from .ingest import issue_event, repo_workflows

    config = DetectConfig.from_env()
    event = issue_event(args.repo, args.number, history=enabled(args.account_history), workflows=repo_workflows)
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


def drop_deleted_lines(text: str) -> str:
    """Strip a unified diff's `-` deletion lines, keeping additions and context.

    A diff carries the code being REMOVED as well as the code being added, and the detectors read plain text, so scanning a raw diff flags a change for a payload it is DELETING. That turns every remediation commit red, which is the worst possible failure mode for a security gate: it penalises exactly the change you wanted. `---` (the file header) is kept; only true `-` deletion lines go.

    Non-diff input is returned untouched: the check is per line, so a plain source file has no `-`- prefixed lines to lose. `scan --include-deletions` opts back in when you want to audit what a change removed (a payload can also be hidden by deleting a check)."""
    if not text:
        return text
    return "\n".join(ln for ln in text.split("\n")
                     if not (ln.startswith("-") and not ln.startswith("---")))


def _cmd_scan(args) -> int:
    """The deterministic HALF of the pipeline, standalone: run the indicator suite over text and exit non-zero on a hit at/above the floor. No LLM, no network, no creds, no Deno, just `indicators`.

    This is what makes the detector safe to dogfood in our OWN CI. The full `pr`/`classify` path needs `DS_*` creds, and the only way to hand creds to a fork PR's run is `pull_request_target`, the exact misconfiguration that opened the AsyncAPI "Miasma" supply-chain compromise. `scan` needs nothing, so it runs under the same read-only `contents: read` token an untrusted fork PR already gets."""
    from .indicators import scan_diff
    from .schema import severity_rank

    threshold = severity_rank(args.fail_on)
    hits = []
    for path in args.path:
        if path == "-":
            # a lone CR is an ordinary character to a shell: it is read as it is, not as the newline that text mode makes of it
            raw = getattr(sys.stdin, "buffer", None)
            text, label = (raw.read().decode("utf-8", errors="replace") if raw is not None else sys.stdin.read()), "<stdin>"
        else:
            with open(path, "r", encoding="utf-8", errors="replace", newline="") as fh:
                text = fh.read()
            label = path
        if not args.include_deletions:
            text = drop_deleted_lines(text)
        owner = args.repo.split("/", 1)[0] if "/" in args.repo else ""
        hits.extend(scan_diff(text, location=label, files=True, owner=owner))

    worst = max((severity_rank(h.severity) for h in hits), default=-1)
    failed = worst >= threshold

    if args.json:
        print(json.dumps({"hits": [h.model_dump() for h in hits], "count": len(hits),
                          "max_severity": SEVERITIES[worst] if worst >= 0 else None,
                          "fail_on": args.fail_on, "failed": failed}, indent=2))
        return 1 if failed else 0

    if not hits:
        print("scan: no indicators fired.")
        return 0
    print(f"scan: {len(hits)} indicator(s), max severity={SEVERITIES[worst]} (fail-on={args.fail_on})")
    for h in sorted(hits, key=lambda h: -severity_rank(h.severity)):
        where = f" ({h.location})" if h.location else ""
        print(f"  [{h.severity:8}] {h.rule}{where}: {h.title}")
        print(f"             evidence: {h.evidence[:160]}")
    print(f"FAIL — a hit at/above `{args.fail_on}`." if failed
          else f"OK — every hit is below `{args.fail_on}`.")
    return 1 if failed else 0


def _cmd_release_watch(args) -> int:
    import logging
    import signal

    from .images import ImageWatcher
    from .npm import NpmWatcher, parse_npm_packages
    from .releases import ReleaseWatcher, parse_packages, parse_sources

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    if not math.isfinite(args.interval) or args.interval <= 0:
        print("release-watch: --interval must be a positive number of seconds", file=sys.stderr)
        return 2
    texts = list(args.packages) + [os.getenv("DS_RELEASE_PACKAGES", "")]
    try:
        if args.packages_file:
            with open(args.packages_file, encoding="utf-8") as fh:
                texts.append(fh.read())
        packages = parse_packages(texts)
        npm = parse_npm_packages([*args.npm, os.getenv("DS_RELEASE_NPM", "")])
        check_npm = bool(args.check) and args.check[0].startswith("npm:")
        if args.check:
            packages = [] if check_npm else parse_packages([args.check[0]])
            npm = parse_npm_packages([args.check[0][4:]]) if check_npm else []
        images = [i for text in [*args.images, os.getenv("DS_RELEASE_IMAGES", "")] for i in text.replace(",", " ").split()]
        floating = tuple(args.image_tags or os.getenv("DS_RELEASE_IMAGE_TAGS", "latest").replace(",", " ").split())
        image_watcher = ImageWatcher([] if args.check else images, state_dir=args.state, out_dir=args.out,
                                     floating=floating, emit=not args.no_emit)
        try:
            sources = parse_sources([*args.sources, os.getenv("DS_RELEASE_SOURCES", "")])
            watcher = ReleaseWatcher(packages, state_dir=args.state, out_dir=args.out, emit=not args.no_emit,
                                     sources=sources)
        except BaseException:
            image_watcher.close()
            raise
        try:
            npm_watcher = NpmWatcher(npm, state_dir=args.state, out_dir=args.out, emit=not args.no_emit)
        except BaseException:
            image_watcher.close()
            watcher.close()
            raise
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"release-watch: {exc}", file=sys.stderr)
        return 2
    try:
        if args.check:
            result = npm_watcher.check(npm[0], args.check[1]) if check_npm else watcher.check(packages[0], args.check[1])
            print(json.dumps(result, indent=2, default=str))
            return 1 if "error" in result else 0
        if not packages and not npm and not images:
            print("release-watch: nothing to watch (--packages, --packages-file, --npm, --images, or DS_RELEASE_PACKAGES / "
                  "DS_RELEASE_NPM / DS_RELEASE_IMAGES)", file=sys.stderr)
            return 2
        if args.once:
            for result in watcher.poll_once() + npm_watcher.poll_once() + image_watcher.poll_once():
                print(json.dumps(result, default=str))
            return 0
        stopping = []
        signal.signal(signal.SIGTERM, lambda *_: stopping.append(True))
        try:
            while not stopping:
                started = time.monotonic()
                watcher.poll_once()
                npm_watcher.poll_once()
                image_watcher.poll_once()
                while not stopping and time.monotonic() - started < args.interval:
                    time.sleep(min(1.0, args.interval))
        except KeyboardInterrupt:
            pass
        return 0
    finally:
        watcher.close()
        npm_watcher.close()
        image_watcher.close()


def _cmd_render(args) -> int:
    from rlm_harness.trace import load_events

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


def _json_out(obj) -> str:
    """JSON for a terminal: non-ASCII text stays readable, but C0/C1 control characters (which `json.dumps` leaves raw in the 0x80-0x9f range) are escaped so an attacker-influenced string cannot drive the terminal."""
    text = json.dumps(obj, ensure_ascii=False, indent=2)
    return "".join(f"\\u{ord(c):04x}" if _is_terminal_control(c) else c for c in text)


def _is_terminal_control(c: str) -> bool:
    o = ord(c)
    return (0x7F <= o <= 0x9F or o in (0x200B, 0xFEFF) or 0x2028 <= o <= 0x202E or 0x2060 <= o <= 0x2069
            or 0xE0000 <= o <= 0xE007F)


def _cmd_watch(args) -> int:
    import logging
    import signal

    from .watch import WatchConfig, Watcher, WatchState, parse_repos, requeue_failed

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    if args.stats:
        db = os.path.join(args.state, "watch.db")
        if not os.path.exists(db):
            print(f"watch: no state at {db}", file=sys.stderr)
            return 2
        try:
            state = WatchState(db, read_only=True)
        except RuntimeError as exc:
            print(f"watch: {exc}", file=sys.stderr)
            return 2
        try:
            print(json.dumps(state.stats(), indent=2))
        finally:
            state.close()
        return 0
    if args.requeue_failed:
        try:
            ids = requeue_failed(args.state)
        except (RuntimeError, OSError) as exc:
            print(f"watch: {exc}", file=sys.stderr)
            return 2
        print(f"watch: requeued {len(ids)} run(s) that had exhausted their attempts")
        return 0
    repos = list(args.repos or [])
    if args.interval is not None and not math.isfinite(args.interval):
        print("watch: --interval must be a finite number of seconds", file=sys.stderr)
        return 2
    try:
        if args.repos_file:
            with open(args.repos_file, encoding="utf-8") as fh:
                repos.append(fh.read())
        overrides = {
            "repos": parse_repos(repos) if repos else None, "state_dir": args.state, "out_dir": args.out,
            "poll_interval_s": args.interval,
            "backfill_s": int(args.backfill_hours * 3600) if args.backfill_hours is not None else None,
            "recheck_s": int(args.recheck_hours * 3600) if args.recheck_hours is not None else None,
            "screen_only": args.screen_only or None, "deep_min_severity": args.deep_min_severity,
            "max_queue": args.max_queue, "max_deep_per_hour": args.max_deep_per_hour, "workers": args.workers,
        }
        config = WatchConfig.from_env(**overrides)     # also parses DS_WATCH_REPOS and the other env knobs
    except (ValueError, OSError, OverflowError) as exc:
        print(f"watch: {exc}", file=sys.stderr)
        return 2
    if not config.repos:
        print("watch: no repositories — pass --repos / --repos-file or set DS_WATCH_REPOS", file=sys.stderr)
        return 2
    try:
        detect = DetectConfig.screen_from_env() if config.screen_only else DetectConfig.from_env()
    except ValueError as exc:
        print(f"watch: {exc}\n(use --screen-only to run the deterministic tier without model roles)",
              file=sys.stderr)
        return 2
    try:
        from .history import enabled

        watcher = Watcher(config, detect, emit=not args.no_emit, history=enabled(args.account_history))
    except RuntimeError as exc:                        # a state directory written by another build
        print(f"watch: {exc}", file=sys.stderr)
        return 2
    try:
        if args.once:
            watcher.recover()
            report = watcher.poll_once()
            ran = 0 if config.screen_only else watcher.drain()
            print(f"watch --once: listed={report.listed} new={report.new} revised={report.revised} "
                  f"unchanged={report.unchanged} alerts={report.alerts} queued={report.queued} "
                  f"shed={report.shed} ran={ran} errors={len(report.errors)}")
            for e in report.errors:
                print(f"  ! {e}", file=sys.stderr)
            for t in report.truncated:
                print(f"  ! {t}: the listing is deeper than one pass reads — older updates were not examined",
                      file=sys.stderr)
            return 1 if report.errors or report.truncated else 0
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, lambda *_: watcher.stop())
        watcher.serve()
        return 0
    except RuntimeError as exc:                        # another watch holds this state directory
        print(f"watch: {exc}", file=sys.stderr)
        return 2
    finally:
        watcher.close()


def _cmd_actor(args) -> int:
    from .actors import ActorStore, format_dossier
    from .history import enabled
    from .ingest import public_activity

    db = os.path.join(args.state, "actors.db")
    if not os.path.exists(db):
        print(f"actor: no actor store at {db} — run `watch` first (or pass --state)", file=sys.stderr)
        return 2
    try:
        store = ActorStore(db, read_only=True)
    except RuntimeError as exc:
        print(f"actor: {exc}", file=sys.stderr)
        return 2
    try:
        dossier = store.dossier(args.login)
        if dossier is None:
            print(f"actor: nothing recorded for {args.login!r}", file=sys.stderr)
            return 1
        live = public_activity(dossier["login"]) if args.live else None
        lookup = enabled(args.account_history)
        past = lookup(dossier["login"]) if lookup is not None else None
        if args.json:
            print(_json_out({**dossier, **({"live_public_activity": live} if live is not None else {}),
                             **({"account_history": past} if past is not None else {})}))
            return 0
        print(format_dossier(dossier))
        if live is not None:
            print("  live public activity (GitHub keeps ~30 days / 300 events):")
            print(f"    {json.dumps(live, ensure_ascii=False) if live else 'unavailable'}")
        if past is not None:
            print("  public history before the last 30 days (GH Archive, via ClickHouse):")
            print(f"    {json.dumps(past, ensure_ascii=False) if past else 'none, or unavailable'}")
        return 0
    finally:
        store.close()


def _cmd_archive(args) -> int:
    from .snapshot import SnapshotStore

    root = os.path.join(args.state, "snapshots")
    if not os.path.isdir(root):
        print(f"archive: no snapshot archive at {root}", file=sys.stderr)
        return 2
    store = SnapshotStore(root)
    if args.action == "verify":
        problems = store.verify()
        for p in problems:
            print(f"  ! {p}")
        print("archive: intact" if not problems else f"archive: {len(problems)} problem(s)")
        return 1 if problems else 0
    if not args.sha:
        print("archive show: pass a sha256", file=sys.stderr)
        return 2
    try:
        doc = store.get(args.sha)
    except (ValueError, OSError) as exc:
        print(f"archive show: {exc}", file=sys.stderr)
        return 2
    print(_json_out(doc))
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
    pr.add_argument("--account-history", action="store_true",
                    help="look up the author's public history before the last 30 days in GH Archive, via ClickHouse's public playground (sends the login there; or set DS_ACCOUNT_HISTORY=clickhouse; off by default)")
    pr.set_defaults(func=_cmd_pr)

    iss = sub.add_parser("issue", help="classify a GitHub issue")
    iss.add_argument("repo", help="owner/name")
    iss.add_argument("number", type=int)
    iss.add_argument("--out", default="./output")
    iss.add_argument("--no-emit", action="store_true", help="do not emit a SIEM signal")
    iss.add_argument("--account-history", action="store_true",
                     help="look up the author's public history before the last 30 days in GH Archive, via ClickHouse's public playground (sends the login there; or set DS_ACCOUNT_HISTORY=clickhouse; off by default)")
    iss.set_defaults(func=_cmd_issue)

    cl = sub.add_parser("classify", help="classify a change payload you already hold (offline ingest)")
    cl.add_argument("payload", help="path to a JSON payload {repo,kind,number,author,title,body,files}")
    cl.add_argument("--run-id", default=None)
    cl.add_argument("--out", default="./output")
    cl.add_argument("--no-emit", action="store_true", help="do not emit a SIEM signal")
    cl.set_defaults(func=_cmd_classify)

    sc = sub.add_parser("scan", help="deterministic indicator scan over text/diff (offline, no creds)")
    sc.add_argument("path", nargs="+", help="file(s) to scan; `-` reads stdin")
    sc.add_argument("--fail-on", default=SIGNAL_SEVERITY_FLOOR, choices=SEVERITIES,
                    help=f"exit 1 on a hit at/above this severity (default: {SIGNAL_SEVERITY_FLOOR}, "
                         "the SIEM signal floor)")
    sc.add_argument("--json", action="store_true", help="machine-readable output")
    sc.add_argument("--repo", default=os.getenv("GITHUB_REPOSITORY", ""),
                    help="owner/name of the repository the diff is of (GITHUB_REPOSITORY in Actions): a GitHub owner "
                         "that imitates it is flagged")
    sc.add_argument("--include-deletions", action="store_true",
                    help="also scan a diff's `-` lines (default: skip them, so removing a payload "
                         "does not flag the change that removes it)")
    sc.set_defaults(func=_cmd_scan)

    w = sub.add_parser("watch", help="monitor a watchlist of repositories (poll, screen, queue for the model)")
    w.add_argument("--repos", nargs="+", help="owner/name repositories (or set DS_WATCH_REPOS)")
    w.add_argument("--repos-file", help="a file of owner/name entries, one per line (# comments allowed)")
    w.add_argument("--out", default="./output")
    w.add_argument("--state", default=os.getenv("DS_WATCH_STATE_DIR", "./output/state"),
                   help="state directory: watch.db, actors.db, snapshots/")
    w.add_argument("--interval", type=float, default=None, help="seconds between polls (DS_WATCH_INTERVAL)")
    w.add_argument("--backfill-hours", type=float, default=None,
                   help="on first sight of a repo, also examine changes updated this recently (default 0)")
    w.add_argument("--recheck-hours", type=float, default=None,
                   help="re-examine a change for edits / a deleted fork or account for this long (default 24)")
    w.add_argument("--screen-only", action="store_true",
                   help="deterministic tier only: archive, correlate, alert; never run the model (no creds)")
    w.add_argument("--deep-min-severity", default=None, choices=SEVERITIES,
                   help="only queue for the model when the screen reached this severity (default: info = all)")
    w.add_argument("--max-queue", type=int, default=None, help="shed the lowest priority beyond this (0 = off)")
    w.add_argument("--max-deep-per-hour", type=int, default=None, help="cap model runs per hour (0 = off)")
    w.add_argument("--workers", type=int, default=None,
                   help="model runs at once, each in a process of its own (DS_WATCH_WORKERS, default 1)")
    w.add_argument("--no-emit", action="store_true", help="do not emit SIEM signals")
    w.add_argument("--account-history", action="store_true",
                   help="look up the author's public history before the last 30 days in GH Archive, via ClickHouse's public playground (sends the login there; or set DS_ACCOUNT_HISTORY=clickhouse; off by default)")
    w.add_argument("--once", action="store_true", help="one poll, run the queue, exit")
    w.add_argument("--stats", action="store_true", help="print the watcher's state counts and exit (read-only)")
    w.add_argument("--requeue-failed", action="store_true",
                   help="bring back runs that exhausted their attempts (e.g. a model that was down for hours)")
    w.set_defaults(func=_cmd_watch)

    rw = sub.add_parser("release-watch",
                        help="compare each new release of watched PyPI packages with the one before it (no model)")
    rw.add_argument("--packages", nargs="+", default=[], help="PyPI project names (or set DS_RELEASE_PACKAGES)")
    rw.add_argument("--packages-file", help="a file of project names, one per line (# comments allowed)")
    rw.add_argument("--npm", nargs="+", default=[], help="npm package names, @scope/name included (or set DS_RELEASE_NPM)")
    rw.add_argument("--sources", nargs="+", default=[], metavar="PACKAGE=OWNER/NAME",
                    help="the GitHub repository each package is built from, to compare each release with its tag "
                         "(or set DS_RELEASE_SOURCES; default: the repository of the previous release's Trusted Publisher)")
    rw.add_argument("--images", nargs="+", default=[],
                    help="container images (ghcr.io/owner/name, docker.io/owner/name) whose tags are compared by provenance "
                         "(or set DS_RELEASE_IMAGES)")
    rw.add_argument("--image-tags", nargs="+", default=None,
                    help="floating tags whose moves are judged (DS_RELEASE_IMAGE_TAGS, default: latest)")
    rw.add_argument("--out", default="./output")
    rw.add_argument("--state", default=os.getenv("DS_WATCH_STATE_DIR", "./output/state"),
                    help="state directory: releases.db, snapshots/")
    rw.add_argument("--interval", type=float, default=float(os.getenv("DS_RELEASE_INTERVAL", "300")),
                    help="seconds between polls (DS_RELEASE_INTERVAL, default 300)")
    rw.add_argument("--no-emit", action="store_true", help="do not emit SIEM signals")
    rw.add_argument("--once", action="store_true", help="one poll, then exit")
    rw.add_argument("--check", nargs=2, metavar=("PACKAGE", "VERSION"),
                    help="judge one release against the one before it now, print the result, and exit "
                         "(npm:NAME for an npm package)")
    rw.set_defaults(func=_cmd_release_watch)

    ac = sub.add_parser("actor", help="the dossier of an account the watcher has seen (offline)")
    ac.add_argument("login", help="a login, or `id:<github id>`")
    ac.add_argument("--state", default=os.getenv("DS_WATCH_STATE_DIR", "./output/state"))
    ac.add_argument("--live", action="store_true", help="also fetch the account's recent public activity")
    ac.add_argument("--account-history", action="store_true",
                    help="also look up the account's public history before the last 30 days in GH Archive, via ClickHouse's public playground (sends the login there; or set DS_ACCOUNT_HISTORY=clickhouse; off by default)")
    ac.add_argument("--json", action="store_true")
    ac.set_defaults(func=_cmd_actor)

    ar = sub.add_parser("archive", help="verify or read the snapshot archive (offline)")
    ar.add_argument("action", choices=("verify", "show"))
    ar.add_argument("sha", nargs="?", help="for `show`: the capture's sha256")
    ar.add_argument("--state", default=os.getenv("DS_WATCH_STATE_DIR", "./output/state"))
    ar.set_defaults(func=_cmd_archive)

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
