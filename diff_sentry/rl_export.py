"""Export diff-sentry run traces as REWARD-FREE trajectory datasets.

diff-sentry is the ROLLOUT source (rollout → reward → training), NOT the trainer. This module emits raw
materials only: the trajectory splits (sft_turns / classifier / orchestrator), per-run intrinsic LABELS
(verdict / signal / indicator counts — facts, never a reward), and per-run objective METRICS. No reward
scalar is attached (`reward=None` to rlm-kit's exporters); reward/credit-assignment/GRPO live elsewhere.

Usage: python -m diff_sentry.rl_export "traces/*.jsonl" dataset.json
"""

from __future__ import annotations

import glob
import json
import sys

from rlm_kit.dataset import export_actions, export_sft_turns, run_label_bundle
from rlm_kit.trace import group_by_run, load_events

# The second-stage classifier is reached through exactly this tool; every OTHER tool is the PLANNER's own.
CLASSIFIER_TOOL = "deep_classify"
_DEFAULT_MAX_ITERATIONS = 25


def _meta(events: list[dict]) -> dict:
    for e in events:
        if e.get("type") == "run_start":
            return e.get("payload", {}).get("meta") or {}
    return {}


def _resolve_max_iterations(events: list[dict]) -> int:
    m = _meta(events).get("max_iterations")
    return m if isinstance(m, int) and m > 0 else _DEFAULT_MAX_ITERATIONS


def load_runs(*trace_paths: str) -> dict[str, list[dict]]:
    events: list[dict] = []
    for path in trace_paths:
        events.extend(load_events(path))
    return group_by_run(events)


def run_labels(events: list[dict]) -> dict:
    """Intrinsic OUTCOME labels for one run — facts, NOT a reward. Derived from the ASSEMBLED verdict so
    `signal` reads the deterministic union (never the planner's self-report)."""
    from .assemble import verdict_from_events

    assembled = verdict_from_events(events)
    if assembled is None:
        return {"verdict": "none", "signal": False, "indicator_count": 0,
                "max_indicator_severity": "info", "cited_unknown": 0}
    return {
        "verdict": assembled.verdict,
        "signal": bool(assembled.signal),
        "indicator_count": len(assembled.indicators),
        "max_indicator_severity": assembled.max_indicator_severity,
        "cited_unknown": len(assembled.cited_unknown_ids),
    }


def run_metrics(events: list[dict]) -> dict:
    """Objective EFFORT metrics — the raw material a trainer shapes into a reward. Facts, never a score."""
    def _tool(name: str) -> list[dict]:
        return [e for e in events if e["type"] == "tool_call" and e["payload"].get("tool") == name]

    cap = _resolve_max_iterations(events)
    dc = _tool(CLASSIFIER_TOOL)
    steps = sum(1 for e in events if e["type"] == "main_step")
    ts = [e["ts"] for e in events if isinstance(e.get("ts"), (int, float))]
    return {
        "steps": steps,
        "scan_calls": len(_tool("scan_indicators")),
        "deep_classify_calls": sum(1 for g in dc if not g["payload"].get("circuit_broken")),
        "deep_classify_circuit_breaks": sum(1 for g in dc if g["payload"].get("circuit_broken")),
        "analyst_calls": sum(1 for e in events if e["type"] == "sub_call"),
        "fetches": len(_tool("fetch_url")),
        "skill_reads": len(_tool("read_skill")),
        "elapsed_s": round(max(ts) - min(ts), 3) if len(ts) >= 2 else None,
        "hit_iteration_cap": steps >= cap,
    }


def rubric_signal(events: list[dict]) -> dict:
    """The ATLAS rubric surface for one run — the fixed rubric + its deterministic per-criterion FACTS.
    All LABELS: a downstream trainer computes dᵢ∈[0,1] and aggregates; this service never does.

    The reported `rubric` is the EFFECTIVE one — the run_start-meta rubric, or the constant
    `default_rubric()` for a legacy trace that carries none — so it always names the SAME criteria
    `criteria_facts` was computed against (no orphan facts). The `rubric` import is LAZY: it keeps
    rl_export's module top unchanged and can't form a load-time cycle (rubric.trace_facts calls back into
    THIS module, also lazily)."""
    from .rubric import criteria_facts, default_rubric, rubric_from_meta

    rubric = rubric_from_meta(events).criteria or default_rubric().criteria
    return {
        "rubric": [c.model_dump() for c in rubric],
        "criteria_facts": [f.model_dump() for f in criteria_facts(events)],
    }


def export_dataset(runs: dict[str, list[dict]]) -> dict:
    """Build the REWARD-FREE trajectory bundle. Two things map to a SEPARATE model: the `classifier`
    (SINGLE-TURN findings→verdict records) and the ORCHESTRATOR (the RLM root, ONE multi-turn policy —
    `sft_turns` for SFT, `actions`/`export_rl` for RL). Records carry `reward=None`.

    `labels` (intrinsic outcome — verdict/signal/…), `metrics` (objective effort), and `rubric_signal`
    (the ATLAS 4-category decomposition + deterministic per-criterion facts, a re-lens over labels/metrics)
    are the three per-run LABEL surfaces — all reward-free."""
    actions = export_actions(runs, reward=None)
    tool_acts = [a for a in actions if a["kind"] == "tool"]
    classifier = [a for a in tool_acts
                  if a.get("tool") == CLASSIFIER_TOOL and (a.get("outcome") or {}).get("output")]
    return {
        "actions": actions,
        "classifier": classifier,
        "orchestrator_tools": [a for a in tool_acts if a.get("tool") != CLASSIFIER_TOOL],
        "planner": [a for a in actions if a["kind"] == "planner"],
        "sft_turns": export_sft_turns(runs),
        # The three per-run LABEL surfaces ride via rlm-kit's shared run_label_bundle (the canonical
        # {surface: {run_id: fn(events)}} seam) — one bundle shape across consumers, and `reward` is a
        # refused surface name (it raises), so the reward-free invariant is structural at the transport.
        # Output is byte-identical to the old comprehensions. `rubric_signal` is the ATLAS 4-category
        # (TF/TA/TG/PA) rubric + per-criterion deterministic facts (reward-free LABELS).
        **run_label_bundle(runs, labels=run_labels, metrics=run_metrics, rubric_signal=rubric_signal),
    }


def main() -> None:
    if len(sys.argv) < 3:
        print("usage: python -m diff_sentry.rl_export <trace-glob...> <out.json>")
        raise SystemExit(2)
    *globs, out = sys.argv[1:]
    paths = [p for g in globs for p in glob.glob(g)]
    runs = load_runs(*paths)
    bundle = export_dataset(runs)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(bundle, fh, ensure_ascii=False, indent=2, default=str)
    signals = sum(1 for lab in bundle["labels"].values() if lab["signal"])
    print(f"runs={len(runs)} ({signals} signalling) | actions={len(bundle['actions'])} "
          f"(classifier={len(bundle['classifier'])}) | sft_turns={len(bundle['sft_turns'])} "
          f"| reward-free -> {out}")


if __name__ == "__main__":
    main()
