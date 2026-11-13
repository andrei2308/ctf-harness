"""Benchmark runner — measure capture rate over a local challenge suite.

This is the local test loop: point the harness at a converted benchmark (Cybench
/ NYU-CTF / InterCode — see BENCHMARKS.md) and get a comparable report: solve
rate, per-category breakdown, token spend, and solve order/timing. Re-run across
the window for a pass@k picture; a single run reports pass@1 (solve rate).

Unlike production (one challenge per container), the benchmark drives the whole
suite through the multi-challenge Scheduler, which is exactly what that scheduler
is for now that production is single-challenge.

    python -m harness.bench --fixtures <suite-dir> [--backend rule] [--concurrency N]
"""

from __future__ import annotations

import argparse
import json
import math
import sys
import time
from pathlib import Path

from .config import Config, config_from_env, make_model_factory, make_platform
from .flags.submit import FlagSubmitter
from .scheduler.budget import Budget
from .scheduler.scheduler import Scheduler
from .telemetry.run_log import RunLog


def run_benchmark(config: Config) -> dict:
    config.platform = "benchmark"
    log = RunLog(config.run_dir)
    platform = make_platform(config)
    budget = Budget(config.caps)
    submitter = FlagSubmitter(platform, log, dry_run=config.dry_run,
                              penalize_wrong=config.penalize_wrong,
                              max_submits_per_flag=config.max_submits_per_flag)
    scheduler = Scheduler(
        platform=platform, ladder=config.ladder(),
        model_factory=make_model_factory(config), budget=budget, log=log,
        submitter=submitter, executor=config.executor(),
        work_root=Path(config.work_root), concurrency=config.concurrency)

    started = time.time()
    try:
        challenges = platform.list_challenges()
        scheduler.load()
        scheduler.run()
    finally:
        log.close()
        platform.close()

    report = _build_report(challenges, submitter, budget, started)
    report["log"] = str(log.path)
    report_path = Path(config.run_dir) / f"bench-{log.run_id}.json"
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    report["report"] = str(report_path)
    return report


def _build_report(challenges, submitter: FlagSubmitter, budget: Budget, started: float) -> dict:
    solved = set(submitter.summary()["solved"])
    total = len(challenges)

    by_cat: dict[str, dict] = {}
    for ch in challenges:
        cat = ch.category or ch.kind.value or "uncategorized"
        slot = by_cat.setdefault(cat, {"total": 0, "solved": 0})
        slot["total"] += 1
        if ch.id in solved:
            slot["solved"] += 1

    # First-accept time per challenge, from the submitter's own records.
    first_accept: dict[str, float] = {}
    for r in submitter.records:
        if r.accepted and r.challenge not in first_accept:
            first_accept[r.challenge] = r.at
    order = sorted(solved, key=lambda c: first_accept.get(c, math.inf))
    solves = [{
        "challenge": c,
        "category": next((ch.category or ch.kind.value for ch in challenges if ch.id == c), ""),
        "points": next((ch.points for ch in challenges if ch.id == c), None),
        "seconds_to_first_flag": round(first_accept[c] - started, 2) if c in first_accept else None,
    } for c in order]

    snap = budget.snapshot()
    return {
        "challenges": total,
        "solved": len(solved),
        "solve_rate": round(len(solved) / total, 4) if total else 0.0,
        "flags_accepted": submitter.summary()["flags_accepted"],
        "submissions": len(submitter.records),
        "accuracy": round(
            sum(1 for r in submitter.records if r.accepted) / len(submitter.records), 4
        ) if submitter.records else None,
        "by_category": by_cat,
        "tokens": snap["global_tokens"],
        "wall_seconds": round(time.time() - started, 2),
        "solves": solves,
    }


def _print_report(rep: dict) -> None:
    print(f"\n  Benchmark: {rep['solved']}/{rep['challenges']} solved "
          f"({rep['solve_rate']*100:.1f}%)  |  flags {rep['flags_accepted']}  |  "
          f"tokens {rep['tokens']}  |  {rep['wall_seconds']}s")
    acc = rep.get("accuracy")
    if acc is not None:
        print(f"  Submission accuracy: {acc*100:.1f}% over {rep['submissions']} submissions")
    print("  By category:")
    for cat, v in sorted(rep["by_category"].items()):
        print(f"    {cat:<16} {v['solved']}/{v['total']}")
    if rep["solves"]:
        print("  Solve order:")
        for s in rep["solves"]:
            t = f"{s['seconds_to_first_flag']}s" if s["seconds_to_first_flag"] is not None else "-"
            print(f"    {t:>8}  {s['challenge']} ({s['category']})")
    print(f"  Report: {rep['report']}\n")


def _parse(argv: list[str]) -> Config:
    cfg = config_from_env()
    p = argparse.ArgumentParser(prog="harness.bench", description="Run a benchmark suite")
    p.add_argument("--fixtures", default=cfg.fixtures_root, help="benchmark suite directory")
    p.add_argument("--backend", choices=["rule", "null", "anthropic", "openai"],
                   default=cfg.inference_backend)
    p.add_argument("--concurrency", type=int, default=cfg.concurrency)
    p.add_argument("--work-root", default=cfg.work_root)
    p.add_argument("--run-dir", default=cfg.run_dir)
    a = p.parse_args(argv)
    cfg.fixtures_root = a.fixtures
    cfg.inference_backend = a.backend
    cfg.concurrency = a.concurrency
    cfg.work_root = a.work_root
    cfg.run_dir = a.run_dir
    return cfg


def main(argv: list[str] | None = None) -> int:
    cfg = _parse(argv if argv is not None else sys.argv[1:])
    rep = run_benchmark(cfg)
    _print_report(rep)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
