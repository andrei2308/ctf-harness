"""Entrypoint: wire the harness and drive one run.

    python -m harness.run --platform files --fixtures fixtures --backend rule
    python -m harness.run            # all defaults (offline dry rig)

Everything is assembled from Config; swap knobs via flags or env (see config.py).
The default configuration is a fully offline rig: the `rule` model + the files
adapter, so `python -m harness.run` exercises the entire enumerate -> solve ->
ground -> submit -> log loop with no network and no credentials.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .config import Config, config_from_env, make_model_factory, make_platform
from .flags.submit import FlagSubmitter
from .scheduler.budget import Budget
from .scheduler.scheduler import Scheduler
from .telemetry.run_log import RunLog


def run(config: Config) -> dict:
    log = RunLog(config.run_dir)
    platform = make_platform(config)
    budget = Budget(config.caps)
    submitter = FlagSubmitter(platform, log, dry_run=config.dry_run,
                              penalize_wrong=config.penalize_wrong,
                              max_submits_per_flag=config.max_submits_per_flag)
    scheduler = Scheduler(
        platform=platform,
        ladder=config.ladder(),
        model_factory=make_model_factory(config),
        budget=budget,
        log=log,
        submitter=submitter,
        executor=config.executor(),
        work_root=Path(config.work_root),
        concurrency=config.concurrency,
        max_error_retries=config.max_error_retries,
    )
    log.event("config", backend=config.inference_backend, platform=config.platform,
              concurrency=config.concurrency, dry_run=config.dry_run)
    try:
        scheduler.load()
        summary = scheduler.run()
    finally:
        log.close()
        platform.close()
    summary["log"] = str(log.path)
    return summary


def _parse(argv: list[str]) -> Config:
    cfg = config_from_env()
    p = argparse.ArgumentParser(prog="harness.run", description="DefCamp agentic CTF harness")
    p.add_argument("--platform", choices=["files", "mcp"], default=cfg.platform)
    p.add_argument("--fixtures", default=cfg.fixtures_root)
    p.add_argument("--contest-id", default=cfg.contest_id)
    p.add_argument("--backend", choices=["rule", "null", "anthropic", "openai"],
                   default=cfg.inference_backend)
    p.add_argument("--fast-model", default=cfg.fast_model)
    p.add_argument("--strong-model", default=cfg.strong_model)
    p.add_argument("--concurrency", type=int, default=cfg.concurrency)
    p.add_argument("--work-root", default=cfg.work_root)
    p.add_argument("--run-dir", default=cfg.run_dir)
    p.add_argument("--dry-run", action="store_true", default=cfg.dry_run)
    a = p.parse_args(argv)
    cfg.platform = a.platform
    cfg.fixtures_root = a.fixtures
    cfg.contest_id = a.contest_id
    cfg.inference_backend = a.backend
    cfg.fast_model = a.fast_model
    cfg.strong_model = a.strong_model
    cfg.concurrency = a.concurrency
    cfg.work_root = a.work_root
    cfg.run_dir = a.run_dir
    cfg.dry_run = a.dry_run
    return cfg


def main(argv: list[str] | None = None) -> int:
    cfg = _parse(argv if argv is not None else sys.argv[1:])
    summary = run(cfg)
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
