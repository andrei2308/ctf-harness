"""Single-challenge runner — the production path.

The organizers run ONE container per challenge (challenge auto-started, their
model endpoint injected, no internet). So production is: boot, read the one
assigned challenge, solve it as hard as the per-run budget allows, stream flags
as they ground, stop. This module is that path.

It reuses the same Solver, grounding guard, submitter and tool profiles as the
benchmark harness; only the control flow differs — one challenge, escalate effort
in-run up the ladder, no cross-challenge pool. The multi-challenge Scheduler stays
as the local benchmark/dev harness.

Entry point:  python -m harness.single [--challenge ID]
The challenge is taken from --challenge / CTF_CHALLENGE_ID, else the first (and,
in production, only) challenge the platform presents.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path

from .agents.base import Outcome, Solver, SolverState, new_state
from .agents.exttools import probe_tools
from .agents.specialists import route
from .agents.tools import ToolContext
from .config import Config, config_from_env, make_model_factory, make_platform
from .flags.submit import FlagSubmitter
from .platforms.base import Challenge, Platform, PlatformError
from .scheduler.budget import Budget, BudgetExceeded
from .scheduler.ladder import Ladder
from .telemetry.run_log import RunLog


@dataclass
class ChallengeResult:
    challenge: str
    solved: bool
    flags_accepted: int
    attempts: int
    top_rung: int
    reason: str


def _recap(state: SolverState) -> str:
    """A short recap to seed a fresh-context escalation."""
    parts = ["(Your earlier attempt's context was reset to stay focused.)"]
    if state.notes:
        parts.append("What happened: " + "; ".join(state.notes[-5:]))
    flags = state.store.grounded_flags()
    if flags:
        parts.append(f"{len(flags)} flag(s) already found/submitted.")
    parts.append("Take a different approach this time.")
    return "\n".join(parts)


def run_challenge(*, challenge: Challenge, platform: Platform, ladder: Ladder,
                  model_factory, budget: Budget, log: RunLog,
                  submitter: FlagSubmitter, executor, work_root,
                  available: set[str] | None = None, max_attempts: int = 50,
                  plan_first: bool = True, fresh_context: bool = False,
                  top_rung_restarts: int = 6) -> ChallengeResult:
    """Drive one challenge to completion: prepare, then climb the effort ladder
    until solved or the per-run budget is spent.

    This container exists for one challenge, so budget left unspent is wasted.
    Once the ladder is climbed, the top rung is re-run from a clean context (up
    to `top_rung_restarts` times) instead of giving up.

    Outcome handling:
      SOLVED     -> done
      EXHAUSTED  -> per-challenge budget cutoff; stop
      PARKED     -> resume the SAME rung (attempt budget slice spent)
      STALLED    -> next rung; past the top, restart the top rung fresh
      ERROR      -> model endpoint kept failing: retry the same rung, and after
                    three in a row treat it as a stall
    """
    cid = challenge.id
    submitter.register(cid, challenge.flags_required)
    work_dir = Path(work_root) / _safe(cid)
    work_dir.mkdir(parents=True, exist_ok=True)

    if available is None:
        try:
            available = probe_tools(executor, Path(work_root))
            log.event("tools.probed", available=sorted(available))
        except Exception as e:  # noqa: BLE001
            available = set()
            log.event("tools.probe_error", error=repr(e))

    files: list[Path] = []
    conn = None
    try:
        files = platform.download_files(cid, work_dir)
    except PlatformError as e:
        log.event("platform.error", challenge=cid, op="download_files", error=str(e))
    try:
        conn = platform.start_instance(cid)
        if not (conn.host or conn.url):
            conn = None
    except PlatformError as e:
        log.event("platform.error", challenge=cid, op="start_instance", error=str(e))
        conn = None

    specialist = route(challenge, conn)
    ctx = ToolContext(challenge_id=cid, work_dir=work_dir, executor=executor, conn=conn)
    sys_p = specialist.system_prompt()
    task_p = specialist.task_prompt(challenge, work_dir, conn, files, available=available)
    state = new_state(cid, work_dir, ctx, system_prompt=sys_p, task_prompt=task_p)
    log.event("challenge.prepared", challenge=cid, specialist=specialist.profile().name,
              files=len(files), has_target=conn is not None,
              flags_required=challenge.flags_required)

    rung = 0
    attempts = 0
    restarts = 0
    errors_in_a_row = 0
    reason = "no attempt"
    while attempts < max_attempts:
        if submitter.is_solved(cid):
            break
        attempts += 1
        model = model_factory(ladder.rung(rung).spec)
        solver = Solver(model=model, profile=specialist.profile(), state=state,
                        budget=budget, log=log, submitter=submitter,
                        max_iterations=ladder.rung(rung).max_iterations,
                        plan_first=plan_first)
        try:
            out = solver.run()
        except BudgetExceeded as e:
            reason = f"per-run budget exhausted: {e}"
            log.event("challenge.budget_stop", challenge=cid, reason=str(e))
            break
        finally:
            model.close()

        reason = out.reason
        if out.outcome in (Outcome.SOLVED, Outcome.EXHAUSTED):
            break
        if out.outcome == Outcome.PARKED:
            continue                      # resume same rung
        if out.outcome == Outcome.ERROR:
            errors_in_a_row += 1
            if errors_in_a_row < 3:
                continue                  # endpoint trouble: same rung again
        errors_in_a_row = 0

        # STALLED (or persistent errors): escalate. Past the top rung, keep
        # spending the remaining budget on clean-context restarts of the top rung.
        if ladder.has_rung(rung + 1):
            rung += 1
            if fresh_context:
                state.restart_conversation(sys_p, task_p, _recap(state))
                log.event("challenge.fresh_context", challenge=cid, rung=rung)
        elif restarts < top_rung_restarts:
            restarts += 1
            state.restart_conversation(sys_p, task_p, _recap(state))
            log.event("challenge.top_rung_restart", challenge=cid, restart=restarts)
        else:
            break

    solved = submitter.is_solved(cid)
    log.event("challenge.done", challenge=cid, solved=solved, attempts=attempts,
              top_rung=rung, reason=reason)
    return ChallengeResult(challenge=cid, solved=solved,
                           flags_accepted=submitter.accepted_count(cid),
                           attempts=attempts, top_rung=rung, reason=reason)


def solve_one(config: Config, challenge_id: str | None = None) -> dict:
    """Wire the harness for a single challenge and solve it. Returns a summary."""
    log = RunLog(config.run_dir)
    platform = make_platform(config)
    budget = Budget(config.caps)
    submitter = FlagSubmitter(platform, log, dry_run=config.dry_run,
                              penalize_wrong=config.penalize_wrong,
                              max_submits_per_flag=config.max_submits_per_flag)
    log.event("config", mode="solve_one", backend=config.inference_backend,
              platform=config.platform, dry_run=config.dry_run)
    try:
        if challenge_id:
            challenge = platform.get_challenge(challenge_id)
        else:
            challenges = platform.list_challenges()
            if not challenges:
                raise PlatformError("no challenge presented to solve")
            if len(challenges) > 1:
                log.event("solve_one.multiple_challenges",
                          count=len(challenges), picked=challenges[0].id)
            challenge = challenges[0]
        result = run_challenge(
            challenge=challenge, platform=platform, ladder=config.ladder(),
            model_factory=make_model_factory(config), budget=budget, log=log,
            submitter=submitter, executor=config.executor(), work_root=config.work_root,
            plan_first=config.plan_first,
            fresh_context=config.fresh_context_on_escalate,
            top_rung_restarts=config.top_rung_restarts)
        summary = {
            "challenge": result.challenge,
            "solved": result.solved,
            "flags_accepted": result.flags_accepted,
            "attempts": result.attempts,
            "top_rung": result.top_rung,
            "reason": result.reason,
            "budget": budget.snapshot(),
            "submissions": submitter.summary(),
        }
    finally:
        log.close()
        platform.close()
    summary["log"] = str(log.path)
    return summary


def _safe(name: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in name)[:80]


def _parse(argv: list[str]) -> tuple[Config, str | None]:
    cfg = config_from_env()
    p = argparse.ArgumentParser(prog="harness.single",
                                description="Solve a single challenge (production path)")
    p.add_argument("--challenge", default=None,
                   help="challenge id to solve; default: the one the platform presents")
    p.add_argument("--platform", choices=["files", "mcp", "benchmark"], default=cfg.platform)
    p.add_argument("--fixtures", default=cfg.fixtures_root)
    p.add_argument("--contest-id", default=cfg.contest_id)
    p.add_argument("--backend", choices=["rule", "null", "anthropic", "openai"],
                   default=cfg.inference_backend)
    p.add_argument("--work-root", default=cfg.work_root)
    p.add_argument("--run-dir", default=cfg.run_dir)
    p.add_argument("--dry-run", action="store_true", default=cfg.dry_run)
    a = p.parse_args(argv)
    cfg.platform = a.platform
    cfg.fixtures_root = a.fixtures
    cfg.contest_id = a.contest_id
    cfg.inference_backend = a.backend
    cfg.work_root = a.work_root
    cfg.run_dir = a.run_dir
    cfg.dry_run = a.dry_run
    challenge_id = a.challenge or os.environ.get("CTF_CHALLENGE_ID") or None
    return cfg, challenge_id


def main(argv: list[str] | None = None) -> int:
    cfg, challenge_id = _parse(argv if argv is not None else sys.argv[1:])
    summary = solve_one(cfg, challenge_id)
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
