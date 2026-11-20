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

from .agents.base import Outcome, Solver, new_state, restart_recap
from .agents.exttools import probe_tools
from .agents.specialists import route
from .agents.tools import ToolContext
from .config import Config, config_from_env, make_model_factory, make_platform
from . import egress
from .flags.decoys import known_decoys
from .flags.grounding import format_check
from .flags.submit import FlagSubmitter
from .paths import writable_dir
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
    turns: int = 0


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
    # Falls back to a temporary directory if the configured one is unwritable
    # (read-only image, or a container user that does not own it).
    work_dir, as_asked = writable_dir(Path(work_root) / _safe(cid), prefix="ctf-work-")
    if not as_asked:
        log.event("challenge.work_dir_fallback", challenge=cid,
                  asked=str(Path(work_root) / _safe(cid)), using=str(work_dir))

    if available is None:
        try:
            available = probe_tools(executor, work_dir)
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

    if egress.enabled():
        # Rehearsal on shared infrastructure: only this challenge's service,
        # the model and the platform API are reachable. Fail closed.
        try:
            allowed = egress.lockdown(conn)
            log.event("egress.lockdown", challenge=cid, allowed=len(allowed))
        except egress.EgressError as e:
            log.event("egress.error", challenge=cid, error=str(e))
            log.event("challenge.done", challenge=cid, solved=False, attempts=0,
                      top_rung=0, reason="egress lockdown failed")
            return ChallengeResult(challenge=cid, solved=False, flags_accepted=0,
                                   attempts=0, top_rung=0,
                                   reason=f"egress lockdown failed: {e}")

    specialist = route(challenge, conn)
    ctx = ToolContext(challenge_id=cid, work_dir=work_dir, executor=executor, conn=conn)
    sys_p = specialist.system_prompt()
    task_p = specialist.task_prompt(challenge, work_dir, conn, files, available=available)
    total = budget.time_left(cid)
    if total:
        # CTF_SECONDS_PER_TURN: what one model turn costs here, tool included.
        # On the contest's shared model about 40 s (Morse Relay, 20 November:
        # 11 turns in 12 minutes), which makes a run a dozen turns, not dozens.
        per_turn = float(os.environ.get("CTF_SECONDS_PER_TURN") or 0)
        if per_turn > 0:
            turns = max(3, int(total / per_turn))
            task_p += (f"\nTime budget for this challenge: about {max(1, round(total / 60))} "
                       f"minutes in total, which is only about {turns} turns: model calls are "
                       "slow here. Every turn must run a command. Keep your reasoning short, "
                       "put several steps into one shell command or one script, and look "
                       "something up only when you are stuck.")
        else:
            task_p += (f"\nTime budget for this challenge: about {max(1, round(total / 60))} "
                       "minutes in total, which is a few dozen steps.")
    # Flag-shaped strings shipped in the harness's own directories are never the
    # answer in the contest; with the fixtures rig they ARE the answers.
    decoys = frozenset() if platform.answers_on_disk else known_decoys()
    # A hash format stated by the challenge (e.g. "DCTF{sha256}") rules out
    # planted lookalikes such as "DCTF{Try Hard...}".
    check = format_check(challenge.description)
    state = new_state(cid, work_dir, ctx, system_prompt=sys_p, task_prompt=task_p,
                      ignore_flags=decoys, flag_check=check)
    log.event("challenge.decoys", challenge=cid, ignored=len(decoys))
    if check is not None:
        log.event("challenge.flag_format", challenge=cid, hex_lengths=check.lengths)
    log.event("challenge.prepared", challenge=cid, specialist=specialist.profile().name,
              files=len(files), has_target=conn is not None,
              flags_required=challenge.flags_required)
    # The model's first view of the challenge (notes index included); without
    # it a transcript cannot show what the model was told.
    log.event("task.prompt", challenge=cid, chars=len(task_p), text=task_p)

    def fresh_start(at_rung: int) -> None:
        """Reset to a clean context seeded with a handover note written by the
        model at `at_rung` from the transcript it is about to lose."""
        m = model_factory(ladder.rung(at_rung).spec)
        try:
            recap = restart_recap(m, state, specialist.profile_for(conn, available).schemas(),
                                   budget, log)
        finally:
            m.close()
        state.restart_conversation(sys_p, task_p, recap)

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
        solver = Solver(model=model, profile=specialist.profile_for(conn, available),
                        state=state,
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
        try:
            if ladder.has_rung(rung + 1):
                rung += 1
                if fresh_context:
                    fresh_start(rung)
                    log.event("challenge.fresh_context", challenge=cid, rung=rung)
            elif restarts < top_rung_restarts:
                restarts += 1
                fresh_start(rung)
                log.event("challenge.top_rung_restart", challenge=cid, restart=restarts)
            else:
                break
        except BudgetExceeded as e:        # the handover note ran out of budget
            reason = f"per-run budget exhausted: {e}"
            log.event("challenge.budget_stop", challenge=cid, reason=str(e))
            break

    # Last chance for a flag that never reached the grader.
    if submitter.pending_count(cid):
        submitter.flush_pending(cid)
    solved = submitter.is_solved(cid)
    log.event("challenge.done", challenge=cid, solved=solved, attempts=attempts,
              top_rung=rung, reason=reason)
    return ChallengeResult(challenge=cid, solved=solved,
                           flags_accepted=submitter.accepted_count(cid),
                           attempts=attempts, top_rung=rung, reason=reason,
                           turns=state.iters_done)


def solve_one(config: Config, challenge_id: str | None = None) -> dict:
    """Wire the harness for a single challenge and solve it. Returns a summary."""
    log = RunLog(config.run_dir, mirror=config.log_mirror)
    platform = make_platform(config)
    budget = Budget(config.caps)
    # A platform that reports the run's clock and takes timeline events.
    if hasattr(platform, "seconds_left"):
        budget.resync = platform.seconds_left
    if hasattr(platform, "on_event"):
        log.sinks.append(platform.on_event)
    summary: dict = {"solved": False, "reason": "crashed before the run started"}
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
            "turns": result.turns,
            "top_rung": result.top_rung,
            "reason": result.reason,
            "budget": budget.snapshot(),
            "submissions": submitter.summary(),
        }
    except BudgetExceeded as e:
        # Raised outside an attempt (the plan or a handover note): the run is
        # out of budget all the same.
        summary = {"solved": False, "reason": f"per-run budget exhausted: {e}",
                   "budget": budget.snapshot(), "submissions": submitter.summary()}
    except Exception as e:  # noqa: BLE001
        summary = {"solved": False, "reason": f"crash: {type(e).__name__}: {e}"[:300],
                   "budget": budget.snapshot(), "submissions": submitter.summary()}
        log.event("run.crash", error=repr(e)[:500])
        raise
    finally:
        try:
            platform.finish(summary)
        except Exception as e:  # noqa: BLE001 - the note is not worth a crash
            log.event("platform.error", op="finish", error=repr(e)[:200])
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
    p.add_argument("--platform", default=cfg.platform,
                   help="files | benchmark | mcp, or module:Class for a custom adapter")
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


def _checks_first(cfg: Config) -> bool:
    """`@preflight` / `@check-only` in the run's INSTRUCTIONS (AISafe platform):
    print the model checks and the run's budgets to stdout, which the team can
    read after a run on the practice challenge. Returns True when the run
    should stop there. The checks cost model calls: use them on one run."""
    if not (os.environ.get("GATEWAY_URL") and os.environ.get("RUN_TOKEN")):
        return False
    from .platforms.starter_kit import split_instructions
    _, directives = split_instructions(os.environ.get("INSTRUCTIONS", ""))
    if not (directives.get("preflight") or directives.get("check-only")):
        return False
    platform = None
    try:
        platform = make_platform(cfg)
        before = platform.health() or {}
        print(f"[checks] run {os.environ.get('RUN_ID', '?')}: health before: {before}", flush=True)
        print(f"[checks] TARGETS={os.environ.get('TARGETS', '')!r} "
              f"TIME_LIMIT_SECONDS={os.environ.get('TIME_LIMIT_SECONDS', '')!r} "
              f"COST_LIMIT_CENTS={os.environ.get('COST_LIMIT_CENTS', '')!r}", flush=True)
        from . import preflight
        try:
            preflight.main([])
        except Exception as e:  # noqa: BLE001 - a failed check must still be reported
            print(f"[checks] preflight crashed: {type(e).__name__}: {e}", flush=True)
        after = platform.health() or {}
        print(f"[checks] health after: {after}", flush=True)
        try:
            spent = float(before["centsLeft"]) - float(after["centsLeft"])
            print(f"[checks] the model checks cost {spent:g} cents", flush=True)
        except (KeyError, TypeError, ValueError):
            pass
        if directives.get("check-only"):
            platform.give_up("check only, see stdout")
            return True
    except Exception as e:  # noqa: BLE001
        print(f"[checks] could not run: {type(e).__name__}: {e}", flush=True)
    finally:
        if platform is not None:
            platform.close()
    return False


def main(argv: list[str] | None = None) -> int:
    cfg, challenge_id = _parse(argv if argv is not None else sys.argv[1:])
    if _checks_first(cfg):
        return 0
    summary = solve_one(cfg, challenge_id)
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
