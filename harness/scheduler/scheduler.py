"""The scheduler: fixed-concurrency worker pool + escalation + park-and-resume.

This is the answer to "you cannot out-parallelize other teams". A fixed number
of slots run at once; the policy decides what each slot does next:

  1. Breadth-first first pass — every challenge gets one cheap rung-0 attempt
     before anything escalates, so easy/rare flags bank early (tiebreak favours
     earliest last-flag, and dynamic scoring rewards banking quickly).
  2. Escalation — a challenge that stalls moves up the ladder; a challenge that
     parks (ran out of its attempt slice) resumes at the same rung with its state
     intact. No slot ever idles while eligible work remains.
  3. Prioritisation — when choosing among resumable challenges, prefer ones that
     already produced partial signal, then higher-value, then cheaper-to-push.
  4. Hard cutoff — the per-challenge budget drops a rabbit-hole: write notes,
     move on. The global budget stops the whole run cleanly.

Concurrency here is threads (solvers are IO-bound: model calls, subprocesses,
sockets). If the contest runtime enforces concurrency at the process/container
level instead, the *policy* below is unchanged — only the worker-spawn mechanism
swaps out.

Open knob: `slots_per_challenge` (default 1). Whether multiple slots may attack
one challenge in parallel (best-of-N within a run) is an organizer question; for
now best-of-N comes from re-runs across the retry window.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from ..agents.base import Outcome, Solver, SolverState, new_state
from ..agents.exttools import probe_tools
from ..agents.specialists import Specialist, route
from ..agents.tools import Executor, ToolContext
from ..flags.submit import FlagSubmitter
from ..inference.base import Model, ModelSpec
from ..platforms.base import Challenge, Platform, PlatformError
from ..telemetry.run_log import RunLog
from .budget import Budget, BudgetExceeded
from .ladder import Ladder
from ..flags.grounding import format_check

ModelFactory = Callable[[ModelSpec], Model]

# Terminal statuses: the challenge leaves the active set.
_TERMINAL = {"solved", "dropped"}


@dataclass
class ChallengeRecord:
    challenge: Challenge
    rung: int = 0
    attempts: int = 0
    errors: int = 0
    status: str = "pending"   # pending|running|parked|stalled|solved|dropped
    state: SolverState | None = None
    specialist: Specialist | None = None
    grounded_any: bool = False
    last_reason: str = ""

    @property
    def points(self) -> int:
        return self.challenge.points or 0

    @property
    def attempted(self) -> bool:
        return self.attempts > 0


class Scheduler:
    def __init__(self, *, platform: Platform, ladder: Ladder,
                 model_factory: ModelFactory, budget: Budget, log: RunLog,
                 submitter: FlagSubmitter, executor: Executor, work_root: Path,
                 concurrency: int = 4, max_error_retries: int = 1,
                 plan_first: bool = True):
        self.platform = platform
        self.ladder = ladder
        self.model_factory = model_factory
        self.budget = budget
        self.log = log
        self.submitter = submitter
        self.executor = executor
        self.work_root = Path(work_root)
        self.concurrency = max(1, concurrency)
        self.max_error_retries = max_error_retries
        self.plan_first = plan_first

        self._records: dict[str, ChallengeRecord] = {}
        self._lock = threading.Condition()
        self._stop = False          # set when global budget is exhausted
        self._running = 0
        self._available: set[str] | None = None  # installed tools, probed once

    # --- public API --------------------------------------------------------

    def load(self) -> None:
        """Enumerate challenges into records. Safe to call once per run."""
        try:
            challenges = self.platform.list_challenges()
        except PlatformError as e:
            self.log.event("platform.error", op="list_challenges", error=str(e))
            raise
        with self._lock:
            for c in challenges:
                if c.id not in self._records:
                    self._records[c.id] = ChallengeRecord(challenge=c)
        self.log.event("scheduler.loaded", count=len(self._records),
                       ids=[c.id for c in challenges])

    def run(self) -> dict:
        """Drive the pool until every challenge is terminal or budget stops us."""
        self.work_root.mkdir(parents=True, exist_ok=True)
        threads = [threading.Thread(target=self._worker, name=f"slot-{i}", daemon=True)
                   for i in range(self.concurrency)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        summary = self._summary()
        self.log.event("scheduler.done", **summary)
        return summary

    # --- worker loop -------------------------------------------------------

    def _worker(self) -> None:
        while True:
            rec = self._next_task()
            if rec is None:
                return  # no work left and nothing running, or stopping
            try:
                self._attempt(rec)
            except BudgetExceeded as e:
                # Global cap: stop the whole run; return this record to the pool.
                with self._lock:
                    self._stop = True
                    rec.status = "parked"
                    rec.last_reason = f"global budget: {e}"
                    self._running -= 1
                    self._lock.notify_all()
                self.log.event("scheduler.stop", reason=str(e))
                return
            except Exception as e:  # noqa: BLE001 - never let one slot kill the pool
                with self._lock:
                    rec.errors += 1
                    rec.status = "dropped" if rec.errors > self.max_error_retries else "stalled"
                    rec.last_reason = f"worker error: {e!r}"
                    self._running -= 1
                    self._lock.notify_all()
                self.log.event("scheduler.worker_error", challenge=rec.challenge.id, error=repr(e))

    def _next_task(self) -> ChallengeRecord | None:
        """Block until an eligible record is available; mark it running.

        Returns None when the run is over (stopping, or nothing eligible and
        nothing in flight that could re-queue work).
        """
        with self._lock:
            while True:
                if self._stop:
                    return None
                rec = self._select_locked()
                if rec is not None:
                    rec.status = "running"
                    self._running += 1
                    return rec
                # Nothing eligible now. If work is in flight it may re-queue; wait.
                if self._running == 0:
                    self._lock.notify_all()
                    return None
                self._lock.wait()

    def _select_locked(self) -> ChallengeRecord | None:
        """Pick the best eligible record. Caller holds the lock.

        Eligible = not terminal, not currently running, and still has a rung to
        run. Breadth-first first pass takes priority; then resumable work ordered
        by (partial signal, value, cheapness)."""
        eligible = [r for r in self._records.values()
                    if r.status not in _TERMINAL and r.status != "running"
                    and self.ladder.has_rung(r.rung)
                    and not self.budget.challenge_exhausted(r.challenge.id)
                    and not self.submitter.is_solved(r.challenge.id)]
        if not eligible:
            return None
        fresh = [r for r in eligible if not r.attempted]
        if fresh:
            # First pass: bank value early — highest nominal points first.
            fresh.sort(key=lambda r: (-r.points, r.challenge.id))
            return fresh[0]
        # Resumers: partial signal first, then value, then lowest rung (cheapest
        # to push), then stable by id.
        eligible.sort(key=lambda r: (not r.grounded_any, -r.points, r.rung, r.challenge.id))
        return eligible[0]

    # --- one attempt -------------------------------------------------------

    def _attempt(self, rec: ChallengeRecord) -> None:
        cid = rec.challenge.id
        if rec.state is None:
            rec.state, rec.specialist = self._prepare(rec)

        rung = self.ladder.rung(rec.rung)
        model = self.model_factory(rung.spec)
        solver = Solver(model=model,
                        profile=rec.specialist.profile_for(rec.state.ctx.conn, self._available),
                        state=rec.state, budget=self.budget, log=self.log,
                        submitter=self.submitter, max_iterations=rung.max_iterations,
                        plan_first=self.plan_first)
        try:
            result = solver.run()
        finally:
            model.close()

        with self._lock:
            rec.attempts += 1
            rec.grounded_any = rec.grounded_any or result.grounded_any
            self._apply_outcome_locked(rec, result.outcome, result.reason)
            self._running -= 1
            self._lock.notify_all()

        self.log.event("scheduler.attempt_done", challenge=cid,
                       outcome=result.outcome.value, rung=rec.rung,
                       status=rec.status, grounded=rec.grounded_any)

    def _apply_outcome_locked(self, rec: ChallengeRecord, outcome: Outcome, reason: str) -> None:
        rec.last_reason = reason
        if outcome == Outcome.SOLVED:
            rec.status = "solved"
        elif outcome == Outcome.EXHAUSTED:
            rec.status = "dropped"          # per-challenge cutoff: write notes, move on
        elif outcome == Outcome.PARKED:
            rec.status = "parked"           # resume same rung later; no slot idles
        elif outcome == Outcome.STALLED:
            # Escalate: next rung, or drop if the ladder is used up.
            if self.ladder.has_rung(rec.rung + 1):
                rec.rung += 1
                rec.status = "stalled"
            else:
                rec.status = "dropped"
        else:  # ERROR
            rec.errors += 1
            if rec.errors > self.max_error_retries:
                rec.status = "dropped"
            else:
                rec.status = "stalled"

    def _prepare(self, rec: ChallengeRecord) -> tuple[SolverState, Specialist]:
        """Materialise files, start any instance, build the tool context and the
        initial solver state. Done once per challenge; reused across resumes."""
        c = rec.challenge
        self.submitter.register(c.id, c.flags_required)
        work_dir = self.work_root / _safe(c.id)
        work_dir.mkdir(parents=True, exist_ok=True)
        if self._available is None:
            try:
                self._available = probe_tools(self.executor, self.work_root)
                self.log.event("tools.probed", available=sorted(self._available))
            except Exception as e:  # noqa: BLE001 - probing must never break a run
                self._available = set()
                self.log.event("tools.probe_error", error=repr(e))
        files: list[Path] = []
        conn = None
        try:
            files = self.platform.download_files(c.id, work_dir)
        except PlatformError as e:
            self.log.event("platform.error", challenge=c.id, op="download_files", error=str(e))
        try:
            conn = self.platform.start_instance(c.id)
            if not (conn.host or conn.url):
                conn = None
        except PlatformError as e:
            self.log.event("platform.error", challenge=c.id, op="start_instance", error=str(e))

        specialist = route(c, conn)
        ctx = ToolContext(challenge_id=c.id, work_dir=work_dir,
                          executor=self.executor, conn=conn)
        state = new_state(c.id, work_dir, ctx,
                          system_prompt=specialist.system_prompt(),
                          task_prompt=specialist.task_prompt(c, work_dir, conn, files,
                                                             available=self._available),
                          flag_check=format_check(c.description))
        self.log.event("scheduler.prepared", challenge=c.id,
                       specialist=specialist.profile().name, files=len(files),
                       has_target=conn is not None)
        return state, specialist

    # --- reporting ---------------------------------------------------------

    def _summary(self) -> dict:
        with self._lock:
            by_status: dict[str, int] = {}
            for r in self._records.values():
                by_status[r.status] = by_status.get(r.status, 0) + 1
            return {
                "challenges": len(self._records),
                "by_status": by_status,
                "solved": self.submitter.solved_count(),
                "budget": self.budget.snapshot(),
                "submissions": self.submitter.summary(),
            }


def _safe(name: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in name)[:80]
