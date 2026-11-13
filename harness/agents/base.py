"""The solver loop — one specialist working one challenge.

Responsibilities, kept deliberately small:
  * drive a model<->tools conversation,
  * route every tool's REAL output into the EvidenceStore (grounding),
  * stream any grounded flag to the submitter the instant it appears,
  * meter budget and *park* (save state) when the attempt slice runs out, so no
    slot idles and the challenge can resume later up the ladder,
  * never let a model-authored string become a flag unless it is in evidence.

The loop is model-agnostic and type-agnostic: specialists only supply a system
prompt and a tool profile. Escalation is just running this loop again on the same
SolverState with a higher rung's model.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from ..flags.grounding import DEFAULT_FLAG_RE, EvidenceStore, verify_candidate
from ..flags.submit import FlagSubmitter
from ..inference.base import (ContextOverflow, Message, Model, ModelError)
from ..scheduler.budget import Budget, BudgetExceeded
from ..telemetry.run_log import RunLog
from .tools import ToolContext, ToolProfile, ToolResult


class Outcome(str, Enum):
    SOLVED = "solved"        # a grounded flag was accepted
    PARKED = "parked"        # attempt slice spent; resumable at a higher rung
    EXHAUSTED = "exhausted"  # per-challenge cutoff hit; drop it
    STALLED = "stalled"      # model stopped without a flag; may retry later
    ERROR = "error"          # unrecoverable error this attempt


@dataclass
class SolveOutcome:
    outcome: Outcome
    challenge: str
    reason: str = ""
    grounded_any: bool = False
    iterations: int = 0


@dataclass
class SolverState:
    """Carried across attempts so escalation resumes rather than restarts."""

    challenge_id: str
    messages: list[Message]
    store: EvidenceStore
    ctx: ToolContext
    iters_done: int = 0
    notes: list[str] = field(default_factory=list)
    planned: bool = False          # a planning step has run for this challenge

    def note(self, text: str) -> None:
        self.notes.append(text)

    def restart_conversation(self, system_prompt: str, task_prompt: str,
                             recap: str = "") -> None:
        """Reset the transcript to a clean context (system + task + a short recap),
        keeping the evidence store and notes. Used for a fresh-context escalation:
        research finds a clean window can beat compaction once state is
        externalised (and our grounded flags live in the store, not the chat)."""
        self.messages = [Message(role="system", content=system_prompt),
                         Message(role="user", content=task_prompt)]
        if recap:
            self.messages.append(Message(role="user", content=recap))
        self.planned = False       # allow a fresh plan at the new rung


def new_state(challenge_id: str, work_dir: Path, ctx: ToolContext,
              system_prompt: str, task_prompt: str) -> SolverState:
    store = EvidenceStore(pattern=DEFAULT_FLAG_RE)
    messages = [
        Message(role="system", content=system_prompt),
        Message(role="user", content=task_prompt),
    ]
    return SolverState(challenge_id=challenge_id, messages=messages, store=store, ctx=ctx)


class Solver:
    """Runs (or resumes) one attempt against a SolverState with a given model."""

    def __init__(self, *, model: Model, profile: ToolProfile, state: SolverState,
                 budget: Budget, log: RunLog, submitter: FlagSubmitter,
                 max_iterations: int = 40, stuck_patience: int = 6,
                 stuck_dup_threshold: int = 3, plan_first: bool = True):
        self.model = model
        self.profile = profile
        self.state = state
        self.budget = budget
        self.log = log
        self.submitter = submitter
        self.max_iterations = max_iterations
        self.plan_first = plan_first
        self._tools = profile.by_name()
        # Stuck-loop detection: end an attempt early (so the ladder escalates)
        # when it stops making progress or repeats an action, instead of burning
        # the capped token budget spinning.
        self.stuck_patience = stuck_patience              # turns w/o new evidence
        self.stuck_dup_threshold = stuck_dup_threshold    # consecutive repeated calls
        self._recent_sigs: deque[str] = deque(maxlen=6)
        self._dup_hits = 0
        self._no_progress = 0
        self._last_evidence_bytes = state.store.total_bytes
        self._stuck_nudged = False

    def _submit_grounded(self, newly: list) -> list:
        """Submit each newly grounded flag immediately. Returns the results so the
        caller can tell 'accepted, more needed' from 'grader rejected it'."""
        results = []
        for gf in newly:
            results.append(self.submitter.submit(self.state.challenge_id, gf))
        return results

    def _progress_note(self) -> str:
        cid = self.state.challenge_id
        acc, req = self.submitter.accepted_count(cid), self.submitter.required(cid)
        return f"{acc} of {req} flag(s) accepted for this challenge."

    def _plan(self) -> None:
        """One upfront planning turn (no tools). The ReAct&Plan literature finds a
        single planning step drives the biggest single gain (arXiv:2412.02776).
        Costs one model call."""
        cid = self.state.challenge_id
        self.state.messages.append(Message(role="user", content=(
            "Before acting, write a brief numbered plan (3-6 steps): what to check "
            "first, the most likely vulnerability/technique for this challenge, and "
            "which tools you will use. If unsure of the type, say how you'll "
            "identify it. Keep it short; then begin executing.")))
        try:
            resp = self.model.complete(self.state.messages, [])   # planning: no tools
        except (ModelError, ContextOverflow):
            self.state.planned = True
            return
        self.budget.charge_usage(cid, resp.usage)
        self.state.messages.append(Message(role="assistant",
                                           content=resp.text or "(no plan produced)"))
        self.state.planned = True
        self.log.event("solver.plan", challenge=cid, chars=len(resp.text or ""))

    def _handle_tool_call(self, tc) -> Message:
        # Track repeated actions for stuck detection: a repeated (tool, args)
        # bumps the dup counter; variety resets it.
        sig = f"{tc.name}:{sorted((tc.arguments or {}).items())!r}"[:240]
        self._dup_hits = self._dup_hits + 1 if sig in self._recent_sigs else 0
        self._recent_sigs.append(sig)

        tool = self._tools.get(tc.name)
        if tool is None:
            res = ToolResult(tc.name, b"", f"{tc.name}:unknown",
                             error=f"no such tool: {tc.name}")
        else:
            try:
                res = tool.run(tc.arguments, self.state.ctx)
            except Exception as e:  # noqa: BLE001 - a tool bug must not kill the attempt
                res = ToolResult(tc.name, b"", f"{tc.name}:exception", error=repr(e))

        # Record REAL output as evidence and stream any grounded flag now.
        # Reference material (knowledge base, summaries) is NOT evidence: an
        # example CTF{...} in a writeup must never ground.
        newly = (self.state.store.record(res.source, res.output)
                 if res.output and res.is_evidence else [])
        self.log.observe(self.state.challenge_id, res.name, len(res.output), res.truncated)
        if newly:
            self._submit_grounded(newly)
        return Message(role="tool", content=res.as_text(),
                       tool_call_id=tc.id, name=tc.name)

    def run(self) -> SolveOutcome:
        cid = self.state.challenge_id
        self.budget.start_attempt(cid)
        self.log.attempt_start(cid, self.model.spec.label(), int(self.model.spec.effort))

        if self.submitter.is_solved(cid):
            return SolveOutcome(Outcome.SOLVED, cid, "already solved", True,
                                self.state.iters_done)

        if self.plan_first and not self.state.planned:
            self._plan()

        grounded_any = bool(self.state.store.grounded_flags())

        while self.state.iters_done < self.max_iterations:
            # Hard caps: per-challenge cutoff and global pool.
            try:
                self.budget.check(cid)
            except BudgetExceeded as e:
                if e.scope.startswith("challenge"):
                    self.state.note(f"per-challenge budget hit: {e}")
                    self.log.attempt_end(cid, Outcome.EXHAUSTED.value, str(e))
                    return SolveOutcome(Outcome.EXHAUSTED, cid, str(e), grounded_any,
                                        self.state.iters_done)
                raise  # global cap: let the scheduler stop the whole run

            # Soft cap: park with state saved so a freed slot can resume later.
            if self.budget.should_park(cid):
                self.state.note("parked: attempt slice spent")
                self.log.attempt_end(cid, Outcome.PARKED.value, "attempt slice spent")
                return SolveOutcome(Outcome.PARKED, cid, "attempt slice spent",
                                    grounded_any, self.state.iters_done)

            # Stuck-loop detection: assess after real turns. Nudge once, then bail
            # to STALLED so the scheduler escalates a rung instead of spinning.
            if self.state.iters_done > 0:
                cur = self.state.store.total_bytes
                self._no_progress = 0 if cur > self._last_evidence_bytes else self._no_progress + 1
                self._last_evidence_bytes = cur
                if (self._no_progress >= self.stuck_patience
                        or self._dup_hits >= self.stuck_dup_threshold):
                    if not self._stuck_nudged:
                        self._stuck_nudged = True
                        self._no_progress = 0
                        self._dup_hits = 0
                        self._recent_sigs.clear()
                        self.log.event("solver.stuck_nudge", challenge=cid)
                        self.state.messages.append(Message(role="user", content=(
                            "You appear stuck — no new information for several steps, "
                            "or you are repeating an action that is not working. Change "
                            "approach now: use a different tool or input, re-read the "
                            "actual file/service output, or call `knowledge` for the "
                            "standard technique for this challenge type. Do not repeat a "
                            "command that already failed.")))
                    else:
                        self.state.note("stuck-loop: no progress after nudge")
                        self.log.attempt_end(cid, Outcome.STALLED.value, "stuck-loop")
                        return SolveOutcome(Outcome.STALLED, cid,
                                            "stuck-loop (no new progress)",
                                            grounded_any, self.state.iters_done)

            self.state.iters_done += 1
            try:
                resp = self.model.complete(self.state.messages, self.profile.schemas())
            except ContextOverflow:
                self._compact()
                continue
            except ModelError as e:
                self.state.note(f"model error: {e}")
                self.log.attempt_end(cid, Outcome.PARKED.value, f"model error: {e}")
                return SolveOutcome(Outcome.PARKED, cid, f"model error: {e}",
                                    grounded_any, self.state.iters_done)

            self.budget.charge_usage(cid, resp.usage)

            if resp.wants_tools:
                self.state.messages.append(Message(role="assistant", content=resp.text))
                for tc in resp.tool_calls:
                    self.state.messages.append(self._handle_tool_call(tc))
                if self.state.store.grounded_flags():
                    grounded_any = True
                    if self.submitter.is_solved(cid):
                        self.log.attempt_end(cid, Outcome.SOLVED.value, "flag accepted")
                        return SolveOutcome(Outcome.SOLVED, cid, "flag accepted",
                                            True, self.state.iters_done)
                    # Multi-flag: a flag landed but the challenge needs more. Keep
                    # the model on it rather than letting it drift off.
                    if self.submitter.required(cid) > 1 and self.submitter.accepted_count(cid) > 0:
                        self.state.messages.append(Message(
                            role="user",
                            content=self._progress_note() + " Find the remaining flag(s)."))
                continue

            # No tool call => the model thinks it is done. Accept a flag ONLY if it
            # is present in real evidence (confab guard). The model's prose is never
            # evidence on its own.
            self.state.messages.append(Message(role="assistant", content=resp.text))
            claimed = self._claimed_flag(resp.text)
            if claimed:
                gf = verify_candidate(self.state.store, claimed)
                if gf:
                    grounded_any = True
                    results = self._submit_grounded([gf])
                    if self.submitter.is_solved(cid):
                        self.log.attempt_end(cid, Outcome.SOLVED.value, "flag accepted")
                        return SolveOutcome(Outcome.SOLVED, cid, "flag accepted",
                                            True, self.state.iters_done)
                    # Grounded but the challenge is not fully solved: either it
                    # needs more flags, or the grader rejected this one. Steer the
                    # model to keep going instead of stalling.
                    took = bool(results and (results[0].accepted or results[0].already_solved))
                    if took:
                        nudge = (self._progress_note() + " This challenge needs more "
                                 "flags — find the remaining one(s).")
                    else:
                        nudge = ("The grader did not accept that flag. If this is a "
                                 "staged challenge, find the earlier-stage flag "
                                 "first; otherwise keep looking.")
                    self.state.messages.append(Message(role="user", content=nudge))
                    continue
                else:
                    # Model asserted a flag we cannot find in evidence: reject,
                    # tell it so, and let it keep working.
                    self.log.flag_candidate(cid, claimed[:16], grounded=False, source="model-prose")
                    self.state.messages.append(Message(
                        role="user",
                        content=("That flag is not present in any tool output I "
                                 "captured, so it cannot be submitted. Produce the "
                                 "flag from real output (read the file / service), "
                                 "or keep working."),
                    ))
                    continue

            # Nothing grounded and no new tool call: the attempt stalled.
            self.state.note("model stopped without a grounded flag")
            self.log.attempt_end(cid, Outcome.STALLED.value, "no grounded flag")
            return SolveOutcome(Outcome.STALLED, cid, "model stopped without a flag",
                                grounded_any, self.state.iters_done)

        self.log.attempt_end(cid, Outcome.PARKED.value, "max iterations")
        return SolveOutcome(Outcome.PARKED, cid, "max iterations reached",
                            grounded_any, self.state.iters_done)

    # --- helpers -----------------------------------------------------------

    @staticmethod
    def _claimed_flag(text: str) -> str | None:
        m = DEFAULT_FLAG_RE.search(text.encode("utf-8", "replace"))
        return m.group(0).decode("utf-8", "replace") if m else None

    def _compact(self) -> None:
        """Trim the middle of the conversation on context overflow, keeping the
        system prompt, the task, and the most recent exchanges. Evidence (and
        thus any grounded flag) lives in the store, not the messages, so trimming
        here never loses a flag."""
        msgs = self.state.messages
        if len(msgs) <= 4:
            return
        head = msgs[:2]                 # system + task
        tail = msgs[-6:]
        dropped = len(msgs) - len(head) - len(tail)
        self.state.messages = head + [Message(
            role="user", content=f"[{dropped} earlier messages elided to fit context]")
        ] + tail
        self.state.note(f"compacted conversation (-{dropped} messages)")
