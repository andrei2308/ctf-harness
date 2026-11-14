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

import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from ..flags.grounding import (EvidenceStore, GroundedFlag, flag_pattern,
                               verify_candidate)
from ..flags.submit import FlagSubmitter
from ..inference.base import (ContextOverflow, Message, Model, ModelError)
from ..scheduler.budget import Budget, BudgetExceeded
from ..telemetry.run_log import RunLog
from .tools import ToolContext, ToolProfile, ToolResult


# Waits between retries of a failed model call (rate limit, 5xx, overload). The
# endpoint is shared by every team at the event, so blips are expected.
MODEL_RETRY_DELAYS = (2.0, 5.0, 10.0, 20.0, 30.0)
# Consecutive turns with no tool call (and no accepted flag) before the attempt
# counts as stalled. Each one gets a nudge to act first.
MAX_PROSE_TURNS = 2
_sleep = time.sleep          # indirection so tests can skip real waits


class Outcome(str, Enum):
    SOLVED = "solved"        # a flag was accepted
    PARKED = "parked"        # attempt budget slice spent; resume the same rung
    EXHAUSTED = "exhausted"  # per-challenge cutoff hit; drop it
    STALLED = "stalled"      # out of ideas or out of this rung's iterations: escalate
    ERROR = "error"          # the model endpoint kept failing this attempt


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
    store = EvidenceStore(pattern=flag_pattern())
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

        # A flag that could not reach the grader earlier goes out first.
        self.submitter.flush_pending(cid)
        if self.submitter.is_solved(cid):
            return SolveOutcome(Outcome.SOLVED, cid, "already solved", True,
                                self.state.iters_done)

        if self.plan_first and not self.state.planned:
            self._plan()

        grounded_any = bool(self.state.store.grounded_flags())
        # Iterations are counted per attempt: `max_iterations` is this rung's
        # depth, while state.iters_done keeps the challenge's running total.
        iters = 0
        prose_turns = 0

        while iters < self.max_iterations:
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

            if self.submitter.pending_count(cid):
                self.submitter.flush_pending(cid)
                if self.submitter.is_solved(cid):
                    self.log.attempt_end(cid, Outcome.SOLVED.value, "flag accepted")
                    return SolveOutcome(Outcome.SOLVED, cid, "flag accepted",
                                        True, self.state.iters_done)

            # Stuck-loop detection: assess after real turns. Nudge once, then bail
            # to STALLED so the scheduler escalates a rung instead of spinning.
            if iters > 0:
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

            iters += 1
            self.state.iters_done += 1
            try:
                resp = self._call_model()
            except ContextOverflow:
                self._compact()
                continue
            except ModelError as e:
                self.state.note(f"model error: {e}")
                self.log.attempt_end(cid, Outcome.ERROR.value, f"model error: {e}")
                return SolveOutcome(Outcome.ERROR, cid, f"model error: {e}",
                                    grounded_any, self.state.iters_done)

            self.budget.charge_usage(cid, resp.usage)

            if resp.wants_tools:
                prose_turns = 0
                # The calls stay on the assistant turn: the backend needs them to
                # pair with the results, and the model needs to see what it ran.
                self.state.messages.append(Message(role="assistant", content=resp.text,
                                                   tool_calls=resp.tool_calls))
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

            # No tool call. Either the model is claiming a flag, or it is talking
            # instead of acting (weaker models do this often). Neither ends the
            # attempt by itself: handle the claim, nudge, and only call it a stall
            # after MAX_PROSE_TURNS such turns in a row.
            self.state.messages.append(Message(role="assistant", content=resp.text))
            prose_turns += 1
            nudge, was_grounded = self._handle_claims(resp.text)
            grounded_any = grounded_any or was_grounded
            if self.submitter.is_solved(cid):
                self.log.attempt_end(cid, Outcome.SOLVED.value, "flag accepted")
                return SolveOutcome(Outcome.SOLVED, cid, "flag accepted",
                                    True, self.state.iters_done)
            if prose_turns > MAX_PROSE_TURNS:
                self.state.note("model stopped without an accepted flag")
                self.log.attempt_end(cid, Outcome.STALLED.value, "no accepted flag")
                return SolveOutcome(Outcome.STALLED, cid, "model stopped without a flag",
                                    grounded_any, self.state.iters_done)
            self.state.messages.append(Message(role="user", content=nudge))

        # This rung's depth is spent. That is a reason to escalate, not to resume
        # the same rung: report STALLED so the caller moves up the ladder.
        self.state.note("rung depth spent (max iterations)")
        self.log.attempt_end(cid, Outcome.STALLED.value, "max iterations")
        return SolveOutcome(Outcome.STALLED, cid, "max iterations reached",
                            grounded_any, self.state.iters_done)

    # --- helpers -----------------------------------------------------------

    def _call_model(self):
        """One model turn, retried with backoff on transient failures. Raises
        ModelError once the retries are spent or the time cap is too close to
        wait; ContextOverflow passes straight through for the caller to compact."""
        cid = self.state.challenge_id
        for i in range(len(MODEL_RETRY_DELAYS) + 1):
            try:
                return self.model.complete(self.state.messages, self.profile.schemas())
            except ContextOverflow:
                raise
            except ModelError as e:
                if i == len(MODEL_RETRY_DELAYS):
                    raise
                delay = MODEL_RETRY_DELAYS[i]
                left = self.budget.seconds_left()
                if left is not None and left <= delay:
                    raise
                self.log.event("solver.model_retry", challenge=cid, attempt=i + 1,
                               wait=delay, error=str(e)[:300])
                _sleep(delay)

    def _handle_claims(self, text: str) -> tuple[str, bool]:
        """Act on flag-shaped strings in a prose turn. Returns (the message to
        send back to the model, whether any claim was grounded in evidence).

        A claim found in real tool output is always submitted. One that is not
        is submitted only when wrong flags are free; with a penalty it is
        refused, because model prose alone is not evidence."""
        cid = self.state.challenge_id
        claims = self.state.store.claims_in(text)
        if not claims:
            return ("Do not stop or narrate: act. Make a tool call now. If you "
                    "believe you have the flag, print it with a tool so it appears "
                    "in real output."), False
        grounded = took = submitted = False
        for claimed in claims:
            gf = verify_candidate(self.state.store, claimed)
            if gf:
                grounded = True
            elif self.submitter.allow_ungrounded:
                self.log.flag_candidate(cid, claimed[:16], grounded=False,
                                        source="model-prose")
                gf = GroundedFlag(flag=claimed, raw=claimed.encode("utf-8", "replace"),
                                  source="model-prose (ungrounded)", evidence_seq=0)
            else:
                self.log.flag_candidate(cid, claimed[:16], grounded=False,
                                        source="model-prose")
                continue
            submitted = True
            res = self.submitter.submit(cid, gf)
            took = took or res.accepted or res.already_solved
        if took:
            return (self._progress_note() + " This challenge needs more flags — "
                    "find the remaining one(s)."), grounded
        if submitted:
            return ("The grader did not accept that flag. Do not guess: derive it "
                    "from real output. If this is a staged challenge, find the "
                    "earlier-stage flag first; otherwise keep looking."), grounded
        return ("That flag is not present in any tool output I captured, so it "
                "cannot be submitted. Produce the flag from real output (read the "
                "file / service), or keep working."), grounded

    def _compact(self) -> None:
        """Trim the middle of the conversation on context overflow, keeping the
        system prompt, the task, and the most recent exchanges. Evidence (and
        thus any grounded flag) lives in the store, not the messages, so trimming
        here never loses a flag."""
        msgs = self.state.messages
        if len(msgs) <= 4:
            return
        head = msgs[:2]                 # system + task
        # Keep roughly the last 6 messages, but never start the tail on a tool
        # result: its assistant call must come with it or the backend rejects
        # the transcript.
        cut = len(msgs) - 6
        while cut > 2 and msgs[cut].role == "tool":
            cut -= 1
        if cut <= 2:
            return
        tail = msgs[cut:]
        dropped = len(msgs) - len(head) - len(tail)
        self.state.messages = head + [Message(
            role="user", content=f"[{dropped} earlier messages elided to fit context]")
        ] + tail
        self.state.note(f"compacted conversation (-{dropped} messages)")
