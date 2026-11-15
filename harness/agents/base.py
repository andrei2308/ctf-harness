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

import json
import time
from collections import deque
from dataclasses import dataclass, field, replace
from enum import Enum
from pathlib import Path

from ..flags.grounding import (EvidenceStore, GroundedFlag, flag_pattern,
                               verify_candidate)
from ..flags.submit import FlagSubmitter, _preview
from ..inference.base import (ContextOverflow, Message, Model, ModelError)
from ..scheduler.budget import Budget, BudgetExceeded
from ..telemetry.run_log import RunLog
from .limits import Limits
from .tools import ToolContext, ToolProfile, ToolResult

_TRIM_MARK = "[older output trimmed to save tokens]"


# Waits between retries of a failed model call (rate limit, 5xx, overload). The
# endpoint is shared by every team at the event, so blips are expected.
MODEL_RETRY_DELAYS = (2.0, 5.0, 10.0, 20.0, 30.0)
# Consecutive turns with no tool call (and no accepted flag) before the attempt
# counts as stalled. Each one gets a nudge to act first.
MAX_PROSE_TURNS = 2
_sleep = time.sleep          # indirection so tests can skip real waits
_CUT_OFF_NOTE = ("Your last reply hit the output limit before you acted, so "
                 "nothing came through. Keep your reasoning short and make the "
                 "next tool call now.")


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
    saved_outputs: int = 0         # oversized tool outputs written to .tool_output/
    # Output cap learned the hard way (see Solver._raise_output_cap); carried
    # across attempts so a later rung does not start below it.
    output_floor: int = 0
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
              system_prompt: str, task_prompt: str,
              ignore_flags: frozenset[str] = frozenset()) -> SolverState:
    store = EvidenceStore(pattern=flag_pattern(), ignore=ignore_flags)
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
                 stuck_dup_threshold: int = 3, plan_first: bool = True,
                 limits: Limits | None = None):
        self.limits = limits or Limits.from_env()
        # Tools ask this for their timeout, so none can outrun the time budget.
        state.ctx.max_timeout = self.limits.max_tool_seconds
        state.ctx.time_left = self._tool_time_left
        if state.output_floor > model.spec.max_tokens:
            model.spec = replace(model.spec, max_tokens=state.output_floor)
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
        t0 = time.monotonic()
        try:
            resp = self.model.complete(self.state.messages, [])   # planning: no tools
        except (ModelError, ContextOverflow):
            self.state.planned = True
            return
        finally:
            self.budget.charge_time(cid, time.monotonic() - t0)
        self.budget.charge_usage(cid, resp.usage)
        self.state.messages.append(Message(role="assistant",
                                           content=resp.text or "(no plan produced)"))
        self.state.planned = True
        self.log.event("solver.plan", challenge=cid, chars=len(resp.text or ""),
                       text=self._for_log(resp.text or ""))

    def _handle_tool_call(self, tc) -> Message:
        # Track repeated actions for stuck detection: a repeated (tool, args)
        # bumps the dup counter; variety resets it.
        sig = f"{tc.name}:{sorted((tc.arguments or {}).items())!r}"[:240]
        self._dup_hits = self._dup_hits + 1 if sig in self._recent_sigs else 0
        self._recent_sigs.append(sig)

        cid = self.state.challenge_id
        # Logged BEFORE it runs, so a run killed mid-tool still shows what hung.
        self.log.event("tool.call", challenge=cid, tool=tc.name,
                       args=self._for_log(_args_text(tc.arguments)))
        tool = self._tools.get(tc.name)
        t0 = time.monotonic()
        if tool is None:
            res = ToolResult(tc.name, b"", f"{tc.name}:unknown",
                             error=f"no such tool: {tc.name}")
        else:
            try:
                res = tool.run(tc.arguments, self.state.ctx)
            except Exception as e:  # noqa: BLE001 - a tool bug must not kill the attempt
                res = ToolResult(tc.name, b"", f"{tc.name}:exception", error=repr(e))
        took = time.monotonic() - t0
        self.budget.charge_time(cid, took)

        # Record REAL output as evidence and stream any grounded flag now.
        # Reference material (knowledge base, summaries) is NOT evidence: an
        # example CTF{...} in a writeup must never ground.
        newly = (self.state.store.record(res.source, res.output)
                 if res.output and res.is_evidence else [])
        limit = self.limits.tool_output_bytes
        cut = len(res.output) > limit
        text = res.as_text(limit)
        if cut:
            saved = self._save_output(res.output)
            if saved:
                text += (f"\n[full output saved to {saved} — search it with grep/sed "
                         "instead of re-running the command]")
        self.log.observe(cid, res.name, len(res.output), cut, exit_code=res.exit_code,
                         error=res.error, seconds=round(took, 2),
                         output=self._for_log(res.output.decode("utf-8", "replace")))
        if newly:
            self._submit_grounded(newly)
        return Message(role="tool", content=text, tool_call_id=tc.id, name=tc.name)

    def _raise_output_cap(self) -> None:
        """A turn was cut off at max_tokens with nothing produced: double the
        cap for the rest of this challenge (up to the ceiling), instead of
        paying for the same empty turn again. Without this a reasoning model can
        burn a whole rung at 4096 tokens a turn and never act."""
        cur = self.model.spec.max_tokens
        new = min(self.limits.max_output_tokens, cur * 2)
        if new > cur:
            self.model.spec = replace(self.model.spec, max_tokens=new)
            self.state.output_floor = new
            self.log.event("solver.output_cap_raised", challenge=self.state.challenge_id,
                           was=cur, now=new)

    def _save_output(self, data: bytes) -> str | None:
        """Keep an oversized tool output on disk so the model can search it."""
        try:
            d = self.state.ctx.work_dir / ".tool_output"
            d.mkdir(exist_ok=True)
            self.state.saved_outputs += 1
            path = d / f"{self.state.saved_outputs:04d}.txt"
            path.write_bytes(data)
            return f".tool_output/{path.name}"
        except OSError:
            return None

    def _tool_time_left(self) -> float | None:
        left = self.budget.time_left(self.state.challenge_id)
        return None if left is None else max(0.0, left - self.limits.reserve_seconds)

    def _for_log(self, text: str) -> str:
        """A capped excerpt for the run log, with flags reduced to a preview (the
        log is reviewed; it shows the format, not the secret)."""
        cap = self.limits.log_text_chars
        if len(text) > cap:
            text = (text[: cap * 3 // 4] + f" …[{len(text)} chars]… " + text[-(cap // 4):])
        for claim in sorted(self.state.store.claims_in(text), key=len, reverse=True):
            text = text.replace(claim, _preview(claim))
        return text

    def _diet(self) -> None:
        """Keep the transcript small before each model call. Every message is
        re-sent on every turn, so old tool output is the main token sink: past
        the soft size, results older than the newest few are cut to a stub; past
        the hard size, the middle of the transcript is dropped."""
        lim = self.limits
        msgs = self.state.messages
        if sum(len(m.content) for m in msgs) <= lim.history_soft_chars:
            return
        tool_idx = [i for i, m in enumerate(msgs) if m.role == "tool"]
        old = tool_idx[:-lim.keep_recent_results] if lim.keep_recent_results else tool_idx
        keep = lim.old_result_chars
        for i in old:
            c = msgs[i].content
            if len(c) > keep + len(_TRIM_MARK) + 8 and not c.endswith(_TRIM_MARK):
                msgs[i] = replace(msgs[i], content=(
                    c[: keep * 2 // 3] + "\n…\n" + c[-(keep // 3):] + "\n" + _TRIM_MARK))
        if sum(len(m.content) for m in msgs) > lim.history_hard_chars:
            self._compact()

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
            self._diet()
            t0 = time.monotonic()
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
            finally:
                self.budget.charge_time(cid, time.monotonic() - t0)

            self.budget.charge_usage(cid, resp.usage)
            self.log.event("model.turn", challenge=cid, iter=self.state.iters_done,
                           text=self._for_log(resp.text or ""),
                           calls=[tc.name for tc in resp.tool_calls],
                           tokens_in=resp.usage.input, tokens_out=resp.usage.output,
                           stop=resp.stop_reason,
                           seconds=round(time.monotonic() - t0, 2))

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

            # Cut off at the output cap before it produced anything: a reasoning
            # model spent max_tokens thinking (seen with GLM at rung 0's 4096).
            # That is not the model choosing to talk, so it is not a prose turn,
            # and an empty assistant message is not worth keeping.
            if resp.stop_reason == "length" and not (resp.text or "").strip():
                self._raise_output_cap()
                last = self.state.messages[-1]
                if not (last.role == "user" and last.content == _CUT_OFF_NOTE):
                    self.state.messages.append(Message(role="user", content=_CUT_OFF_NOTE))
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
        # A digest of what was already run, built without a model call, so the
        # model does not redo work it can no longer see.
        # Lines from an earlier digest are carried forward, so repeated
        # compaction does not forget the oldest actions.
        actions: list[str] = []
        for m in msgs[2:cut]:
            if m.role == "user" and "elided to fit context" in m.content:
                actions += [ln for ln in m.content.splitlines() if ln.startswith("- ")]
            actions += [f"- {tc.name}: {_args_text(tc.arguments)[:140]}"
                        for tc in m.tool_calls]
        digest = ""
        if actions:
            shown = actions[-40:]
            digest = ("\nActions already taken in the elided part (oldest first"
                      + (f", last {len(shown)} of {len(actions)}" if len(shown) < len(actions) else "")
                      + "); do not repeat them without a new reason:\n" + "\n".join(shown))
        self.state.messages = head + [Message(
            role="user",
            content=f"[{dropped} earlier messages elided to fit context]{digest}")
        ] + tail
        self.state.note(f"compacted conversation (-{dropped} messages)")


_RECAP_ASK = (
    "This attempt is being stopped and will restart with a clean context: you "
    "will lose everything above. Write the handover note your next attempt starts "
    "from. Plain text, under 300 words, no tool calls:\n"
    "1. Facts established, with exact values (file types, protections, versions, "
    "addresses, offsets, credentials, endpoints, keys).\n"
    "2. What was tried and why each approach failed.\n"
    "3. The most promising next approach that is DIFFERENT from what failed.\n"
    "Do not write a flag unless it appeared in tool output.")


def restart_recap(model: Model, state: SolverState, tools: list[dict], budget: Budget,
                  log: RunLog, limits: Limits | None = None) -> str:
    """The note that seeds a clean-context restart. The model writes it from the
    full transcript it is about to lose (one call); if that fails or comes back
    empty, a mechanical list of the commands already run is used instead. Without
    this a restart begins from nothing and repeats the first attempt."""
    limits = limits or Limits.from_env()
    cid = state.challenge_id
    note = ""
    t0 = time.monotonic()
    try:
        # Tools are passed because some backends reject a transcript containing
        # tool calls when none are declared; the prompt asks for text only.
        resp = model.complete(state.messages + [Message(role="user", content=_RECAP_ASK)],
                              tools)
        budget.charge_usage(cid, resp.usage)
        note = (resp.text or "").strip()[: limits.recap_chars]
    except ModelError as e:
        log.event("solver.recap_error", challenge=cid, error=str(e)[:300])
    finally:
        budget.charge_time(cid, time.monotonic() - t0)
    source = "model"
    if not note:
        source = "mechanical"
        actions = [f"- {tc.name}: {_args_text(tc.arguments)[:140]}"
                   for m in state.messages for tc in m.tool_calls][-25:]
        note = "Commands already run (most recent last):\n" + "\n".join(actions) \
            if actions else "No commands were run."
        if state.notes:
            note += "\nHarness notes: " + "; ".join(state.notes[-5:])
    log.event("solver.recap", challenge=cid, source=source, chars=len(note), text=note)
    found = len(state.store.grounded_flags())
    return ("(Your earlier attempt was reset to a clean context. This is the handover "
            "note it left.)\n" + note + "\n"
            + (f"{found} flag candidate(s) were already found and submitted.\n" if found else "")
            + "Files you created earlier are still in the working directory, and full "
            "outputs of earlier commands are under .tool_output/. Do not redo what "
            "failed: take a different approach.")


def _args_text(arguments: dict) -> str:
    """Tool arguments as one line: the bare command for the common single-string
    case, compact JSON otherwise."""
    if len(arguments) == 1:
        (value,) = arguments.values()
        if isinstance(value, str):
            return value
    try:
        return json.dumps(arguments, ensure_ascii=False, separators=(",", ":"))
    except (TypeError, ValueError):
        return repr(arguments)
