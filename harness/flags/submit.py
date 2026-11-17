"""Streaming flag submission — multi-flag aware.

Tiebreak is earliest last-flag, so a verified flag is submitted the instant it
grounds. This layer also carries the one lesson the organizers' own agent learned
the hard way: a challenge may need several flags submitted in sequence, and the
agent that can find flags but not submit all of them loses the challenge. So:

  * each challenge tracks how many flags it needs (`required`) and which distinct
    flags have been accepted; it is "solved" only when the platform says so or
    enough distinct flags are in;
  * a grounded flag that the grader rejects can be retried a bounded number of
    times — a correct later-stage flag is often rejected until an earlier stage
    is in (`max_submits_per_flag`); this is disabled when wrong guesses are
    penalised;
  * this is still the ONLY path to Platform.submit_flag, so the grounding guard
    cannot be bypassed — a flag reaches here only as a GroundedFlag.

`penalize_wrong` (OPEN with organizers; the predecessor event did NOT penalise
wrong guesses and the winner ran at 64% accuracy) tightens behaviour: one attempt
per flag, no speculative resubmits.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, field

from ..platforms.base import Platform, SubmitResult
from ..telemetry.run_log import RunLog
from .grounding import GroundedFlag


@dataclass
class SubmissionRecord:
    challenge: str
    flag: str
    source: str
    accepted: bool
    already_solved: bool
    at: float


@dataclass
class _ChalState:
    required: int = 1
    accepted: set[str] = field(default_factory=set)   # distinct flags the grader took
    attempts: dict[str, int] = field(default_factory=dict)  # flag -> submit count
    solved: bool = False                               # whole challenge complete


# Waits between tries when the grader is unreachable. A flag in hand is the most
# valuable thing in the run, so a blip must not lose it.
SUBMIT_RETRY_DELAYS = (0.5, 1.0, 2.0, 4.0)
# After those, a flag that still did not reach the grader is re-sent at the
# next flush, then no sooner than this many seconds later (doubling each time),
# and dropped after PENDING_MAX_ROUNDS rounds. Without this a flag was re-sent
# on every turn and every time it reappeared in output: 323 submissions in 21
# minutes in rehearsal.
PENDING_BACKOFF_SECONDS = 30.0
PENDING_MAX_ROUNDS = 8


class FlagSubmitter:
    """Owns all submissions for a run. Thread-safe; dedupes across slots."""

    def __init__(self, platform: Platform, log: RunLog, *, dry_run: bool = False,
                 penalize_wrong: bool = False, max_submits_per_flag: int = 3,
                 retry_delays: tuple[float, ...] = SUBMIT_RETRY_DELAYS,
                 sleep=time.sleep, min_interval: float | None = None):
        self._platform = platform
        self._log = log
        self._dry_run = dry_run
        self._penalize_wrong = penalize_wrong
        self._max_submits = 1 if penalize_wrong else max(1, max_submits_per_flag)
        self._retry_delays = tuple(retry_delays)
        self._sleep = sleep
        self._lock = threading.Lock()
        self._chals: dict[str, _ChalState] = {}
        # Flags that never reached the grader (transport failure), per challenge.
        self._pending: dict[str, dict[str, GroundedFlag]] = {}
        self._pending_rounds: dict[tuple[str, str], int] = {}
        self._next_try: dict[tuple[str, str], float] = {}
        self._clock = time.monotonic
        # Seconds between two calls to the grader. Three candidates sent within
        # a second drew HTTP 429 in rehearsal, and with wrong flags free the
        # contest configuration sends more candidates, not fewer.
        if min_interval is None:
            try:
                min_interval = float(os.environ.get("CTF_SUBMIT_MIN_INTERVAL", "1.0"))
            except ValueError:
                min_interval = 1.0
        self._min_interval = max(0.0, min_interval)
        self._last_call = float("-inf")
        self.records: list[SubmissionRecord] = []

    def _pace(self) -> None:
        with self._lock:
            wait = self._last_call + self._min_interval - self._clock()
            self._last_call = self._clock() + max(0.0, wait)
        if wait > 0:
            self._sleep(wait)

    @property
    def allow_ungrounded(self) -> bool:
        """When a wrong flag costs nothing, a flag the model claims but that is
        not in tool output is still worth one submission. With a penalty it is
        not: only grounded flags go out."""
        return not self._penalize_wrong

    # --- registration ------------------------------------------------------

    def register(self, challenge: str, flags_required: int = 1) -> None:
        """Tell the submitter how many flags a challenge needs (from the platform
        metadata). Safe to call repeatedly; keeps the larger known requirement."""
        with self._lock:
            st = self._chals.setdefault(challenge, _ChalState())
            st.required = max(st.required, max(1, flags_required))

    def _state(self, challenge: str) -> _ChalState:
        return self._chals.setdefault(challenge, _ChalState())

    # --- queries -----------------------------------------------------------

    def is_solved(self, challenge: str) -> bool:
        with self._lock:
            st = self._chals.get(challenge)
            return bool(st and st.solved)

    def accepted_count(self, challenge: str) -> int:
        with self._lock:
            st = self._chals.get(challenge)
            return len(st.accepted) if st else 0

    def required(self, challenge: str) -> int:
        with self._lock:
            st = self._chals.get(challenge)
            return st.required if st else 1

    # --- submission --------------------------------------------------------

    def submit(self, challenge: str, grounded: GroundedFlag) -> SubmitResult:
        """Submit a grounded flag immediately. Dedupes accepted flags; allows a
        bounded number of retries for not-yet-accepted flags (staged challenges).
        """
        flag = grounded.flag
        with self._lock:
            st = self._state(challenge)
            if st.solved:
                return SubmitResult(accepted=True, already_solved=True,
                                    challenge_solved=True, message="challenge already solved")
            if flag in st.accepted:
                return SubmitResult(accepted=True, already_solved=True,
                                    message="flag already accepted")
            key = (challenge, flag)
            if self._clock() < self._next_try.get(key, 0.0):
                return SubmitResult(accepted=False, message="queued; grader retry later",
                                    raw={"transport_error": True, "backoff": True})
            tries = st.attempts.get(flag, 0)
            if tries >= self._max_submits:
                return SubmitResult(accepted=False,
                                    message=f"flag exhausted ({tries} attempts)")
            st.attempts[flag] = tries + 1

        self._log.event("flag.candidate", challenge=challenge,
                        flag_preview=_preview(flag), grounded=True,
                        source=grounded.source, attempt=tries + 1)

        if self._dry_run:
            result = SubmitResult(accepted=True, message="dry-run: not submitted")
        else:
            result = None
            for i in range(len(self._retry_delays) + 1):
                try:
                    self._pace()
                    result = self._platform.submit_flag(challenge, flag)
                    break
                except Exception as e:  # noqa: BLE001 - any adapter failure is retryable here
                    self._log.event("flag.submit_error", challenge=challenge,
                                    error=str(e), attempt=i + 1)
                    if i < len(self._retry_delays):
                        self._sleep(self._retry_delays[i])
            if result is None:
                # Never reached the grader: free the attempt slot and keep the
                # flag so flush_pending() can send it once the grader is back,
                # but not sooner than the backoff, and not forever.
                with self._lock:
                    rounds = self._pending_rounds.get(key, 0) + 1
                    self._pending_rounds[key] = rounds
                    if rounds >= PENDING_MAX_ROUNDS:
                        self._pending.get(challenge, {}).pop(flag, None)
                        self._next_try.pop(key, None)
                        self._chals[challenge].attempts[flag] = self._max_submits
                        give_up = True
                    else:
                        self._chals[challenge].attempts[flag] = tries
                        self._pending.setdefault(challenge, {})[flag] = grounded
                        # The first re-send is immediate (next flush), so a blip
                        # costs nothing; after that, back off.
                        self._next_try[key] = self._clock() + (
                            0.0 if rounds == 1 else PENDING_BACKOFF_SECONDS * 2 ** (rounds - 2))
                        give_up = False
                if give_up:
                    self._log.event("flag.submit_abandoned", challenge=challenge,
                                    flag_preview=_preview(flag), rounds=rounds)
                    return SubmitResult(accepted=False, message="grader unreachable; gave up",
                                        raw={"transport_error": True})
                return SubmitResult(accepted=False, message="submit failed; queued for retry",
                                    raw={"transport_error": True})
            with self._lock:
                self._pending_rounds.pop(key, None)
                self._next_try.pop(key, None)

        with self._lock:
            self._pending.get(challenge, {}).pop(flag, None)

        with self._lock:
            st = self._state(challenge)
            if result.accepted or result.already_solved:
                st.accepted.add(flag)
            if result.challenge_solved or len(st.accepted) >= st.required:
                st.solved = True
            self.records.append(SubmissionRecord(
                challenge=challenge, flag=flag, source=grounded.source,
                accepted=result.accepted or result.already_solved,
                already_solved=result.already_solved, at=time.time(),
            ))
            progress = f"{len(st.accepted)}/{st.required}"

        self._log.event("flag.submit", challenge=challenge, accepted=result.accepted,
                        already=result.already_solved,
                        challenge_solved=self.is_solved(challenge), progress=progress,
                        # What the grader said: without it a rejected flag cannot
                        # be told from a misread response.
                        message=_preview_message(result.message, flag))
        return result

    def flush_pending(self, challenge: str) -> list[SubmitResult]:
        """Resubmit flags that earlier failed to reach the grader. Cheap when
        there are none; the solver calls it every turn."""
        with self._lock:
            waiting = list(self._pending.get(challenge, {}).values())
        return [self.submit(challenge, gf) for gf in waiting]

    def pending_count(self, challenge: str) -> int:
        with self._lock:
            return len(self._pending.get(challenge, {}))

    # --- reporting ---------------------------------------------------------

    def solved_count(self) -> int:
        with self._lock:
            return sum(1 for st in self._chals.values() if st.solved)

    def summary(self) -> dict:
        with self._lock:
            solved = sorted(c for c, st in self._chals.items() if st.solved)
            accepted_total = sum(len(st.accepted) for st in self._chals.values())
            last = max((r.at for r in self.records if r.accepted), default=None)
            return {
                "solved": solved,
                "solved_count": len(solved),
                "flags_accepted": accepted_total,
                "submissions": len(self.records),
                "last_flag_at": last,
            }


def _preview(flag: str, keep: int = 8) -> str:
    """A short, non-revealing preview for logs. Shows the format, not the secret."""
    if "{" in flag and flag.endswith("}"):
        pre, body = flag.split("{", 1)
        body = body[:-1]
        shown = body[:keep]
        return f"{pre}{{{shown}{'…' if len(body) > keep else ''}}}"
    return flag[:keep] + ("…" if len(flag) > keep else "")


def _preview_message(message: str, flag: str) -> str:
    """The grader's message for the log, short, with the flag itself masked."""
    return (message or "").replace(flag, _preview(flag))[:200]
