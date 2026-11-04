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

import threading
import time
from dataclasses import dataclass, field

from ..platforms.base import Platform, PlatformError, SubmitResult
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


class FlagSubmitter:
    """Owns all submissions for a run. Thread-safe; dedupes across slots."""

    def __init__(self, platform: Platform, log: RunLog, *, dry_run: bool = False,
                 penalize_wrong: bool = False, max_submits_per_flag: int = 3):
        self._platform = platform
        self._log = log
        self._dry_run = dry_run
        self._penalize_wrong = penalize_wrong
        self._max_submits = 1 if penalize_wrong else max(1, max_submits_per_flag)
        self._lock = threading.Lock()
        self._chals: dict[str, _ChalState] = {}
        self.records: list[SubmissionRecord] = []

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
            try:
                result = self._platform.submit_flag(challenge, flag)
            except PlatformError as e:
                self._log.event("flag.submit_error", challenge=challenge, error=str(e))
                with self._lock:  # never reached the grader: free the attempt slot
                    self._chals[challenge].attempts[flag] = tries
                raise

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
                        challenge_solved=self.is_solved(challenge), progress=progress)
        return result

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
