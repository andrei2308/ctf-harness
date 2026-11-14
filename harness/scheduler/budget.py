"""Budget accounting: tokens and wall-clock, global pool + per-challenge slices.

The rules make efficiency a *scored constraint*: hard organizer-set token and
time limits, equal for all, and an explicit ban on burning tokens (padding/junk).
Hitting a limit stops the run. So budget is not bookkeeping we read at the end —
it gates every attempt and drives park-and-resume.

Two independent resources, each with a global cap and a per-challenge slice:
  * tokens  — billable input (excl. cache hits) + output, summed across calls
  * seconds — wall-clock spent inside an attempt

The exact scope of the limits (per-run / per-challenge / event pool; whether
cache counts; whether crash re-runs reset) is OPEN with organizers. The knobs
here cover every combination; wire the real numbers into Config when they land.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

from ..inference.base import Usage


class BudgetExceeded(Exception):
    """Raised when a spend would cross a hard cap. Carries which resource/scope."""

    def __init__(self, resource: str, scope: str, used: float, cap: float):
        self.resource = resource
        self.scope = scope
        self.used = used
        self.cap = cap
        super().__init__(f"{resource} {scope} budget exceeded: {used:.0f}/{cap:.0f}")


@dataclass
class Caps:
    """Limits. 0 / None means 'no cap on this axis' (useful for local testing)."""

    # Global, whole-run.
    total_tokens: int | None = None
    total_seconds: float | None = None
    # Per-challenge slice: how much any single challenge may consume before it is
    # parked (soft) or abandoned (hard). The scheduler reads these for the ladder.
    per_challenge_tokens: int | None = None
    per_challenge_seconds: float | None = None
    # One uninterrupted attempt's slice before park-and-resume kicks in.
    per_attempt_tokens: int | None = None
    per_attempt_seconds: float | None = None
    # Whether cache-hit input tokens count toward caps. Organizer-dependent.
    count_cached_input: bool = True


@dataclass
class _Counter:
    tokens: int = 0
    seconds: float = 0.0


class Budget:
    """Thread-safe spend tracker. One instance per run, shared across slots.

    Usage:
        budget.charge_usage(chal_id, response.usage)     # after each model call
        budget.charge_time(chal_id, dt)                  # around tool/model work
        budget.check(chal_id)                            # raises if over a hard cap
        remaining = budget.attempt_remaining(chal_id)    # drives park decisions
    """

    def __init__(self, caps: Caps):
        self.caps = caps
        self._lock = threading.RLock()
        self._global = _Counter()
        self._per_chal: dict[str, _Counter] = {}
        # Per-attempt counters reset when an attempt (re)starts.
        self._per_attempt: dict[str, _Counter] = {}
        self._started = time.monotonic()

    # --- charging -----------------------------------------------------------

    def _tok(self, usage: Usage) -> int:
        return usage.input + usage.output if self.caps.count_cached_input \
            else usage.billable_in + usage.output

    def charge_usage(self, challenge: str, usage: Usage) -> None:
        tok = self._tok(usage)
        with self._lock:
            self._global.tokens += tok
            self._per_chal.setdefault(challenge, _Counter()).tokens += tok
            self._per_attempt.setdefault(challenge, _Counter()).tokens += tok

    def charge_time(self, challenge: str, seconds: float) -> None:
        with self._lock:
            self._global.seconds += seconds
            self._per_chal.setdefault(challenge, _Counter()).seconds += seconds
            self._per_attempt.setdefault(challenge, _Counter()).seconds += seconds

    def start_attempt(self, challenge: str) -> None:
        """Reset the per-attempt slice. Per-challenge and global totals persist
        (park-and-resume: a resumed challenge keeps its cumulative spend)."""
        with self._lock:
            self._per_attempt[challenge] = _Counter()

    # --- checks -------------------------------------------------------------

    def check(self, challenge: str) -> None:
        """Raise BudgetExceeded if any *hard* cap (global or per-challenge) is
        crossed. Per-attempt limits are soft (park, not abandon) and checked via
        attempt_remaining()."""
        with self._lock:
            c = self.caps
            if c.total_tokens and self._global.tokens >= c.total_tokens:
                raise BudgetExceeded("tokens", "global", self._global.tokens, c.total_tokens)
            elapsed = time.monotonic() - self._started
            if c.total_seconds and elapsed >= c.total_seconds:
                raise BudgetExceeded("seconds", "global", elapsed, c.total_seconds)
            pc = self._per_chal.get(challenge)
            if pc:
                if c.per_challenge_tokens and pc.tokens >= c.per_challenge_tokens:
                    raise BudgetExceeded("tokens", f"challenge:{challenge}",
                                         pc.tokens, c.per_challenge_tokens)
                if c.per_challenge_seconds and pc.seconds >= c.per_challenge_seconds:
                    raise BudgetExceeded("seconds", f"challenge:{challenge}",
                                         pc.seconds, c.per_challenge_seconds)

    def seconds_left(self) -> float | None:
        """Wall-clock seconds before the global time cap, or None if uncapped."""
        if not self.caps.total_seconds:
            return None
        return max(0.0, self.caps.total_seconds - (time.monotonic() - self._started))

    def attempt_remaining(self, challenge: str) -> tuple[float, float]:
        """(token_fraction_left, second_fraction_left) for the current attempt
        slice, each in [0, 1]. The scheduler parks when either nears 0. Returns
        (1, 1) when per-attempt caps are unset."""
        with self._lock:
            a = self._per_attempt.get(challenge, _Counter())
            tf = 1.0
            if self.caps.per_attempt_tokens:
                tf = max(0.0, 1.0 - a.tokens / self.caps.per_attempt_tokens)
            sf = 1.0
            if self.caps.per_attempt_seconds:
                sf = max(0.0, 1.0 - a.seconds / self.caps.per_attempt_seconds)
            return tf, sf

    def should_park(self, challenge: str, floor: float = 0.05) -> bool:
        tf, sf = self.attempt_remaining(challenge)
        return tf <= floor or sf <= floor

    def challenge_exhausted(self, challenge: str) -> bool:
        """True when a challenge has burned its whole per-challenge slice: the
        hard cutoff — write notes, drop it, move on."""
        with self._lock:
            c = self.caps
            pc = self._per_chal.get(challenge, _Counter())
            if c.per_challenge_tokens and pc.tokens >= c.per_challenge_tokens:
                return True
            if c.per_challenge_seconds and pc.seconds >= c.per_challenge_seconds:
                return True
            return False

    # --- reporting (for logging) -------------------------------------------

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "global_tokens": self._global.tokens,
                "global_seconds": round(time.monotonic() - self._started, 2),
                "per_challenge": {
                    k: {"tokens": v.tokens, "seconds": round(v.seconds, 2)}
                    for k, v in self._per_chal.items()
                },
            }

    def fraction_used(self) -> float:
        """Global token fraction in [0, 1], for breadth-vs-depth decisions."""
        with self._lock:
            if not self.caps.total_tokens:
                return 0.0
            return min(1.0, self._global.tokens / self.caps.total_tokens)
