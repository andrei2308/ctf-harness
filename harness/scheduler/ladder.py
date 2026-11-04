"""The escalation ladder.

Fixed, equal concurrency means we cannot out-parallelize anyone; the edge is in
what each slot does and how attempts are scheduled. The ladder is the policy:
  * rung 0 is cheap and shallow — a fast model, low effort, few iterations — run
    breadth-first across every challenge so easy flags fall quickly and cheaply;
  * higher rungs spend more (stronger model / higher effort / more iterations)
    and are applied only to challenges that resisted the cheaper rungs.

Whether several distinct models are even available is OPEN (organizer answer #1).
If only one model is provided, the ladder degrades gracefully to effort/iteration
rungs on that one model — the shape is unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..inference.base import Effort, ModelSpec


@dataclass(frozen=True)
class Rung:
    spec: ModelSpec
    max_iterations: int

    def label(self) -> str:
        return f"{self.spec.label()}/{self.max_iterations}it"


@dataclass
class Ladder:
    rungs: list[Rung]

    def __len__(self) -> int:
        return len(self.rungs)

    def rung(self, index: int) -> Rung:
        """Clamp to the top rung so an over-escalated challenge still runs."""
        return self.rungs[min(max(index, 0), len(self.rungs) - 1)]

    def has_rung(self, index: int) -> bool:
        return 0 <= index < len(self.rungs)

    def top(self) -> int:
        return len(self.rungs) - 1


def default_ladder(fast_model: str, strong_model: str | None = None) -> Ladder:
    """A sensible default ladder; swap model names for the organizers' models.

    If only one model exists, pass it as `fast_model` and leave `strong_model`
    None: the ladder then escalates by effort and depth on that single model.
    """
    strong = strong_model or fast_model
    return Ladder([
        # Cheap breadth-first sweep.
        Rung(ModelSpec(name=fast_model, effort=Effort.LOW, max_tokens=4096), max_iterations=12),
        # First escalation: same-ish cost, more room to think and iterate.
        Rung(ModelSpec(name=fast_model, effort=Effort.MEDIUM, max_tokens=8192), max_iterations=25),
        # Bring in the strong model for the resisters.
        Rung(ModelSpec(name=strong, effort=Effort.HIGH, max_tokens=16384), max_iterations=40),
        # Last resort for high-value hard challenges.
        Rung(ModelSpec(name=strong, effort=Effort.MAX, max_tokens=32768), max_iterations=60),
    ])


def single_model_ladder(model: str) -> Ladder:
    """Explicit one-model ladder (escalate effort + depth only)."""
    return default_ladder(model, model)
