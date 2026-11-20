"""Platform interface.

Every component in the harness talks to the contest through this interface and
nothing else. No platform-specific calls (MCP tool names, HTTP routes, file
paths) leak into solver or scheduler logic. Swapping the live CyberEDU MCP for a
files-on-disk fixture is a matter of swapping the adapter passed to the runner.

Design rule: adapters translate; they never decide. Retry/backoff policy,
budget accounting, and flag handling live above this layer so they behave
identically no matter which adapter is wired in.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class ChallengeKind(str, Enum):
    """Coarse routing hint. Maps to a specialist agent + tool profile.

    This is a *hint*, not a contract. The organizers may not label challenges,
    so adapters fill this in best-effort (from category text, file types, or
    presence of a network service) and the router is allowed to re-classify.
    """

    STATIC = "static"          # file(s) on disk, no live service: rev, crypto, forensics, stego
    INTERACTIVE = "interactive"  # a network service to talk to: pwn, some crypto/misc
    WEB = "web"                # an HTTP(S) target
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Challenge:
    """Immutable description of one challenge as the platform reports it."""

    id: str
    name: str
    kind: ChallengeKind = ChallengeKind.UNKNOWN
    category: str = ""            # raw organizer category string, kept verbatim
    points: int | None = None     # current/nominal points if exposed (dynamic scoring)
    description: str = ""
    # How many distinct flags this challenge needs to be fully scored. Some
    # challenges (forensics especially) require several flags submitted in
    # sequence — the exact gap that beat the organizers' own reference agent.
    # Best-effort from the platform; defaults to 1. The harness keeps hunting
    # and submitting until this many flags are accepted.
    flags_required: int = 1
    # Opaque extra metadata from the platform. Solvers must not depend on keys
    # here; promote anything load-bearing into a typed field instead.
    meta: dict = field(default_factory=dict)


@dataclass(frozen=True)
class ConnInfo:
    """How to reach a live instance of an interactive/web challenge."""

    host: str | None = None
    port: int | None = None
    url: str | None = None        # for web challenges
    expires_at: float | None = None  # epoch seconds; None = no known expiry
    meta: dict = field(default_factory=dict)


@dataclass(frozen=True)
class SubmitResult:
    """Outcome of a flag submission.

    `accepted` is the only field solvers branch on. `already_solved` lets the
    submit layer treat a resubmit as success without penalty accounting.
    `penalty` is reserved for platforms that charge for wrong guesses (TBD for
    DefCamp); the grounding guard tightens when this is known to be > 0.
    """

    accepted: bool
    already_solved: bool = False
    # True when the platform says the WHOLE challenge is now complete (all of its
    # flags are in), as opposed to `accepted` meaning just this one flag was
    # correct. For multi-flag challenges these differ; when the platform does not
    # distinguish, the submitter falls back to counting accepted flags against
    # Challenge.flags_required.
    challenge_solved: bool = False
    penalty: float = 0.0
    message: str = ""
    raw: dict = field(default_factory=dict)


class PlatformError(RuntimeError):
    """Raised by adapters for transport/auth failures the caller may retry.

    Adapters raise this (not bare exceptions) so the scheduler can distinguish a
    recoverable platform hiccup from a bug in solver logic.
    """


class Platform(abc.ABC):
    """The contest surface. Implementations: CyberEduMcpPlatform, FilesTargetPlatform."""

    # True when this platform grades against answers stored on the local disk
    # (the fixtures rig). The harness then must not treat flag-shaped strings
    # found in its own directories as decoys: the real answers are among them.
    answers_on_disk: bool = False

    @abc.abstractmethod
    def list_challenges(self) -> list[Challenge]:
        """Enumerate every challenge currently visible to us."""

    @abc.abstractmethod
    def get_challenge(self, challenge_id: str) -> Challenge:
        """Fetch a single challenge's current state (points may change: dynamic scoring)."""

    @abc.abstractmethod
    def download_files(self, challenge_id: str, dest: Path) -> list[Path]:
        """Materialise any attached files under `dest`. Returns the paths written.

        `dest` is a per-challenge working directory owned by the caller. Returns
        an empty list when a challenge ships no files (e.g. a pure service).
        """

    @abc.abstractmethod
    def start_instance(self, challenge_id: str) -> ConnInfo:
        """Start (or reuse) a live instance for an interactive/web challenge.

        For static challenges this returns an empty ConnInfo. Must be idempotent
        enough that calling it again returns a usable connection (restart/extend
        is an adapter concern, surfaced through this call).
        """

    @abc.abstractmethod
    def get_conn_info(self, challenge_id: str) -> ConnInfo:
        """Current connection details without forcing a (re)start."""

    @abc.abstractmethod
    def submit_flag(self, challenge_id: str, flag: str) -> SubmitResult:
        """Submit one candidate flag. Must be safe to call repeatedly (idempotent
        on the platform side for an already-solved challenge)."""

    # --- optional capabilities; default to no-op so adapters opt in ----------

    def extend_instance(self, challenge_id: str) -> ConnInfo:
        """Push back an instance's expiry. Default: re-start."""
        return self.start_instance(challenge_id)

    def finish(self, summary: dict) -> None:
        """The run is over; `summary` is what the harness prints at the end.
        A platform that wants to be told (a give-up note) does it here.
        Default: no-op."""

    def close(self) -> None:
        """Release adapter resources (sessions, subprocesses). Default: no-op."""
