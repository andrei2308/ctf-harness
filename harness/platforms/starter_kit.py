"""Adapter for the organizers' starter kit — fill in when the docs arrive.

Six methods connect the harness to the contest. Everything else (retries, flag
queueing, budgets, logging) already sits above this layer. To switch it on, set
in contest.env:

    CTF_PLATFORM=harness.platforms.starter_kit:StarterKitPlatform

Rules of the road:
  * Read endpoints and credentials from the environment, never hard-code them.
  * Raise PlatformError for anything transport-related (timeouts, 5xx, auth);
    submit_flag failures are then retried and the flag is queued, not lost.
  * In production there is one challenge per container: list_challenges() can
    return a single item, and start_instance() returns where the already-running
    service is (or an empty ConnInfo for a files-only challenge).
"""

from __future__ import annotations

from pathlib import Path

from .base import Challenge, ConnInfo, Platform, PlatformError, SubmitResult

_TODO = "starter-kit adapter not written yet: see harness/platforms/starter_kit.py"


class StarterKitPlatform(Platform):
    def list_challenges(self) -> list[Challenge]:
        # Return the challenge(s) this container was given. Fill at least id and
        # name; category drives which specialist is picked (pwn, rev, crypto,
        # forensics, web, mobile, blockchain, pyjail); description goes into the
        # prompt verbatim; flags_required > 1 for multi-flag challenges.
        raise PlatformError(_TODO)

    def get_challenge(self, challenge_id: str) -> Challenge:
        for c in self.list_challenges():
            if c.id == challenge_id:
                return c
        raise PlatformError(f"unknown challenge: {challenge_id}")

    def download_files(self, challenge_id: str, dest: Path) -> list[Path]:
        # Copy/download the attachments into `dest` and return the paths written.
        # Return [] when the challenge has no files.
        raise PlatformError(_TODO)

    def start_instance(self, challenge_id: str) -> ConnInfo:
        # ConnInfo(url="http://host:port") for web, ConnInfo(host=..., port=...)
        # for a TCP service, ConnInfo() when there is nothing to connect to.
        raise PlatformError(_TODO)

    def get_conn_info(self, challenge_id: str) -> ConnInfo:
        return self.start_instance(challenge_id)

    def submit_flag(self, challenge_id: str, flag: str) -> SubmitResult:
        # SubmitResult(accepted=True/False). Set challenge_solved=True if the
        # grader says the whole challenge is complete (matters for multi-flag).
        raise PlatformError(_TODO)
