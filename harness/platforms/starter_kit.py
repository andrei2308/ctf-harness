"""Adapter for the organizers' starter kit. Fill in when the docs arrive.

Switch it on in contest.env:

    CTF_PLATFORM=harness.platforms.starter_kit:StarterKitPlatform

Then check it BEFORE uploading (it is read-only unless you pass --submit):

    python -m harness.adapter_check
    python -m harness.adapter_check --submit 'CTF{deliberately_wrong}'

Four methods to write: list_challenges, download_files, start_instance and
submit_flag. Retries, flag queueing, budgets and logging sit above this layer.
`harness/platforms/kit.py` has the tested pieces (http_json, http_download,
parse_address, conn_from, describe); `cyberedu_mcp.py` is a complete, working
adapter to copy from, including an MCP stdio transport.

WHAT THE REHEARSAL TAUGHT (each of these cost a solve the first time)

 1. Give the agent everything a player reads. If flags are numbered questions
    with their own text ("What is the WPA2 password?", "format: ctf{sha256}"),
    that text must be in Challenge.description: use kit.describe(). An agent
    that does not know the answer format can solve a challenge and still fail.
 2. flags_required = the number of flags the platform scores, not a guess.
 3. Keep each file's real name and extension (kit.http_download does).
 4. Read the service address in whatever form it comes ("nc HOST PORT",
    "host:port", a URL): kit.conn_from() does, and raises if it cannot. Never
    return an empty ConnInfo for a challenge that has a service.
 5. category decides the specialist. Pass the platform's category label only
    (pwn, rev, crypto, forensics, network, stego, web, mobile, blockchain,
    misc). Event names and skill tags belong in the description as hints.
 6. In submit_flag, a 4xx is the grader's ANSWER: return SubmitResult. Raise
    PlatformError only when there was no answer (transport error, 5xx, 429);
    the submitter retries those. kit.http_json makes exactly this split.
 7. "Already solved" is not "accepted". Return accepted=False with
    already_solved=True only if the platform says THIS value is the solved
    flag; if it answers that way for any value, return a plain rejection.
 8. accepted=True ends the run. Set it only when the grader says so in a field
    you have seen in the docs or in a live response, never from a guess such
    as "the HTTP status was 200".
 9. Secrets (tokens, cookies) come from the environment at run time. Call
    harness.secrets.register(value) so they are scrubbed from tool output, and
    do not leave them in os.environ for the agent's shell to find.
10. One challenge per container: list_challenges() may return a single item.
"""

from __future__ import annotations

import os
from pathlib import Path

from . import kit  # noqa: F401 - the building blocks; see the recipes below
from .base import Challenge, ConnInfo, Platform, PlatformError, SubmitResult

_TODO = "starter-kit adapter not written yet: see harness/platforms/starter_kit.py"


class StarterKitPlatform(Platform):
    def __init__(self) -> None:
        # Example: an HTTP API with a bearer token injected at run time.
        #   self.base = os.environ["CTF_API_URL"].rstrip("/")
        #   token = os.environ.pop("CTF_API_TOKEN")          # pop: not left for the agent
        #   from ..secrets import register; register(token)
        #   self.headers = {"Authorization": f"Bearer {token}"}
        self._cache: dict[str, dict] = {}

    # --- 1. which challenge(s) is this container for -------------------------
    def list_challenges(self) -> list[Challenge]:
        # HTTP:   status, data = kit.http_json("GET", f"{self.base}/challenges", headers=self.headers)
        # env:    one challenge described by variables / a mounted directory
        # Build each with self._challenge(raw).
        raise PlatformError(_TODO)

    def get_challenge(self, challenge_id: str) -> Challenge:
        for c in self.list_challenges():
            if c.id == challenge_id:
                return c
        raise PlatformError(f"unknown challenge: {challenge_id}")

    def _challenge(self, raw: dict) -> Challenge:
        """Translate the platform's challenge record. Adjust the field names."""
        self._cache[str(raw["id"])] = raw
        flags = raw.get("flags") or []
        return Challenge(
            id=str(raw["id"]),
            name=str(raw.get("name") or raw.get("title") or raw["id"]),
            category=str(raw.get("category") or ""),               # lesson 5
            description=kit.describe(                               # lesson 1
                raw.get("description") or "",
                questions=[f for f in flags if isinstance(f, (dict, str))] or None,
                flag_format=str(raw.get("flag_format") or "")),
            flags_required=max(1, len(flags)),                      # lesson 2
            points=raw.get("points"),
        )

    # --- 2. the challenge's files -------------------------------------------
    def download_files(self, challenge_id: str, dest: Path) -> list[Path]:
        # HTTP:    return [kit.http_download(f["url"], dest, f.get("name"), headers=self.headers)
        #                  for f in self._cache[challenge_id].get("files", [])]
        # mounted: copy from the directory the kit names (shutil.copy2), keep names
        # Return [] when the challenge has no files.
        raise PlatformError(_TODO)

    # --- 3. the challenge's service -----------------------------------------
    def start_instance(self, challenge_id: str) -> ConnInfo:
        # The challenge is started for us; this only reports where it is.
        #   addr = os.environ.get("CTF_TARGET") or self._cache[challenge_id].get("address")
        #   if not addr: return ConnInfo()                 # files-only challenge
        #   return kit.conn_from(addr, web=is_web)         # lesson 4: raises if unreadable
        raise PlatformError(_TODO)

    def get_conn_info(self, challenge_id: str) -> ConnInfo:
        return self.start_instance(challenge_id)

    # --- 4. submitting -------------------------------------------------------
    # If each flag is a question with its own id (CyberEDU, the drill's mock),
    # the value must go to the right question: try each question not yet
    # solved, in order, and remember which ones accepted. Space your own calls
    # with kit.Pacer (self._pace = kit.Pacer(1.0); self._pace.wait() before
    # each POST): several calls inside one submit_flag hit a rate limit (429)
    # in the drill. harness/platforms/example_http.py is a worked example.
    def submit_flag(self, challenge_id: str, flag: str) -> SubmitResult:
        # status, data = kit.http_json("POST", f"{self.base}/challenges/{challenge_id}/submit",
        #                              body={"flag": flag}, headers=self.headers)
        # # http_json already raised for no-answer / 5xx / 429 (lesson 6).
        # ok = isinstance(data, dict) and data.get("correct") is True        # lesson 8
        # return SubmitResult(accepted=ok,
        #                     challenge_solved=bool(isinstance(data, dict) and data.get("solved")),
        #                     message=str(data)[:200], raw=data if isinstance(data, dict) else {})
        raise PlatformError(_TODO)


def _env(name: str, default: str = "") -> str:
    """An environment value, stripped. Kept so adapters read settings one way."""
    return os.environ.get(name, default).strip()
