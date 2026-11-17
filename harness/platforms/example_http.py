"""Worked example: an adapter written from starter_kit.py against a mock kit.

This is the result of the adapter drill (CLAUDE_CODE_FINAL.md task 7): an HTTP
API with a bearer token, one challenge with a file, a service given as
"nc HOST PORT", two flags as numbered questions, and a submit endpoint that
answers 200 correct / 400 wrong / 429 too fast. The mock lives in
tests/mock_kit.py. On the day, copy the shape, not the field names.

    CTF_PLATFORM=harness.platforms.example_http:ExampleHttpPlatform
    CTF_API_URL=http://127.0.0.1:8080   CTF_API_TOKEN=...   (token: env only)
"""

from __future__ import annotations

import os
from pathlib import Path

from . import kit
from ..secrets import register
from .base import Challenge, ConnInfo, Platform, PlatformError, SubmitResult


class ExampleHttpPlatform(Platform):
    def __init__(self) -> None:
        self.base = os.environ.get("CTF_API_URL", "").rstrip("/")
        token = os.environ.pop("CTF_API_TOKEN", "")          # pop: not left for the agent
        if not self.base or not token:
            raise PlatformError("CTF_API_URL and CTF_API_TOKEN must be set")
        register(token)                                       # scrubbed from tool output
        self.headers = {"Authorization": f"Bearer {token}"}
        self._cache: dict[str, dict] = {}
        self._pace = kit.Pacer(1.1)                           # the kit answers 429 within 1 s

    # --- 1. which challenge(s) ----------------------------------------------
    def list_challenges(self) -> list[Challenge]:
        status, data = kit.http_json("GET", f"{self.base}/api/v1/challenge", headers=self.headers)
        if status != 200 or not isinstance(data, dict) or "challenge" not in data:
            raise PlatformError(f"challenge list: HTTP {status}: {str(data)[:200]}")
        return [self._challenge(data["challenge"])]           # one per container

    def get_challenge(self, challenge_id: str) -> Challenge:
        for c in self.list_challenges():
            if c.id == challenge_id:
                return c
        raise PlatformError(f"unknown challenge: {challenge_id}")

    def _challenge(self, raw: dict) -> Challenge:
        cid = str(raw["slug"])
        self._cache[cid] = raw
        questions = [{"question": q.get("text"), "description": q.get("format")}
                     for q in raw.get("questions") or []]
        return Challenge(
            id=cid,
            name=str(raw.get("title") or cid),
            category=str(raw.get("type") or ""),              # the category label only
            description=kit.describe(raw.get("body") or "", questions=questions or None),
            flags_required=max(1, len(questions)),
            points=raw.get("points"),
        )

    def _raw(self, challenge_id: str) -> dict:
        if challenge_id not in self._cache:
            self.list_challenges()
        return self._cache[challenge_id]

    # --- 2. files ----------------------------------------------------------
    def download_files(self, challenge_id: str, dest: Path) -> list[Path]:
        return [kit.http_download(f"{self.base}{a['href']}", dest, a.get("name"), headers=self.headers)
                for a in self._raw(challenge_id).get("attachments") or []]

    # --- 3. service ----------------------------------------------------------
    def start_instance(self, challenge_id: str) -> ConnInfo:
        addr = self._raw(challenge_id).get("endpoint")
        if not addr:
            return ConnInfo()                                 # files-only challenge
        return kit.conn_from(addr)                            # raises if unreadable

    def get_conn_info(self, challenge_id: str) -> ConnInfo:
        return self.start_instance(challenge_id)

    # --- 4. submit ----------------------------------------------------------
    def submit_flag(self, challenge_id: str, flag: str) -> SubmitResult:
        """Each flag is a question with its own id; the answer has to go to the
        right one. A value is tried against each question not yet solved, in
        order, until one accepts it."""
        done = self._cache.setdefault(f"{challenge_id}#solved", {})
        open_q = [q for q in self._raw(challenge_id).get("questions") or [] if q["qid"] not in done]
        last: object = None
        for q in open_q:
            self._pace.wait()
            status, data = kit.http_json("POST", f"{self.base}/api/v1/answer",
                                         body={"qid": q["qid"], "answer": flag}, headers=self.headers)
            last = data
            # A 4xx came back as an answer; 5xx/429 raised inside http_json.
            if isinstance(data, dict) and data.get("result") == "correct":   # seen in the docs
                done[q["qid"]] = True
                return SubmitResult(accepted=True, challenge_solved=bool(data.get("all_solved")),
                                    message=str(data)[:200], raw=data)
        return SubmitResult(accepted=False, message=str(last)[:200],
                            raw=last if isinstance(last, dict) else {})
