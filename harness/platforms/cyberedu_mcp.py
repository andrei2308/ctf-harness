"""CyberEDU platform adapter, through the official MCP server.

The server is `github.com/CyberEDU-Cyber-Range/cyberedu-mcp` (`python -m
cyberedu_mcp`, stdio). It exposes every `CyberEduClient` method as a tool named
`cyberedu_<method>`. Tool names, arguments and response shapes below were read
from that source and checked against the live API on 2026-11-16.

Two modes:
  * practice catalogue (default): `cyberedu_get_challenge`, `_download_file`,
    `_start_service`, `_get_service_status`, `_extend_service`, `_submit_flag`.
  * contest (`contest_slug` set): the `_contest_` variants of the same calls,
    which take `contest_slug`. Written from the server source; not yet run
    against a live contest.

Rules this adapter is built around:
  * Never read a flag. The server has `get_flag` / `get_contest_flag`; they are
    refused here (`FORBIDDEN_TOOLS`) whatever the caller asks.
  * The cookie is read from CYBEREDU_SESSION_COOKIE (the variable the server
    reads), removed from this process's environment, registered with
    harness.secrets for scrubbing, and passed only to the server subprocess,
    whose environment is otherwise minimal. The server gets a private, empty
    HOME, so it does not persist the cookie to ~/.cyberedu-mcp/session.json.
  * Only the harness talks to the server. The agent's tools never see it.
  * The server cannot stop an instance (it has start, status, extend and
    restart, no stop). An instance runs until CyberEDU's lifetime ends it
    (60 minutes as observed). `close()` says so in the log.

A challenge's flags are questions with ids (`flags: [{"id": 4744}]`); a
submission names the flag id. A candidate is tried against each flag id not yet
accepted, in order, until one accepts it.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Protocol

from .. import secrets
from .base import (Challenge, ChallengeKind, ConnInfo, Platform, PlatformError,
                   SubmitResult)

COOKIE_ENV = "CYBEREDU_SESSION_COOKIE"
# get_flag returns a flag's QUESTION (what a player sees on the site: "What is
# the flag", "ctf{sha256(flag)}") but also fields that are not the agent's to
# see: `value` (the account's last submitted answer), `rejection_reason`, and
# `hints` (unlocking one costs points). It is called only through _question(),
# which keeps QUESTION_FIELDS and nothing else; any other use is refused.
FORBIDDEN_TOOLS = frozenset({"cyberedu_get_flag", "cyberedu_get_contest_flag"})
QUESTION_FIELDS = ("question", "description", "type", "options", "multiple", "limit", "found")
INSTANCE_POLL_SECONDS = 5.0


class McpTransport(Protocol):
    def call_tool(self, name: str, args: dict) -> Any: ...
    def close(self) -> None: ...


class StdioMcpTransport:
    """Runs an MCP stdio server in a background asyncio loop and exposes a sync
    call_tool(). Lazy-imports the `mcp` client so the harness imports without it."""

    def __init__(self, command: str, args: list[str], env: dict[str, str],
                 timeout: float = 120.0):
        self._command = command
        self._args = args
        self._env = env
        self._timeout = timeout
        self._loop = None
        self._session = None
        self._stop_event = None
        self._ready = threading.Event()
        self._err: Exception | None = None
        self._start()

    def _start(self) -> None:
        import asyncio

        def runner() -> None:
            try:
                from mcp import ClientSession, StdioServerParameters
                from mcp.client.stdio import stdio_client
            except ImportError:
                self._err = PlatformError("mcp client not installed (pip install 'mcp<2')")
                self._ready.set()
                return
            loop = asyncio.new_event_loop()
            self._loop = loop
            asyncio.set_event_loop(loop)

            async def main() -> None:
                params = StdioServerParameters(command=self._command, args=self._args,
                                               env=self._env)
                async with stdio_client(params) as (read, write):
                    async with ClientSession(read, write) as session:
                        await session.initialize()
                        self._stop_event = asyncio.Event()
                        self._session = session
                        self._ready.set()
                        await self._stop_event.wait()

            try:
                loop.run_until_complete(main())
            except Exception as e:  # noqa: BLE001
                self._err = PlatformError(f"MCP server failed: {e}")
                self._ready.set()

        threading.Thread(target=runner, name="mcp-loop", daemon=True).start()
        self._ready.wait(timeout=60)
        if self._err:
            raise self._err
        if self._session is None:
            raise PlatformError("MCP session did not initialise within 60s")

    def call_tool(self, name: str, args: dict) -> Any:
        import asyncio
        if self._session is None or self._loop is None:
            raise PlatformError("MCP transport not ready")
        fut = asyncio.run_coroutine_threadsafe(self._session.call_tool(name, args), self._loop)
        try:
            result = fut.result(timeout=self._timeout)
        except Exception as e:  # noqa: BLE001
            raise PlatformError(f"MCP call {name} failed: {e}") from e
        return _unwrap(result)

    def close(self) -> None:
        if self._loop and self._stop_event is not None:
            self._loop.call_soon_threadsafe(self._stop_event.set)


def _unwrap(result: Any) -> Any:
    """CallToolResult -> data. The server returns one text block of JSON."""
    texts = [getattr(b, "text", "") for b in (getattr(result, "content", None) or [])
             if getattr(b, "type", None) == "text"]
    joined = "\n".join(texts)
    try:
        return json.loads(joined)
    except (json.JSONDecodeError, ValueError):
        return {"text": joined}


class CyberEduMcpPlatform(Platform):
    def __init__(self, tenant: str = "cyberedu", contest_slug: str | None = None,
                 transport: McpTransport | None = None,
                 session_cookie: str | None = None,
                 instance_wait: float = 240.0):
        self.tenant = tenant
        self.contest_slug = contest_slug or None
        self.instance_wait = instance_wait
        self._challenges: dict[str, dict] = {}     # raw detail by id
        self._accepted: dict[str, set[int]] = {}   # flag ids accepted, by challenge
        self._closed: dict[str, set[int]] = {}     # flag ids solved before this run
        self._questions: dict[str, list[dict]] = {}  # per flag, QUESTION_FIELDS only
        self._limits: dict[str, dict[int, int]] = {}  # flag id -> attempt limit (0 = none)
        self._tries: dict[str, dict[int, int]] = {}   # flag id -> submissions this run
        self._started: set[str] = set()
        self._home: str | None = None
        if transport is None:
            # Take the cookie out of this process's environment, so nothing
            # started later can inherit it.
            cookie = session_cookie or os.environ.pop(COOKIE_ENV, None)
            if not cookie:
                raise PlatformError(f"{COOKIE_ENV} is not set")
            secrets.register(cookie)
            self._home = tempfile.mkdtemp(prefix="cyberedu-mcp-")
            env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": self._home,
                   COOKIE_ENV: cookie, "CYBEREDU_TENANT": tenant}
            python = os.environ.get("CTF_CYBEREDU_MCP_PYTHON", "python")
            transport = StdioMcpTransport(python, ["-m", "cyberedu_mcp"], env)
        self._t = transport

    # --- transport -----------------------------------------------------------

    def _call(self, tool: str, args: dict, _question: bool = False) -> Any:
        if tool in FORBIDDEN_TOOLS and not _question:
            raise PlatformError(f"refusing flag-retrieval tool {tool}")
        data = self._t.call_tool(tool, args)
        if isinstance(data, dict) and "error" in data:
            status = data.get("status_code")
            raise PlatformError(f"{tool}: {data.get('error')}"
                                + (f" {status}" if status else "")
                                + f": {str(data.get('response') or data.get('message'))[:200]}",
                                ) from None if status is None else _HttpError(status)
        return data

    def _tool(self, base: str) -> str:
        return f"cyberedu_{base.replace('X', 'contest_' if self.contest_slug else '')}"

    def _args(self, challenge_id: str, **extra) -> dict:
        args = {"challenge_id": challenge_id, **extra}
        if self.contest_slug:
            args["contest_slug"] = self.contest_slug
        return args

    # --- Platform ------------------------------------------------------------

    def list_challenges(self) -> list[Challenge]:
        if self.contest_slug:
            data = self._call("cyberedu_get_contest", {"contest_slug": self.contest_slug})
            items = data.get("challenges", []) if isinstance(data, dict) else data
        else:
            items = self._call("cyberedu_list_challenges", {})
        return [self._to_challenge(it) for it in (items or []) if isinstance(it, dict)]

    def get_challenge(self, challenge_id: str) -> Challenge:
        data = self._call(self._tool("get_Xchallenge"), self._args(challenge_id))
        if not isinstance(data, dict) or not data.get("id"):
            raise PlatformError(f"no such challenge: {challenge_id}")
        self._challenges[challenge_id] = data
        # Each flag's question carries what a player is told on the site, often
        # the answer's format ("ctf{sha256(flag)}"); without it the agent cracked
        # a password and could not know how to hand it in.
        questions = []
        if data.get("is_subscribed") or self.contest_slug:
            for f in data.get("flags") or []:
                try:
                    q = self._question(challenge_id, int(f["id"]))
                except PlatformError:
                    q = {}
                questions.append(q)
                if q.get("found"):
                    self._closed.setdefault(challenge_id, set()).add(int(f["id"]))
                if q.get("limit"):
                    self._limits.setdefault(challenge_id, {})[int(f["id"])] = int(q["limit"])
        self._questions[challenge_id] = questions
        return self._to_challenge(data, questions)

    def _question(self, challenge_id: str, flag_id: int) -> dict:
        """A flag's question, reduced to QUESTION_FIELDS. The only use of the
        get_flag tool."""
        tool = "cyberedu_get_contest_flag" if self.contest_slug else "cyberedu_get_flag"
        data = self._call(tool, self._args(challenge_id, flag_id=str(flag_id)), _question=True)
        if not isinstance(data, dict):
            return {}
        return {k: data[k] for k in QUESTION_FIELDS if k in data}

    def _detail(self, challenge_id: str) -> dict:
        if challenge_id not in self._challenges:
            self.get_challenge(challenge_id)
        return self._challenges[challenge_id]

    def download_files(self, challenge_id: str, dest: Path) -> list[Path]:
        detail = self._detail(challenge_id)
        if not self.contest_slug and not detail.get("is_subscribed"):
            # Subscribing unlocks files and flags, and may cost credits: a
            # decision for the account owner, never made here.
            raise PlatformError("not subscribed to this challenge; subscribe on the site first")
        dest = Path(dest).resolve()
        dest.mkdir(parents=True, exist_ok=True)
        written: list[Path] = []
        for media in detail.get("media") or []:
            data = self._call(self._tool("download_Xfile"),
                              self._args(challenge_id, file_id=str(media["id"]),
                                         save_path=str(dest)))
            path = Path(str(data.get("path", ""))).resolve() if isinstance(data, dict) else None
            if not path or not path.is_file():
                raise PlatformError(f"download of file {media.get('id')} returned no file")
            # The server names the file from a response header that the API does
            # not send, so files arrived as "downloaded_file". The challenge
            # lists the real name; its extension is a clue. Keep it in dest.
            want = Path(str(media.get("file_name") or path.name)).name or path.name
            safe = dest / want
            if path != safe:
                if safe.exists():
                    safe = dest / f"{media.get('id')}-{want}"
                shutil.move(str(path), safe)
                path = safe
            written.append(path)
        return written

    def start_instance(self, challenge_id: str) -> ConnInfo:
        status = self._status(challenge_id)
        if status is None:
            return ConnInfo()                     # no service: files only
        if not _running(status):
            self._call(self._tool("start_Xservice"), self._args(challenge_id))
            self._started.add(challenge_id)
            deadline = time.monotonic() + self.instance_wait
            while not _running(status):
                if time.monotonic() > deadline:
                    raise PlatformError(f"instance not running after {self.instance_wait:.0f}s: "
                                        f"{status.get('deploymentStatus')}")
                time.sleep(INSTANCE_POLL_SECONDS)
                status = self._status(challenge_id) or {}
        return self._to_conn(status, self._detail(challenge_id))

    def get_conn_info(self, challenge_id: str) -> ConnInfo:
        status = self._status(challenge_id)
        if status is None or not _running(status):
            return ConnInfo()
        return self._to_conn(status, self._detail(challenge_id))

    def extend_instance(self, challenge_id: str) -> ConnInfo:
        self._call(self._tool("extend_Xservice"), self._args(challenge_id))
        return self.get_conn_info(challenge_id)

    def submit_flag(self, challenge_id: str, flag: str) -> SubmitResult:
        detail = self._detail(challenge_id)
        ids = [int(f["id"]) for f in detail.get("flags") or [] if "id" in f]
        if not ids:
            raise PlatformError("challenge lists no flag ids to submit against")
        done = self._accepted.setdefault(challenge_id, set())
        closed = self._closed.setdefault(challenge_id, set())
        limits = self._limits.get(challenge_id, {})
        tries = self._tries.setdefault(challenge_id, {})
        open_ids = [i for i in ids if i not in done and i not in closed
                    and not (limits.get(i) and tries.get(i, 0) >= limits[i])]
        if not open_ids:
            # Not already_solved: the submitter would count this candidate as
            # accepted. The account solved these flags before the run; that is
            # no verdict on what the agent found.
            return SubmitResult(accepted=False,
                                message="no open flag left on this challenge "
                                        "(solved on this account before the run)")
        last: dict = {}
        for flag_id in open_ids:
            tries[flag_id] = tries.get(flag_id, 0) + 1
            try:
                data = self._call(self._tool("submit_Xflag"),
                                  self._args(challenge_id, flag_id=str(flag_id), flag_value=flag))
            except PlatformError as e:
                status = getattr(e.__cause__, "status", None)
                if status is None or status >= 500:
                    raise                      # transport or server error: retryable
                # A 4xx is the grader's answer, not an outage: never retried.
                # 403 "Challenge already solved" comes back for ANY value sent to
                # a flag this account already solved (seen live on biscuiti), so it
                # says nothing about this candidate: close that id, try the next.
                if status == 403 and "already solved" in str(e).lower():
                    closed.add(flag_id)
                    continue
                last = {"status": "rejected", "http_status": status, "message": str(e)[:200]}
                continue
            last = data if isinstance(data, dict) else {"text": str(data)}
            if _accepted(last):
                done.add(flag_id)
                return SubmitResult(accepted=True, challenge_solved=len(done) == len(ids),
                                    message=str(last.get("message", "")), raw=last)
        if not last:            # every id we tried was already solved before this run
            return SubmitResult(accepted=False,
                                message="flag(s) already solved on this account before this run")
        return SubmitResult(accepted=False, message=str(last.get("message", "")), raw=last)

    def close(self) -> None:
        try:
            self._t.close()
        finally:
            if self._home:
                shutil.rmtree(self._home, ignore_errors=True)

    @property
    def started_instances(self) -> set[str]:
        """Instances this adapter started. The server cannot stop them; they
        end at CyberEDU's lifetime."""
        return set(self._started)

    # --- helpers -------------------------------------------------------------

    def _status(self, challenge_id: str) -> dict | None:
        """Service status, or None when the challenge has no service (the API
        answers 400 for a files-only challenge)."""
        try:
            data = self._call(self._tool("get_Xservice_status"), self._args(challenge_id))
        except PlatformError as e:
            if isinstance(e.__cause__, _HttpError) and e.__cause__.status == 400:
                return None
            raise
        return data if isinstance(data, dict) else {}

    @staticmethod
    def _to_challenge(it: dict, questions: list[dict] | None = None) -> Challenge:
        all_tags = [t for t in it.get("tags") or [] if isinstance(t, dict) and t.get("name")]
        # Only 'default' tags are categories (Web, Pwn, Network, ...). The rest
        # are the event ('collection') and skill tags ('cwe', 'mittre', 'wstg'):
        # good hints, bad routing keys (fair-dice's CWE "...from Previous
        # Values" contains "rev" and went to the rev specialist).
        cats = [t["name"] for t in all_tags if t.get("type", "default") == "default"]
        hints = [t["name"] for t in all_tags if t.get("type", "default") != "default"]
        tags = cats or [t["name"] for t in all_tags]
        category = ", ".join(tags)
        flags = it.get("flags")
        description = str(it.get("description") or "")
        if hints:
            description += "\n\nTags: " + "; ".join(hints)
        if questions and any(q.get("question") or q.get("description") for q in questions):
            description += "\n\n" + _questions_text(questions)
        return Challenge(
            id=str(it.get("id", "")),
            name=str(it.get("title", "")),
            kind=_kind_from_tags(tags),
            category=category,
            points=_int(it.get("points")),
            description=description,
            flags_required=len(flags) if isinstance(flags, list) and flags else 1,
            meta={k: it.get(k) for k in ("difficulty", "is_subscribed", "is_owned", "tenant")},
        )

    @staticmethod
    def _to_conn(status: dict, detail: dict) -> ConnInfo:
        address = str(status.get("address") or status.get("formattedAddress") or "")
        host, _, port = address.rpartition(":")
        if not host:
            return ConnInfo()
        url = None
        if _kind_from_tags([t.get("name", "") for t in detail.get("tags") or []
                            if isinstance(t, dict) and t.get("type", "default") == "default"]
                           ) == ChallengeKind.WEB:
            url = f"http://{address}"
        expires = (status.get("terminate_at") or {}).get("timestamp")
        return ConnInfo(host=host, port=_int(port), url=url,
                        expires_at=float(expires) if expires else None,
                        meta={"service_type": status.get("service_type"),
                              "addresses": status.get("formattedAddresses")})


def _questions_text(questions: list[dict]) -> str:
    """The flags' questions as the site shows them, for the agent's prompt."""
    lines = ["Flags to find (one answer each, in order):"]
    for n, q in enumerate(questions, 1):
        text = " ".join(str(q.get(k) or "").strip() for k in ("question",)).strip() or "flag"
        line = f"{n}. {text}"
        if q.get("description"):
            line += f" (format: {str(q['description']).strip()})"
        if q.get("options"):
            line += " Options: " + "; ".join(str(o.get("value", o) if isinstance(o, dict) else o)
                                            for o in q["options"])
        if q.get("found"):
            line += " [already solved on this account]"
        lines.append(line)
    return "\n".join(lines)


class _HttpError(Exception):
    def __init__(self, status: int):
        super().__init__(status)
        self.status = status


def _running(status: dict) -> bool:
    return status.get("deploymentStatus") == "running" and bool(status.get("address"))


def _accepted(data: dict) -> bool:
    # Live, 2026-11-16: a correct flag on wifi-get-me came back accepted through
    # this check; a wrong value came back not accepted. A flag the account
    # solved earlier answers HTTP 403 instead (handled in submit_flag).
    return str(data.get("status", "")).lower() == "success"


def _int(v: Any) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _kind_from_tags(tags: list[str]) -> ChallengeKind:
    t = " ".join(tags).lower()
    if "web" in t:
        return ChallengeKind.WEB
    if any(k in t for k in ("pwn", "exploit", "network")):
        return ChallengeKind.INTERACTIVE
    if any(k in t for k in ("reverse", "crypto", "forensic", "stego", "osint", "misc")):
        return ChallengeKind.STATIC
    return ChallengeKind.UNKNOWN
