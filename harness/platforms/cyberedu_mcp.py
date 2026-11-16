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
# Flag-retrieval tools. Never called, whatever happens.
FORBIDDEN_TOOLS = frozenset({"cyberedu_get_flag", "cyberedu_get_contest_flag"})
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

    def _call(self, tool: str, args: dict) -> Any:
        if tool in FORBIDDEN_TOOLS:
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
        return self._to_challenge(data)

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
            if dest not in path.parents:
                # The server names the file from a response header; keep it in dest.
                safe = dest / Path(str(media.get("file_name") or path.name)).name
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
        open_ids = [i for i in ids if i not in done]
        if not open_ids:
            return SubmitResult(accepted=False, already_solved=True, challenge_solved=True,
                                message="every flag of this challenge is already accepted")
        last: dict = {}
        for flag_id in open_ids:
            data = self._call(self._tool("submit_Xflag"),
                              self._args(challenge_id, flag_id=str(flag_id), flag_value=flag))
            last = data if isinstance(data, dict) else {"text": str(data)}
            if _accepted(last):
                done.add(flag_id)
                return SubmitResult(accepted=True, challenge_solved=len(done) == len(ids),
                                    message=str(last.get("message", "")), raw=last)
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
    def _to_challenge(it: dict) -> Challenge:
        tags = [t.get("name", "") for t in it.get("tags") or [] if isinstance(t, dict)]
        category = ", ".join(t for t in tags if t)
        flags = it.get("flags")
        return Challenge(
            id=str(it.get("id", "")),
            name=str(it.get("title", "")),
            kind=_kind_from_tags(tags),
            category=category,
            points=_int(it.get("points")),
            description=str(it.get("description") or ""),
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
                            if isinstance(t, dict)]) == ChallengeKind.WEB:
            url = f"http://{address}"
        expires = (status.get("terminate_at") or {}).get("timestamp")
        return ConnInfo(host=host, port=_int(port), url=url,
                        expires_at=float(expires) if expires else None,
                        meta={"service_type": status.get("service_type"),
                              "addresses": status.get("formattedAddresses")})


class _HttpError(Exception):
    def __init__(self, status: int):
        super().__init__(status)
        self.status = status


def _running(status: dict) -> bool:
    return status.get("deploymentStatus") == "running" and bool(status.get("address"))


def _accepted(data: dict) -> bool:
    # Checked against a live submission on 2026-11-16; see the tests.
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
