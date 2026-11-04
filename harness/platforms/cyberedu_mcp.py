"""CyberEDU MCP Platform adapter.

Maps the Platform interface onto the official `CyberEDU-Cyber-Range/cyberedu-mcp`
server (`python -m cyberedu_mcp`, stdio transport). Contest-scoped tool mapping:

    list_challenges  -> cyberedu_list_contests / get_contest_challenge(s)
    get_challenge    -> get_contest_challenge
    download_files   -> download_contest_file
    start_instance   -> start_contest_service (+ status/extend/restart)
    get_conn_info    -> get_contest_service status
    submit_flag      -> submit_contest_flag
    (get_contest_flag exists for flag retrieval where the platform exposes it)

Two cautions this adapter is written around (both OPEN with organizers):

  1. Credentials. Auth is a browser session cookie (`cyberedu_session`), not an
     API token, and it is account-bound. It is read ONLY from the environment
     (`CYBEREDU_SESSION`) and passed to the server subprocess — never read from a
     committed file and never written anywhere this harness ships. For the live
     contest the organizers must inject a scoped contest session into the
     sandbox; we read it from env there too. For LOCAL rehearsal you may let the
     server use its own `~/.cyberedu-mcp/session.json`, which must never be
     committed.

  2. "No internet" vs calling cyber-edu.co. If the sanctioned runtime mounts
     challenges locally, use FilesTargetPlatform instead; do not hardcode a call
     to the public site. This adapter is primarily the local test rig to rehearse
     enumerate->solve->submit against past challenges with your own cookie.

Response shapes vary; extraction below is deliberately tolerant and every
load-bearing field name is marked CONFIRM — verify against the live server before
relying on it in the contest.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any, Protocol

from .base import (Challenge, ChallengeKind, ConnInfo, Platform, PlatformError,
                   SubmitResult)


class McpTransport(Protocol):
    def call_tool(self, name: str, args: dict) -> Any: ...
    def close(self) -> None: ...


class StdioMcpTransport:
    """Runs an MCP stdio server in a background asyncio loop and exposes a sync
    call_tool(). Lazy-imports the `mcp` client so the harness imports without it."""

    def __init__(self, command: str = "python", args: list[str] | None = None,
                 env: dict | None = None):
        self._command = command
        self._args = args or ["-m", "cyberedu_mcp"]
        self._env = {**os.environ, **(env or {})}
        self._loop = None
        self._thread = None
        self._session = None
        self._ready = threading.Event()
        self._err: Exception | None = None
        self._start()

    def _start(self) -> None:
        import asyncio

        def runner() -> None:
            try:
                import mcp  # noqa: F401
                from mcp import ClientSession, StdioServerParameters
                from mcp.client.stdio import stdio_client
            except ImportError as e:  # pragma: no cover
                self._err = PlatformError("mcp client not installed; `pip install mcp`")
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
                        self._session = session
                        self._ready.set()
                        # Keep the session open until close() stops the loop.
                        stop = asyncio.Event()
                        self._stop_event = stop
                        await stop.wait()

            try:
                loop.run_until_complete(main())
            except Exception as e:  # pragma: no cover
                self._err = e
                self._ready.set()

        self._thread = threading.Thread(target=runner, name="mcp-loop", daemon=True)
        self._thread.start()
        self._ready.wait(timeout=30)
        if self._err:
            raise self._err
        if self._session is None:
            raise PlatformError("MCP session failed to initialise within 30s")

    def call_tool(self, name: str, args: dict) -> Any:
        import asyncio
        if self._session is None or self._loop is None:
            raise PlatformError("MCP transport not ready")

        async def _call():
            return await self._session.call_tool(name, args)

        fut = asyncio.run_coroutine_threadsafe(_call(), self._loop)
        try:
            result = fut.result(timeout=120)
        except Exception as e:  # noqa: BLE001
            raise PlatformError(f"MCP call {name} failed: {e}") from e
        return _unwrap(result)

    def close(self) -> None:
        if self._loop and getattr(self, "_stop_event", None):
            self._loop.call_soon_threadsafe(self._stop_event.set)


def _unwrap(result: Any) -> Any:
    """Turn an MCP CallToolResult into plain data. Prefers structured content,
    then JSON-parsed text blocks, then raw text."""
    structured = getattr(result, "structuredContent", None)
    if structured:
        return structured
    content = getattr(result, "content", None) or []
    texts = []
    for block in content:
        if getattr(block, "type", None) == "text":
            texts.append(getattr(block, "text", ""))
    joined = "\n".join(texts)
    try:
        return json.loads(joined)
    except (json.JSONDecodeError, ValueError):
        return {"text": joined}


def _first(d: dict, *keys: str, default=None):
    """Tolerant key lookup across naming variants (CONFIRM real field names)."""
    for k in keys:
        if isinstance(d, dict) and k in d and d[k] is not None:
            return d[k]
    return default


class CyberEduMcpPlatform(Platform):
    def __init__(self, contest_id: str, transport: McpTransport | None = None,
                 session_cookie: str | None = None):
        self.contest_id = contest_id
        cookie = session_cookie or os.environ.get("CYBEREDU_SESSION")
        # The cookie is handed to the server via env only; never persisted here.
        env = {"CYBEREDU_SESSION": cookie} if cookie else {}
        self._transport = transport or StdioMcpTransport(env=env)

    # The tool names below follow the documented server; CONFIRM arg schemas.

    def list_challenges(self) -> list[Challenge]:
        data = self._transport.call_tool(
            "get_contest_challenges", {"contest_id": self.contest_id})
        items = data if isinstance(data, list) else _first(data, "challenges", "items", default=[])
        return [self._to_challenge(it) for it in items]

    def get_challenge(self, challenge_id: str) -> Challenge:
        data = self._transport.call_tool(
            "get_contest_challenge",
            {"contest_id": self.contest_id, "challenge_id": challenge_id})
        return self._to_challenge(data if isinstance(data, dict) else _first(data, "challenge", default={}))

    def download_files(self, challenge_id: str, dest: Path) -> list[Path]:
        dest = Path(dest)
        dest.mkdir(parents=True, exist_ok=True)
        data = self._transport.call_tool(
            "download_contest_file",
            {"contest_id": self.contest_id, "challenge_id": challenge_id})
        # CONFIRM: server may return file paths it wrote, base64 blobs, or a list
        # of {name, content_b64}. Handle the two most likely shapes.
        written: list[Path] = []
        files = _first(data, "files", "attachments", default=[]) if isinstance(data, dict) else data
        for f in files or []:
            if isinstance(f, str) and Path(f).is_file():
                target = dest / Path(f).name
                target.write_bytes(Path(f).read_bytes())
                written.append(target)
            elif isinstance(f, dict):
                name = _first(f, "name", "filename", default="file.bin")
                b64 = _first(f, "content_b64", "base64", "data")
                path = _first(f, "path")
                target = dest / Path(name).name
                if b64:
                    import base64
                    target.write_bytes(base64.b64decode(b64))
                    written.append(target)
                elif path and Path(path).is_file():
                    target.write_bytes(Path(path).read_bytes())
                    written.append(target)
        return written

    def start_instance(self, challenge_id: str) -> ConnInfo:
        data = self._transport.call_tool(
            "start_contest_service",
            {"contest_id": self.contest_id, "challenge_id": challenge_id})
        return self._to_conn(data)

    def get_conn_info(self, challenge_id: str) -> ConnInfo:
        data = self._transport.call_tool(
            "get_contest_service_status",
            {"contest_id": self.contest_id, "challenge_id": challenge_id})
        return self._to_conn(data)

    def extend_instance(self, challenge_id: str) -> ConnInfo:
        data = self._transport.call_tool(
            "extend_contest_service",
            {"contest_id": self.contest_id, "challenge_id": challenge_id})
        return self._to_conn(data)

    def submit_flag(self, challenge_id: str, flag: str) -> SubmitResult:
        data = self._transport.call_tool(
            "submit_contest_flag",
            {"contest_id": self.contest_id, "challenge_id": challenge_id, "flag": flag})
        if not isinstance(data, dict):
            data = {"text": str(data)}
        accepted = bool(_first(data, "correct", "accepted", "success", "solved", default=False))
        already = bool(_first(data, "already_solved", "already", default=False))
        # Whole-challenge completion, if the server distinguishes it from a single
        # correct flag (CONFIRM field names). Falls back to the submitter's count.
        remaining = _first(data, "remaining", "flags_remaining")
        challenge_solved = bool(_first(data, "challenge_solved", "fully_solved",
                                       "completed", default=False)) \
            or (remaining is not None and int(remaining) == 0)
        return SubmitResult(accepted=accepted, already_solved=already,
                            challenge_solved=challenge_solved,
                            message=str(_first(data, "message", "msg", "text", default="")),
                            raw=data)

    def close(self) -> None:
        self._transport.close()

    # --- parsing helpers ---------------------------------------------------

    @staticmethod
    def _to_challenge(it: dict) -> Challenge:
        if not isinstance(it, dict):
            it = {}
        cat = str(_first(it, "category", "type", default=""))
        flags = _first(it, "flags", "flag_slots")
        if isinstance(flags, list) and flags:
            flags_required = len(flags)
        else:
            flags_required = int(_first(it, "flags_required", "num_flags",
                                        "flag_count", default=1) or 1)
        return Challenge(
            id=str(_first(it, "id", "challenge_id", "slug", default="")),
            name=str(_first(it, "name", "title", default="")),
            kind=_kind_from_category(cat),
            category=cat,
            points=_first(it, "points", "score", "value"),
            description=str(_first(it, "description", "desc", "statement", default="")),
            flags_required=flags_required,
            meta=it,
        )

    @staticmethod
    def _to_conn(data: Any) -> ConnInfo:
        if not isinstance(data, dict):
            return ConnInfo()
        conn = _first(data, "connection", "service", default=data)
        if not isinstance(conn, dict):
            conn = data
        return ConnInfo(
            host=_first(conn, "host", "ip", "hostname"),
            port=_first(conn, "port"),
            url=_first(conn, "url", "link"),
            expires_at=_first(conn, "expires_at", "expiry"),
            meta=conn,
        )


def _kind_from_category(category: str) -> ChallengeKind:
    c = category.lower()
    if any(k in c for k in ("web",)):
        return ChallengeKind.WEB
    if any(k in c for k in ("pwn", "exploit", "binary", "misc")):
        return ChallengeKind.INTERACTIVE
    if any(k in c for k in ("rev", "crypto", "forensic", "stego", "osint")):
        return ChallengeKind.STATIC
    return ChallengeKind.UNKNOWN
