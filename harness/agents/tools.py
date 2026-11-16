"""Tools and tool profiles.

A specialist agent acts only through tools. Each tool:
  * declares a JSON-schema signature (vendor-neutral; the inference adapters
    translate it to the backend's tool format),
  * returns a ToolResult whose `output` bytes are REAL output — these become the
    evidence the grounding guard scans. The model never sees a flag we did not
    capture from a tool.

Scope containment is enforced here, not trusted to the prompt: network tools are
bound to the challenge's ConnInfo and refuse any other host. That operationalises
"stay in scope / no internet": a specialist literally cannot open a socket to an
address the platform did not hand it.

Execution of shell commands goes through an Executor so the local dev sandbox
(subprocess in a work dir) can be swapped for a hardened worker container
(read-only rootfs, /input ro, /work rw, no runtime installs) without touching
tool code.
"""

from __future__ import annotations

import abc
import os
import re
import signal
import socket
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from ..platforms.base import ConnInfo

# Default bytes of one result fed back to the model (the evidence store keeps
# everything). Every result is re-sent on every later turn, so this is the single
# biggest lever on token spend. Tune with CTF_TOOL_OUTPUT_BYTES (agents/limits.py).
MAX_TOOL_OUTPUT = 8 * 1024


# Lines worth keeping when summarising long output: flags, secrets, errors,
# addresses, and long base64/hex blobs. Pure heuristic — no LLM call, so it costs
# no tokens (the scored budget), unlike EnIGMA's LM summariser.
_INTEREST_RE = re.compile(
    r"(flag|CTF\{|key|pass(word)?|secret|token|cookie|error|traceback|exception|"
    r"denied|0x[0-9a-fA-F]{5,}|[A-Za-z0-9+/]{24,}={0,2}|[0-9a-fA-F]{32,})", re.I)


def summarize_output(data: bytes, limit: int) -> str:
    """Model-facing view of tool output. Small output passes through; large output
    becomes head + lines-of-interest from the elided middle + tail, sized so the
    whole view stays close to `limit`. The FULL bytes still go to the evidence
    store, so grounding never loses a flag this trims."""
    text = data.decode("utf-8", "replace")
    if len(data) <= limit:
        return text
    head_n, tail_n, mid_budget = limit * 45 // 100, limit * 25 // 100, limit * 30 // 100
    head, tail = text[:head_n], text[-tail_n:]
    seen: set[str] = set()
    interesting: list[str] = []
    used = 0
    for ln in text[head_n:len(text) - tail_n].splitlines():
        s = ln.strip()
        if s and s not in seen and _INTEREST_RE.search(s):
            seen.add(s)
            ln = ln[:200]
            if used + len(ln) + 1 > mid_budget:
                break
            interesting.append(ln)
            used += len(ln) + 1
    mid = ("\n".join(interesting)
           if interesting else "(no lines matched the interest filter)")
    return (f"{head}\n"
            f"…[{len(data)} bytes total; middle elided — lines of interest:]\n"
            f"{mid}\n"
            f"…[tail {tail_n} bytes:]\n{tail}")


@dataclass
class ToolResult:
    name: str
    output: bytes                 # raw bytes produced; recorded as evidence
    source: str                   # evidence label, e.g. "shell:cat flag"
    exit_code: int | None = None
    truncated: bool = False
    error: str = ""               # set when the tool itself failed (not grounds for a flag)
    # False for reference material (knowledge base, summaries) that must NEVER be
    # treated as flag evidence — otherwise an example CTF{...} in a writeup could
    # confabulate a flag.
    is_evidence: bool = True
    meta: dict = field(default_factory=dict)

    def as_text(self, limit: int = MAX_TOOL_OUTPUT) -> str:
        text = summarize_output(self.output, limit)
        if self.error:
            text = f"[tool error: {self.error}]\n" + text
        return text


# --------------------------------------------------------------------------- #
# Execution backends                                                          #
# --------------------------------------------------------------------------- #

class Executor(abc.ABC):
    """Runs shell commands somewhere. Swap LocalExecutor for a container executor
    in production without changing any tool."""

    @abc.abstractmethod
    def run(self, cmd: str, cwd: Path, timeout: float) -> tuple[bytes, int]:
        ...


def agent_argv_prefix() -> list[str]:
    """Prefix for every process the agent drives. Under the egress lockdown
    (harness/egress.py) it drops NET_ADMIN and NET_RAW from the capability
    bounding set, so the agent cannot rewrite the firewall or send raw
    packets, even as root. Empty otherwise."""
    if os.environ.get("CTF_EGRESS_LOCKDOWN", "").strip().lower() in ("1", "true", "yes"):
        return ["setpriv", "--bounding-set=-net_admin,-net_raw", "--"]
    return []


def agent_env(cwd: Path) -> dict[str, str]:
    """Environment for every process the agent can drive (its shell, gdb).

    Inherit the image's PATH so baked-in tools (a venv with pwntools, Ghidra's
    analyzeHeadless, radare2) are reachable, but NOT the rest of the
    environment: the model endpoint credentials must never reach the agent."""
    return {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": str(cwd),
        # Keep tools non-interactive: no pagers, no prompts, dumb term. An
        # autonomous agent must never block a slot waiting for input.
        "PAGER": "cat", "GIT_PAGER": "cat", "TERM": "dumb",
        "DEBIAN_FRONTEND": "noninteractive",
    }


class LocalExecutor(Executor):
    """Runs in a subprocess under `cwd`. For the LOCAL dev loop only.

    Production MUST run commands in an isolated worker container: read-only
    rootfs, writable /work + /artifacts, no network except the challenge target
    and the model endpoint, digest-pinned image, no runtime installs. This class
    deliberately does not pretend to sandbox; it just confines cwd and time.
    """

    def __init__(self, env: dict | None = None):
        self._env = env or {}

    def run(self, cmd: str, cwd: Path, timeout: float) -> tuple[bytes, int]:
        try:
            proc = subprocess.Popen(
                # Not a login shell: `-l` sources /etc/profile, which on Debian
                # and Kali resets PATH (dropping the image's venv and tool dirs),
                # and ~/.profile, which with HOME=cwd is a file in the untrusted
                # challenge directory.
                agent_argv_prefix() + ["bash", "-c", cmd],
                cwd=str(cwd),
                env={**agent_env(cwd), **self._env},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                # Own process group, so a timeout can kill everything the command
                # spawned. Otherwise a timed-out hashcat/angr keeps burning CPU
                # for the rest of the run.
                start_new_session=True,
            )
        except OSError as e:
            return f"[could not start shell: {e}]".encode(), 126
        try:
            out, err = proc.communicate(timeout=timeout)
            return out + err, proc.returncode
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                proc.kill()
            try:
                out, err = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                out, err = b"", b""
            return out + err + f"\n[timed out after {timeout:g}s]".encode(), 124


# --------------------------------------------------------------------------- #
# Tool context + base                                                         #
# --------------------------------------------------------------------------- #

@dataclass
class ToolContext:
    """Everything a tool needs for one challenge. Built by the agent per attempt."""

    challenge_id: str
    work_dir: Path
    executor: Executor
    conn: ConnInfo | None = None       # the only network endpoint tools may reach
    default_timeout: float = 30.0
    # Ceiling on one tool call, and a callback giving the seconds this challenge
    # may still spend on a tool (None = no time cap). Set by the solver, so no
    # tool can run past the budget whatever timeout the model asks for.
    max_timeout: float = 900.0
    time_left: Callable[[], float | None] | None = None
    # Live service sessions, keyed by name, persisted across tool calls so an
    # interactive agent can send/recv over one connection.
    sessions: dict = field(default_factory=dict)

    def clamp(self, requested: float | None, default: float | None = None) -> float:
        """The timeout a tool should actually use: what was asked for (or the
        default), capped by max_timeout and by the time budget left."""
        try:
            t = float(requested) if requested else 0.0
        except (TypeError, ValueError):
            t = 0.0
        if t <= 0:
            t = default if default is not None else self.default_timeout
        t = min(t, self.max_timeout)
        left = self.time_left() if self.time_left else None
        if left is not None:
            t = min(t, left)
        return max(1.0, t)


class Tool(abc.ABC):
    name: str = ""
    description: str = ""

    @abc.abstractmethod
    def input_schema(self) -> dict: ...

    @abc.abstractmethod
    def run(self, args: dict, ctx: ToolContext) -> ToolResult: ...

    def schema(self) -> dict:
        return {"name": self.name, "description": self.description,
                "input_schema": self.input_schema()}


# --------------------------------------------------------------------------- #
# Concrete tools                                                              #
# --------------------------------------------------------------------------- #

_SCANNERS = re.compile(r"\b(nmap|masscan|rustscan|zmap|unicornscan|naabu)\b")
_NC_SCAN = re.compile(r"\b(nc|ncat|netcat)\b[^|;&\n]*\s-[a-zA-Z]*z")


def scope_violation(cmd: str, conn: "ConnInfo | None") -> str | None:
    """Why `cmd` would reach beyond the challenge's own service, or None.

    The target is one host:port. On shared infrastructure (CyberEDU's nodes,
    and likely the contest's) other ports on the same host are other people's
    instances: in rehearsal the agent port-scanned the node and opened them.
    This catches scanners pointed at the target host and the target host named
    with another port. It is a guard, not a firewall: a script that builds the
    address at run time gets past it."""
    if conn is None:
        return None
    host, port = conn.host, conn.port
    if conn.url:
        from urllib.parse import urlsplit
        u = urlsplit(conn.url)
        host = host or u.hostname
        port = port or u.port or (443 if u.scheme == "https" else 80)
    if not host or host not in cmd:
        return None
    if _SCANNERS.search(cmd) or _NC_SCAN.search(cmd):
        return f"port scanning {host} is out of scope"
    for m in re.finditer(re.escape(host) + r"""['"]?\s*[:,\s]\s*['"]?(\d{1,5})\b""", cmd):
        if port and int(m.group(1)) != int(port):
            return f"{host}:{m.group(1)} is not this challenge's service"
    return None


class ShellTool(Tool):
    """Run a shell command in the challenge work dir. The workhorse for static
    challenges (rev/crypto/forensics): file, strings, binwalk, python, ghidra
    headless, volatility, etc. — whatever the base image provides."""

    name = "shell"
    description = ("Run a bash command in the challenge working directory and "
                   "return combined stdout+stderr. Use for file inspection, "
                   "scripts, and analysis tools. No network except the target.")

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "cmd": {"type": "string", "description": "bash command to execute"},
                "timeout": {"type": "number", "description": "seconds (optional)"},
            },
            "required": ["cmd"],
        }

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        cmd = str(args.get("cmd", "")).strip()
        if not cmd:
            return ToolResult(self.name, b"", "shell:empty", error="empty command")
        why = scope_violation(cmd, ctx.conn)
        if why:
            return ToolResult(self.name, b"", "shell:out-of-scope", error=(
                f"refused: {why}. Your only target is the service given in the task; "
                "other ports and hosts belong to other people."))
        timeout = ctx.clamp(args.get("timeout"))
        out, code = ctx.executor.run(cmd, ctx.work_dir, timeout)
        truncated = len(out) > MAX_TOOL_OUTPUT
        label = f"shell:{cmd[:60]}"
        return ToolResult(self.name, out, label, exit_code=code, truncated=truncated)


class ServiceConnectTool(Tool):
    """Open (or reuse) a TCP connection to the challenge's bound target.

    Interactive/pwn work needs a real send/recv loop, not one-shot bash. The
    connection is stored in ctx.sessions so send/recv tools share it. The host
    and port come from ConnInfo only — any other address is refused."""

    name = "connect"
    description = ("Open a TCP connection to the challenge service (the platform-"
                   "provided target). Reuses an existing connection if open.")

    def input_schema(self) -> dict:
        return {"type": "object", "properties": {
            "timeout": {"type": "number", "description": "connect timeout seconds"}}}

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        if not ctx.conn or not ctx.conn.host or not ctx.conn.port:
            return ToolResult(self.name, b"", "connect:none",
                              error="no target host/port for this challenge")
        sess = ctx.sessions.get("svc")
        if sess is not None and not getattr(sess, "_closed", True):
            return ToolResult(self.name, b"", "connect:reuse",
                              meta={"host": ctx.conn.host, "port": ctx.conn.port})
        timeout = ctx.clamp(args.get("timeout"))
        try:
            sock = socket.create_connection((ctx.conn.host, ctx.conn.port), timeout=timeout)
        except OSError as e:
            return ToolResult(self.name, b"", "connect:fail", error=str(e))
        ctx.sessions["svc"] = _SocketSession(sock)
        return ToolResult(self.name, b"", "connect:ok",
                          meta={"host": ctx.conn.host, "port": ctx.conn.port})


class ServiceSendTool(Tool):
    name = "send"
    description = "Send bytes to the connected service, then read the reply."

    def input_schema(self) -> dict:
        return {"type": "object", "properties": {
            "data": {"type": "string", "description": "payload; \\n, \\x41 escapes honoured"},
            "newline": {"type": "boolean", "description": "append newline (default true)"},
            "recv_timeout": {"type": "number"},
        }, "required": ["data"]}

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        sess = ctx.sessions.get("svc")
        if sess is None or getattr(sess, "_closed", True):
            return ToolResult(self.name, b"", "send:noconn",
                              error="not connected; call connect first")
        payload = _unescape(str(args.get("data", "")))
        if args.get("newline", True):
            payload += b"\n"
        timeout = ctx.clamp(args.get("recv_timeout"), 5.0)
        try:
            sess.send(payload)
            reply = sess.recv(timeout=timeout)
        except OSError as e:
            return ToolResult(self.name, b"", "send:fail", error=str(e))
        return ToolResult(self.name, reply, "svc:recv")


class ServiceRecvTool(Tool):
    name = "recv"
    description = "Read any pending bytes from the connected service."

    def input_schema(self) -> dict:
        return {"type": "object", "properties": {"recv_timeout": {"type": "number"}}}

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        sess = ctx.sessions.get("svc")
        if sess is None or getattr(sess, "_closed", True):
            return ToolResult(self.name, b"", "recv:noconn", error="not connected")
        timeout = ctx.clamp(args.get("recv_timeout"), 5.0)
        try:
            data = sess.recv(timeout=timeout)
        except OSError as e:
            return ToolResult(self.name, b"", "recv:fail", error=str(e))
        return ToolResult(self.name, data, "svc:recv")


class HttpTool(Tool):
    """Minimal HTTP client bound to the challenge's web target.

    Refuses any URL whose origin differs from the ConnInfo.url the platform
    provided — a specialist cannot browse the internet, only the target app."""

    name = "http"
    description = ("Make an HTTP request to the challenge web target. Path is "
                   "joined onto the provided base URL; other hosts are refused.")

    def input_schema(self) -> dict:
        return {"type": "object", "properties": {
            "method": {"type": "string", "enum": ["GET", "POST", "PUT", "HEAD", "OPTIONS"]},
            "path": {"type": "string", "description": "path+query, joined onto the target base URL"},
            "headers": {"type": "object"},
            "body": {"type": "string"},
        }, "required": ["path"]}

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        if not ctx.conn or not ctx.conn.url:
            return ToolResult(self.name, b"", "http:none", error="no web target for this challenge")
        try:
            import requests
            from urllib.parse import urljoin, urlparse
        except ImportError:
            return ToolResult(self.name, b"", "http:deps", error="requests not installed")
        base = ctx.conn.url
        url = urljoin(base, str(args.get("path", "")))
        if urlparse(url).netloc != urlparse(base).netloc:
            return ToolResult(self.name, b"", "http:scope",
                              error=f"refused: {url} is outside target {base}")
        method = str(args.get("method", "GET")).upper()
        try:
            resp = requests.request(method, url, headers=args.get("headers") or {},
                                    data=args.get("body"), timeout=ctx.clamp(None),
                                    allow_redirects=True)
        except Exception as e:  # noqa: BLE001 - surface any client error to the agent
            return ToolResult(self.name, b"", "http:fail", error=str(e))
        head = f"HTTP {resp.status_code}\n".encode() + \
               "\n".join(f"{k}: {v}" for k, v in resp.headers.items()).encode() + b"\n\n"
        return ToolResult(self.name, head + resp.content, f"http:{method} {args.get('path')}",
                          meta={"status": resp.status_code})


class WriteFileTool(Tool):
    """Write a file into the work dir (e.g. an exploit script the agent authored,
    then run via shell). Confined to the work dir."""

    name = "write_file"
    description = "Write a text file into the challenge working directory."

    def input_schema(self) -> dict:
        return {"type": "object", "properties": {
            "path": {"type": "string"}, "content": {"type": "string"}},
            "required": ["path", "content"]}

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        rel = Path(str(args.get("path", ""))).as_posix().lstrip("/")
        dest = (ctx.work_dir / rel).resolve()
        try:
            dest.relative_to(ctx.work_dir.resolve())
        except ValueError:
            return ToolResult(self.name, b"", "write:scope", error="path escapes work dir")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(str(args.get("content", "")), encoding="utf-8")
        return ToolResult(self.name, f"wrote {rel} ({dest.stat().st_size} bytes)".encode(),
                          f"write:{rel}")


# --------------------------------------------------------------------------- #
# Socket session helper                                                       #
# --------------------------------------------------------------------------- #

class _SocketSession:
    def __init__(self, sock: socket.socket):
        self._sock = sock
        self._closed = False

    def send(self, data: bytes) -> None:
        self._sock.sendall(data)

    def recv(self, timeout: float = 5.0, bufsize: int = 65536) -> bytes:
        self._sock.settimeout(timeout)
        chunks: list[bytes] = []
        try:
            while True:
                part = self._sock.recv(bufsize)
                if not part:
                    self._closed = True
                    break
                chunks.append(part)
                if len(part) < bufsize:
                    break
        except socket.timeout:
            pass
        return b"".join(chunks)

    def close(self) -> None:
        self._closed = True
        try:
            self._sock.close()
        except OSError:
            pass


def _unescape(s: str) -> bytes:
    """Decode \\n \\t \\xNN style escapes into raw bytes for service payloads."""
    try:
        return s.encode("utf-8").decode("unicode_escape").encode("latin-1")
    except (UnicodeDecodeError, UnicodeEncodeError):
        return s.encode("utf-8", "surrogatepass")


# --------------------------------------------------------------------------- #
# Tool profiles                                                               #
# --------------------------------------------------------------------------- #

class SubmitFlagTool(Tool):
    """Submit an answer that is not flag-shaped (a password, a name, a number).

    CTF{...} flags are submitted automatically the moment they appear in tool
    output. Some challenges ask for something else: in rehearsal the agent
    cracked a WPA2 handshake in 49 seconds (aircrack-ng: KEY FOUND! [ s3cretpass ])
    and then repeated the password for the rest of its budget, because nothing
    could submit it. The solver handles this tool (it owns the submitter and
    the evidence), so run() is never reached in a solve."""

    name = "submit_flag"
    description = ("Submit the challenge's answer when it is NOT in the usual flag "
                   "format, e.g. a password or value the challenge asks for. Give it "
                   "exactly as it appeared in real tool output. CTF{...}-style flags are "
                   "submitted automatically; you do not need this tool for them.")

    def input_schema(self) -> dict:
        return {"type": "object", "properties": {
            "flag": {"type": "string", "description": "the exact answer"},
        }, "required": ["flag"]}

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        return ToolResult(self.name, b"", "submit_flag:unhandled",
                          error="submit_flag is handled by the solver")


@dataclass
class ToolProfile:
    """A named set of tools handed to a specialist."""

    name: str
    tools: list[Tool]

    def schemas(self) -> list[dict]:
        return [t.schema() for t in self.tools]

    def by_name(self) -> dict[str, Tool]:
        return {t.name: t for t in self.tools}


def static_profile() -> ToolProfile:
    """Type A — static files: rev, crypto, forensics, stego, misc."""
    return ToolProfile("static", [ShellTool(), WriteFileTool()])


def interactive_profile() -> ToolProfile:
    """Type B — a live service: pwn, interactive crypto/misc. Real send/recv plus
    shell (to run pwntools/gdb-driven exploit scripts the agent writes)."""
    return ToolProfile("interactive", [
        ShellTool(), WriteFileTool(),
        ServiceConnectTool(), ServiceSendTool(), ServiceRecvTool(),
    ])


def web_profile() -> ToolProfile:
    """Type C — an HTTP target."""
    return ToolProfile("web", [ShellTool(), WriteFileTool(), HttpTool()])
