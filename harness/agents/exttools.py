"""Wrappers for the heavyweight analysis tools: gdb/pwndbg, Ghidra headless,
Volatility, and a capability probe.

The ShellTool can already run any of these — so why wrap them?

  1. Autonomy safety. An autonomous agent must never launch something that waits
     for interactive input (an interactive gdb, a pager, a REPL): it blocks the
     slot until the timeout. These wrappers force non-interactive/batch mode.
  2. Fiddly invocation. Ghidra headless and Volatility have long, error-prone
     command lines; a wrapper gets them right every time and saves the model from
     burning tokens rediscovering the incantation.
  3. Honest degradation. If a tool is not installed in the sandbox, the wrapper
     says so clearly (as a tool error, never a fabricated result), and the
     capability probe tells each specialist up front what it actually has.

Everything these tools emit is REAL output and flows into the EvidenceStore, so
a flag found via decompilation or a memory dump grounds exactly like any other.
"""

from __future__ import annotations

import os
import select
import shlex
import subprocess
import time
from pathlib import Path

from .tools import MAX_TOOL_OUTPUT, Tool, ToolContext, ToolResult

# The analysis tools we probe for and advertise to specialists. Binaries checked
# with `command -v`; python modules with an import.
_PROBE_BINARIES = [
    # rev
    "gdb", "gdb-multiarch", "objdump", "readelf", "nm", "strings", "file", "xxd",
    "ltrace", "strace", "radare2", "r2", "analyzeHeadless", "upx", "yara", "floss",
    "capa", "uncompyle6", "qemu-aarch64-static",
    # pwn
    "checksec", "patchelf", "pwninit", "ropper", "ROPgadget", "one_gadget",
    "seccomp-tools",
    # forensics
    "binwalk", "foremost", "scalpel", "bulk_extractor", "fls", "testdisk",
    "photorec", "exiftool", "tshark", "tcpdump", "pdftotext", "qpdf", "olevba",
    "convert", "ffmpeg", "7z",
    # stego
    "steghide", "stegseek", "zsteg", "outguess", "stegsnow", "zbarimg", "sox",
    "multimon-ng",
    # crypto
    "sage", "gp", "RsaCtfTool", "xortool", "yafu", "openssl",
    # cracking
    "john", "hashcat", "hashid", "hydra", "fcrackzip", "pdfcrack", "hcxpcapngtool",
    # web
    "sqlmap", "gobuster", "ffuf", "feroxbuster", "nikto", "whatweb", "wfuzz",
    "commix", "wafw00f", "nmap", "flask-unsign", "jwt_tool",
    # mobile
    "apktool", "jadx", "d2j-dex2jar", "apksigner",
    # net / wifi
    "aircrack-ng", "socat", "ngrep", "tcpflow", "dig",
    # ocr
    "tesseract",
    # blockchain
    "forge", "cast", "anvil", "slither", "solc",
]
_PROBE_PYMODULES = {
    "pwntools": "pwn", "z3": "z3", "angr": "angr", "capstone": "capstone",
    "unicorn": "unicorn", "volatility3": "volatility3", "pycryptodome": "Crypto",
    "requests": "requests", "scapy": "scapy", "sympy": "sympy", "numpy": "numpy",
    "gmpy2": "gmpy2", "fpylll": "fpylll", "oletools": "oletools",
    "web3": "web3", "pytesseract": "pytesseract",
}


def probe_tools(ctx_executor, work_dir: Path) -> set[str]:
    """Return the set of analysis tools available IN THE EXECUTOR (not this
    process — in production the tools live in the worker container). Run once per
    run and fed into specialist prompts so the agent only reaches for what exists.
    """
    bins = " ".join(shlex.quote(b) for b in _PROBE_BINARIES)
    # Imports run in parallel: angr alone takes several seconds to import, and
    # done one after another the probe could hit its timeout and report tools
    # that are installed as missing.
    pychecks = "\n".join(
        f'( python3 -c "import {mod}" 2>/dev/null && echo "{name}" ) &'
        for name, mod in _PROBE_PYMODULES.items()
    )
    script = (
        f'for t in {bins}; do command -v "$t" >/dev/null 2>&1 && echo "$t"; done\n'
        f'{pychecks}\nwait\n'
    )
    out, _ = ctx_executor.run(script, work_dir, timeout=120)
    found = {ln.strip() for ln in out.decode("utf-8", "replace").splitlines() if ln.strip()}
    # Normalise a couple of aliases for the prompt.
    if "analyzeHeadless" in found:
        found.add("ghidra")
    if "r2" in found or "radare2" in found:
        found.add("radare2")
    return found


class GdbTool(Tool):
    """Run gdb (with pwndbg/GEF if the sandbox's .gdbinit loads them) in BATCH
    mode against a binary. Never interactive — commands are supplied up front."""

    name = "gdb"
    description = ("Run gdb in batch mode on a binary with a list of commands "
                   "(e.g. 'info functions', 'disassemble main', 'checksec', "
                   "'b *0x...', 'run < input', 'x/32gx $rsp'). Non-interactive: "
                   "give every command in order; output is returned.")

    def input_schema(self) -> dict:
        return {"type": "object", "properties": {
            "binary": {"type": "string", "description": "path to the binary (in the work dir)"},
            "commands": {"type": "array", "items": {"type": "string"},
                         "description": "gdb commands run in order"},
            "timeout": {"type": "number"},
        }, "required": ["binary", "commands"]}

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        binary = str(args.get("binary", "")).strip()
        cmds = args.get("commands") or []
        if not binary or not cmds:
            return ToolResult(self.name, b"", "gdb:args", error="binary and commands required")
        # --nx ignores ALL init files, including a malicious .gdbinit planted in
        # the untrusted challenge dir. When the image ships a trusted pwndbg/GEF
        # init, CTF_GDB_INIT points at it and we load only that, explicitly.
        parts = ["gdb", "--batch", "--nx"]
        init = os.environ.get("CTF_GDB_INIT")
        if init and Path(init).is_file():
            parts += ["-ix", init]
        parts += ["-ex", "set pagination off", "-ex", "set confirm off"]
        for c in cmds:
            parts += ["-ex", str(c)]
        parts.append(binary)
        cmd = " ".join(shlex.quote(p) for p in parts)
        timeout = ctx.clamp(args.get("timeout"))
        out, code = ctx.executor.run(cmd, ctx.work_dir, timeout)
        if code == 127:
            return ToolResult(self.name, out, "gdb:missing",
                              error="gdb not installed in this sandbox")
        return ToolResult(self.name, out, f"gdb:{binary}", exit_code=code,
                          truncated=len(out) > MAX_TOOL_OUTPUT)


# A Ghidra post-script (Jython) that decompiles functions to C. Written into the
# work dir and passed to analyzeHeadless. With no argument it dumps every
# function; with a function name it dumps just that one.
_GHIDRA_DECOMPILE_SCRIPT = """\
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
args = getScriptArgs()
want = args[0] if args else None
program = getCurrentProgram()
dec = DecompInterface()
dec.openProgram(program)
monitor = ConsoleTaskMonitor()
fm = program.getFunctionManager()
for f in fm.getFunctions(True):
    if want and f.getName() != want:
        continue
    res = dec.decompileFunction(f, 60, monitor)
    if res and res.decompileCompleted():
        print("// ==== %s @ %s ====" % (f.getName(), f.getEntryPoint()))
        print(res.getDecompiledFunction().getC())
"""


class GhidraDecompileTool(Tool):
    """Decompile a binary to C with Ghidra headless (analyzeHeadless). Returns the
    decompiled C. Optionally restrict to one function to save tokens."""

    name = "ghidra_decompile"
    description = ("Decompile a binary to C using Ghidra headless. Give the binary "
                   "path and optionally a single function name (recommended once "
                   "you know the target function — decompiling everything is "
                   "token-heavy).")

    def input_schema(self) -> dict:
        return {"type": "object", "properties": {
            "binary": {"type": "string"},
            "function": {"type": "string", "description": "optional: one function to decompile"},
            "timeout": {"type": "number", "description": "seconds; Ghidra analysis is slow"},
        }, "required": ["binary"]}

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        binary = str(args.get("binary", "")).strip()
        if not binary:
            return ToolResult(self.name, b"", "ghidra:args", error="binary required")
        func = str(args.get("function", "")).strip()
        script_path = ctx.work_dir / ".ghidra_decompile.py"
        script_path.write_text(_GHIDRA_DECOMPILE_SCRIPT, encoding="utf-8")
        proj = ctx.work_dir / ".ghidra_proj"
        proj.mkdir(exist_ok=True)
        parts = ["analyzeHeadless", str(proj), "tmp",
                 "-import", binary,
                 "-scriptPath", str(ctx.work_dir),
                 "-postScript", ".ghidra_decompile.py"]
        if func:
            parts.append(func)
        parts.append("-deleteProject")
        cmd = " ".join(shlex.quote(p) for p in parts)
        timeout = ctx.clamp(args.get("timeout"), max(ctx.default_timeout, 300.0))
        out, code = ctx.executor.run(cmd, ctx.work_dir, timeout)
        if code == 127:
            return ToolResult(self.name, out, "ghidra:missing",
                              error="Ghidra (analyzeHeadless) not installed in this sandbox")
        return ToolResult(self.name, out, f"ghidra:{binary}", exit_code=code,
                          truncated=len(out) > MAX_TOOL_OUTPUT)


class VolatilityTool(Tool):
    """Run a Volatility 3 plugin against a memory image. Core forensics tool."""

    name = "volatility"
    description = ("Run a Volatility 3 plugin on a memory image (e.g. "
                   "windows.pslist, windows.cmdline, linux.bash, windows.filescan, "
                   "windows.dumpfiles). Give the image path and the plugin.")

    def input_schema(self) -> dict:
        return {"type": "object", "properties": {
            "image": {"type": "string", "description": "memory image path (in the work dir)"},
            "plugin": {"type": "string", "description": "e.g. windows.pslist"},
            "args": {"type": "array", "items": {"type": "string"},
                     "description": "extra plugin arguments"},
            "timeout": {"type": "number"},
        }, "required": ["image", "plugin"]}

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        image = str(args.get("image", "")).strip()
        plugin = str(args.get("plugin", "")).strip()
        if not image or not plugin:
            return ToolResult(self.name, b"", "vol:args", error="image and plugin required")
        extra = " ".join(shlex.quote(str(a)) for a in (args.get("args") or []))
        # Prefer the vol3 module; fall back to a `vol`/`vol.py` launcher.
        base = (f'if python3 -c "import volatility3" 2>/dev/null; then '
                f'python3 -m volatility3 -q -f {shlex.quote(image)} {shlex.quote(plugin)} {extra}; '
                f'elif command -v vol >/dev/null 2>&1; then '
                f'vol -q -f {shlex.quote(image)} {shlex.quote(plugin)} {extra}; '
                f'elif command -v vol.py >/dev/null 2>&1; then '
                f'vol.py -q -f {shlex.quote(image)} {shlex.quote(plugin)} {extra}; '
                f'else echo "__NO_VOLATILITY__"; exit 127; fi')
        timeout = ctx.clamp(args.get("timeout"), max(ctx.default_timeout, 120.0))
        out, code = ctx.executor.run(base, ctx.work_dir, timeout)
        if code == 127 or b"__NO_VOLATILITY__" in out:
            return ToolResult(self.name, b"", "vol:missing",
                              error="Volatility 3 not installed in this sandbox")
        return ToolResult(self.name, out, f"vol:{plugin}", exit_code=code,
                          truncated=len(out) > MAX_TOOL_OUTPUT)


# --------------------------------------------------------------------------- #
# Persistent interactive gdb session (EnIGMA-style Interactive Agent Tool)     #
# --------------------------------------------------------------------------- #

class _GdbSession:
    """A long-lived gdb process driven over pipes. Each command is followed by an
    `echo <sentinel>` so we can read exactly up to the end of that command's
    output, regardless of gdb's prompt behaviour on a non-tty."""

    _SENT = "__CTFGDB_%d__"

    def __init__(self, proc: subprocess.Popen):
        self._p = proc
        self._closed = False
        self._n = 0

    def _read_until(self, marker: bytes, timeout: float) -> bytes:
        fd = self._p.stdout.fileno()
        buf = b""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._p.poll() is not None:
                try:
                    buf += self._p.stdout.read() or b""
                except (OSError, ValueError):
                    pass
                self._closed = True
                break
            r, _, _ = select.select([fd], [], [], 0.2)
            if r:
                try:
                    chunk = os.read(fd, 65536)
                except OSError:
                    break
                if not chunk:
                    self._closed = True
                    break
                buf += chunk
                if marker in buf:
                    break
        return buf

    def send(self, cmd: str, timeout: float = 30.0) -> bytes:
        if self._closed or self._p.poll() is not None:
            self._closed = True
            raise OSError("gdb session is closed")
        self._n += 1
        marker = self._SENT % self._n
        self._p.stdin.write((cmd + f"\necho {marker}\\n\n").encode())
        self._p.stdin.flush()
        out = self._read_until(marker.encode(), timeout)
        idx = out.find(marker.encode())
        return out[:idx] if idx != -1 else out

    def close(self) -> None:
        self._closed = True
        try:
            self._p.stdin.write(b"quit\n")
            self._p.stdin.flush()
        except (OSError, ValueError):
            pass
        try:
            self._p.terminate()
            self._p.wait(timeout=3)
        except Exception:  # noqa: BLE001
            try:
                self._p.kill()
            except OSError:
                pass


class InteractiveGdbTool(Tool):
    """Stateful gdb: start once on a binary, then issue commands across calls
    (breakpoints, run, stepi, x/, info registers, heap inspection) with state
    preserved — unlike the one-shot `gdb` tool. Non-interactive from the agent's
    side: each call returns that command's output."""

    name = "gdb_session"
    description = ("Persistent interactive gdb session. action=start (give "
                   "`binary`) opens it; action=cmd (give `cmd`) runs one gdb "
                   "command with state kept between calls; action=stop closes it. "
                   "Use for stateful debugging (break, run, step, inspect).")

    def input_schema(self) -> dict:
        return {"type": "object", "properties": {
            "action": {"type": "string", "enum": ["start", "cmd", "stop"]},
            "binary": {"type": "string", "description": "binary to debug (action=start)"},
            "cmd": {"type": "string", "description": "a gdb command (action=cmd)"},
            "timeout": {"type": "number"},
        }, "required": ["action"]}

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        action = str(args.get("action", "")).strip()
        sess = ctx.sessions.get("gdb")

        if action == "start":
            binary = str(args.get("binary", "")).strip()
            if not binary:
                return ToolResult(self.name, b"", "gdb_session:args",
                                  error="binary required to start")
            if sess is not None and not getattr(sess, "_closed", True):
                sess.close()
            parts = ["gdb", "--nx", "-q"]
            init = os.environ.get("CTF_GDB_INIT")
            if init and Path(init).is_file():
                parts += ["-ix", init]
            parts += ["-ex", "set pagination off", "-ex", "set confirm off", binary]
            try:
                proc = subprocess.Popen(parts, cwd=str(ctx.work_dir),
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, bufsize=0)
            except FileNotFoundError:
                return ToolResult(self.name, b"", "gdb_session:missing",
                                  error="gdb not installed in this sandbox")
            except OSError as e:
                return ToolResult(self.name, b"", "gdb_session:fail", error=str(e))
            session = _GdbSession(proc)
            ctx.sessions["gdb"] = session
            try:
                banner = session.send("echo (gdb session ready)\\n", timeout=20)
            except OSError as e:
                return ToolResult(self.name, b"", "gdb_session:fail",
                                  error=f"gdb did not start: {e}")
            return ToolResult(self.name, banner or b"(gdb session started)",
                              "gdb_session:start")

        if action == "cmd":
            if sess is None or getattr(sess, "_closed", True):
                return ToolResult(self.name, b"", "gdb_session:noconn",
                                  error="no gdb session; action=start first")
            cmd = str(args.get("cmd", "")).strip()
            if not cmd:
                return ToolResult(self.name, b"", "gdb_session:args", error="cmd required")
            try:
                out = sess.send(cmd, timeout=ctx.clamp(args.get("timeout"), 30.0))
            except OSError as e:
                return ToolResult(self.name, b"", "gdb_session:fail", error=str(e))
            return ToolResult(self.name, out, f"gdb_session:{cmd[:40]}",
                              truncated=len(out) > MAX_TOOL_OUTPUT)

        if action == "stop":
            if sess is not None:
                sess.close()
                ctx.sessions.pop("gdb", None)
            return ToolResult(self.name, b"(gdb session stopped)", "gdb_session:stop")

        return ToolResult(self.name, b"", "gdb_session:badaction",
                          error="action must be start | cmd | stop")
