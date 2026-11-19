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
import re
import select
import shlex
import shutil
import subprocess
import time
from pathlib import Path

from .tools import (MAX_TOOL_OUTPUT, Tool, ToolContext, ToolResult, agent_argv_prefix,
                    agent_env)


def gdb_binary() -> str:
    """The debugger to launch: CTF_GDB (the image sets it to the portable
    pwndbg) when that is on PATH, else plain gdb. A failed pwndbg install must
    degrade to gdb, not break both gdb tools."""
    want = os.environ.get("CTF_GDB", "").strip()
    if want and shutil.which(want):
        return want
    return "gdb"


def gdb_argv(*flags: str) -> list[str]:
    """Debugger command line up to the user's commands. --nx ignores ALL init
    files, including a malicious .gdbinit planted in the untrusted challenge
    dir; a trusted init in CTF_GDB_INIT is loaded explicitly instead. pwndbg
    colours every line with ANSI codes, which the model pays for in tokens;
    plain gdb has no such setting and would print an error for it."""
    binary = gdb_binary()
    parts = [binary, *flags, "--nx"]
    init = os.environ.get("CTF_GDB_INIT")
    if init and Path(init).is_file():
        parts += ["-ix", init]
    if binary != "gdb":
        parts += ["-ex", "set disable-colors on"]
    return parts + ["-ex", "set pagination off", "-ex", "set confirm off"]

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


def image_tier() -> str:
    """Which build of the image this is. "full" is the image every rehearsal ran
    on, and what an unset CTF_IMAGE_TIER means; Dockerfile.slim sets the name of
    a smaller tier, which has fewer tools than the playbooks name."""
    return os.environ.get("CTF_IMAGE_TIER", "").strip().lower() or "full"


# Probe names that the playbooks spell differently.
_PLAYBOOK_NAMES = {
    "analyzeHeadless": "ghidra", "qemu-aarch64-static": "qemu", "zbarimg": "zbar",
    "d2j-dex2jar": "dex2jar", "r2": "radare2", "hcxpcapngtool": "hcxtools",
    "bulk_extractor": "bulk-extractor", "volatility3": "volatility",
}
# What to reach for instead, where the stand-in is not obvious.
_STAND_INS = {
    "sage": "use `gp` (PARI/GP), `sympy`, `gmpy2`, `fpylll`",
    "ghidra": "no `ghidra_decompile`: read code with `r2 -q -A -c 'pdf @ main' FILE`, "
              "`objdump -d -M intel`, `gdb`",
    "hashcat": "use `john`",
    "yafu": "factor with `gp -q` or `sympy.factorint`",
    "qemu": "a foreign-architecture binary cannot be run here: analyse it statically",
    "jadx": "for an APK: unzip it and disassemble classes.dex with `r2 -q -A`, "
            "which reads Dalvik: `afl`, then `pdf @ <method>`",
    "forge": "use `web3` and `solc` from Python",
    "tesseract": "look at pictures with `view_image`",
    "hydra": "script the login loop in Python",
}


# Told to every specialist of a tier that lacks them, named by its playbook or
# not: the file that needs the tool can turn up in any category. Measured on the
# core tier (TIERS_REPORT.md): an APK carved out of a pcap went to the forensics
# specialist, whose playbook does not name jadx, and the model spent 25 turns
# writing a DEX parser before a second run found r2.
_ANY_CATEGORY = ("jadx",)


# angr ships a decompiler (`python -m angr decompile`, angr 10): C for a function
# in about two seconds, on stripped binaries too, with no Java. Measured on a
# small crackme with the pinned angr 10.0.7: readable, but it dropped the loop
# counter's increment, hence the advice to check against the disassembly.
_GHIDRA_VIA_ANGR = ("no `ghidra_decompile`: decompile to C with "
                    "`python3 -m angr -n decompile FILE --functions main` (without "
                    "--functions: every function; stripped binaries have `sub_<addr>` "
                    "names), and check odd-looking code against `objdump -d -M intel`, "
                    "it can drop a statement")


def _stand_in(name: str, available: set[str]) -> str:
    if name == "ghidra" and "angr" in available:
        return _GHIDRA_VIA_ANGR
    return _STAND_INS.get(name, "")


def missing_note(available: set[str], playbook: str) -> str:
    """One line for the task prompt of a smaller image tier: the tools this
    specialist's playbook names that are not installed (and the few in
    _ANY_CATEGORY), with a stand-in where there is one. Without it the model spends a turn on `sage: command not
    found` and another deciding what to do instead.

    Empty in the full image (so its prompts are exactly the rehearsed ones) and
    when the probe returned nothing (a failed probe must not declare every tool
    missing)."""
    if image_tier() == "full" or not available:
        return ""
    text = playbook.lower()
    missing: dict[str, str] = {}
    for probe in list(_PROBE_BINARIES) + list(_PROBE_PYMODULES):
        name = _PLAYBOOK_NAMES.get(probe, probe)
        if probe in available or name in available or name in missing:
            continue
        if name in _ANY_CATEGORY or re.search(r"(?<![a-z0-9_])" + re.escape(name.lower()), text):
            missing[name] = _stand_in(name, available)
    if not missing:
        return ""
    parts = [f"{n} ({why})" if why else n for n, why in sorted(missing.items())]
    return "Not installed in this image, do not call them: " + "; ".join(parts) + "."


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
        parts = gdb_argv("--batch")
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


# A Ghidra post-script that decompiles functions to C. Written into the work dir
# and passed to analyzeHeadless. With no argument it dumps every function; with
# a function name it dumps just that one. Java, not Python: Ghidra compiles Java
# scripts with its own JDK on every version, while .py scripts depend on Jython
# or PyGhidra being set up.
_GHIDRA_MARKER = "// ==== "
_GHIDRA_SCRIPT_NAME = "CtfDecompile.java"
_GHIDRA_DECOMPILE_SCRIPT = """\
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

public class CtfDecompile extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String want = args.length > 0 ? args[0] : null;
        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (want != null && !f.getName().equals(want)) continue;
            DecompileResults r = dec.decompileFunction(f, 60, monitor);
            if (r != null && r.decompileCompleted()) {
                System.out.println("// ==== " + f.getName() + " @ " + f.getEntryPoint() + " ====");
                System.out.println(r.getDecompiledFunction().getC());
            }
        }
    }
}
"""


class GhidraDecompileTool(Tool):
    """Decompile a binary to C with Ghidra headless (analyzeHeadless). Returns the
    decompiled C. Optionally restrict to one function to save tokens."""

    needs = "ghidra"

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
        # Ghidra rejects any path element starting with '.', so no dot-dirs.
        tool_dir = ctx.work_dir / "ghidra_tool"
        proj = tool_dir / "proj"
        proj.mkdir(parents=True, exist_ok=True)
        (tool_dir / _GHIDRA_SCRIPT_NAME).write_text(_GHIDRA_DECOMPILE_SCRIPT, encoding="utf-8")
        # Ghidra keeps settings under $XDG_CONFIG_HOME or Java's user.home
        # (/root), not $HOME: on a read-only root it could not start (task 1,
        # `docker run --read-only`). Keep all of it in the work dir.
        home = tool_dir / "home"
        home.mkdir(parents=True, exist_ok=True)
        parts = ["env", f"XDG_CONFIG_HOME={home / '.config'}", f"XDG_CACHE_HOME={home / '.cache'}",
                 f"_JAVA_OPTIONS=-Duser.home={home}",
                 "analyzeHeadless", str(proj), "tmp",
                 "-import", binary,
                 "-scriptPath", str(tool_dir),
                 "-postScript", _GHIDRA_SCRIPT_NAME]
        if func:
            parts.append(func)
        parts.append("-deleteProject")
        cmd = " ".join(shlex.quote(p) for p in parts)
        timeout = ctx.clamp(args.get("timeout"), max(ctx.default_timeout, 300.0))
        out, code = ctx.executor.run(cmd, ctx.work_dir, timeout)
        if code == 127:
            return ToolResult(self.name, out, "ghidra:missing",
                              error="Ghidra (analyzeHeadless) not installed in this sandbox")
        # Headless prints ~8 KB of INFO log around a few hundred bytes of C.
        # Keep only the decompiled functions when there are any; otherwise keep
        # everything, so an error stays visible.
        i = out.find(_GHIDRA_MARKER.encode())
        if code == 0 and i >= 0:
            out = out[i:]
        return ToolResult(self.name, out, f"ghidra:{binary}", exit_code=code,
                          truncated=len(out) > MAX_TOOL_OUTPUT)


class VolatilityTool(Tool):
    """Run a Volatility 3 plugin against a memory image. Core forensics tool."""

    needs = "volatility3"

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
        # Prefer the `vol` launcher. The volatility3 package has no __main__, so
        # `python3 -m volatility3` always fails; the module fallback calls the
        # CLI entry point the way the launcher does.
        rest = f"-q -f {shlex.quote(image)} {shlex.quote(plugin)} {extra}"
        base = (f'if command -v vol >/dev/null 2>&1; then vol {rest}; '
                f'elif command -v vol.py >/dev/null 2>&1; then vol.py {rest}; '
                f'elif python3 -c "import volatility3" 2>/dev/null; then '
                f'python3 -c "import sys; from volatility3.cli import main; '
                f'sys.argv[0] = \'vol\'; sys.exit(main())" {rest}; '
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
            parts = agent_argv_prefix() + gdb_argv("-q") + [binary]
            try:
                proc = subprocess.Popen(parts, cwd=str(ctx.work_dir),
                                        env=agent_env(ctx.work_dir),
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


# --------------------------------------------------------------------------- #
# Looking at an image                                                          #
# --------------------------------------------------------------------------- #

MAX_IMAGE_SIDE = 1024
MAX_IMAGE_BYTES = 3_000_000


class ViewImageTool(Tool):
    """Show an image file to the model.

    In rehearsal the agent rebuilt a handwritten flag from a mouse-movement
    pcap, then spent its whole budget reading the drawing through OCR and ASCII
    art. A model with vision reads it at a glance. The image goes to the model
    in the next message; a model without vision is told so and keeps its tools.
    The image is reference material, not evidence: a flag read from it must
    still be printed by a tool to count as grounded."""

    name = "view_image"
    description = ("Look at an image file (PNG, JPEG, GIF, BMP, ...) in the working "
                   "directory: a rendered plot, a QR code, a screenshot, handwriting. "
                   "It is shown to you in the next message.")

    def input_schema(self) -> dict:
        return {"type": "object", "properties": {
            "path": {"type": "string", "description": "image path, relative to the working directory"},
        }, "required": ["path"]}

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        raw = str(args.get("path", "")).strip()
        if not raw:
            return ToolResult(self.name, b"", "view_image:args", error="path required")
        work = Path(ctx.work_dir).resolve()
        path = (work / raw).resolve()
        if path != work and work not in path.parents and Path("/tmp") not in path.parents:
            return ToolResult(self.name, b"", "view_image:scope",
                              error="only files under the working directory or /tmp")
        if not path.is_file():
            return ToolResult(self.name, b"", "view_image:missing", error=f"no such file: {raw}")
        try:
            data, mime, size = _image_for_model(path)
        except ValueError as e:
            return ToolResult(self.name, b"", "view_image:format", error=str(e))
        import base64
        url = f"data:{mime};base64,{base64.b64encode(data).decode()}"
        note = f"[{raw}: {size[0]}x{size[1]} image, shown in the next message]".encode()
        return ToolResult(self.name, note, f"view_image:{raw}", is_evidence=False,
                          meta={"images": [url], "image_name": raw})


def _image_for_model(path: Path) -> tuple[bytes, str, tuple[int, int]]:
    """PNG bytes no larger than MAX_IMAGE_SIDE per side. Without Pillow, a PNG or
    JPEG under the size limit is passed through as it is."""
    try:
        from PIL import Image
    except ImportError:
        head = path.read_bytes()[:8]
        mime = ("image/png" if head.startswith(b"\x89PNG") else
                "image/jpeg" if head.startswith(b"\xff\xd8") else None)
        if not mime or path.stat().st_size > MAX_IMAGE_BYTES:
            raise ValueError("cannot convert this image here; save it as a small PNG first")
        return path.read_bytes(), mime, (0, 0)
    import io
    try:
        im = Image.open(path)
        im.load()
    except Exception as e:  # noqa: BLE001 - any decoder failure is a bad image
        raise ValueError(f"not an image Pillow can read: {e}") from None
    if im.mode not in ("RGB", "L"):
        im = im.convert("RGB")
    im.thumbnail((MAX_IMAGE_SIDE, MAX_IMAGE_SIDE))
    buf = io.BytesIO()
    im.save(buf, "PNG", optimize=True)
    return buf.getvalue(), "image/png", im.size
