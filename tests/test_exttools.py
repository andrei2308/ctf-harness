"""External-tool wrappers: capability probe + honest degradation.

Hermetic — a fake executor returns canned output so these pass on any box
(the real tools need not be installed in CI)."""

import tempfile
from pathlib import Path

from harness.agents.exttools import (GdbTool, GhidraDecompileTool, VolatilityTool,
                                     probe_tools)
from harness.agents.tools import ToolContext


class FakeExecutor:
    """Returns (bytes, exit_code) by matching substrings in the command."""

    def __init__(self, rules):
        self.rules = rules          # list of (substr, (bytes, code))
        self.last_cmd = None

    def run(self, cmd, cwd, timeout):
        self.last_cmd = cmd
        for sub, out in self.rules:
            if sub in cmd:
                return out
        return (b"", 0)


def _ctx(ex):
    return ToolContext(challenge_id="c", work_dir=Path(tempfile.mkdtemp()), executor=ex)


def test_probe_parses_installed_set():
    ex = FakeExecutor([("command -v", (b"gdb\nobjdump\nanalyzeHeadless\n", 0)),
                       ("import volatility3", (b"volatility3\n", 0))])
    # The probe runs one combined script; return the union for any call.
    ex.rules = [("", (b"gdb\nobjdump\nanalyzeHeadless\nvolatility3\n", 0))]
    found = probe_tools(ex, Path("."))
    assert {"gdb", "objdump", "analyzeHeadless", "volatility3"} <= found
    assert "ghidra" in found           # alias added when analyzeHeadless present


def test_gdb_missing_degrades():
    ex = FakeExecutor([("gdb", (b"bash: gdb: command not found\n", 127))])
    r = GdbTool().run({"binary": "./x", "commands": ["info functions"]}, _ctx(ex))
    assert "not installed" in r.error


def test_gdb_batch_is_noninteractive():
    ex = FakeExecutor([("gdb", (b"Dump of assembler code...\n", 0))])
    GdbTool().run({"binary": "./x", "commands": ["disassemble main"]}, _ctx(ex))
    # Must force batch + no-init + pagination off; never an interactive gdb.
    assert "--batch" in ex.last_cmd and "set pagination off" in ex.last_cmd


def test_volatility_missing_degrades():
    ex = FakeExecutor([("volatility", (b"__NO_VOLATILITY__\n", 127))])
    r = VolatilityTool().run({"image": "m.raw", "plugin": "windows.pslist"}, _ctx(ex))
    assert "not installed" in r.error


def test_ghidra_writes_script_and_passes_output():
    ex = FakeExecutor([("analyzeHeadless", (b"// ==== main ====\nint main(){}\n", 0))])
    ctx = _ctx(ex)
    r = GhidraDecompileTool().run({"binary": "./bin", "function": "main"}, ctx)
    assert b"int main" in r.output
    assert (ctx.work_dir / ".ghidra_decompile.py").is_file()   # post-script written
    assert "-postScript" in ex.last_cmd and "main" in ex.last_cmd
