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


def test_gdb_missing_degrades(monkeypatch):
    monkeypatch.delenv("CTF_GDB", raising=False)      # the image sets it
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
    assert (ctx.work_dir / "ghidra_tool" / "CtfDecompile.java").is_file()   # post-script written
    assert "-postScript" in ex.last_cmd and "main" in ex.last_cmd


def test_ghidra_paths_have_no_dot_elements():
    # Ghidra aborts on any path element starting with '.' (seen in the image:
    # "Path element starting with '.' is not permitted").
    ex = FakeExecutor([])
    ctx = _ctx(ex)
    GhidraDecompileTool().run({"binary": "./bin"}, ctx)
    proj = ex.last_cmd.split()[1]
    assert not any(part.startswith(".") for part in Path(proj).parts)
    assert ".ghidra" not in ex.last_cmd


def test_ghidra_output_keeps_only_decompiled_code():
    log = b"INFO  Using log file ...\n" * 200
    ex = FakeExecutor([("analyzeHeadless",
                        (log + b"// ==== win @ 00101139 ====\nint win(){}\n", 0))])
    r = GhidraDecompileTool().run({"binary": "./bin", "function": "win"}, _ctx(ex))
    assert r.output.startswith(b"// ==== win") and b"INFO" not in r.output


def test_ghidra_error_output_is_kept_whole():
    err = b"ERROR Abort due to Headless analyzer error: boom\n"
    ex = FakeExecutor([("analyzeHeadless", (err, 1))])
    r = GhidraDecompileTool().run({"binary": "./bin"}, _ctx(ex))
    assert r.output == err and r.exit_code == 1


def test_gdb_uses_ctf_gdb_when_on_path(monkeypatch, tmp_path):
    fake = tmp_path / "pwndbg"
    fake.write_text("#!/bin/sh\n")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")
    monkeypatch.setenv("CTF_GDB", "pwndbg")
    ex = FakeExecutor([])
    GdbTool().run({"binary": "./x", "commands": ["checksec"]}, _ctx(ex))
    assert ex.last_cmd.startswith("pwndbg --batch --nx")
    assert "'set disable-colors on'" in ex.last_cmd      # no ANSI codes for the model


def test_gdb_falls_back_to_plain_gdb_when_ctf_gdb_missing(monkeypatch):
    # A skipped pwndbg install must degrade to gdb, not break the tool.
    monkeypatch.setenv("CTF_GDB", "no-such-debugger-xyz")
    ex = FakeExecutor([])
    GdbTool().run({"binary": "./x", "commands": ["checksec"]}, _ctx(ex))
    assert ex.last_cmd.startswith("gdb --batch --nx")
    assert "disable-colors" not in ex.last_cmd           # plain gdb would error on it


def test_volatility_reaches_the_cli_when_the_module_is_installed(monkeypatch, tmp_path):
    # Real bash, fake tools that mirror the real package: `import volatility3`
    # works but `python3 -m volatility3` does not (there is no __main__).
    from harness.agents.tools import LocalExecutor
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "python3").write_text(
        '#!/bin/sh\n[ "$1" = -m ] && { echo "No module named volatility3.__main__"; exit 1; }\n'
        'exit 0\n')
    (bin_dir / "vol").write_text('#!/bin/sh\necho "VOL $*"\n')
    for f in bin_dir.iterdir():
        f.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin:/bin")
    ctx = ToolContext(challenge_id="c", work_dir=tmp_path, executor=LocalExecutor())
    r = VolatilityTool().run({"image": "m.raw", "plugin": "windows.info"}, ctx)
    assert b"VOL -q -f m.raw windows.info" in r.output, r.output
