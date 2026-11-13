"""Persistent interactive gdb session — exercised against real gdb (skipped if
gdb or a C compiler is unavailable)."""

import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from harness.agents.exttools import InteractiveGdbTool
from harness.agents.tools import LocalExecutor, ToolContext

pytestmark = pytest.mark.skipif(
    not shutil.which("gdb") or not (shutil.which("cc") or shutil.which("gcc")),
    reason="needs gdb and a C compiler")


def _build(d: Path) -> str:
    (d / "t.c").write_text("#include <stdio.h>\nint add(int a,int b){return a+b;}\n"
                           "int main(){printf(\"%d\\n\", add(2,2));return 0;}\n")
    cc = shutil.which("cc") or shutil.which("gcc")
    subprocess.run([cc, "-o", "t", "t.c"], cwd=d, check=True)
    return "./t"


def test_stateful_gdb_session():
    with tempfile.TemporaryDirectory() as dd:
        d = Path(dd)
        binary = _build(d)
        ctx = ToolContext(challenge_id="c", work_dir=d, executor=LocalExecutor())
        tool = InteractiveGdbTool()

        start = tool.run({"action": "start", "binary": binary}, ctx)
        assert not start.error, start.error
        assert "gdb" in ctx.sessions

        funcs = tool.run({"action": "cmd", "cmd": "info functions add"}, ctx)
        assert b"add" in funcs.output

        # state persists across calls: set a breakpoint, run, inspect.
        tool.run({"action": "cmd", "cmd": "break add"}, ctx)
        run = tool.run({"action": "cmd", "cmd": "run"}, ctx)
        assert b"add" in run.output or b"Breakpoint" in run.output
        calc = tool.run({"action": "cmd", "cmd": "print 21+21"}, ctx)
        assert b"42" in calc.output

        stop = tool.run({"action": "stop"}, ctx)
        assert "stop" in stop.source
        assert "gdb" not in ctx.sessions


def test_cmd_without_start_errors():
    with tempfile.TemporaryDirectory() as dd:
        ctx = ToolContext(challenge_id="c", work_dir=Path(dd), executor=LocalExecutor())
        r = InteractiveGdbTool().run({"action": "cmd", "cmd": "info registers"}, ctx)
        assert "no gdb session" in r.error
