"""Transcript logging, the token diet, and the time budget."""

import io
import json
import os
import tempfile
import time
from pathlib import Path

from harness.agents.base import Outcome, Solver, new_state
from harness.agents.limits import Limits
from harness.agents.tools import (LocalExecutor, ShellTool, Tool, ToolContext,
                                   ToolProfile, ToolResult, summarize_output)
from harness.config import Config
from harness.flags.submit import FlagSubmitter
from harness.inference.base import (Effort, Model, ModelResponse, ModelSpec,
                                    ToolCall, Usage)
from harness.inference.openai_client import is_context_overflow
from harness.judge import print_transcript
from harness.platforms.base import Platform, SubmitResult
from harness.scheduler.budget import Budget, Caps
from harness.telemetry.run_log import RunLog

FLAG = "CTF{0123456789abcdef0123456789abcdef}"
SPEC = ModelSpec(name="m", effort=Effort.LOW)


class _Plat(Platform):
    def __init__(self): self.calls = []
    def list_challenges(self): return []
    def get_challenge(self, cid): ...
    def download_files(self, cid, dest): return []
    def start_instance(self, cid): ...
    def get_conn_info(self, cid): ...
    def submit_flag(self, cid, flag):
        self.calls.append(flag)
        return SubmitResult(accepted=flag == FLAG)


class _Out(Tool):
    name = "out"
    description = "echo"
    def input_schema(self): return {"type": "object", "properties": {}}
    def run(self, args, ctx):
        time.sleep(float(args.get("sleep", 0)))
        return ToolResult(self.name, str(args.get("text", "")).encode(), "out:x", exit_code=0)


class _Fn(Model):
    def __init__(self, fn):
        super().__init__(SPEC)
        self.fn, self.n = fn, 0
    def complete(self, messages, tools=None):
        self.n += 1
        return self.fn(self.n, messages)


def _call(n, **args):
    return ModelResponse(text=f"step {n}", tool_calls=(ToolCall(f"c{n}", "out", args),),
                         usage=Usage(7, 3), spec=SPEC)


def _solver(model, *, limits=None, caps=None, max_iterations=10, tools=None):
    d = Path(tempfile.mkdtemp())
    log = RunLog(d / "logs")
    sub = FlagSubmitter(_Plat(), log)
    ctx = ToolContext(challenge_id="c", work_dir=d, executor=LocalExecutor())
    state = new_state("c", d, ctx, "sys", "go")
    solver = Solver(model=model, profile=ToolProfile("t", tools or [_Out()]), state=state,
                    budget=Budget(caps or Caps()), log=log, submitter=sub,
                    max_iterations=max_iterations, plan_first=False,
                    limits=limits or Limits())
    return solver, state, log, d


def _events(log):
    return [json.loads(l) for l in log.path.read_text().splitlines()]


# --- token diet --------------------------------------------------------------

def test_summary_stays_near_the_limit_even_with_many_interesting_lines():
    data = b"".join(b"error: failure number %d with a fairly long tail of text\n" % i
                    for i in range(20000))
    out = summarize_output(data, limit=8192)
    assert len(out) < 8192 * 1.15


def test_big_tool_output_is_capped_and_saved_for_grep():
    big = "\n".join(f"line {i} of boring output" for i in range(20000))
    solver, state, log, d = _solver(_Fn(lambda n, m: _call(n, text=big)),
                                    limits=Limits(tool_output_bytes=2000), max_iterations=1)
    solver.run()
    tool_msg = [m for m in state.messages if m.role == "tool"][0]
    assert len(tool_msg.content) < 2600
    assert ".tool_output/0001.txt" in tool_msg.content
    assert (d / ".tool_output" / "0001.txt").read_text() == big


def test_flag_in_the_cut_part_of_output_still_solves():
    big = "x\n" * 50000 + FLAG + "\n" + "y\n" * 50000
    solver, _, _, _ = _solver(_Fn(lambda n, m: _call(n, text=big)),
                              limits=Limits(tool_output_bytes=1000))
    assert solver.run().outcome == Outcome.SOLVED


def test_old_results_are_trimmed_once_history_is_large():
    lim = Limits(history_soft_chars=5000, keep_recent_results=2, old_result_chars=300,
                 history_hard_chars=10**9)
    solver, state, _, _ = _solver(_Fn(lambda n, m: _call(n, text=f"r{n} " + "A" * 1500)),
                                  limits=lim, max_iterations=8)
    solver.run()
    tools = [m for m in state.messages if m.role == "tool"]
    # the newest results are intact (the last one was added after the final diet)
    assert all(len(m.content) > 1500 for m in tools[-3:])
    old = tools[:-3]
    assert old and all(len(m.content) < 400 and "trimmed" in m.content for m in old)
    assert old[0].content.startswith("r1 ")           # head of the result survives
    # pairing is untouched: every result still has its id
    assert [m.tool_call_id for m in tools] == [f"c{i}" for i in range(1, 9)]


def test_hard_limit_compacts_with_a_digest_of_actions():
    solver, state, _, _ = _solver(
        _Fn(lambda n, m: _call(n, note=f"cmd-{n}", text="B" * 900)),
        limits=Limits(history_soft_chars=0, keep_recent_results=100, history_hard_chars=6000),
        max_iterations=12)
    solver.run()
    digest = [m.content for m in state.messages if "elided" in m.content]
    assert len(digest) == 1 and "Actions already taken" in digest[0]
    # compacted more than once, yet the very first action is still listed
    assert "cmd-1\"" in digest[0] and "cmd-5\"" in digest[0]
    assert sum(len(m.content) for m in state.messages) < 12000


# --- transcript logging ------------------------------------------------------

def test_log_records_what_the_agent_did():
    def fn(n, m):
        return _call(n, text="nothing yet") if n == 1 else _call(n, text=f"got {FLAG}")
    solver, _, log, _ = _solver(_Fn(fn))
    solver.run()
    log.close()
    ev = _events(log)
    calls = [e for e in ev if e["kind"] == "tool.call"]
    assert calls[0]["tool"] == "out" and calls[0]["args"] == "nothing yet"
    obs = [e for e in ev if e["kind"] == "tool.observe"]
    assert obs[0]["output"] == "nothing yet" and obs[0]["exit_code"] == 0
    turns = [e for e in ev if e["kind"] == "model.turn"]
    assert turns[0]["text"] == "step 1" and turns[0]["calls"] == ["out"]
    assert turns[0]["tokens_in"] == 7 and turns[0]["tokens_out"] == 3
    # the reviewed log shows the flag's format, never the whole flag
    assert FLAG not in log.path.read_text()
    assert "CTF{01234567…}" in obs[1]["output"]


def test_log_excerpts_are_capped():
    solver, _, log, _ = _solver(_Fn(lambda n, m: _call(n, text="Z" * 50000)),
                                limits=Limits(log_text_chars=200), max_iterations=1)
    solver.run()
    log.close()
    assert all(len(json.dumps(e)) < 1200 for e in _events(log))


def test_log_mirror_goes_to_stderr(tmp_path, capsys):
    log = RunLog(tmp_path, mirror=True)
    log.event("hello", challenge="c", n=1)
    log.close()
    err = capsys.readouterr().err
    assert '"kind":"hello"' in err and capsys.readouterr().out == ""


def test_transcript_viewer(tmp_path):
    solver, _, log, _ = _solver(_Fn(lambda n, m: _call(n, text=f"got {FLAG}")))
    solver.run()
    log.close()
    buf = io.StringIO()
    assert print_transcript(log.path, "c", out=buf) > 3
    text = buf.getvalue()
    assert "MODEL #1" in text and "$ out:" in text and "flag.submit" in text


# --- time budget -------------------------------------------------------------

def test_tool_timeout_is_clamped_to_the_time_left():
    shell = lambda n, m: ModelResponse(
        tool_calls=(ToolCall(f"c{n}", "shell", {"cmd": "sleep 30", "timeout": 500}),),
        usage=Usage(1, 1), spec=SPEC)
    solver, _, _, _ = _solver(_Fn(shell), caps=Caps(total_seconds=3),
                              limits=Limits(reserve_seconds=1), tools=[ShellTool()],
                              max_iterations=1)
    t = time.monotonic()
    solver.run()
    assert time.monotonic() - t < 6


def test_tool_timeout_has_a_ceiling_without_any_cap():
    ctx = ToolContext("c", Path("."), LocalExecutor(), max_timeout=900)
    assert ctx.clamp(99999) == 900 and ctx.clamp(None) == 30 and ctx.clamp("junk") == 30


def test_timeout_kills_the_whole_process_group(tmp_path):
    out, code = LocalExecutor().run("sleep 300 & echo $!; sleep 300", tmp_path, 1)
    assert code == 124
    pid = int(out.split()[0])
    time.sleep(0.3)
    try:
        os.kill(pid, 0)
        alive = Path(f"/proc/{pid}/stat").read_text().split()[2] != "Z"
    except (ProcessLookupError, FileNotFoundError):
        alive = False
    assert not alive, "background child survived the timeout"


def test_wall_clock_is_charged_so_per_challenge_seconds_works():
    solver, _, _, _ = _solver(_Fn(lambda n, m: _call(n, text=f"t{n}", sleep=0.25)),
                              caps=Caps(per_challenge_seconds=0.6), max_iterations=50)
    out = solver.run()
    assert out.outcome == Outcome.EXHAUSTED and out.iterations <= 4
    assert solver.budget.snapshot()["per_challenge"]["c"]["seconds"] >= 0.5


# --- knobs -------------------------------------------------------------------

def test_overflow_detection_is_specific():
    assert is_context_overflow("This model's maximum context length is 32768 tokens")
    assert is_context_overflow("prompt is too long: 210000 tokens > 200000")
    assert not is_context_overflow("upstream error: context deadline exceeded")
    assert not is_context_overflow("429 rate limit")


def test_max_output_tokens_clamps_every_rung():
    assert max(r.spec.max_tokens for r in Config().ladder().rungs) == 32768
    assert max(r.spec.max_tokens for r in Config(max_output_tokens=4096).ladder().rungs) == 4096


def test_limits_from_env(monkeypatch):
    monkeypatch.setenv("CTF_TOOL_OUTPUT_BYTES", "4096")
    monkeypatch.setenv("CTF_RESERVE_SECONDS", "45")
    monkeypatch.setenv("CTF_HISTORY_SOFT_CHARS", "not-a-number")
    lim = Limits.from_env()
    assert (lim.tool_output_bytes, lim.reserve_seconds) == (4096, 45.0)
    assert lim.history_soft_chars == Limits().history_soft_chars
