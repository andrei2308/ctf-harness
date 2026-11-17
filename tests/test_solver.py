"""Solver-level tests: the loop must stream a grounded flag and must refuse a
flag the model only asserted in prose."""

import tempfile
from pathlib import Path

from harness.agents.base import Outcome, Solver, new_state
from harness.agents.tools import (LocalExecutor, ToolContext, ToolProfile,
                                   ToolResult, Tool)
from harness.flags.submit import FlagSubmitter
from harness.inference.base import ModelResponse, ModelSpec, ToolCall, Usage
from harness.inference.null import ScriptedModel
from harness.platforms.base import Platform, SubmitResult
from harness.scheduler.budget import Budget, Caps
from harness.telemetry.run_log import RunLog

FLAG = "CTF{solver_flag}"


class _Plat(Platform):
    def __init__(self): self.calls = []
    def list_challenges(self): return []
    def get_challenge(self, cid): ...
    def download_files(self, cid, dest): return []
    def start_instance(self, cid): ...
    def get_conn_info(self, cid): ...
    def submit_flag(self, cid, flag):
        self.calls.append(flag)
        return SubmitResult(accepted=True)


class _EchoFlagTool(Tool):
    name = "reveal"
    description = "returns the flag as real output"
    def input_schema(self): return {"type": "object", "properties": {}}
    def run(self, args, ctx):
        return ToolResult(self.name, f"the flag is {FLAG}".encode(), "reveal:out")


def _mk(model, profile, penalize_wrong=False):
    d = tempfile.mkdtemp()
    log = RunLog(d)
    plat = _Plat()
    sub = FlagSubmitter(plat, log, penalize_wrong=penalize_wrong)
    ctx = ToolContext(challenge_id="c1", work_dir=Path(d), executor=LocalExecutor())
    state = new_state("c1", Path(d), ctx, system_prompt="sys", task_prompt="go")
    solver = Solver(model=model, profile=profile, state=state,
                    budget=Budget(Caps()), log=log, submitter=sub, max_iterations=10, plan_first=False)
    return solver, plat, sub, log


def test_grounded_flag_via_tool_is_solved_and_submitted():
    model = ScriptedModel([
        ModelResponse(tool_calls=(ToolCall(id="1", name="reveal", arguments={}),),
                      usage=Usage(input=10, output=5), stop_reason="tool"),
        ModelResponse(text="done", stop_reason="end"),
    ])
    solver, plat, sub, log = _mk(model, ToolProfile("t", [_EchoFlagTool()]))
    out = solver.run()
    log.close()
    assert out.outcome == Outcome.SOLVED
    assert plat.calls == [FLAG]


def test_prose_flag_without_evidence_is_refused():
    # The model asserts a flag it never obtained from a tool. When wrong flags
    # are penalised it must not be submitted. (When they are free it is worth a
    # try: see test_review_fixes.py.)
    model = ScriptedModel([
        ModelResponse(text=f"The flag is {FLAG}", stop_reason="end"),
        ModelResponse(text="ok I give up", stop_reason="end"),
    ])
    solver, plat, sub, log = _mk(model, ToolProfile("t", [_EchoFlagTool()]),
                                 penalize_wrong=True)
    out = solver.run()
    log.close()
    assert plat.calls == []                      # nothing submitted
    assert out.outcome == Outcome.STALLED
    assert not sub.is_solved("c1")


def test_length_cut_empty_turn_gets_a_note_not_a_stall():
    # A reasoning model can spend all of max_tokens thinking and return nothing
    # (GLM 5.3 Flash at rung 0). That must not count toward a stall, and no
    # empty assistant message should be kept.
    cut = ModelResponse(text="", usage=Usage(input=10, output=4096), stop_reason="length")
    model = ScriptedModel([
        cut, cut, cut,
        ModelResponse(tool_calls=(ToolCall(id="1", name="reveal", arguments={}),),
                      usage=Usage(input=10, output=5), stop_reason="tool_calls"),
    ])
    solver, plat, sub, log = _mk(model, ToolProfile("t", [_EchoFlagTool()]))
    out = solver.run()
    log.close()
    assert out.outcome == Outcome.SOLVED and plat.calls == [FLAG]
    msgs = solver.state.messages
    assert not any(m.role == "assistant" and not m.content and not m.tool_calls for m in msgs)
    # one note, not one per cut-off turn, and the cap was doubled each time
    assert sum("hit the output limit" in m.content for m in msgs if m.role == "user") == 1
    assert solver.state.output_floor > 0


def test_model_turn_logs_stop_reason():
    model = ScriptedModel([
        ModelResponse(tool_calls=(ToolCall(id="1", name="reveal", arguments={}),),
                      usage=Usage(input=10, output=5), stop_reason="tool_calls"),
    ])
    solver, plat, sub, log = _mk(model, ToolProfile("t", [_EchoFlagTool()]))
    solver.run()
    log.close()
    import json
    turns = [json.loads(l) for l in open(log.path) if '"model.turn"' in l]
    assert turns and turns[0]["stop"] == "tool_calls"


def test_secret_values_never_reach_the_model_or_the_log(monkeypatch):
    # In one container the agent can `cat /proc/1/environ`; whatever it prints,
    # a known credential value must not travel on.
    from harness import secrets
    key = "sk-test-secret-value-0123456789"
    monkeypatch.setenv("OPENAI_API_KEY", key)

    class _Leaky(Tool):
        name = "leak"
        description = "prints the environment"
        def input_schema(self): return {"type": "object", "properties": {}}
        def run(self, args, ctx):
            return ToolResult(self.name, f"OPENAI_API_KEY={key}\n".encode(), "leak:out",
                              error=f"also in error {key}")

    model = ScriptedModel([
        ModelResponse(tool_calls=(ToolCall(id="1", name="leak", arguments={}),),
                      usage=Usage(input=10, output=5), stop_reason="tool_calls"),
        ModelResponse(text="done", stop_reason="stop"),
        ModelResponse(text="done", stop_reason="stop"),
        ModelResponse(text="done", stop_reason="stop"),
    ])
    solver, plat, sub, log = _mk(model, ToolProfile("t", [_Leaky()]))
    solver.run()
    log.close()
    sent = "\n".join(m.content for m in solver.state.messages)
    assert key not in sent and secrets.MARK in sent
    assert key not in open(log.path).read()
    secrets._registered.discard(key)


def test_model_turn_logs_reasoning_tokens():
    model = ScriptedModel([
        ModelResponse(tool_calls=(ToolCall(id="1", name="reveal", arguments={}),),
                      usage=Usage(input=10, output=900), stop_reason="tool_calls",
                      reasoning_tokens=850),
    ])
    solver, plat, sub, log = _mk(model, ToolProfile("t", [_EchoFlagTool()]))
    solver.run()
    log.close()
    import json
    turn = next(json.loads(l) for l in open(log.path) if '"model.turn"' in l)
    assert turn["reasoning"] == 850
