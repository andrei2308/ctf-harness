"""Stuck-loop detection: a solver that repeats an unproductive action is nudged
once, then bailed to STALLED so the ladder escalates instead of spinning."""

import tempfile
from pathlib import Path

from harness.agents.base import Outcome, Solver, new_state
from harness.agents.tools import LocalExecutor, ToolContext, ToolProfile, Tool, ToolResult
from harness.flags.submit import FlagSubmitter
from harness.inference.base import ModelResponse, ToolCall, Usage
from harness.inference.null import ScriptedModel
from harness.platforms.base import Platform, SubmitResult
from harness.scheduler.budget import Budget, Caps
from harness.telemetry.run_log import RunLog


class _Plat(Platform):
    def list_challenges(self): return []
    def get_challenge(self, cid): ...
    def download_files(self, cid, dest): return []
    def start_instance(self, cid): ...
    def get_conn_info(self, cid): ...
    def submit_flag(self, cid, flag): return SubmitResult(accepted=True)


class _NoopTool(Tool):
    name = "noop"
    description = "does nothing"
    def input_schema(self): return {"type": "object", "properties": {}}
    def run(self, args, ctx): return ToolResult("noop", b"", "noop:x")


def test_repeated_action_leads_to_stall():
    with tempfile.TemporaryDirectory() as d:
        log = RunLog(d)
        sub = FlagSubmitter(_Plat(), log)
        ctx = ToolContext(challenge_id="c", work_dir=Path(d), executor=LocalExecutor())
        state = new_state("c", Path(d), ctx, "sys", "go")
        # The model keeps issuing the exact same empty-output tool call.
        same = ModelResponse(tool_calls=(ToolCall(id="1", name="noop", arguments={}),),
                             usage=Usage(input=5, output=2), stop_reason="tool")
        model = ScriptedModel([same] * 20)
        solver = Solver(model=model, profile=ToolProfile("t", [_NoopTool()]),
                        state=state, budget=Budget(Caps()), log=log, submitter=sub,
                        max_iterations=40, stuck_patience=6, stuck_dup_threshold=3)
        out = solver.run()
        log.close()
        assert out.outcome == Outcome.STALLED
        assert "stuck" in out.reason
        # bailed early — nowhere near the 40-iteration cap
        assert out.iterations < 20


def test_stuck_nudge_logged():
    with tempfile.TemporaryDirectory() as d:
        log = RunLog(d)
        sub = FlagSubmitter(_Plat(), log)
        ctx = ToolContext(challenge_id="c", work_dir=Path(d), executor=LocalExecutor())
        state = new_state("c", Path(d), ctx, "sys", "go")
        same = ModelResponse(tool_calls=(ToolCall(id="1", name="noop", arguments={}),),
                             usage=Usage(input=5, output=2), stop_reason="tool")
        Solver(model=ScriptedModel([same] * 20), profile=ToolProfile("t", [_NoopTool()]),
               state=state, budget=Budget(Caps()), log=log, submitter=sub,
               stuck_dup_threshold=3).run()
        log.close()
        assert '"kind":"solver.stuck_nudge"' in Path(log.path).read_text()
