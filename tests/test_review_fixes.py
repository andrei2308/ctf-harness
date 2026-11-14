"""Regression tests for the defects found in review. Each one failed before its
fix; none of them was reachable with the scripted models the suite used."""

import json
import shutil
import tempfile
import threading
from pathlib import Path

import pytest

import harness.agents.base as solver_mod
from harness.agents.base import Outcome, Solver, new_state
from harness.agents.tools import (LocalExecutor, Tool, ToolContext, ToolProfile,
                                   ToolResult)
from harness.flags.grounding import EvidenceStore, flag_pattern
from harness.flags.submit import FlagSubmitter
from harness.inference.anthropic_client import AnthropicModel
from harness.inference.base import (ContextOverflow, Effort, Message, Model,
                                    ModelError, ModelResponse, ModelSpec, ToolCall,
                                    Usage)
from harness.inference.openai_client import OpenAIModel
from harness.platforms.base import Platform, PlatformError, SubmitResult
from harness.platforms.files_target import FilesTargetPlatform
from harness.scheduler.budget import Budget, Caps
from harness.scheduler.ladder import Ladder, Rung
from harness.scheduler.scheduler import Scheduler
from harness.single import run_challenge
from harness.telemetry.run_log import RunLog

FLAG = "CTF{review_flag}"
SPEC = ModelSpec(name="m", effort=Effort.LOW)


@pytest.fixture(autouse=True)
def _no_real_sleep(monkeypatch):
    monkeypatch.setattr(solver_mod, "_sleep", lambda s: None)


class _Plat(Platform):
    def __init__(self, answer=FLAG, fail_first=0):
        self.calls, self.answer, self.fail_first = [], answer, fail_first
    def list_challenges(self): return []
    def get_challenge(self, cid): ...
    def download_files(self, cid, dest): return []
    def start_instance(self, cid): ...
    def get_conn_info(self, cid): ...
    def submit_flag(self, cid, flag):
        self.calls.append(flag)
        if len(self.calls) <= self.fail_first:
            raise PlatformError("503 from grader")
        return SubmitResult(accepted=flag == self.answer)


class _Out(Tool):
    """Returns whatever text it is asked to, as real tool output."""
    name = "out"
    description = "echo"
    def input_schema(self): return {"type": "object", "properties": {"text": {"type": "string"}}}
    def run(self, args, ctx):
        return ToolResult(self.name, str(args.get("text", "")).encode(), "out:x")


class _Fn(Model):
    """A model driven by a function of the call number (1-based)."""
    def __init__(self, fn, spec=SPEC):
        super().__init__(spec)
        self.fn, self.n = fn, 0
    def complete(self, messages, tools=None):
        self.n += 1
        return self.fn(self.n, messages)


def _call(n, text):
    return ModelResponse(tool_calls=(ToolCall(f"c{n}", "out", {"text": text}),),
                         usage=Usage(5, 5), spec=SPEC)


def _solver(model, *, plat=None, max_iterations=10, penalize_wrong=False, caps=None):
    d = Path(tempfile.mkdtemp())
    log = RunLog(d / "logs")
    plat = plat or _Plat()
    sub = FlagSubmitter(plat, log, penalize_wrong=penalize_wrong, sleep=lambda s: None)
    ctx = ToolContext(challenge_id="c", work_dir=d, executor=LocalExecutor())
    state = new_state("c", d, ctx, "sys", "go")
    solver = Solver(model=model, profile=ToolProfile("t", [_Out()]), state=state,
                    budget=Budget(caps or Caps()), log=log, submitter=sub,
                    max_iterations=max_iterations, plan_first=False)
    return solver, plat, sub, state


def _ladder(*depths):
    return Ladder([Rung(SPEC, d) for d in depths])


# --- 1. running out of a rung's iterations must escalate, not spin -----------

def test_iterations_are_per_attempt_and_spent_rung_escalates():
    busy = _Fn(lambda n, m: _call(n, f"step {n}"))
    solver, _, _, state = _solver(busy, max_iterations=3)
    out = solver.run()
    assert out.outcome == Outcome.STALLED and "max iterations" in out.reason
    assert busy.n == 3
    # A second attempt on the same state gets its own depth, not zero turns.
    solver2 = Solver(model=busy, profile=ToolProfile("t", [_Out()]), state=state,
                     budget=Budget(Caps()), log=solver.log, submitter=solver.submitter,
                     max_iterations=4, plan_first=False)
    solver2.run()
    assert busy.n == 7 and state.iters_done == 7


def _fixture_root(tmp: Path) -> Path:
    c = tmp / "fx" / "only"
    (c / "files").mkdir(parents=True)
    (c / "files" / "f.txt").write_text("nothing here\n")
    (c / "challenge.json").write_text(json.dumps(
        {"id": "only", "name": "only", "category": "misc", "flag": FLAG}))
    return tmp / "fx"


def _run_single(tmp, model_fn, **kw):
    plat = FilesTargetPlatform(_fixture_root(tmp))
    log = RunLog(tmp / "logs")
    sub = FlagSubmitter(plat, log, sleep=lambda s: None)
    models = []
    def factory(spec):
        models.append(_Fn(model_fn, spec))
        return models[-1]
    res = run_challenge(challenge=plat.get_challenge("only"), platform=plat,
                        ladder=_ladder(2, 3), model_factory=factory,
                        budget=Budget(kw.pop("caps", Caps())), log=log, submitter=sub,
                        executor=LocalExecutor(), work_root=tmp / "w", available=set(),
                        plan_first=False, **kw)
    return res, sum(m.n for m in models), sub


def test_single_climbs_ladder_then_restarts_top_rung(tmp_path):
    shell = lambda n, m: ModelResponse(
        tool_calls=(ToolCall(f"c{n}", "shell", {"cmd": f"echo step{len(m)}"}),),
        usage=Usage(5, 5), spec=SPEC)
    res, calls, _ = _run_single(tmp_path, shell, top_rung_restarts=2)
    # rung 0 (2 turns) + rung 1 (3) + two clean restarts of rung 1 (3 each)
    assert calls == 2 + 3 + 3 + 3
    assert res.attempts == 4 and res.top_rung == 1 and not res.solved


def test_single_stops_on_budget_not_on_ideas(tmp_path):
    shell = lambda n, m: ModelResponse(
        tool_calls=(ToolCall(f"c{n}", "shell", {"cmd": "echo x"}),),
        usage=Usage(50, 50), spec=SPEC)
    res, calls, _ = _run_single(tmp_path, shell, caps=Caps(total_tokens=1000),
                                top_rung_restarts=99)
    assert calls == 10 and "budget" in res.reason


def test_scheduler_does_not_spin_on_spent_rung(tmp_path):
    plat = FilesTargetPlatform(_fixture_root(tmp_path))
    log = RunLog(tmp_path / "logs")
    sub = FlagSubmitter(plat, log)
    shell = lambda n, m: ModelResponse(
        tool_calls=(ToolCall(f"c{n}", "shell", {"cmd": f"echo s{len(m)}"}),),
        usage=Usage(5, 5), spec=SPEC)
    s = Scheduler(platform=plat, ladder=_ladder(2, 2), model_factory=lambda sp: _Fn(shell, sp),
                  budget=Budget(Caps()), log=log, submitter=sub, executor=LocalExecutor(),
                  work_root=tmp_path / "w", concurrency=1, plan_first=False)
    s.load()
    t = threading.Thread(target=s.run, daemon=True)
    t.start()
    t.join(20)
    assert not t.is_alive(), "scheduler never terminated"
    rec = next(iter(s._records.values()))
    assert rec.status == "dropped" and rec.attempts == 2


# --- 2. tool calls stay in the transcript ------------------------------------

def test_solver_keeps_tool_calls_on_the_assistant_turn():
    model = _Fn(lambda n, m: _call(n, "nothing") if n == 1 else _call(n, FLAG))
    solver, _, _, state = _solver(model)
    assert solver.run().outcome == Outcome.SOLVED
    assistant = [m for m in state.messages if m.role == "assistant"]
    assert assistant[0].tool_calls[0].arguments == {"text": "nothing"}
    tool = [m for m in state.messages if m.role == "tool"]
    assert tool[0].tool_call_id == assistant[0].tool_calls[0].id


def _history():
    return [Message("system", "s"), Message("user", "task"),
            Message("assistant", "", tool_calls=(ToolCall("a", "shell", {"cmd": "ls"}),
                                                 ToolCall("b", "shell", {"cmd": "id"}))),
            Message("tool", "f.txt", tool_call_id="a", name="shell"),
            Message("tool", "uid=0", tool_call_id="b", name="shell")]


def test_openai_payload_pairs_calls_with_results():
    chat = OpenAIModel._to_chat(_history())
    calls = chat[2]["tool_calls"]
    assert [c["id"] for c in calls] == ["a", "b"]
    assert json.loads(calls[0]["function"]["arguments"]) == {"cmd": "ls"}
    assert [m["tool_call_id"] for m in chat[3:]] == ["a", "b"]


def test_anthropic_payload_pairs_calls_with_results():
    _, msgs = AnthropicModel._split(_history())
    assert [b["type"] for b in msgs[1]["content"]] == ["tool_use", "tool_use"]
    # both results in ONE user turn, straight after the assistant turn
    assert len(msgs) == 3 and msgs[2]["role"] == "user"
    assert [b["tool_use_id"] for b in msgs[2]["content"]] == ["a", "b"]


def test_compaction_never_orphans_a_tool_result():
    def fn(n, m):
        if n == 6:
            raise ContextOverflow("too long")
        return ModelResponse(tool_calls=(ToolCall(f"a{n}", "out", {"text": "x%d" % n}),
                                         ToolCall(f"b{n}", "out", {"text": "y%d" % n}),
                                         ToolCall(f"d{n}", "out", {"text": "z%d" % n})),
                             usage=Usage(5, 5), spec=SPEC)
    solver, _, _, state = _solver(_Fn(fn), max_iterations=7)
    solver.run()
    seen = set()
    for m in state.messages:
        seen.update(tc.id for tc in m.tool_calls)
        if m.role == "tool":
            assert m.tool_call_id in seen, "tool result without its call"
    assert any("elided" in m.content for m in state.messages)


# --- 4. the agent shell is not a login shell ---------------------------------

def test_shell_does_not_source_profile_from_the_challenge_dir(tmp_path):
    for name in (".profile", ".bash_profile", ".bash_login"):
        (tmp_path / name).write_text("echo PLANTED\nexport PATH=/nonexistent\n")
    out, code = LocalExecutor().run("echo ok; command -v ls >/dev/null && echo path-intact",
                                    tmp_path, 10)
    assert b"PLANTED" not in out
    assert out.split() == [b"ok", b"path-intact"] and code == 0


# --- 5. a turn of prose is nudged, not treated as giving up ------------------

def test_prose_only_turns_get_a_nudge_before_stalling():
    def fn(n, m):
        if n <= 2:
            return ModelResponse(text="Let me analyse the binary next.", spec=SPEC)
        return _call(n, FLAG)
    solver, plat, _, state = _solver(_Fn(fn))
    assert solver.run().outcome == Outcome.SOLVED
    assert sum("Make a tool call now" in m.content for m in state.messages) == 2


def test_persistent_prose_still_stalls():
    model = _Fn(lambda n, m: ModelResponse(text="thinking...", spec=SPEC))
    solver, _, _, _ = _solver(model, max_iterations=50)
    assert solver.run().outcome == Outcome.STALLED
    assert model.n == 3


# --- 7. grader and model blips do not lose the flag or the run ---------------

def test_submit_is_retried_through_a_grader_blip():
    plat = _Plat(fail_first=2)
    solver, _, sub, _ = _solver(_Fn(lambda n, m: _call(n, FLAG)), plat=plat)
    assert solver.run().outcome == Outcome.SOLVED
    assert plat.calls == [FLAG, FLAG, FLAG]


def test_flag_survives_a_grader_outage_and_is_resubmitted():
    plat = _Plat(fail_first=5)            # outlasts the in-call retries
    model = _Fn(lambda n, m: _call(n, FLAG if n == 1 else f"other {n}"))
    solver, _, sub, _ = _solver(model, plat=plat)
    out = solver.run()                    # must not raise
    assert out.outcome == Outcome.SOLVED and sub.is_solved("c")
    assert model.n == 1                   # resubmitted before the next model call
    assert sub.pending_count("c") == 0


def test_unexpected_adapter_exception_does_not_escape_submit():
    class Boom(_Plat):
        def submit_flag(self, cid, flag):
            raise ConnectionResetError("peer reset")
    solver, _, sub, _ = _solver(_Fn(lambda n, m: _call(n, FLAG)), plat=Boom(),
                                max_iterations=2)
    assert solver.run().outcome == Outcome.STALLED
    assert sub.pending_count("c") == 1


def test_model_errors_are_retried_with_backoff(monkeypatch):
    waits = []
    monkeypatch.setattr(solver_mod, "_sleep", waits.append)
    def fn(n, m):
        if n <= 2:
            raise ModelError("429 rate limited")
        return _call(n, FLAG)
    solver, _, _, _ = _solver(_Fn(fn))
    assert solver.run().outcome == Outcome.SOLVED
    assert waits == list(solver_mod.MODEL_RETRY_DELAYS[:2])


def test_dead_endpoint_ends_the_attempt_as_error():
    def fn(n, m):
        raise ModelError("connection refused")
    model = _Fn(fn)
    solver, _, _, _ = _solver(model)
    assert solver.run().outcome == Outcome.ERROR
    assert model.n == len(solver_mod.MODEL_RETRY_DELAYS) + 1


# --- 8. flag format ----------------------------------------------------------

def test_prefixed_flag_yields_both_candidates():
    store = EvidenceStore(pattern=flag_pattern())
    assert [g.flag for g in store.record("x", b"got DCTF{abc123} here")] == \
        ["CTF{abc123}", "DCTF{abc123}"]
    assert [g.flag for g in store.record("y", b"plain CTF{zzz}.")] == ["CTF{zzz}"]


def test_prefixed_flag_is_solved_end_to_end():
    plat = _Plat(answer="DCTF{abc123}")
    solver, _, _, _ = _solver(_Fn(lambda n, m: _call(n, "flag: DCTF{abc123}")), plat=plat)
    assert solver.run().outcome == Outcome.SOLVED
    assert plat.calls == ["CTF{abc123}", "DCTF{abc123}"]


def test_flag_regex_from_env(monkeypatch):
    monkeypatch.setenv("CTF_FLAG_REGEX", r"flag\{[^}]+\}")
    plat = _Plat(answer="flag{custom}")
    solver, _, _, _ = _solver(_Fn(lambda n, m: _call(n, "CTF{decoy} flag{custom}")), plat=plat)
    assert solver.run().outcome == Outcome.SOLVED
    assert plat.calls == ["flag{custom}"]


def test_invalid_flag_regex_falls_back(monkeypatch):
    monkeypatch.setenv("CTF_FLAG_REGEX", "flag{[")
    assert flag_pattern().search(b"CTF{x}")


def test_prose_claim_is_submitted_when_wrong_flags_are_free():
    def fn(n, m):
        return ModelResponse(text=f"I decoded it by hand: {FLAG}", spec=SPEC)
    solver, plat, _, _ = _solver(_Fn(fn))
    assert solver.run().outcome == Outcome.SOLVED
    assert plat.calls == [FLAG]


def test_wrong_prose_claim_is_bounded():
    model = _Fn(lambda n, m: ModelResponse(text="The flag is CTF{guess}", spec=SPEC))
    solver, plat, _, _ = _solver(model, max_iterations=50)
    assert solver.run().outcome == Outcome.STALLED
    assert plat.calls == ["CTF{guess}"] * 3 and model.n == 3
