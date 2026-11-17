"""submit_flag: answers that are not flag-shaped. Rehearsal (wifi-get-me): the
agent cracked a WPA2 password in 49 s and then repeated it for the rest of
its budget, because nothing could submit 's3cretpass'."""

import tempfile
from pathlib import Path

from harness.agents.base import Outcome, Solver, new_state
from harness.agents.tools import (LocalExecutor, SubmitFlagTool, Tool, ToolContext,
                                   ToolProfile, ToolResult)
from harness.flags.grounding import EvidenceStore
from harness.flags.submit import FlagSubmitter
from harness.inference.base import ModelResponse, ToolCall, Usage
from harness.inference.null import ScriptedModel
from harness.platforms.base import Platform, SubmitResult
from harness.scheduler.budget import Budget, Caps
from harness.telemetry.run_log import RunLog

ANSWER = "s3cretpass"


def test_independent_evidence_excludes_a_command_that_prints_the_value():
    s = EvidenceStore()
    s.record("shell:echo", f"{ANSWER}\n".encode(), cmd=f'{{"cmd": "echo {ANSWER}"}}')
    assert s.contains_independent(ANSWER) is None
    s.record("shell:aircrack", f"KEY FOUND! [ {ANSWER} ]".encode(),
             cmd='{"cmd": "aircrack-ng -w rockyou.txt handshake.cap"}')
    assert s.contains_independent(ANSWER).source == "shell:aircrack"


class _Plat(Platform):
    def __init__(self, answer=ANSWER): self.answer, self.calls = answer, []
    def list_challenges(self): return []
    def get_challenge(self, c): ...
    def download_files(self, c, d): return []
    def start_instance(self, c): ...
    def get_conn_info(self, c): ...
    def submit_flag(self, c, flag):
        self.calls.append(flag)
        return SubmitResult(accepted=flag == self.answer, message="" if flag == self.answer else "wrong")


class _Out(Tool):
    """Stands in for shell: prints what it is told, like a real command would."""
    name = "shell"
    description = "run"
    def input_schema(self): return {"type": "object", "properties": {"cmd": {"type": "string"}}}
    def run(self, args, ctx):
        cmd = args["cmd"]
        text = (f"KEY FOUND! [ {ANSWER} ]" if cmd.startswith("aircrack")
                else cmd.removeprefix("echo ") if cmd.startswith("echo ") else "")
        return ToolResult(self.name, text.encode(), f"shell:{cmd[:60]}")


def _call(i, name, **args):
    return ModelResponse(tool_calls=(ToolCall(id=str(i), name=name, arguments=args),),
                         usage=Usage(input=1, output=1), stop_reason="tool_calls")


def _run(script, penalize=True):
    d = tempfile.mkdtemp()
    log, plat = RunLog(d), _Plat()
    sub = FlagSubmitter(plat, log, penalize_wrong=penalize)
    state = new_state("c", Path(d), ToolContext("c", Path(d), LocalExecutor()),
                      system_prompt="s", task_prompt="t")
    out = Solver(model=ScriptedModel(script + [ModelResponse(text="done", stop_reason="stop")] * 4),
                 profile=ToolProfile("t", [_Out(), SubmitFlagTool()]), state=state,
                 budget=Budget(Caps()), log=log, submitter=sub, max_iterations=10,
                 plan_first=False).run()
    log.close()
    return out, plat, state


def test_a_cracked_password_is_submitted_and_solves():
    out, plat, _ = _run([_call(1, "shell", cmd="aircrack-ng -w rockyou.txt handshake.cap"),
                         _call(2, "submit_flag", flag=ANSWER)])
    assert plat.calls == [ANSWER] and out.outcome == Outcome.SOLVED


def test_an_echoed_value_is_not_evidence_when_wrong_answers_cost():
    out, plat, state = _run([_call(1, "shell", cmd=f"echo {ANSWER}"),
                             _call(2, "submit_flag", flag=ANSWER)])
    assert plat.calls == [] and out.outcome != Outcome.SOLVED
    assert any("not in the output of any command" in m.content for m in state.messages)


def test_when_wrong_answers_are_free_an_ungrounded_answer_is_tried():
    out, plat, _ = _run([_call(1, "submit_flag", flag=ANSWER)], penalize=False)
    assert plat.calls == [ANSWER] and out.outcome == Outcome.SOLVED


def test_explicit_submissions_are_capped_when_wrong_answers_cost():
    from harness.agents.base import MAX_ANSWER_SUBMITS_PENALIZED as cap
    wrong = [f"guess{i}" for i in range(cap + 2)]
    # each guess appears in independent output, so only the cap stops them
    class Many(_Out):
        def run(self, args, ctx):
            return ToolResult(self.name, " ".join(wrong).encode(), "shell:list")
    d = tempfile.mkdtemp()
    log, plat = RunLog(d), _Plat()
    state = new_state("c", Path(d), ToolContext("c", Path(d), LocalExecutor()),
                      system_prompt="s", task_prompt="t")
    calls = [_call(0, "shell", cmd="list")] + [_call(i + 1, "submit_flag", flag=w)
                                              for i, w in enumerate(wrong)]
    Solver(model=ScriptedModel(calls + [ModelResponse(text="done", stop_reason="stop")] * 4),
           profile=ToolProfile("t", [Many(), SubmitFlagTool()]), state=state,
           budget=Budget(Caps()), log=log, submitter=FlagSubmitter(plat, log, penalize_wrong=True),
           max_iterations=20, plan_first=False).run()
    log.close()
    assert len(plat.calls) == cap


def test_ungrounded_guesses_are_capped_when_wrong_flags_are_free():
    # Contest mode on zodiac: 22 guessed spellings went out.
    from harness.agents.base import MAX_GUESSES
    script = [_call(10 + i, "submit_flag", flag=f"ctf{{try_{i}}}") for i in range(MAX_GUESSES + 4)]
    out, plat, state = _run(script, penalize=False)
    assert len(plat.calls) == MAX_GUESSES
    assert any("guess budget" in m.content for m in state.messages)


def test_a_flag_shaped_answer_must_meet_the_stated_format():
    # metar-station: format UNBRK{sha256}; the model pushed a planted
    # CTF{try_harder...} through submit_flag at the end of its time.
    from harness.flags.grounding import format_check
    d = tempfile.mkdtemp()
    log, plat = RunLog(d), _Plat(answer="UNBRK{" + "a" * 64 + "}")
    state = new_state("c", Path(d), ToolContext("c", Path(d), LocalExecutor()),
                      system_prompt="s", task_prompt="t",
                      flag_check=format_check("1. What is the flag? (format: UNBRK{sha256})"))

    class Page(_Out):
        def run(self, args, ctx):
            return ToolResult(self.name, b"report: CTF{try_harder_you_are_close} | pin 4821",
                              "shell:curl")
    script = [_call(1, "shell", cmd="curl"), _call(2, "submit_flag", flag="CTF{try_harder_you_are_close}"),
              _call(3, "submit_flag", flag="4821")]
    Solver(model=ScriptedModel(script + [ModelResponse(text="done", stop_reason="stop")] * 4),
           profile=ToolProfile("t", [Page(), SubmitFlagTool()]), state=state, budget=Budget(Caps()),
           log=log, submitter=FlagSubmitter(plat, log, penalize_wrong=True),
           max_iterations=6, plan_first=False).run()
    log.close()
    assert "CTF{try_harder_you_are_close}" not in plat.calls      # refused: wrong format
    assert "4821" in plat.calls                                     # a non-flag answer still goes
    assert any("does not match the flag format" in m.content for m in state.messages)
