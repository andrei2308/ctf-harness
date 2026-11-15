"""Restart handover notes, the notes index in the task prompt, and preflight."""

import json
import tempfile
from pathlib import Path

import pytest

from harness import preflight
from harness.agents.base import new_state, restart_recap
from harness.agents.knowledge import KnowledgeSearchTool, primer, read_note
from harness.agents.limits import Limits
from harness.agents.specialists import route
from harness.agents.tools import LocalExecutor, ToolContext
from harness.config import Config
from harness.flags.submit import FlagSubmitter
from harness.inference.base import (Effort, Message, Model, ModelError,
                                    ModelResponse, ModelSpec, ToolCall, Usage)
from harness.platforms.base import Challenge
from harness.platforms.files_target import FilesTargetPlatform
from harness.scheduler.budget import Budget, Caps
from harness.scheduler.ladder import Ladder, Rung
from harness.single import run_challenge
from harness.telemetry.run_log import RunLog

SPEC = ModelSpec(name="m", effort=Effort.LOW)


class _Fn(Model):
    def __init__(self, fn, spec=SPEC):
        super().__init__(spec)
        self.fn, self.n = fn, 0
    def complete(self, messages, tools=None):
        self.n += 1
        return self.fn(self.n, messages, tools)


# --- notes index -------------------------------------------------------------

@pytest.fixture
def kb(tmp_path, monkeypatch):
    base = tmp_path / "kb"
    (base / "ctf-notes" / "pwn_notes").mkdir(parents=True)
    (base / "ctf-notes" / "crypto").mkdir()
    (base / "README.md").write_text("# about this folder\n")
    (base / "ctf-notes" / "pwn_notes" / "format_string.md").write_text(
        "# Format String Vulnerability\n\n## Finding the Offset\nsend %p until AAAA shows\n"
        "```python\n# not a heading\npayload = fmtstr_payload(6, {got: win})\n```\n"
        "## Writing Data\nuse fmtstr_payload\n")
    (base / "ctf-notes" / "pwn_notes" / "decision_matrix.md").write_text("### pick a house\n")
    (base / "ctf-notes" / "crypto" / "PLAYBOOK.md").write_text(
        "# Crypto playbook\n## RSA small exponent\ncube root when e=3\n## LCG\npredict\n")
    (base / "ctf-notes" / "crypto" / "crypto_solver.py").write_text("print('x')\n")
    (base / "ctf-notes" / "web_notes.md").write_text("## SQL injection\nsqlmap\n")
    monkeypatch.setenv("CTF_KNOWLEDGE_DIR", str(base))
    return base


def test_primer_lists_only_this_categorys_notes_with_headings(kb):
    text = primer("pwn")
    assert "format_string.md: Format String Vulnerability; Finding the Offset; Writing Data" in text
    assert "not a heading" not in text                 # code-block comments are skipped
    assert "crypto" not in text.split("\n", 1)[1] and "web_notes" not in text
    # the decision guide is listed before ordinary notes
    assert text.index("decision_matrix.md") < text.index("format_string.md")
    assert str(kb.resolve()) in text                   # absolute path, usable from shell


def test_primer_points_at_the_matching_section_and_lists_scripts(kb):
    text = primer("crypto", hint="baby rsa with a small public exponent")
    assert "Likely relevant to this challenge: ctf-notes/crypto/PLAYBOOK.md § RSA small exponent" in text
    assert "crypto_solver.py (script)" in text


def test_primer_is_bounded_and_can_be_disabled(kb):
    assert len(primer("generalist", max_chars=300)) < 700
    assert "more (search with `knowledge`)" in primer("generalist", max_chars=300)
    assert primer("pwn", max_chars=0) == ""
    assert primer("mobile") == ""                      # no notes for it: say nothing


def test_task_prompt_carries_the_index(kb):
    ch = Challenge(id="c", name="fmt", category="pwn", description="printf(buf) bug")
    spec = route(ch, None)
    prompt = spec.task_prompt(ch, Path("/w"), None, [])
    assert "Offline notes for this category" in prompt and "format_string.md" in prompt
    assert prompt.rstrip().endswith("Find the flag.")


def test_knowledge_tool_reads_a_note_or_one_section(kb):
    tool = KnowledgeSearchTool()
    ctx = ToolContext("c", kb, LocalExecutor())
    res = tool.run({"path": "ctf-notes/pwn_notes/format_string.md", "section": "offset"}, ctx)
    text = res.output.decode()
    assert text.startswith("## Finding the Offset") and "Writing Data" not in text
    assert res.is_evidence is False
    whole = tool.run({"path": "ctf-notes/pwn_notes/format_string.md"}, ctx).output.decode()
    assert "Writing Data" in whole
    assert "no section matching" in read_note(kb, "ctf-notes/crypto/PLAYBOOK.md", "nope")
    assert "outside the knowledge base" in read_note(kb, "../../etc/passwd")
    assert tool.run({}, ctx).error


# --- restart handover note ---------------------------------------------------

def _state(tmp):
    ctx = ToolContext("c", tmp, LocalExecutor())
    st = new_state("c", tmp, ctx, "sys", "task")
    st.messages += [
        Message("assistant", "", tool_calls=(ToolCall("1", "shell", {"cmd": "checksec ./vuln"}),)),
        Message("tool", "NX enabled, no PIE", tool_call_id="1", name="shell")]
    return st


def test_recap_is_written_by_the_model_and_charged(tmp_path):
    seen = {}
    def fn(n, messages, tools):
        seen["last"], seen["tools"] = messages[-1].content, tools
        return ModelResponse(text="NX on, no PIE. ret2win failed: canary. Try fmt leak.",
                             usage=Usage(100, 40), spec=SPEC)
    log = RunLog(tmp_path / "l")
    budget = Budget(Caps())
    recap = restart_recap(_Fn(fn), _state(tmp_path), [{"name": "shell"}], budget, log)
    assert "clean context" in seen["last"] and seen["tools"] == [{"name": "shell"}]
    assert "ret2win failed: canary" in recap and ".tool_output/" in recap
    assert budget.snapshot()["global_tokens"] == 140


def test_recap_falls_back_to_the_command_list(tmp_path):
    def boom(n, messages, tools):
        raise ModelError("503")
    log = RunLog(tmp_path / "l")
    recap = restart_recap(_Fn(boom), _state(tmp_path), [], Budget(Caps()), log)
    assert "- shell: checksec ./vuln" in recap
    empty = restart_recap(_Fn(lambda n, m, t: ModelResponse(text="  ", spec=SPEC)),
                          _state(tmp_path), [], Budget(Caps()), log)
    assert "- shell: checksec ./vuln" in empty


def test_restart_starts_from_the_handover_note(tmp_path):
    c = tmp_path / "fx" / "only"
    (c / "files").mkdir(parents=True)
    (c / "challenge.json").write_text(json.dumps({"id": "only", "name": "only", "flag": "CTF{x}"}))
    plat = FilesTargetPlatform(tmp_path / "fx")
    log = RunLog(tmp_path / "logs")
    first_user_msgs = []
    def fn(n, messages, tools):
        if "handover note your next attempt" in messages[-1].content:
            return ModelResponse(text="HANDOVER: offset is 72", spec=SPEC)
        first_user_msgs.append([m.content for m in messages if m.role == "user"])
        return ModelResponse(tool_calls=(ToolCall(f"c{len(messages)}", "shell",
                                                  {"cmd": f"echo {len(messages)}"}),),
                             usage=Usage(1, 1), spec=SPEC)
    run_challenge(challenge=plat.get_challenge("only"), platform=plat,
                  ladder=Ladder([Rung(SPEC, 2)]), model_factory=lambda s: _Fn(fn, s),
                  budget=Budget(Caps()), log=log, submitter=FlagSubmitter(plat, log),
                  executor=LocalExecutor(), work_root=tmp_path / "w", available=set(),
                  plan_first=False, top_rung_restarts=1)
    # the first turn after the restart sees task + note, and nothing of the old transcript
    after = first_user_msgs[2]
    assert len(after) == 2 and "HANDOVER: offset is 72" in after[1]


# --- preflight ---------------------------------------------------------------

def _good(n, messages, tools):
    if tools and not any(m.role == "tool" for m in messages):
        return ModelResponse(tool_calls=(ToolCall("t1", "shell", {"cmd": "echo preflight"}),),
                             usage=Usage(20, 5), spec=SPEC)
    return ModelResponse(text="ready", usage=Usage(20, 2), spec=SPEC)


def test_preflight_passes_on_a_working_endpoint():
    res = preflight.run(Config(inference_backend="openai"), lambda spec: _Fn(_good, spec))
    assert all(ok for _, ok, _ in res), res
    assert [n[0] for n, _, _ in res][:4] == ["1", "2", "3", "4"]
    assert sum(n.startswith("5.") for n, _, _ in res) == 4      # one per distinct rung


def test_preflight_names_the_fix_when_a_rung_is_rejected():
    def picky(spec):
        def fn(n, messages, tools):
            if spec.max_tokens > 8192:
                raise ModelError("max_tokens is too large: 16384 > 8192")
            return _good(n, messages, tools)
        return _Fn(fn, spec)
    res = preflight.run(Config(inference_backend="openai"), picky)
    failed = [(n, d) for n, ok, d in res if not ok]
    assert len(failed) == 2 and all("CTF_MAX_OUTPUT_TOKENS" in d for _, d in failed)
    ok = preflight.run(Config(inference_backend="openai", max_output_tokens=8192), picky)
    assert all(o for _, o, _ in ok)


def test_preflight_flags_missing_tool_calling_and_usage():
    def no_tools(n, messages, tools):
        return ModelResponse(text="I cannot call tools", spec=SPEC)   # and no usage
    res = preflight.run(Config(inference_backend="openai"), lambda s: _Fn(no_tools, s))
    by = {n[0]: (ok, d) for n, ok, d in res}
    assert by["1"][0] and not by["2"][0] and "token caps will never trigger" in by["2"][1]
    assert not by["3"][0] and "tool (function) calling" in by["3"][1]
    assert "4" not in by


def test_preflight_stops_early_when_unreachable():
    def dead(n, messages, tools):
        raise ModelError("Connection error.")
    res = preflight.run(Config(inference_backend="openai"), lambda s: _Fn(dead, s))
    assert len(res) == 1 and not res[0][1] and "base URL" in res[0][2]


def test_describe_never_prints_the_key(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-very-secret")
    monkeypatch.setenv("OPENAI_BASE_URL", "http://10.0.0.5:8000/v1")
    text = "\n".join(preflight.describe(Config(inference_backend="openai", fast_model="qwen")))
    assert "sk-very-secret" not in text and "api key        set" in text
    assert "10.0.0.5:8000" in text and "qwen" in text


def test_task_prompt_gives_an_absolute_work_dir_the_shell_is_already_in(kb):
    # A relative path made models `cd runs/work/<id>` from inside it.
    ch = Challenge(id="c", name="x", category="misc")
    prompt = route(ch, None).task_prompt(ch, Path("runs/work/c"), None, [Path("a.txt")])
    assert f"already runs in your working directory, {Path('runs/work/c').resolve()}" in prompt
    assert "Files in your working directory: a.txt" in prompt
