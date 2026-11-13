"""Offline knowledge retrieval, and the guarantee that knowledge output can
never ground a flag."""

import tempfile
from pathlib import Path

from harness.agents.base import Outcome, Solver, new_state
from harness.agents.knowledge import KnowledgeSearchTool, search_knowledge
from harness.agents.tools import LocalExecutor, ToolContext, ToolProfile
from harness.flags.submit import FlagSubmitter
from harness.inference.base import ModelResponse, ToolCall, Usage
from harness.inference.null import ScriptedModel
from harness.platforms.base import Platform, SubmitResult
from harness.scheduler.budget import Budget, Caps
from harness.telemetry.run_log import RunLog


def _kb(root: Path):
    root.mkdir(parents=True, exist_ok=True)
    (root / "rsa.md").write_text(
        "# RSA attacks\nWiener attack for small d.\nCommon modulus when same n.\n"
        "Franklin-Reiter for related messages.\n")
    (root / "stego.md").write_text("# Stego\nzsteg for PNG LSB. steghide for JPEG.\n")


def test_search_returns_relevant_snippet():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d) / "kb"
        _kb(root)
        out = search_knowledge(root, "Wiener small d RSA")
        assert "Wiener" in out and "rsa.md" in out


def test_search_no_match():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d) / "kb"
        _kb(root)
        assert "No knowledge-base entries matched" in search_knowledge(root, "zzzqqq")


def test_knowledge_tool_marks_output_non_evidence(monkeypatch):
    with tempfile.TemporaryDirectory() as d:
        root = Path(d) / "kb"
        _kb(root)
        monkeypatch.setenv("CTF_KNOWLEDGE_DIR", str(root))
        ctx = ToolContext(challenge_id="c", work_dir=Path(d), executor=LocalExecutor())
        res = KnowledgeSearchTool().run({"query": "Wiener"}, ctx)
        assert res.is_evidence is False and b"Wiener" in res.output


class _Plat(Platform):
    def __init__(self): self.calls = []
    def list_challenges(self): return []
    def get_challenge(self, cid): ...
    def download_files(self, cid, dest): return []
    def start_instance(self, cid): ...
    def get_conn_info(self, cid): ...
    def submit_flag(self, cid, flag):
        self.calls.append(flag); return SubmitResult(accepted=True)


class _FlagInKnowledgeTool(KnowledgeSearchTool):
    """Simulates a writeup snippet that contains an example flag."""
    def run(self, args, ctx):
        from harness.agents.tools import ToolResult
        return ToolResult("knowledge", b"example: CTF{this_is_from_a_writeup}",
                          "knowledge:x", is_evidence=False)


def test_flag_in_knowledge_output_does_not_ground():
    with tempfile.TemporaryDirectory() as d:
        log = RunLog(d)
        plat = _Plat()
        sub = FlagSubmitter(plat, log)
        ctx = ToolContext(challenge_id="c", work_dir=Path(d), executor=LocalExecutor())
        state = new_state("c", Path(d), ctx, "sys", "go")
        model = ScriptedModel([
            ModelResponse(tool_calls=(ToolCall(id="1", name="knowledge",
                                               arguments={"query": "x"}),),
                          usage=Usage(input=5, output=5), stop_reason="tool"),
            ModelResponse(text="The flag is CTF{this_is_from_a_writeup}", stop_reason="end"),
        ])
        solver = Solver(model=model, profile=ToolProfile("t", [_FlagInKnowledgeTool()]),
                        state=state, budget=Budget(Caps()), log=log, submitter=sub,
                        max_iterations=6, plan_first=False)
        out = solver.run()
        log.close()
        # The flag appeared only in knowledge output (non-evidence) and in model
        # prose — so it must NOT be submitted.
        assert plat.calls == []
        assert not sub.is_solved("c")
        assert out.outcome in (Outcome.STALLED,)
