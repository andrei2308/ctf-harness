"""view_image: an image reaches the model in a user message after the tool
results; a model that rejects images is told in text and the run goes on."""

import base64
import struct
import tempfile
import zlib
from pathlib import Path
from types import SimpleNamespace

from harness.agents.base import Solver, new_state
from harness.agents.exttools import ViewImageTool
from harness.agents.tools import LocalExecutor, ToolContext, ToolProfile
from harness.flags.submit import FlagSubmitter
from harness.inference.base import Message, ModelResponse, ModelSpec, ToolCall, Usage
from harness.inference.null import ScriptedModel
from harness.inference.openai_client import OpenAIModel
from harness.platforms.base import Platform, SubmitResult
from harness.scheduler.budget import Budget, Caps
from harness.telemetry.run_log import RunLog


def _png(path: Path, w=8, h=8):
    rows = b"".join(b"\x00" + bytes([0] * w) for _ in range(h))
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xffffffff)
    path.write_bytes(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 0, 0, 0, 0))
                     + chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b""))


def _ctx(d):
    return ToolContext(challenge_id="c", work_dir=Path(d), executor=LocalExecutor())


def test_view_image_returns_a_data_url_and_is_not_evidence(tmp_path):
    _png(tmp_path / "trail.png")
    r = ViewImageTool().run({"path": "trail.png"}, _ctx(tmp_path))
    assert not r.error and not r.is_evidence
    url = r.meta["images"][0]
    assert url.startswith("data:image/png;base64,")
    assert base64.b64decode(url.split(",", 1)[1]).startswith(b"\x89PNG")


def test_view_image_refuses_files_outside_the_work_dir_and_bad_input(tmp_path):
    assert "only files" in ViewImageTool().run({"path": "/etc/passwd"}, _ctx(tmp_path)).error
    assert "no such file" in ViewImageTool().run({"path": "nope.png"}, _ctx(tmp_path)).error
    (tmp_path / "x.png").write_text("not an image")
    assert ViewImageTool().run({"path": "x.png"}, _ctx(tmp_path)).error


class _Plat(Platform):
    def list_challenges(self): return []
    def get_challenge(self, cid): ...
    def download_files(self, cid, dest): return []
    def start_instance(self, cid): ...
    def get_conn_info(self, cid): ...
    def submit_flag(self, cid, flag): return SubmitResult(accepted=False)


def test_solver_attaches_the_image_after_tool_results_and_keeps_only_the_newest(tmp_path):
    _png(tmp_path / "a.png"); _png(tmp_path / "b.png")
    view = lambda i, p: ModelResponse(tool_calls=(ToolCall(id=i, name="view_image",
                                                           arguments={"path": p}),),
                                      usage=Usage(input=1, output=1), stop_reason="tool_calls")
    model = ScriptedModel([view("1", "a.png"), view("2", "b.png")] +
                          [ModelResponse(text="done", stop_reason="stop")] * 4)
    log = RunLog(tempfile.mkdtemp())
    state = new_state("c", tmp_path, _ctx(tmp_path), system_prompt="s", task_prompt="t")
    Solver(model=model, profile=ToolProfile("t", [ViewImageTool()]), state=state,
           budget=Budget(Caps()), log=log, submitter=FlagSubmitter(_Plat(), log),
           max_iterations=6, plan_first=False).run()
    log.close()
    msgs = state.messages
    with_images = [i for i, m in enumerate(msgs) if m.images]
    assert len(with_images) == 1                          # only the newest is still attached
    i = with_images[0]
    assert msgs[i].role == "user" and "b.png" in msgs[i].content
    assert msgs[i - 1].role == "tool"                     # right after the tool result
    assert any("image no longer shown" in m.content for m in msgs if m.role == "user")


def _resp():
    return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content="a square",
                           tool_calls=None), finish_reason="stop")],
                           usage=SimpleNamespace(prompt_tokens=3, completion_tokens=1,
                                                 prompt_tokens_details=None))


def test_openai_adapter_sends_image_parts():
    sent = []
    client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(
        create=lambda **kw: sent.append(kw) or _resp())))
    OpenAIModel(ModelSpec(name="seeing"), client=client).complete(
        [Message("user", "look", images=("data:image/png;base64,AAAA",))])
    content = sent[0]["messages"][0]["content"]
    assert content[0] == {"type": "text", "text": "look"}
    assert content[1]["image_url"]["url"] == "data:image/png;base64,AAAA"


def test_a_model_that_rejects_images_is_told_in_text_and_remembered():
    OpenAIModel._no_vision_models.discard("blind")
    sent = []

    def create(**kw):
        sent.append(kw)
        if isinstance(kw["messages"][0]["content"], list):
            raise RuntimeError("Error code: 400 - messages.content.type is invalid, "
                               "allowed values: ['text']")
        return _resp()

    client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
    msg = [Message("user", "look", images=("data:image/png;base64,AAAA",))]
    assert OpenAIModel(ModelSpec(name="blind"), client=client).complete(msg).text == "a square"
    assert len(sent) == 2 and "does not accept images" in sent[1]["messages"][0]["content"]
    sent.clear()
    OpenAIModel(ModelSpec(name="blind"), client=client).complete(msg)   # remembered
    assert len(sent) == 1
    OpenAIModel._no_vision_models.discard("blind")
