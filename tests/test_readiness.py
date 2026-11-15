"""Contest readiness: reasoning models, decoy flags, hashed fixture answers."""

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

from harness import preflight
from harness.agents.base import Outcome, Solver, new_state
from harness.agents.limits import Limits
from harness.agents.tools import LocalExecutor, Tool, ToolContext, ToolProfile, ToolResult
from harness.config import Config
from harness.flags.decoys import REPO_ROOT, collect_decoys, known_decoys
from harness.flags.grounding import EvidenceStore, flag_pattern
from harness.flags.submit import FlagSubmitter
from harness.inference.base import (Effort, Message, Model, ModelResponse, ModelSpec,
                                    ToolCall, Usage)
from harness.inference.openai_client import OpenAIModel
from harness.platforms.base import Challenge, ConnInfo, Platform, SubmitResult
from harness.platforms.files_target import FilesTargetPlatform
from harness.scheduler.budget import Budget, Caps
from harness.scheduler.ladder import Ladder, Rung
from harness.single import run_challenge
from harness.telemetry.run_log import RunLog

# Built at run time: tests/ is scanned for decoys, so a literal flag written in
# this file would itself be ignored by the harness.
REAL = "CTF" + "{the_real_contest_flag}"


class _Out(Tool):
    name = "out"
    description = "echo"
    def input_schema(self): return {"type": "object", "properties": {}}
    def run(self, args, ctx):
        return ToolResult(self.name, str(args.get("text", "")).encode(), "out:x")


class _Fn(Model):
    def __init__(self, fn, spec):
        super().__init__(spec)
        self.fn, self.n, self.caps_seen = fn, 0, []
    def complete(self, messages, tools=None):
        self.n += 1
        self.caps_seen.append(self.spec.max_tokens)
        return self.fn(self.n, messages, tools)


class _Remote(Platform):
    """A contest-like platform: the answer is NOT on this disk."""
    def __init__(self): self.calls = []
    def list_challenges(self): return [self.get_challenge("c")]
    def get_challenge(self, cid): return Challenge(id="c", name="c", category="misc")
    def download_files(self, cid, dest): return []
    def start_instance(self, cid): return ConnInfo()
    def get_conn_info(self, cid): return ConnInfo()
    def submit_flag(self, cid, flag):
        self.calls.append(flag)
        return SubmitResult(accepted=flag == REAL)


def _solver(model, tmp, limits=None):
    log = RunLog(tmp / "logs")
    sub = FlagSubmitter(_Remote(), log)
    state = new_state("c", tmp, ToolContext("c", tmp, LocalExecutor()), "sys", "go")
    return Solver(model=model, profile=ToolProfile("t", [_Out()]), state=state,
                  budget=Budget(Caps()), log=log, submitter=sub, max_iterations=10,
                  plan_first=False, limits=limits or Limits()), state, log


# --- reasoning models --------------------------------------------------------

def test_output_floor_raises_low_rungs_and_cap_still_wins():
    assert [r.spec.max_tokens for r in Config(min_output_tokens=12000).ladder().rungs] == \
        [12000, 12000, 16384, 32768]
    assert [r.spec.max_tokens for r in
            Config(min_output_tokens=12000, max_output_tokens=8192).ladder().rungs] == [8192] * 4


def test_cut_off_turn_doubles_the_cap_up_to_the_ceiling(tmp_path):
    def fn(n, messages, tools):
        if n <= 3:
            return ModelResponse(text="", stop_reason="length", usage=Usage(10, 4096))
        return ModelResponse(tool_calls=(ToolCall("1", "out", {"text": REAL}),))
    model = _Fn(fn, ModelSpec(name="m", max_tokens=4096))
    solver, state, log = _solver(model, tmp_path, Limits(max_output_tokens=10000))
    assert solver.run().outcome == Outcome.SOLVED
    assert model.caps_seen == [4096, 8192, 10000, 10000]
    assert state.output_floor == 10000
    log.close()
    raised = [json.loads(l) for l in log.path.read_text().splitlines()
              if '"solver.output_cap_raised"' in l]
    assert [(e["was"], e["now"]) for e in raised] == [(4096, 8192), (8192, 10000)]


def test_learned_cap_carries_into_the_next_attempt(tmp_path):
    cut = lambda n, m, t: ModelResponse(text="", stop_reason="length")
    solver, state, _ = _solver(_Fn(cut, ModelSpec(name="m", max_tokens=4096)), tmp_path)
    solver.run()
    nxt = _Fn(lambda n, m, t: ModelResponse(tool_calls=(ToolCall("1", "out", {"text": REAL}),)),
              ModelSpec(name="m", max_tokens=8192))
    Solver(model=nxt, profile=ToolProfile("t", [_Out()]), state=state, budget=Budget(Caps()),
           log=solver.log, submitter=solver.submitter, plan_first=False, limits=Limits()).run()
    assert nxt.caps_seen[0] == state.output_floor == 32768


def _fake_client(message, usage):
    create = lambda **kw: SimpleNamespace(
        choices=[SimpleNamespace(message=message, finish_reason="stop")], usage=usage)
    return SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))


def test_adapter_reports_reasoning_tokens():
    usage = SimpleNamespace(prompt_tokens=5, completion_tokens=900, prompt_tokens_details=None,
                            completion_tokens_details=SimpleNamespace(reasoning_tokens=850))
    msg = SimpleNamespace(content="ok", tool_calls=None)
    r = OpenAIModel(ModelSpec(name="m"), client=_fake_client(msg, usage)).complete([Message("user", "x")])
    assert r.reasoning_tokens == 850
    # an endpoint that returns the reasoning text but no count
    usage2 = SimpleNamespace(prompt_tokens=5, completion_tokens=900, prompt_tokens_details=None)
    msg2 = SimpleNamespace(content="ok", tool_calls=None, reasoning_content="t" * 400)
    r2 = OpenAIModel(ModelSpec(name="m"), client=_fake_client(msg2, usage2)).complete([Message("user", "x")])
    assert r2.reasoning_tokens == 100


def test_preflight_catches_a_reasoning_model_cut_off_at_rung_0():
    def fn(n, messages, tools):
        if "reverse-engineering" in messages[-1].content:
            return ModelResponse(text="", stop_reason="length", reasoning_tokens=4096,
                                 usage=Usage(50, 4096))
        if tools and not any(m.role == "tool" for m in messages):
            return ModelResponse(tool_calls=(ToolCall("t", "shell", {"cmd": "echo preflight"}),),
                                 usage=Usage(20, 5))
        return ModelResponse(text="ready", usage=Usage(20, 2))
    res = preflight.run(Config(inference_backend="openai"), lambda s: _Fn(fn, s))
    six = [(ok, d) for n, ok, d in res if n.startswith("6.")]
    assert len(six) == 1 and not six[0][0]
    assert "CTF_MIN_OUTPUT_TOKENS" in six[0][1] and "4096 hidden tokens" in six[0][1]


# --- decoy flags -------------------------------------------------------------

def test_decoys_come_from_tests_and_fixtures_not_notes(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "x.json").write_text('{"flag": "CTF{toy_one}"} and DCTF{toy_two}')
    found = collect_decoys([tmp_path / "a", tmp_path / "missing"], flag_pattern())
    assert {"CTF{toy_one}", "CTF{toy_two}", "DCTF{toy_two}"} <= found
    shipped = known_decoys()
    fixture_flag = json.loads((REPO_ROOT / "fixtures/warmup-01/challenge.json").read_text())["flag"]
    assert fixture_flag in shipped
    assert not any("knowledge" in str(p) for p in __import__("harness.flags.decoys",
                   fromlist=["_scan_roots"])._scan_roots())


def test_store_never_latches_or_claims_a_decoy():
    store = EvidenceStore(pattern=flag_pattern(), ignore=frozenset({"CTF{toy}"}))
    assert [g.flag for g in store.record("x", f"CTF{{toy}} then {REAL}".encode())] == [REAL]
    assert store.claims_in("it is CTF{toy}") == []


def test_contest_run_ignores_shipped_toy_flags_but_the_fixture_rig_does_not(tmp_path):
    toy = json.loads((REPO_ROOT / "fixtures/warmup-01/challenge.json").read_text())["flag"]
    spec = ModelSpec(name="m", effort=Effort.LOW)
    wander = lambda n, m, t: ModelResponse(tool_calls=(ToolCall(
        f"c{n}", "shell", {"cmd": f"echo '{toy}'; echo '{REAL}'"}),))
    plat = _Remote()
    log = RunLog(tmp_path / "l")
    res = run_challenge(challenge=plat.get_challenge("c"), platform=plat,
                        ladder=Ladder([Rung(spec, 3)]), model_factory=lambda s: _Fn(wander, s),
                        budget=Budget(Caps()), log=log, submitter=FlagSubmitter(plat, log),
                        executor=LocalExecutor(), work_root=tmp_path / "w", available=set(),
                        plan_first=False)
    assert res.solved and plat.calls == [REAL]            # the toy flag was never sent
    # with the fixtures rig the same toy flag is the answer and must still work
    fx = FilesTargetPlatform(REPO_ROOT / "fixtures")
    log2 = RunLog(tmp_path / "l2")
    res2 = run_challenge(challenge=fx.get_challenge("warmup-01"), platform=fx,
                         ladder=Ladder([Rung(spec, 3)]), model_factory=lambda s: _Fn(wander, s),
                         budget=Budget(Caps()), log=log2, submitter=FlagSubmitter(fx, log2),
                         executor=LocalExecutor(), work_root=tmp_path / "w2", available=set(),
                         plan_first=False)
    assert res2.solved


# --- hashed fixture answers --------------------------------------------------

def _suite(tmp, meta, flag_txt=None):
    c = tmp / "suite" / "t1"
    c.mkdir(parents=True)
    (c / "challenge.json").write_text(json.dumps({"id": "t1", "name": "t1", **meta}))
    if flag_txt:
        (c / "flag.txt").write_text(flag_txt)
    return tmp / "suite"


def test_files_platform_grades_against_hashes(tmp_path):
    h = lambda f: hashlib.sha256(f.encode()).hexdigest()
    root = _suite(tmp_path, {"flags_sha256": [h("CTF{a}"), h("CTF{b}")]})
    plat = FilesTargetPlatform(root)
    assert plat.get_challenge("t1").flags_required == 2
    assert plat.submit_flag("t1", " CTF{b}\n").accepted
    assert not plat.submit_flag("t1", "CTF{c}").accepted
    assert "sha256" not in json.dumps(plat.get_challenge("t1").meta)


def test_hash_flags_script_removes_plaintext(tmp_path):
    root = _suite(tmp_path, {"category": "rev"}, flag_txt="CTF{from_file}\n")
    (root / "t2").mkdir()
    (root / "t2" / "challenge.json").write_text(json.dumps({"id": "t2", "flags": ["CTF{x}", "CTF{y}"]}))
    out = subprocess.run([sys.executable, str(REPO_ROOT / "scripts/hash_flags.py"), str(root)],
                         capture_output=True, text=True)
    assert out.returncode == 0 and "2 challenge(s) updated" in out.stdout
    everything = "".join(p.read_text() for p in root.rglob("*") if p.is_file())
    assert "CTF{" not in everything and not (root / "t1" / "flag.txt").exists()
    plat = FilesTargetPlatform(root)
    assert plat.submit_flag("t1", "CTF{from_file}").accepted
    assert plat.submit_flag("t2", "CTF{y}").accepted and plat.get_challenge("t2").flags_required == 2
