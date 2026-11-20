"""Changes made after the CyberEDU rehearsal: guards that do not misfire, what
the model is told about submissions and time, and the contest-day adapter kit."""

from base64 import b64encode

from echo_fake import hide, shown
import io
import json
import sys
import threading
import types
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from harness import adapter_check, preflight
from harness.agents.base import Outcome, Solver, new_state, restart_recap
from harness.agents.limits import Limits
from harness.agents.specialists import route
from harness.agents.tools import (LocalExecutor, ShellTool, Tool, ToolContext, ToolProfile,
                                   ToolResult, _REPO_ROOT, harness_violation, scope_violation)
from harness.config import Config
from harness.flags.grounding import format_check
from harness.flags.submit import FlagSubmitter
from harness.inference.base import Message, Model, ModelError, ModelResponse, ModelSpec, ToolCall, Usage
from harness.paths import writable_dir
from harness.platforms import kit
from harness.platforms.base import Challenge, ConnInfo, Platform, PlatformError, SubmitResult
from harness.platforms.files_target import FilesTargetPlatform
from harness.platforms.starter_kit import StarterKitPlatform
from harness.scheduler.budget import Budget, Caps
from harness.scheduler.ladder import Ladder, Rung
from harness.single import run_challenge
from harness.telemetry.run_log import RunLog

SPEC = ModelSpec(name="m")
# Built at run time: tests/ is a decoy source, so a literal flag here is ignored.
REAL = "CTF" + "{0123456789abcdef_real}"
WRONG = "CTF" + "{not_the_answer_at_all}"

SVC = ConnInfo(host="10.10.5.7", port=31337)
WEB = ConnInfo(url="http://chall.example.org")


# --- scope guard --------------------------------------------------------------

@pytest.mark.parametrize("cmd,conn", [
    ("curl -s http://chall.example.org 2>/dev/null | head", WEB),
    ("curl -s chall.example.org 2>&1", WEB),
    ("ping -c 1 10.10.5.7 2>&1", SVC),
    ("printf 'a\\n' | nc -w 3 10.10.5.7 31337 2>&1 | head -5", SVC),
    ("nc -zv 10.10.5.7 31337", SVC),
    ("nmap -sV -p 31337 10.10.5.7", SVC),
    ("python3 x.py 10.10.5.7 31337 64", SVC),
    ("r = remote('10.10.5.7', 31337)", SVC),
    ("curl http://110.10.5.7:80/", SVC),                 # another host entirely
])
def test_ordinary_commands_at_the_target_are_not_refused(cmd, conn):
    assert scope_violation(cmd, conn) is None


@pytest.mark.parametrize("cmd", [
    "curl http://10.10.5.7:8080/", "nmap -sV 10.10.5.7", "nmap -p31337,22 10.10.5.7",
    "nc -zv 10.10.5.7 1-1000", "s.connect(('10.10.5.7', 22))",
])
def test_other_ports_on_a_shared_host_are_still_refused(cmd):
    assert scope_violation(cmd, SVC)


def test_scope_setting_and_whole_host_targets(monkeypatch):
    box = ConnInfo(host="10.10.5.7")                     # a machine, no port given
    assert scope_violation("nmap -sV 10.10.5.7", box) is None
    ch = Challenge(id="c", name="b", category="network")
    assert "on any port" in route(ch, box).task_prompt(ch, Path("/w"), box, [])
    monkeypatch.setenv("CTF_TARGET_SCOPE", "host")
    assert scope_violation("nmap -sV 10.10.5.7", SVC) is None
    assert scope_violation("curl http://10.10.5.7:8080/", SVC) is None
    assert "on any port" in route(ch, SVC).task_prompt(ch, Path("/w"), SVC, [])
    monkeypatch.setenv("CTF_TARGET_SCOPE", "any")
    assert "Scope:" not in route(ch, SVC).task_prompt(ch, Path("/w"), SVC, [])
    monkeypatch.setenv("CTF_TARGET_SCOPE", "nonsense")   # unknown value: the strict default
    assert scope_violation("nmap -sV 10.10.5.7", SVC)


# --- the harness's own files ---------------------------------------------------

def test_harness_files_are_off_limits_but_notes_and_work_dir_are_not(tmp_path, monkeypatch):
    root = str(_REPO_ROOT)
    work = _REPO_ROOT / "runs" / "work" / "c1"
    for cmd in (f"cat {root}/fixtures/locked-02/challenge.json", f"ls -la {root}/",
                f"grep -r flag {root}/runs/logs", f"cat '{root}/harness/single.py'"):
        assert harness_violation(cmd, work), cmd
    for cmd in (f"python3 {root}/knowledge/ctf-notes/crypto/solver.py 3",
                f"cat {root}/runs/work/c1/note.txt", f"cd {root}/runs/work/c1 && ls",
                "ls /opt; strings ./bin | head", f"cat {root}-other/readme"):
        assert harness_violation(cmd, work) is None, cmd
    monkeypatch.setenv("CTF_GUARD_HARNESS", "0")
    assert harness_violation(f"ls {root}", work) is None


def test_shell_refuses_a_harness_path_without_running_it(tmp_path):
    class NoRun:
        def run(self, *a):
            raise AssertionError("must not run")
    ctx = ToolContext("c", tmp_path, NoRun())
    r = ShellTool().run({"cmd": f"cat {_REPO_ROOT}/tests/test_solver.py"}, ctx)
    assert r.error and "runner's own code" in r.error


def test_prompt_asks_for_batched_steps_and_names_the_runner_off_limits():
    text = route(Challenge(id="c", name="x", category="rev"), None).system_prompt()
    assert "ONE shell call" in text and "never in the runner itself" in text
    assert "One concrete action per step" not in text


# --- what the model is told about submissions -----------------------------------

class _Out(Tool):
    name = "out"
    description = "echo"
    def input_schema(self): return {"type": "object", "properties": {}}
    def run(self, args, ctx):
        return ToolResult(self.name, shown(args.get("text", "")), "out:x")


class _Fn(Model):
    def __init__(self, fn, spec=SPEC):
        super().__init__(spec)
        self.fn, self.n, self.timeouts = fn, 0, []
    def complete(self, messages, tools=None):
        self.n += 1
        self.timeouts.append(self.request_timeout)
        return self.fn(self.n, messages, tools)


class _Grader(Platform):
    def __init__(self, fail=0): self.calls, self.fail = [], fail
    def list_challenges(self): return [self.get_challenge("c")]
    def get_challenge(self, cid): return Challenge(id="c", name="c", category="misc")
    def download_files(self, cid, dest): return []
    def start_instance(self, cid): return ConnInfo()
    def get_conn_info(self, cid): return ConnInfo()
    def submit_flag(self, cid, flag):
        self.calls.append(flag)
        if len(self.calls) <= self.fail:
            raise PlatformError("503")
        return SubmitResult(accepted=flag == REAL, message="" if flag == REAL else "Incorrect flag")


def _solver(model, tmp, *, caps=None, penalize=False, flag_check=None, plat=None, **kw):
    log = RunLog(tmp / "logs")
    sub = FlagSubmitter(plat or _Grader(), log, penalize_wrong=penalize, sleep=lambda s: None,
                        retry_delays=())
    state = new_state("c", tmp, ToolContext("c", tmp, LocalExecutor()), "sys", "go",
                      flag_check=flag_check)
    solver = Solver(model=model, profile=ToolProfile("t", [_Out()]), state=state,
                    budget=Budget(caps or Caps()), log=log, submitter=sub, plan_first=False,
                    limits=Limits(reserve_seconds=0), **kw)
    return solver, state


def _say(n, text):
    return ModelResponse(tool_calls=(ToolCall(f"c{n}", "out", {"text": hide(text)}),), usage=Usage(1, 1))


def _tool_texts(state):
    return [m.content for m in state.messages if m.role == "tool"]


def test_model_is_told_when_an_auto_submitted_flag_is_rejected_or_accepted(tmp_path):
    model = _Fn(lambda n, m, t: _say(n, f"found {WRONG}") if n == 1 else _say(n, f"found {REAL}"))
    solver, state = _solver(model, tmp_path)
    assert solver.run().outcome == Outcome.SOLVED
    first, second = _tool_texts(state)
    assert "NOT accepted (Incorrect flag)" in first and "ACCEPTED" not in first
    assert "ACCEPTED. 1 of 1 flag(s) accepted" in second
    # the note shows a preview, never a second full copy of the flag
    assert first.count(WRONG) == 1


def test_model_is_told_when_the_grader_did_not_answer(tmp_path):
    model = _Fn(lambda n, m, t: _say(n, f"found {REAL}"))
    solver, state = _solver(model, tmp_path, plat=_Grader(fail=1), max_iterations=1)
    solver.run()
    assert "the grader did not answer" in _tool_texts(state)[0]


def test_model_is_told_when_a_lookalike_fails_the_stated_format(tmp_path):
    lookalike = "DCTF" + "{Try Harder Next Time}"
    model = _Fn(lambda n, m, t: _say(n, f"note: {lookalike}"))
    plat = _Grader()
    solver, state = _solver(model, tmp_path, plat=plat, max_iterations=1,
                            flag_check=format_check("Flag format: DCTF{sha256}"))
    solver.run()
    assert plat.calls == []
    assert "does not match the format" in _tool_texts(state)[0]
    assert "submit_flag" in _tool_texts(state)[0]


# --- time -----------------------------------------------------------------------

def test_one_late_time_note_and_it_invites_a_guess_only_when_guesses_are_free(tmp_path):
    def run(penalize, sub):
        model = _Fn(lambda n, m, t: _say(n, f"step {n}"))
        solver, state = _solver(model, sub, caps=Caps(total_seconds=1000), penalize=penalize,
                                max_iterations=4)
        solver.budget.time_left = lambda cid, _n=[0]: [900, 600, 150, 100, 60][min(_n.__setitem__(0, _n[0] + 1) or _n[0] - 1, 4)]
        state.time_total = 1000
        solver.run()
        return [m.content for m in state.messages if m.role == "user" and "time budget remain" in m.content]
    (tmp_path / "a").mkdir(); (tmp_path / "b").mkdir()
    free = run(False, tmp_path / "a")
    assert len(free) == 1 and "costs nothing" in free[0] and "minute" in free[0]
    strict = run(True, tmp_path / "b")
    assert len(strict) == 1 and "costs nothing" not in strict[0]


def test_no_time_note_without_a_time_cap(tmp_path):
    model = _Fn(lambda n, m, t: _say(n, f"step {n}"))
    solver, state = _solver(model, tmp_path, max_iterations=3)
    solver.run()
    assert not any("time budget remain" in m.content for m in state.messages)


def test_task_prompt_states_the_time_budget(tmp_path):
    seen = []
    def fn(n, messages, tools):
        seen.append(messages[1].content)
        return ModelResponse(text="x")
    plat = _Grader()
    log = RunLog(tmp_path / "l")
    run_challenge(challenge=plat.get_challenge("c"), platform=plat, ladder=Ladder([Rung(SPEC, 1)]),
                  model_factory=lambda s: _Fn(fn, s), budget=Budget(Caps(total_seconds=1200)),
                  log=log, submitter=FlagSubmitter(plat, log), executor=LocalExecutor(),
                  work_root=tmp_path / "w", available=set(), plan_first=False, top_rung_restarts=0)
    assert "about 20 minutes in total" in seen[0]


def test_plan_and_recap_requests_are_capped_by_the_time_left(tmp_path):
    model = _Fn(lambda n, m, t: ModelResponse(text="plan") if not t else _say(n, REAL))
    solver, state = _solver(model, tmp_path, caps=Caps(total_seconds=500))
    solver.plan_first = True
    solver.run()
    assert model.timeouts[0] is not None and 0 < model.timeouts[0] <= 500      # the plan call
    recap_model = _Fn(lambda n, m, t: ModelResponse(text="note"))
    restart_recap(recap_model, state, [], Budget(Caps(total_seconds=300)), solver.log,
                  Limits(reserve_seconds=20))
    assert 0 < recap_model.timeouts[0] <= 280


def test_sdk_does_not_retry_on_its_own(monkeypatch):
    seen = {}
    fake = types.ModuleType("openai")
    fake.OpenAI = lambda **kw: seen.update(kw) or object()
    monkeypatch.setitem(sys.modules, "openai", fake)
    from harness.inference.openai_client import OpenAIModel
    OpenAIModel(SPEC)._ensure_client()
    assert seen["max_retries"] == 0


# --- submission pacing ----------------------------------------------------------

def test_submissions_are_spaced_out(tmp_path):
    waits, now = [], [100.0]
    def sleep(s):
        waits.append(round(s, 2)); now[0] += s
    sub = FlagSubmitter(_Grader(), RunLog(tmp_path), sleep=sleep, min_interval=1.0)
    sub._clock = lambda: now[0]
    sub.register("c", 3)
    from harness.flags.grounding import GroundedFlag
    for f in ("CTF" + "{a}", "CTF" + "{b}", "CTF" + "{c}"):
        sub.submit("c", GroundedFlag(flag=f, raw=f.encode(), source="t", evidence_seq=1))
    assert waits == [1.0, 1.0]                       # none before the first


# --- unwritable directories ------------------------------------------------------

def test_writable_dir_falls_back_to_a_temp_dir(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    got, as_asked = writable_dir(tmp_path / "ok" / "deep")
    assert as_asked and got.is_dir()
    got, as_asked = writable_dir(blocker / "cannot" / "exist")
    assert not as_asked and got.is_dir()


def test_run_survives_unwritable_work_and_log_dirs(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    log = RunLog(blocker / "logs")
    assert log.path.parent.is_dir()
    plat = _Grader()
    res = run_challenge(challenge=plat.get_challenge("c"), platform=plat,
                        ladder=Ladder([Rung(SPEC, 2)]),
                        model_factory=lambda s: _Fn(lambda n, m, t: ModelResponse(tool_calls=(
                            ToolCall(f"c{n}", "shell", {"cmd": f"echo {b64encode(REAL.encode()).decode()} | base64 -d"}),)), s),
                        budget=Budget(Caps()), log=log, submitter=FlagSubmitter(plat, log),
                        executor=LocalExecutor(), work_root=blocker / "work", available=set(),
                        plan_first=False)
    assert res.solved
    log.close()
    kinds = [json.loads(l)["kind"] for l in log.path.read_text().splitlines()]
    assert "run.log_dir_fallback" in kinds and "challenge.work_dir_fallback" in kinds


# --- the adapter kit --------------------------------------------------------------

@pytest.fixture
def api():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def _send(self, code, body, ctype="application/json", extra=None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)
        def do_GET(self):
            if self.path == "/file":
                self._send(200, b"PK-data", "application/octet-stream",
                           {"Content-Disposition": 'attachment; filename="capture one.pcapng"'})
            elif self.path == "/text":
                self._send(200, b"plain words", "text/plain")
            else:
                self._send(int(self.path.strip("/")), b'{"detail": "x"}')
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            ok = body.get("flag") == "right" and self.headers.get("Authorization") == "Bearer t"
            self._send(200 if ok else 400, json.dumps({"correct": ok}).encode())
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def test_http_json_returns_answers_and_raises_only_for_no_answer(api):
    hdr = {"Authorization": "Bearer t"}
    assert kit.http_json("POST", api + "/submit", body={"flag": "right"}, headers=hdr) == (200, {"correct": True})
    assert kit.http_json("POST", api + "/submit", body={"flag": "nope"}, headers=hdr) == (400, {"correct": False})
    assert kit.http_json("GET", api + "/404") == (404, {"detail": "x"})
    assert kit.http_json("GET", api + "/text") == (200, "plain words")
    for code in (429, 500, 503):
        with pytest.raises(PlatformError) as e:
            kit.http_json("GET", f"{api}/{code}")
        assert e.value.status == code
    with pytest.raises(PlatformError):
        kit.http_json("GET", "http://127.0.0.1:1/unreachable", timeout=2)


def test_http_download_keeps_the_real_name(api, tmp_path):
    p = kit.http_download(api + "/file", tmp_path)
    assert p.name == "capture one.pcapng" and p.read_bytes() == b"PK-data"
    assert kit.http_download(api + "/file", tmp_path, "../../x.zip").parent == tmp_path
    assert kit.safe_name("../../etc/pass wd.pcapng") == "pass wd.pcapng"


@pytest.mark.parametrize("text,want", [
    ("35.242.202.105:32287", ("35.242.202.105", 32287)),
    ("nc 34.159.226.213 30206", ("34.159.226.213", 30206)),
    ("Connect with: nc 1.2.3.4 99", ("1.2.3.4", 99)),
    ("ncat --ssl chal.ctf.ro 443", ("chal.ctf.ro", 443)),
    ("http://chal.ctf.ro:8080/login", ("chal.ctf.ro", 8080)),
    ("https://chal.ctf.ro", ("chal.ctf.ro", 443)),
    ("ssh ctf@10.0.0.4 -p 2222", ("10.0.0.4", 2222)),
    ("ssh -p 2222 ctf@10.0.0.4", ("10.0.0.4", 2222)),
    ("The service runs at chal.ctf.ro:31337 until 12:30", ("chal.ctf.ro", 31337)),
    ("no address here, see you at 12:30", (None, None)),
    ("", (None, None)),
])
def test_parse_address(text, want):
    assert kit.parse_address(text) == want


def test_conn_from_and_describe():
    c = kit.conn_from("http://chal.ctf.ro:8080/login")
    assert (c.host, c.port, c.url) == ("chal.ctf.ro", 8080, "http://chal.ctf.ro:8080/login")
    assert kit.conn_from("1.2.3.4:80", web=True).url == "http://1.2.3.4:80"
    assert kit.conn_from("nc 1.2.3.4 99").url is None
    with pytest.raises(PlatformError):
        kit.conn_from("somewhere")
    text = kit.describe("Crack it.", questions=["What is the WPA2 password?",
                                                {"question": "Flag", "description": "ctf{sha256}"}])
    assert "1. What is the WPA2 password?" in text and "2. Flag (format: ctf{sha256})" in text
    assert format_check(text) is not None            # the stated format reaches the flag check


def test_the_contest_adapter_refuses_to_start_outside_a_run(monkeypatch):
    monkeypatch.delenv("GATEWAY_URL", raising=False)
    monkeypatch.delenv("RUN_TOKEN", raising=False)
    with pytest.raises(PlatformError, match="not inside a run"):
        StarterKitPlatform()


# --- adapter check ---------------------------------------------------------------

def test_adapter_check_passes_on_a_working_adapter_and_shows_the_prompt():
    out = io.StringIO()
    failed = adapter_check.check(FilesTargetPlatform(_REPO_ROOT / "fixtures"), "multi-03",
                                 submit="CTF" + "{wrong}", out=out)
    text = out.getvalue()
    assert failed == 0 and "what the agent is told" in text
    assert "flags_required=2" in text and "accepted=False" in text


def test_adapter_check_catches_a_broken_adapter():
    class Broken(_Grader):
        def get_challenge(self, cid):
            return Challenge(id="c", name="c", category="pwn",
                             kind=__import__("harness.platforms.base", fromlist=["x"]).ChallengeKind.INTERACTIVE)
        def submit_flag(self, cid, flag):
            return SubmitResult(accepted=True)          # says yes to anything
    out = io.StringIO()
    failed = adapter_check.check(Broken(), submit="CTF" + "{wrong}", out=out)
    text = out.getvalue()
    assert failed == 2                                   # no service, and nothing to work on
    assert "no service address came back" in text and "reports every flag as correct" in text
    assert "empty description" in text

    class Dead(_Grader):
        def list_challenges(self): raise PlatformError("401 unauthorized")
    assert adapter_check.check(Dead(), out=io.StringIO()) == 1


# --- preflight: vision --------------------------------------------------------------

def test_preflight_reports_a_blind_model_without_blocking(monkeypatch, capsys):
    class Blind(_Fn):
        _no_vision_models: set = set()
        def complete(self, messages, tools=None):
            if messages[-1].images:
                type(self)._no_vision_models.add(self.spec.name)
                return ModelResponse(text="I cannot see an image.", usage=Usage(5, 5))
            if tools and not any(m.role == "tool" for m in messages):
                return ModelResponse(tool_calls=(ToolCall("t", "shell", {"cmd": "echo preflight"}),),
                                     usage=Usage(20, 5))
            return ModelResponse(text="ready", usage=Usage(20, 2))
    res = preflight.run(Config(inference_backend="openai"), lambda s: Blind(None, s))
    seven = [(ok, d) for n, ok, d in res if n.startswith("7.")]
    assert seven and not seven[0][0] and "CTF_VISION=0" in seven[0][1]
    assert all(ok for n, ok, _ in res if not n.startswith("7."))
    assert preflight._red_square().startswith("data:image/png;base64,iVBOR")


# --- ladder depths ----------------------------------------------------------------

def test_ladder_depths_setting(monkeypatch):
    depths = lambda c: [r.max_iterations for r in c.ladder().rungs]
    assert depths(Config()) == [12, 25, 40, 60]
    assert depths(Config(ladder_depths=(3, 4))) == [3, 4, 40, 60]
    assert depths(Config(ladder_depths=(0, 5, 6, 7, 99))) == [1, 5, 6, 7]
    from harness.config import _depths
    assert _depths("3, 4,5") == (3, 4, 5) and _depths("") == () and _depths("3,x") == ()


def test_fresh_context_setting(monkeypatch):
    from harness.config import config_from_env
    assert config_from_env().fresh_context_on_escalate is False
    monkeypatch.setenv("CTF_FRESH_CONTEXT", "1")
    assert config_from_env().fresh_context_on_escalate is True


# --- after the final report: scanner guard, timeouts, reply length ------------------

@pytest.mark.parametrize("cmd", [
    "ffuf -u 'http://h/?a=FUZZ&b=2' -w w.txt -t 10",
    'hydra -l admin -P p.txt h http-post-form "/login:user=^USER^&pass=^PASS^:F=bad"',
    'wfuzz -d "a=FUZZ&b=1" http://h/',
    'sqlmap -u "http://h/page?id=1&cat=2" --batch',
    "ffuf -u http://h/FUZZ -w w.txt 2>&1 | head",
    "gobuster dir -u http://h -w w && echo done",
])
def test_an_ampersand_inside_quotes_is_not_a_background_job(cmd):
    from harness.agents.tools import background_scan
    assert background_scan(cmd) is None


@pytest.mark.parametrize("cmd", [
    "nohup ffuf -u http://h/FUZZ -w w.txt &",
    "ffuf -u 'http://h/?a=FUZZ&b=1' -w w.txt > out.txt 2>&1 &",
    "(sqlmap -u http://h/?id=1 --batch &) ; sleep 5",
])
def test_a_backgrounded_scanner_is_still_refused(cmd):
    from harness.agents.tools import background_scan
    assert background_scan(cmd)


def _timeout_model(pattern, spec):
    """pattern: 'T' = time out, anything else = solve. Records the cap of each call."""
    from harness.inference.base import ModelTimeout
    caps = []
    def fn(n, messages, tools):
        caps.append((spec_holder[0].spec.max_tokens, messages[-1].content[:30]))
        if n <= len(pattern) and pattern[n - 1] == "T":
            raise ModelTimeout("Request timed out.")
        return _say(n, f"found {REAL}")
    spec_holder = [_Fn(fn, spec)]
    return spec_holder[0], caps


def test_one_timeout_is_a_stall_and_changes_nothing(tmp_path, monkeypatch):
    # The rehearsal logs: 11 full-length timeouts, all endpoint stalls; the same
    # request answered when sent again. So: ask again at once, as it was.
    import harness.agents.base as base
    slept = []
    monkeypatch.setattr(base, "_sleep", slept.append)
    model, caps = _timeout_model("T", ModelSpec(name="m", max_tokens=32768))
    solver, state = _solver(model, tmp_path)
    assert solver.run().outcome == Outcome.SOLVED
    assert [c for c, _ in caps] == [32768, 32768] and slept == []
    assert state.output_ceiling == 0
    assert not any("took too long" in m.content for m in state.messages)


def test_a_second_timeout_in_a_row_changes_the_request(tmp_path):
    model, caps = _timeout_model("TTT", ModelSpec(name="m", max_tokens=32768))
    solver, state = _solver(model, tmp_path)
    solver_out = solver.run()
    assert solver_out.outcome == Outcome.ERROR and model.n == 3
    # unchanged after the first, halved after the second (the third call saw it)
    assert [c for c, _ in caps] == [32768, 32768, 16384]
    notes = [m.content for m in state.messages if m.role == "user" and "took too long" in m.content]
    assert len(notes) == 1                             # told once, not once per timeout
    assert caps[2][1].startswith("Your last reply took too long")
    assert state.output_ceiling == 8192                # halved again by the third
    events = [json.loads(l) for l in solver.log.path.read_text().splitlines()]
    assert [e["in_a_row"] for e in events if e["kind"] == "solver.model_timeout"] == [1, 2, 3]
    # the next rung asks for 32768; it starts at the learned ceiling instead
    nxt = _Fn(lambda n, m, t: _say(n, f"found {REAL}"), ModelSpec(name="m", max_tokens=32768))
    Solver(model=nxt, profile=ToolProfile("t", [_Out()]), state=state, budget=Budget(Caps()),
           log=solver.log, submitter=solver.submitter, plan_first=False, limits=Limits())
    assert nxt.spec.max_tokens == 8192


def test_timeouts_at_the_floor_leave_no_ceiling_behind(tmp_path):
    # Every stall in rehearsal happened at an 8192 cap. That must not clamp the
    # upper rungs or the cut-off raise for the rest of the challenge.
    from harness.inference.base import ModelTimeout
    def fn(n, messages, tools):
        if n <= 2:
            raise ModelTimeout("Request timed out.")
        if n == 3:
            return ModelResponse(text="", stop_reason="length")
        return _say(n, f"found {REAL}")
    model = _Fn(fn, ModelSpec(name="m", max_tokens=8192))
    solver, state = _solver(model, tmp_path)
    assert solver.run().outcome == Outcome.SOLVED
    assert state.output_ceiling == 0
    assert model.spec.max_tokens == 16384              # the cut-off raise still works
    nxt = _Fn(lambda n, m, t: _say(n, "x"), ModelSpec(name="m", max_tokens=32768))
    Solver(model=nxt, profile=ToolProfile("t", [_Out()]), state=state, budget=Budget(Caps()),
           log=solver.log, submitter=solver.submitter, plan_first=False, limits=Limits())
    assert nxt.spec.max_tokens == 32768


def test_adapters_name_a_timeout(monkeypatch):
    from types import SimpleNamespace
    from harness.inference.base import ModelTimeout, is_timeout
    from harness.inference.openai_client import OpenAIModel
    class APITimeoutError(Exception):
        pass
    def create(**kw):
        raise APITimeoutError("Request timed out.")
    client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
    with pytest.raises(ModelTimeout):
        OpenAIModel(SPEC, client=client).complete([Message("user", "x")])
    assert is_timeout(TimeoutError("x")) and not is_timeout(RuntimeError("429 rate limit"))


def _speedy(tokens, seconds, monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(preflight.time, "monotonic", lambda: clock[0])
    def fn(n, messages, tools):
        if messages[-1].images:
            return ModelResponse(text="red", usage=Usage(5, 5))
        if "reverse-engineering" in messages[-1].content:
            clock[0] += seconds
            return ModelResponse(tool_calls=(ToolCall("t", "shell", {"cmd": "file chall"}),),
                                 usage=Usage(50, tokens))
        if tools and not any(m.role == "tool" for m in messages):
            return ModelResponse(tool_calls=(ToolCall("t", "shell", {"cmd": "echo preflight"}),),
                                 usage=Usage(20, 5))
        return ModelResponse(text="ready", usage=Usage(20, 2))
    res = preflight.run(Config(inference_backend="openai"), lambda s: _Fn(fn, s))
    return [(ok, d) for n, ok, d in res if n.startswith("8.")][0]


def test_preflight_warns_when_a_full_reply_cannot_fit_the_request_limit(monkeypatch):
    monkeypatch.setenv("CTF_MODEL_TIMEOUT", "180")
    monkeypatch.delenv("CTF_MIN_OUTPUT_TOKENS", raising=False)
    ok, detail = _speedy(tokens=500, seconds=10, monkeypatch=monkeypatch)     # 50 tokens/s
    assert not ok and "CTF_MAX_OUTPUT_TOKENS=7168" in detail and "655 s" in detail
    ok, detail = _speedy(tokens=5000, seconds=10, monkeypatch=monkeypatch)    # 500 tokens/s
    assert ok and "inside the 180 s" in detail
    ok, detail = _speedy(tokens=10, seconds=1, monkeypatch=monkeypatch)
    assert ok and "too little output" in detail


def test_preflight_never_advises_a_cap_below_the_output_floor(monkeypatch):
    # GLM on the day of the pre-freeze check: ~29 tokens/s from one short
    # reply, limit 180 s -> 4096, which would override the 8192 floor (the cap
    # wins) and bring back the turns a reasoning model thinks away.
    monkeypatch.setenv("CTF_MODEL_TIMEOUT", "180")
    monkeypatch.setenv("CTF_MIN_OUTPUT_TOKENS", "8192")
    ok, detail = _speedy(tokens=290, seconds=10, monkeypatch=monkeypatch)     # 29 tokens/s
    assert not ok and "CTF_MAX_OUTPUT_TOKENS=8192, not lower" in detail
    assert "CTF_MAX_OUTPUT_TOKENS=4096" not in detail
    ok, detail = _speedy(tokens=500, seconds=10, monkeypatch=monkeypatch)     # 50 tokens/s: 7168 < 8192
    assert "CTF_MAX_OUTPUT_TOKENS=8192, not lower" in detail
    monkeypatch.setenv("CTF_MIN_OUTPUT_TOKENS", "4096")
    ok, detail = _speedy(tokens=500, seconds=10, monkeypatch=monkeypatch)     # above that floor: as before
    assert "CTF_MAX_OUTPUT_TOKENS=7168, or raise" in detail


def test_no_model_call_is_started_inside_the_reserve(tmp_path):
    # Pre-freeze live runs: in the last 20 s (the reserve) every request got a
    # 1 s timeout; ~20 doomed requests, three in a row ending each attempt, and
    # the ladder climbed to the top rung (string-comparer: 19 of 21 attempts).
    calls = []
    model = _Fn(lambda n, m, t: calls.append(n) or _say(n, f"found {REAL}"))
    log = RunLog(tmp_path / "logs")
    state = new_state("c", tmp_path, ToolContext("c", tmp_path, LocalExecutor()), "sys", "go")
    solver = Solver(model=model, profile=ToolProfile("t", [_Out()]), state=state,
                    budget=Budget(Caps(total_seconds=24)), log=log,
                    submitter=FlagSubmitter(_Grader(), log, sleep=lambda s: None, retry_delays=()),
                    plan_first=True, limits=Limits(reserve_seconds=20))
    out = solver.run()
    assert out.outcome == Outcome.EXHAUSTED and calls == []        # not even the plan
    assert "reserve" in out.reason
    # With time to spare the same setup calls the model and solves.
    calls.clear()
    tmp2 = tmp_path / "b"; tmp2.mkdir()
    s2, _ = _solver(_Fn(lambda n, m, t: calls.append(n) or _say(n, f"found {REAL}")), tmp2,
                    caps=Caps(total_seconds=600))
    assert s2.run().outcome == Outcome.SOLVED and calls
