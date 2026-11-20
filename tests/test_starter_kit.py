"""The AISafe contest adapter (harness/platforms/starter_kit.py) and the pieces
of the harness it leans on: the gateway's header and status codes in the model
client, the run's clock in the budget, the give-up note, split flags."""

import http.server
import json
import os
import socket
import socketserver
import threading
import time
from pathlib import Path

import pytest

from harness.platforms import starter_kit as sk
from harness.platforms.base import ChallengeKind, PlatformError
from harness.scheduler.budget import Budget, BudgetExceeded, Caps, RunEnded
from tests.fake_gateway import FakeGateway

FLAG = "flag{" + "ab" * 16 + "}"
WRONG = "flag{" + "00" * 16 + "}"


@pytest.fixture
def gw():
    g = FakeGateway(flag=FLAG)
    yield g
    g.close()


@pytest.fixture
def http_target(tmp_path):
    (tmp_path / "srv").mkdir()
    (tmp_path / "srv" / "index.html").write_text("hello")
    handler = lambda *a, **k: http.server.SimpleHTTPRequestHandler(  # noqa: E731
        *a, directory=str(tmp_path / "srv"), **k)
    handler.log_message = lambda *a: None
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


@pytest.fixture
def tcp_target():
    class H(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.sendall(b"Welcome to the vault. Password: ")
            try:
                self.request.recv(100)
            except OSError:
                pass
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), H)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


def _run_env(monkeypatch, gw, tmp_path, targets="", instructions="", code=None):
    code = code if code is not None else tmp_path / "code"
    code.mkdir(exist_ok=True)
    for k, v in {"GATEWAY_URL": gw.url, "RUN_TOKEN": gw.token, "RUN_ID": "r-42",
                 "TARGETS": targets, "INSTRUCTIONS": instructions,
                 "TIME_LIMIT_SECONDS": "600", "COST_LIMIT_CENTS": "100",
                 "CTF_CODE_DIR": str(code)}.items():
        monkeypatch.setenv(k, v)
    return code


# --- INSTRUCTIONS ---------------------------------------------------------------

def test_instruction_lines_starting_with_at_steer_the_harness_and_are_hidden():
    notes, d = sk.split_instructions(
        "The admin page is at /panel.\n@category rev\n@set CTF_LADDER_DEPTHS=8,16\n"
        "@set OPENAI_API_KEY=x\n@name vault\n@preflight\n@someone on twitter said so\n")
    assert notes == "The admin page is at /panel.\n@someone on twitter said so"
    assert d["category"] == "rev" and d["name"] == "vault" and d["preflight"] is True
    assert d["set"] == {"CTF_LADDER_DEPTHS": "8,16"}        # only CTF_ settings


def test_bootstrap_maps_the_platforms_variables(monkeypatch):
    env = {"GATEWAY_URL": "http://gateway.internal/gateway/", "RUN_TOKEN": "s3cret-token",
           "TIME_LIMIT_SECONDS": "900", "TARGETS": "a:80,b:1337",
           "INSTRUCTIONS": "@set CTF_LADDER_DEPTHS=8,16\n@set CTF_MODEL_TIMEOUT=200",
           "CTF_MODEL_TIMEOUT": "240"}
    applied = sk.bootstrap(env)
    assert env["OPENAI_BASE_URL"] == "http://gateway.internal/gateway/v1"
    assert env["CTF_MODEL_HEADERS"] == "X-Run-Token=s3cret-token"
    assert env["CTF_PLATFORM"] == sk.PLATFORM and env["CTF_BACKEND"] == "openai"
    assert env["CTF_TOTAL_SECONDS"] == "870"                 # 30 s kept for the last calls
    assert env["CTF_TARGET_SCOPE"] == "any"                  # two targets
    assert env["CTF_LADDER_DEPTHS"] == "8,16"
    assert env["CTF_MODEL_TIMEOUT"] == "200"                 # @set beats the image's value
    assert "CTF_LADDER_DEPTHS" in applied
    # The token never reaches the model or the log.
    from harness.secrets import scrub_text
    assert "s3cret-token" not in scrub_text("X-Run-Token: s3cret-token")


def test_bootstrap_does_nothing_outside_a_run():
    env = {"CTF_BACKEND": "rule"}
    assert sk.bootstrap(env) == {} and env == {"CTF_BACKEND": "rule"}


def test_bootstrap_keeps_what_the_image_or_environment_set():
    env = {"GATEWAY_URL": "http://g/gateway", "RUN_TOKEN": "t", "TIME_LIMIT_SECONDS": "600",
           "CTF_TOTAL_SECONDS": "300", "OPENAI_BASE_URL": "http://other/v1"}
    sk.bootstrap(env)
    assert env["CTF_TOTAL_SECONDS"] == "300" and env["OPENAI_BASE_URL"] == "http://other/v1"


# --- targets --------------------------------------------------------------------

def test_targets_are_parsed_and_probed(http_target, tcp_target):
    assert sk.parse_targets("web:80, db.internal:5432,,bad") == [("web", 80), ("db.internal", 5432)]
    p = sk.probe_target("127.0.0.1", http_target)
    assert p["proto"] == "http" and "200" in p["info"]
    p = sk.probe_target("127.0.0.1", tcp_target)
    assert p["proto"] == "tcp" and "Welcome to the vault" in p["info"]
    s = socket.socket(); s.bind(("127.0.0.1", 0)); closed = s.getsockname()[1]; s.close()
    assert sk.probe_target("127.0.0.1", closed, timeout=1)["proto"] == "down"


# --- the challenge ----------------------------------------------------------------

def test_the_challenge_is_built_from_files_targets_and_notes(monkeypatch, gw, tmp_path, http_target):
    code = _run_env(monkeypatch, gw, tmp_path, targets=f"127.0.0.1:{http_target}",
                    instructions="Look at the cookie first.\n@name vault")
    (code / "README.txt").write_text("The secret is behind the login.")
    (code / "app").mkdir()
    (code / "app" / "server.py").write_text("from flask import Flask\napp = Flask(__name__)\n")
    plat = sk.StarterKitPlatform()
    [chal] = plat.list_challenges()
    assert chal.id == "r-42" and chal.name == "vault"
    assert chal.category == "web" and chal.kind == ChallengeKind.WEB
    d = chal.description
    assert "Your team's notes for this run" in d and "Look at the cookie first." in d
    assert "@name" not in d
    assert "README.txt says:\nThe secret is behind the login." in d
    assert "app/server.py" in d and f"http://127.0.0.1:{http_target}/" in d
    assert "32 lowercase hex" in d and "No files were shipped" not in d
    conn = plat.start_instance(chal.id)
    assert conn.url == f"http://127.0.0.1:{http_target}" and conn.port == http_target
    out = plat.download_files(chal.id, tmp_path / "work")
    assert sorted(p.relative_to(tmp_path / "work").as_posix() for p in out) == ["README.txt", "app/server.py"]
    assert plat.get_challenge("anything").id == "r-42"


def test_a_raw_tcp_service_with_a_binary_is_pwn_and_shows_its_banner(monkeypatch, gw, tmp_path, tcp_target):
    code = _run_env(monkeypatch, gw, tmp_path, targets=f"127.0.0.1:{tcp_target}")
    (code / "vault").write_bytes(b"\x7fELF" + b"\x00" * 60)
    (code / "libc.so.6").write_bytes(b"\x7fELF" + b"\x00" * 60)
    plat = sk.StarterKitPlatform()
    [chal] = plat.list_challenges()
    assert chal.category == "pwn" and chal.kind == ChallengeKind.INTERACTIVE
    assert "on connect it sends: 'Welcome to the vault. Password:'" in chal.description
    conn = plat.start_instance(chal.id)
    assert (conn.host, conn.port, conn.url) == ("127.0.0.1", tcp_target, None)


def test_category_guesses(tmp_path):
    def files(**content):
        out = []
        for name, data in content.items():
            p = tmp_path / name.replace("__", ".")
            p.write_bytes(data if isinstance(data, bytes) else data.encode())
            out.append(p)
        return out
    elf = b"\x7fELF" + b"\x00" * 20
    assert sk.guess_category(files(crackme=elf), []) == "rev"
    assert sk.guess_category(files(chall=elf, libc__so__6=elf), ["tcp"]) == "pwn"
    assert sk.guess_category(files(capture__pcap=b"x"), []) == "forensics"
    assert sk.guess_category(files(app__apk=b"PK"), ["http"]) == "mobile"
    assert sk.guess_category(files(Vault__sol="contract Vault {}"), ["http"]) == "blockchain"
    assert sk.guess_category(files(chall__py="from Crypto.Util.number import getPrime\n"), ["tcp"]) == "crypto"
    assert sk.guess_category(files(output__txt="n = " + "9" * 40 + "\ne = 65537\n"), []) == "crypto"
    assert sk.guess_category(files(index__php="<?php echo 1;"), ["http"]) == "web"
    assert sk.guess_category(files(jail__py="while True: print(eval(input()))  # blacklist"), ["tcp"]) == "pyjail"
    assert sk.guess_category(files(photo__png=b"\x89PNG"), []) == "stego"
    # Source of a TCP service that is not a binary: something to script against.
    assert sk.guess_category(files(relay__py="import socketserver, random, time\nMORSE = {}\n"), ["tcp"]) == "misc"
    assert sk.guess_category([], ["http"]) == "web"
    assert sk.guess_category([], ["tcp"]) == ""             # the router decides by the connection


def test_the_teams_category_wins_over_the_guess(monkeypatch, gw, tmp_path):
    code = _run_env(monkeypatch, gw, tmp_path, instructions="@category crypto")
    (code / "crackme").write_bytes(b"\x7fELF" + b"\x00" * 20)
    [chal] = sk.StarterKitPlatform().list_challenges()
    assert chal.category == "crypto" and chal.kind == ChallengeKind.STATIC
    assert "No live target" in chal.description


def test_instructions_are_fetched_from_the_gateway_when_the_variable_is_empty(monkeypatch, gw, tmp_path):
    gw.instructions = "Try the backup endpoint.\n@category web"
    _run_env(monkeypatch, gw, tmp_path, instructions="")
    plat = sk.StarterKitPlatform()
    assert plat.notes == "Try the backup endpoint." and plat.directives["category"] == "web"
    assert all({k.lower(): v for k, v in h.items()}.get("x-run-token") == "tok"
               for h in gw.headers_seen)


# --- flags ----------------------------------------------------------------------

def test_flag_submission_reads_the_gateways_answer(monkeypatch, gw, tmp_path):
    _run_env(monkeypatch, gw, tmp_path)
    plat = sk.StarterKitPlatform()
    r = plat.submit_flag("r-42", WRONG)
    assert r.accepted is False and r.message == "incorrect flag"
    r = plat.submit_flag("r-42", FLAG)
    assert r.accepted is True and r.challenge_solved is True and "250 points" in r.message
    # The run is over: nothing more is sent, and no give-up note follows a capture.
    assert plat.submit_flag("r-42", WRONG).accepted is False
    plat.finish({"solved": True})
    assert gw.flags == [WRONG, FLAG] and gw.notes == []


def test_the_wrong_flag_cooldown_is_waited_out(monkeypatch, gw, tmp_path):
    _run_env(monkeypatch, gw, tmp_path)
    monkeypatch.setattr(sk.time, "sleep", lambda s: None)
    gw.cooldowns = 2
    assert sk.StarterKitPlatform().submit_flag("r-42", FLAG).accepted is True
    gw2_plat = sk.StarterKitPlatform()
    gw.ended, gw.cooldowns = False, 10
    with pytest.raises(PlatformError, match="cooldown"):     # the submitter queues and retries
        gw2_plat.submit_flag("r-42", FLAG)


def test_an_ended_run_is_an_answer_not_a_retry(monkeypatch, gw, tmp_path):
    _run_env(monkeypatch, gw, tmp_path)
    plat = sk.StarterKitPlatform()
    gw.ended = True
    r = plat.submit_flag("r-42", FLAG)
    assert r.accepted is False and "ended" in r.message
    plat.finish({"reason": "x"})
    assert gw.notes == []                                    # nothing to give up on


def test_a_bad_token_is_an_error_not_a_wrong_flag(monkeypatch, gw, tmp_path):
    _run_env(monkeypatch, gw, tmp_path)
    plat = sk.StarterKitPlatform()
    plat.token = "other"
    with pytest.raises(PlatformError, match="401"):
        plat.submit_flag("r-42", FLAG)


# --- what the team sees ---------------------------------------------------------

def test_an_unsolved_run_ends_with_a_note_of_32_characters(monkeypatch, gw, tmp_path):
    _run_env(monkeypatch, gw, tmp_path, instructions="@category rev")
    plat = sk.StarterKitPlatform()
    plat.list_challenges()
    plat.finish({"solved": False, "turns": 61, "top_rung": 2,
                 "reason": "per-run budget exhausted: seconds global budget exceeded: 570/570",
                 "submissions": {"submissions": 1, "flags_accepted": 0}})
    assert gw.notes == ["rev 61t r2 w1 time"]
    assert all(len(n) <= 32 for n in gw.notes)


@pytest.mark.parametrize("reason,word", [
    ("per-run budget exhausted: cost cap reached (402)", "cost"),
    ("per-run budget exhausted: tokens global budget exceeded: 9/9", "tokens"),
    ("stuck-loop (no new progress)", "stuck"),
    ("model error: connection refused", "model"),
    ("crash: KeyError: 'x'", "crash"),
    ("per-run budget exhausted: the run has ended (409)", "ended"),
])
def test_the_note_says_why_the_run_stopped(reason, word):
    note = sk.make_note({"reason": reason, "turns": 123456, "top_rung": 3}, "forensics")
    assert note.endswith(word) and len(note) <= 32


def test_the_note_carries_no_flag_or_file_content():
    note = sk.make_note({"reason": "flag{deadbeef} seen in /code/secret", "turns": 3}, "web")
    assert "flag{" not in note and "secret" not in note


def test_timeline_events_follow_the_run_log_and_stop_at_the_limit(monkeypatch, gw, tmp_path):
    _run_env(monkeypatch, gw, tmp_path)
    plat = sk.StarterKitPlatform()
    plat.on_event({"kind": "tool.call", "tool": "shell"})
    plat.on_event({"kind": "tool.call", "tool": "gdb"})
    plat.on_event({"kind": "attempt.start"})
    plat.on_event({"kind": "solver.model_timeout"})
    plat.on_event({"kind": "model.turn"})                    # not a timeline event
    plat.on_event({"kind": "challenge.done", "solved": False})
    assert gw.logs == [{"event": "tool_use", "meta": {"tool": "bash"}},
                       {"event": "tool_use", "meta": {"tool": "other"}},
                       {"event": "progress"}, {"event": "error"}, {"event": "stuck"}]
    for _ in range(400):
        plat.on_event({"kind": "tool.call", "tool": "shell"})
    assert len(gw.logs) == sk.LOG_LIMIT - 40                 # room kept for the last events
    plat.on_event({"kind": "challenge.done", "solved": False})
    assert gw.logs[-1] == {"event": "stuck"} and len(gw.logs) < 300


def test_a_gateway_that_is_gone_does_not_stop_the_run(monkeypatch, gw, tmp_path):
    _run_env(monkeypatch, gw, tmp_path)
    plat = sk.StarterKitPlatform()
    gw.close()
    for _ in range(6):
        plat.timeline("progress")                            # no exception
    assert plat.health() is None and plat.seconds_left() is None
    plat.finish({"reason": "x"})                             # no exception


# --- the run's clock and cost -----------------------------------------------------

def test_the_budget_follows_the_platforms_clock(monkeypatch, gw, tmp_path):
    _run_env(monkeypatch, gw, tmp_path)
    plat = sk.StarterKitPlatform()
    budget = Budget(Caps(total_seconds=570))
    budget.resync, budget.resync_every = plat.seconds_left, 0.0
    gw.seconds = 900                                         # time handed back for waiting
    budget.check("c")
    assert 868 <= budget.seconds_left() <= 870               # 900 less the 30 s reserve
    gw.seconds = 20                                          # nearly over
    with pytest.raises(BudgetExceeded):
        budget.check("c")


def test_a_spent_cost_cap_ends_the_run(monkeypatch, gw, tmp_path):
    _run_env(monkeypatch, gw, tmp_path)
    plat = sk.StarterKitPlatform()
    budget = Budget(Caps(total_seconds=570))
    budget.resync, budget.resync_every = plat.seconds_left, 0.0
    gw.cents = 0
    with pytest.raises(RunEnded, match="cost cap"):
        budget.check("c")
    plat.finish({"reason": "per-run budget exhausted: cost cap reached (0 cents left)", "turns": 9})
    assert gw.notes == ["misc 9t r0 w0 cost"]


def test_a_failing_health_call_changes_nothing():
    budget = Budget(Caps(total_seconds=100))
    budget.resync, budget.resync_every = (lambda: 1 / 0), 0.0
    budget.check("c")
    assert budget.seconds_left() > 99


# --- the model client on the gateway ----------------------------------------------

def _model(monkeypatch, gw):
    from harness.inference.base import Effort, ModelSpec
    from harness.inference import openai_client as oc
    monkeypatch.setenv("OPENAI_BASE_URL", gw.url + "/v1")
    monkeypatch.setenv("OPENAI_API_KEY", "gateway")
    monkeypatch.setenv("CTF_MODEL_HEADERS", f"X-Run-Token={gw.token}")
    monkeypatch.setenv("CTF_GATEWAY_STATUS", "1")
    waits = []
    monkeypatch.setattr(oc, "_sleep", waits.append)
    spec = ModelSpec(name="qwen3.8-27b", effort=Effort.LOW, max_tokens=8192)
    return oc.OpenAIModel(spec), waits


def _msgs():
    from harness.inference.base import Message
    return [Message(role="user", content="hi")]


def test_model_calls_carry_the_run_token(monkeypatch, gw):
    pytest.importorskip("openai")
    model, _ = _model(monkeypatch, gw)
    assert model.complete(_msgs()).text == "ok"
    sent = {k.lower(): v for k, v in gw.headers_seen[-1].items()}
    assert sent.get("x-run-token") == "tok"
    assert gw.llm_calls[-1]["max_tokens"] == 8192


def test_a_busy_model_is_waited_for_as_long_as_it_asks(monkeypatch, gw):
    pytest.importorskip("openai")
    model, waits = _model(monkeypatch, gw)
    gw.llm_script = [(429, {"Retry-After": "7"}), (503, {"Retry-After": "5"}), {"content": "done"}]
    assert model.complete(_msgs()).text == "done"
    assert waits == [7.0, 5.0] and len(gw.llm_calls) == 3


def test_waiting_for_a_busy_model_has_a_limit(monkeypatch, gw):
    pytest.importorskip("openai")
    from harness.inference.base import ModelError
    model, waits = _model(monkeypatch, gw)
    monkeypatch.setenv("CTF_MODEL_BUSY_WAIT", "20")
    gw.llm_script = [(429, {"Retry-After": "9"})] * 10
    with pytest.raises(ModelError, match="429"):
        model.complete(_msgs())
    assert waits == [9.0, 9.0]
    # ...and it never waits past the time the request was given.
    model.request_timeout = 12
    gw.llm_script = [(429, {"Retry-After": "9"})] * 10
    waits.clear()
    with pytest.raises(ModelError):
        model.complete(_msgs())
    assert waits == []


def test_a_spent_budget_or_an_ended_run_stops_instead_of_retrying(monkeypatch, gw):
    pytest.importorskip("openai")
    model, waits = _model(monkeypatch, gw)
    for status, word in ((402, "cost cap"), (409, "ended")):
        gw.llm_script = [(status, {})]
        with pytest.raises(RunEnded, match=word):
            model.complete(_msgs())
    assert waits == []


def test_a_400_from_the_gateway_is_a_conversation_too_long(monkeypatch, gw):
    pytest.importorskip("openai")
    from harness.inference.base import ContextOverflow
    model, _ = _model(monkeypatch, gw)
    gw.llm_script = [(400, {})]
    with pytest.raises(ContextOverflow):
        model.complete(_msgs())


def test_a_503_after_minutes_is_a_model_that_kept_reasoning(monkeypatch, gw):
    pytest.importorskip("openai")
    from harness.inference import openai_client as oc
    from harness.inference.base import ModelTimeout
    model, waits = _model(monkeypatch, gw)
    clock = iter([0.0, 181.0, 181.0, 181.0])
    monkeypatch.setattr(oc.time, "monotonic", lambda: next(clock))
    gw.llm_script = [(503, {"Retry-After": "5"})]
    with pytest.raises(ModelTimeout, match="503 after 181s"):
        model.complete(_msgs())
    assert waits == []


# --- a flag in pieces --------------------------------------------------------------

def test_a_flag_split_across_surfaces_is_assembled(monkeypatch):
    import re
    from harness.flags.grounding import EvidenceStore
    monkeypatch.setenv("CTF_FLAG_PIECES", "1")
    st = EvidenceStore(pattern=re.compile(rb"flag\{[0-9a-f]{32}\}"))
    assert st.record("shell:a", b"flag{\nThe flag is split in three\n", cmd="cat /code/*.txt") == []
    [gf] = st.record("shell:b", b"abababababababababababababababab\n}\n", cmd="curl t/flag.txt t/brace.txt")
    assert gf.flag == FLAG and "assembled" in gf.source
    # Source code is full of lone braces and hashes: at most two built this way.
    for n in range(5):
        st.record("shell:c", f"{n:032x}\n".encode(), cmd="md5sum *")
    assert sum("assembled" in g.source for g in st.grounded_flags()) == 2


def test_pieces_are_not_assembled_unless_switched_on(monkeypatch):
    import re
    from harness.flags.grounding import EvidenceStore
    monkeypatch.delenv("CTF_FLAG_PIECES", raising=False)
    st = EvidenceStore(pattern=re.compile(rb"flag\{[0-9a-f]{32}\}"))
    st.record("shell:a", b"flag{\n", cmd="x")
    assert st.record("shell:b", b"abababababababababababababababab\n}\n", cmd="y") == []


# --- a whole run --------------------------------------------------------------------

def test_a_whole_run_against_the_gateway(monkeypatch, gw, tmp_path, http_target):
    """The kit's own practice challenge, with a scripted model: a plan, one
    command that prints the pieces, and nothing more. The harness assembles the
    flag, submits it, and the run ends; no give-up note."""
    pytest.importorskip("openai")
    code = _run_env(monkeypatch, gw, tmp_path, targets=f"127.0.0.1:{http_target}")
    (code / "flag.txt").write_text("flag{\n")
    (code / "README.txt").write_text("The flag is split in three.\n")
    srv = tmp_path / "srv"
    (srv / "flag.txt").write_text("ab" * 16 + "\n")
    (srv / "brace.txt").write_text("}\n")
    for k in ("OPENAI_BASE_URL", "OPENAI_API_KEY", "CTF_MODEL_HEADERS", "CTF_TOTAL_SECONDS",
              "CTF_PLATFORM", "CTF_BACKEND", "CTF_FLAG_PIECES", "CTF_GATEWAY_STATUS"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("CTF_FLAG_REGEX", r"flag\{[0-9a-f]{32}\}")
    monkeypatch.setenv("CTF_WORK_ROOT", str(tmp_path / "work"))
    monkeypatch.setenv("CTF_RUN_DIR", str(tmp_path / "logs"))
    command = ("cat flag.txt; for t in $(echo \"$TARGETS\" | tr ',' ' '); do "
               "curl -s http://$t/flag.txt; curl -s http://$t/brace.txt; done")
    gw.llm_script = [
        {"content": "Plan: read the files, then the target."},
        {"content": None, "tool_calls": [{"id": "c1", "type": "function", "function": {
            "name": "shell", "arguments": json.dumps({"command": command})}}]},
    ]
    from harness.config import config_from_env
    from harness.single import solve_one
    summary = solve_one(config_from_env())
    assert summary["solved"] is True and gw.flags == [FLAG] and gw.notes == []
    assert {"event": "tool_use", "meta": {"tool": "bash"}} in gw.logs
    assert os.environ["OPENAI_BASE_URL"] == gw.url + "/v1"
    # The run token is not in the log.
    assert "X-Run-Token=tok" not in Path(summary["log"]).read_text()


def test_a_run_that_runs_out_of_cost_gives_up_with_a_note(monkeypatch, gw, tmp_path):
    pytest.importorskip("openai")
    _run_env(monkeypatch, gw, tmp_path)
    for k in ("OPENAI_BASE_URL", "OPENAI_API_KEY", "CTF_MODEL_HEADERS", "CTF_TOTAL_SECONDS",
              "CTF_PLATFORM", "CTF_BACKEND", "CTF_FLAG_PIECES", "CTF_GATEWAY_STATUS"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("CTF_WORK_ROOT", str(tmp_path / "work"))
    monkeypatch.setenv("CTF_RUN_DIR", str(tmp_path / "logs"))
    gw.llm_script = [{"content": "Plan."}, (402, {})]
    from harness.config import config_from_env
    from harness.single import solve_one
    summary = solve_one(config_from_env())
    assert summary["solved"] is False and "cost cap reached" in summary["reason"]
    assert len(gw.notes) == 1 and gw.notes[0].endswith("cost")


# --- the tool list recorded at build time --------------------------------------------

def test_the_tool_list_recorded_at_build_time_replaces_the_probe(monkeypatch, tmp_path):
    from harness.agents import exttools

    class Boom:
        def run(self, *a, **k):
            raise AssertionError("probed although a recorded list exists")

    cache = tmp_path / "tools.json"
    cache.write_text(json.dumps(["gdb", "angr", "radare2"]))
    monkeypatch.setenv("CTF_TOOLS_CACHE", str(cache))
    assert exttools.probe_tools(Boom(), tmp_path) == {"gdb", "angr", "radare2"}
    # A missing, empty or broken record falls back to probing.
    for bad in ("", "[]", "{not json", '{"a": 1}'):
        cache.write_text(bad)
        assert exttools.cached_tools() is None
    monkeypatch.setenv("CTF_TOOLS_CACHE", str(tmp_path / "absent.json"))
    assert exttools.cached_tools() is None


def test_the_contest_dockerfile_records_the_tool_list():
    text = (Path(__file__).resolve().parent.parent / "Dockerfile.contest").read_text()
    assert "ENV CTF_TOOLS_CACHE=/opt/ctf-tools.json" in text and "write_tools_cache('/opt/ctf-tools.json')" in text


# --- a service to script against (Morse Relay, 20 November) ---------------------------

def test_a_misc_tcp_service_goes_to_the_generalist_not_to_pwn(monkeypatch, gw, tmp_path, tcp_target):
    from harness.agents.specialists import GeneralistSpecialist, PwnSpecialist, route
    code = _run_env(monkeypatch, gw, tmp_path, targets=f"127.0.0.1:{tcp_target}")
    (code / "relay.py").write_text("import socketserver, random, time\nMORSE = {'A': '.-'}\n")
    plat = sk.StarterKitPlatform()
    [chal] = plat.list_challenges()
    conn = plat.start_instance(chal.id)
    assert chal.category == "misc"
    spec = route(chal, conn)
    assert isinstance(spec, GeneralistSpecialist)
    assert {"connect", "send", "recv"} <= {t.name for t in spec.profile_for(conn).tools}
    # ...and the model is told to script it and to give the script time.
    assert "ONE script" in chal.description and "`timeout`" in chal.description
    # A binary behind the same port is still pwn.
    (code / "relay").write_bytes(b"\x7fELF" + b"\x00" * 20)
    plat2 = sk.StarterKitPlatform()
    [chal2] = plat2.list_challenges()
    assert isinstance(route(chal2, plat2.start_instance(chal2.id)), PwnSpecialist)


def test_the_team_can_send_any_challenge_to_the_generalist(monkeypatch, gw, tmp_path, tcp_target):
    from harness.agents.specialists import GeneralistSpecialist, route
    code = _run_env(monkeypatch, gw, tmp_path, targets=f"127.0.0.1:{tcp_target}",
                    instructions="@category misc")
    (code / "relay").write_bytes(b"\x7fELF" + b"\x00" * 20)
    plat = sk.StarterKitPlatform()
    [chal] = plat.list_challenges()
    assert isinstance(route(chal, plat.start_instance(chal.id)), GeneralistSpecialist)
