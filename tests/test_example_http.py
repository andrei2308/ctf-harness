"""The adapter drill's worked example against its mock kit (tests/mock_kit.py),
and the kit pieces the drill added."""

import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

from harness.platforms import kit

MOCK = Path(__file__).with_name("mock_kit.py")
FLAG1, PIN = "MOCK{v4ult_d00r_0p3n}", "4821"


def _free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


@pytest.fixture
def kit_env(monkeypatch):
    http, tcp = _free_port(), _free_port()
    env = {**os.environ, "MOCK_TOKEN": "tok-123456789012", "MOCK_HTTP_PORT": str(http),
           "MOCK_TCP_PORT": str(tcp)}
    proc = subprocess.Popen([sys.executable, str(MOCK)], env=env)
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", http), 0.2).close(); break
        except OSError:
            time.sleep(0.1)
    monkeypatch.setenv("CTF_API_URL", f"http://127.0.0.1:{http}")
    monkeypatch.setenv("CTF_API_TOKEN", "tok-123456789012")
    yield tcp
    proc.terminate(); proc.wait(5)


def test_example_adapter_end_to_end_against_the_mock(kit_env):
    from harness.platforms.example_http import ExampleHttpPlatform
    p = ExampleHttpPlatform()
    assert "CTF_API_TOKEN" not in os.environ                   # taken out of the env
    (c,) = p.list_challenges()
    assert (c.id, c.category, c.flags_required) == ("vault-01", "Crypto", 2)
    assert "What is the admin PIN? (format: four digits)" in c.description
    (f,) = p.download_files(c.id, Path(tempfile.mkdtemp()))
    assert f.name == "vault.dump"
    conn = p.start_instance(c.id)                              # "nc 127.0.0.1 PORT"
    assert (conn.host, conn.port) == ("127.0.0.1", kit_env)
    wrong = p.submit_flag(c.id, "CTF{nope}")                   # two questions, paced: no 429
    assert not wrong.accepted
    assert p.submit_flag(c.id, FLAG1).accepted
    last = p.submit_flag(c.id, PIN)
    assert last.accepted and last.challenge_solved


def test_pacer_spaces_calls():
    now, slept = [0.0], []
    pace = kit.Pacer(1.0, clock=lambda: now[0], sleep=lambda s: slept.append(s))
    pace.wait(); now[0] += 0.3; pace.wait()
    assert slept == [pytest.approx(0.7)]


def test_adapter_check_warns_when_the_stated_format_is_not_matched(monkeypatch):
    from harness.adapter_check import stated_flag_examples
    from harness.flags.grounding import flag_pattern
    monkeypatch.delenv("CTF_FLAG_REGEX", raising=False)
    exs = stated_flag_examples("1. What is the vault key? (format: MOCK{...})")
    assert exs == ["MOCK{x0x0x0x0}"] and not flag_pattern().search(exs[0].encode())
    assert flag_pattern().search(stated_flag_examples("format: DCTF{sha256}")[0].encode())
