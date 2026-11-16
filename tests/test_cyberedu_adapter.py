"""CyberEDU adapter against a fake transport. Response shapes are the ones the
live API returned on 2026-11-16 (trimmed); no network is used."""

import pytest

import harness.platforms.cyberedu_mcp as cm
from harness.platforms.base import ChallengeKind, PlatformError
from harness.platforms.cyberedu_mcp import FORBIDDEN_TOOLS, CyberEduMcpPlatform

CID = "32f17da0-b3bc-11eb-9896-654a273992be"
DETAIL = {
    "id": CID, "title": "pingster", "description": "Ping, ping, ping.",
    "difficulty": "Easy", "points": "50", "is_subscribed": True, "is_owned": False,
    "tags": [{"id": 1, "name": "Web", "type": "default"}],
    "flags": [{"id": 4744}], "media": [{"id": 10368, "file_name": "app.zip", "size": 3}],
}
NO_SERVICE = {"error": "HTTP Error", "status_code": 400,
              "message": "Client error '400 Bad Request'", "response": '{"message": "Bad request."}'}
NOT_FOUND = {"deploymentStatus": "not_found", "address": "", "service_type": "ip:port",
             "permissions": {"start": True}}
PROVISIONING = {"deploymentStatus": "provisioning", "address": "", "service_type": "ip:port"}
RUNNING = {"deploymentStatus": "running", "address": "35.242.202.105:32287",
           "formattedAddresses": [{"address": "35.242.202.105:32287", "name": "Port 3000"}],
           "service_type": "ip:port", "terminate_at": {"timestamp": 1794852706}}


class FakeTransport:
    def __init__(self, replies, tmp=None):
        self.replies = {k: list(v) if isinstance(v, list) else v for k, v in replies.items()}
        self.calls = []
        self.tmp = tmp
        self.closed = False

    def call_tool(self, name, args):
        self.calls.append((name, dict(args)))
        if name == "cyberedu_download_file":
            # Live: the API sends no filename header, so the server falls back
            # to a generic name.
            p = __import__("pathlib").Path(args["save_path"]) / "downloaded_file"
            p.write_bytes(b"zip")
            return {"type": "file_saved", "path": str(p), "size_bytes": 3}
        r = self.replies[name]
        if isinstance(r, list):
            return r.pop(0) if len(r) > 1 else r[0]
        return r

    def close(self):
        self.closed = True


def _plat(replies, **kw):
    replies = {"cyberedu_get_challenge": DETAIL, **replies}
    t = FakeTransport(replies)
    return CyberEduMcpPlatform(transport=t, **kw), t


def test_flag_retrieval_tools_are_refused():
    p, t = _plat({})
    for tool in FORBIDDEN_TOOLS:
        with pytest.raises(PlatformError, match="refusing"):
            p._call(tool, {"challenge_id": CID, "flag_id": "1"})
    assert t.calls == []


def test_challenge_detail_is_parsed():
    p, _ = _plat({})
    c = p.get_challenge(CID)
    assert (c.name, c.category, c.kind, c.points, c.flags_required) == \
        ("pingster", "Web", ChallengeKind.WEB, 50, 1)
    assert c.meta["difficulty"] == "Easy"


def test_files_are_downloaded_into_the_work_dir(tmp_path):
    p, t = _plat({})
    files = p.download_files(CID, tmp_path)
    assert files == [(tmp_path / "app.zip").resolve()]
    name, args = t.calls[-1]
    assert name == "cyberedu_download_file" and args["file_id"] == "10368"


def test_unsubscribed_challenge_is_not_subscribed_for_you(tmp_path):
    p, t = _plat({"cyberedu_get_challenge": {**DETAIL, "is_subscribed": False}})
    with pytest.raises(PlatformError, match="not subscribed"):
        p.download_files(CID, tmp_path)
    assert not any("subscribe" in n for n, _ in t.calls)


def test_files_only_challenge_starts_no_instance():
    p, t = _plat({"cyberedu_get_service_status": NO_SERVICE})
    conn = p.start_instance(CID)
    assert conn.host is None and conn.url is None
    assert not any(n == "cyberedu_start_service" for n, _ in t.calls)


def test_instance_is_started_and_awaited(monkeypatch):
    monkeypatch.setattr(cm, "INSTANCE_POLL_SECONDS", 0)
    p, t = _plat({"cyberedu_get_service_status": [NOT_FOUND, PROVISIONING, RUNNING],
                  "cyberedu_start_service": {"message": "Deployment started"}})
    conn = p.start_instance(CID)
    assert (conn.host, conn.port, conn.url) == \
        ("35.242.202.105", 32287, "http://35.242.202.105:32287")
    assert [n for n, _ in t.calls].count("cyberedu_start_service") == 1
    assert p.started_instances == {CID}


def test_running_instance_is_reused():
    p, t = _plat({"cyberedu_get_service_status": RUNNING})
    assert p.start_instance(CID).port == 32287
    assert not any(n == "cyberedu_start_service" for n, _ in t.calls)


def test_instance_that_never_runs_raises(monkeypatch):
    monkeypatch.setattr(cm, "INSTANCE_POLL_SECONDS", 0)
    p, _ = _plat({"cyberedu_get_service_status": [NOT_FOUND, PROVISIONING],
                  "cyberedu_start_service": {"message": "Deployment started"}},
                 instance_wait=0)
    with pytest.raises(PlatformError, match="not running"):
        p.start_instance(CID)


def test_correct_flag_is_accepted():
    p, t = _plat({"cyberedu_submit_flag": {"status": "success", "solved": True}})
    r = p.submit_flag(CID, "CTF{x}")
    assert r.accepted and r.challenge_solved
    assert t.calls[-1] == ("cyberedu_submit_flag",
                           {"challenge_id": CID, "flag_id": "4744", "flag_value": "CTF{x}"})


def test_wrong_flag_is_rejected():
    p, _ = _plat({"cyberedu_submit_flag": {"status": "failed", "solved": False}})
    assert not p.submit_flag(CID, "CTF{nope}").accepted


def test_multi_flag_tries_each_open_flag_id():
    two = {**DETAIL, "flags": [{"id": 1}, {"id": 2}]}
    p, t = _plat({"cyberedu_get_challenge": two,
                  "cyberedu_submit_flag": [{"status": "failed"}, {"status": "success"},
                                           {"status": "success"}]})
    first = p.submit_flag(CID, "CTF{b}")
    assert first.accepted and not first.challenge_solved
    assert [a["flag_id"] for n, a in t.calls if n == "cyberedu_submit_flag"] == ["1", "2"]
    second = p.submit_flag(CID, "CTF{a}")                 # only flag 1 is still open
    assert second.accepted and second.challenge_solved
    assert [a["flag_id"] for n, a in t.calls if n == "cyberedu_submit_flag"][-1] == "1"


def test_transport_error_raises_platform_error():
    p, _ = _plat({"cyberedu_submit_flag": {"error": "ConnectError", "message": "boom"}})
    with pytest.raises(PlatformError):
        p.submit_flag(CID, "CTF{x}")


def test_contest_mode_uses_contest_tools_and_slug(tmp_path):
    p, t = _plat({"cyberedu_get_contest_challenge": DETAIL,
                  "cyberedu_submit_contest_flag": {"status": "success"}},
                 contest_slug="dctf-26")
    p.submit_flag(CID, "CTF{x}")
    name, args = t.calls[-1]
    assert name == "cyberedu_submit_contest_flag" and args["contest_slug"] == "dctf-26"


def test_no_method_ever_calls_a_flag_tool(tmp_path, monkeypatch):
    monkeypatch.setattr(cm, "INSTANCE_POLL_SECONDS", 0)
    p, t = _plat({"cyberedu_list_challenges": [DETAIL],
                  "cyberedu_get_service_status": [NOT_FOUND, RUNNING],
                  "cyberedu_start_service": {}, "cyberedu_extend_service": {},
                  "cyberedu_submit_flag": {"status": "success"}})
    p.list_challenges(); p.get_challenge(CID); p.download_files(CID, tmp_path)
    p.start_instance(CID); p.get_conn_info(CID); p.extend_instance(CID)
    p.submit_flag(CID, "CTF{x}"); p.close()
    assert not {n for n, _ in t.calls} & FORBIDDEN_TOOLS
    assert t.closed


def test_cookie_goes_only_to_the_server_with_a_minimal_env(monkeypatch):
    seen = {}

    class Spy:
        def __init__(self, command, args, env):
            seen.update(command=command, args=args, env=env)
        def close(self): ...

    monkeypatch.setattr(cm, "StdioMcpTransport", Spy)
    monkeypatch.setenv("CYBEREDU_SESSION_COOKIE", "eyJpdiI6cookie-value-0123%3D")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-model-key-not-for-the-server")
    p = CyberEduMcpPlatform()
    env = seen["env"]
    assert env["CYBEREDU_SESSION_COOKIE"] == "eyJpdiI6cookie-value-0123%3D"
    assert "OPENAI_API_KEY" not in env and set(env) <= {
        "PATH", "HOME", "CYBEREDU_SESSION_COOKIE", "CYBEREDU_TENANT"}
    assert "CYBEREDU_SESSION_COOKIE" not in __import__("os").environ   # taken out
    home = env["HOME"]
    p.close()
    assert not __import__("os").path.exists(home)                       # nothing persisted


def test_missing_cookie_is_a_clear_error(monkeypatch):
    monkeypatch.delenv("CYBEREDU_SESSION_COOKIE", raising=False)
    with pytest.raises(PlatformError, match="CYBEREDU_SESSION_COOKIE"):
        CyberEduMcpPlatform()


ALREADY = {"error": "HTTP Error", "status_code": 403, "message": "Client error '403 Forbidden'",
           "response": '{\n    "message": "Challenge already solved"\n}'}


def test_a_flag_solved_before_the_run_is_skipped_not_retried_and_not_a_solve():
    # biscuiti, live: flag 1 was solved on the account earlier, so ANY value
    # sent to it gets 403 "Challenge already solved". That is no verdict on the
    # candidate: move on to the open flag, and never report a solve from it.
    two = {**DETAIL, "flags": [{"id": 1}, {"id": 2}]}
    p, t = _plat({"cyberedu_get_challenge": two,
                  "cyberedu_submit_flag": [ALREADY, {"status": "failed"}]})
    r = p.submit_flag(CID, "CTF{candidate}")
    assert not r.accepted and not r.already_solved and not r.challenge_solved
    assert [a["flag_id"] for n, a in t.calls if n == "cyberedu_submit_flag"] == ["1", "2"]
    p.submit_flag(CID, "CTF{other}")                       # flag 1 is not tried again
    assert [a["flag_id"] for n, a in t.calls if n == "cyberedu_submit_flag"][-1] == "2"


def test_single_flag_already_solved_is_not_a_solve():
    p, _ = _plat({"cyberedu_submit_flag": ALREADY})
    r = p.submit_flag(CID, "CTF{x}")
    assert not r.accepted and not r.already_solved and not r.challenge_solved
    again = p.submit_flag(CID, "CTF{y}")
    assert not again.accepted and "no open flag" in again.message


def test_a_4xx_on_submit_is_an_answer_not_a_transport_error():
    bad = {"error": "HTTP Error", "status_code": 422, "message": "Unprocessable", "response": "{}"}
    p, _ = _plat({"cyberedu_submit_flag": bad})
    assert not p.submit_flag(CID, "CTF{x}").accepted          # no PlatformError


def test_a_5xx_on_submit_stays_retryable():
    bad = {"error": "HTTP Error", "status_code": 502, "message": "Bad Gateway", "response": ""}
    p, _ = _plat({"cyberedu_submit_flag": bad})
    with pytest.raises(PlatformError):
        p.submit_flag(CID, "CTF{x}")


def test_files_get_their_real_names(tmp_path):
    p, _ = _plat({})
    (path,) = p.download_files(CID, tmp_path)
    assert path.name == "app.zip" and path.read_bytes() == b"zip"
    assert not (tmp_path / "downloaded_file").exists()


def test_a_name_from_the_platform_cannot_escape_the_work_dir(tmp_path):
    evil = {**DETAIL, "media": [{"id": 7, "file_name": "../../etc/x.bin"}]}
    p, _ = _plat({"cyberedu_get_challenge": evil})
    (path,) = p.download_files(CID, tmp_path)
    assert path.parent == tmp_path.resolve() and path.name == "x.bin"
