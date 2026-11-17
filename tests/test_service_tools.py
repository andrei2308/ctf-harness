"""connect/send/recv against a real local server that hangs up, like the
fair-dice service did on an unknown move."""

import socket
import tempfile
import threading
from pathlib import Path

from harness.agents.tools import (LocalExecutor, ServiceConnectTool, ServiceSendTool,
                                   ToolContext)
from harness.platforms.base import ConnInfo


def _server():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)

    def serve():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            c.sendall(b"Welcome. Pick a colour:\n")
            data = c.recv(100)
            if data.strip() != b"blue":
                c.sendall(b"I do not know that color...\n")
            c.close()                          # hangs up after one move, either way

    threading.Thread(target=serve, daemon=True).start()
    return srv


def test_a_dead_connection_is_not_reused_and_connect_starts_over():
    srv = _server()
    ctx = ToolContext("c", Path(tempfile.mkdtemp()), LocalExecutor(),
                      conn=ConnInfo(host="127.0.0.1", port=srv.getsockname()[1]))
    first = ServiceConnectTool().run({}, ctx)
    assert b"new connection" in first.output and b"Welcome" in first.output
    bad = ServiceSendTool().run({"data": "red", "recv_timeout": 2}, ctx)   # server hangs up
    dead = ServiceSendTool().run({"data": "yellow", "recv_timeout": 2}, ctx)
    told = bad.output + dead.output + (dead.error or "").encode()
    assert b"call connect to start over" in told        # the agent is told, not left guessing
    again = ServiceConnectTool().run({}, ctx)           # must be a fresh connection
    assert b"Welcome" in again.output
    ok = ServiceSendTool().run({"data": "blue", "recv_timeout": 2}, ctx)
    assert not ok.error
    srv.close()
