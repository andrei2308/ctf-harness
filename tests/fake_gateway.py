"""A stand-in for the AISafe gateway, for tests: the routes, the token check and
the status codes of the kit's local/gateway.mjs, plus switches to make it
misbehave (cooldowns, a spent budget, an ended run)."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class FakeGateway:
    def __init__(self, flag: str = "flag{" + "ab" * 16 + "}", token: str = "tok",
                 instructions: str = "", seconds: int = 600, cents: float = 100):
        self.flag, self.token, self.instructions = flag, token, instructions
        self.seconds, self.cents = seconds, cents
        self.cooldowns = 0          # next N wrong-or-right /flag calls answer 429
        self.ended = False
        self.flags: list[str] = []
        self.logs: list[dict] = []
        self.notes: list[str] = []
        self.llm_script: list = []  # per call: an int status, or a dict reply
        self.llm_calls: list[dict] = []
        self.headers_seen: list[dict] = []
        gw = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):  # quiet
                pass

            def _send(self, status, body, headers=None, text=False):
                raw = body.encode() if text else json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "text/plain" if text else "application/json")
                self.send_header("Content-Length", str(len(raw)))
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(raw)

            def _route(self):
                path = self.path.split("?")[0]
                return path[len("/gateway"):] if path.startswith("/gateway") else path

            def do_GET(self):
                gw.headers_seen.append(dict(self.headers))
                if self.headers.get("X-Run-Token") != gw.token:
                    return self._send(401, {"error": "bad or missing X-Run-Token"})
                r = self._route()
                if r == "/health":
                    return self._send(200, {"ok": True, "run": "t", "secondsLeft": gw.seconds,
                                            "centsLeft": gw.cents})
                if r == "/instructions":
                    return self._send(200, gw.instructions, text=True)
                self._send(404, {"error": "not found"})

            def do_POST(self):
                gw.headers_seen.append(dict(self.headers))
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n) or b"{}")
                if self.headers.get("X-Run-Token") != gw.token:
                    return self._send(401, {"error": "bad or missing X-Run-Token"})
                r = self._route()
                if r == "/v1/chat/completions":
                    gw.llm_calls.append(body)
                    step = gw.llm_script.pop(0) if gw.llm_script else {"content": "ok"}
                    if isinstance(step, tuple):
                        status, headers = step
                        return self._send(status, {"error": f"status {status}"}, headers)
                    msg = {"role": "assistant", "content": step.get("content")}
                    if step.get("tool_calls"):
                        msg["tool_calls"] = step["tool_calls"]
                    return self._send(200, {
                        "id": "c", "object": "chat.completion", "model": "m",
                        "choices": [{"index": 0, "message": msg,
                                     "finish_reason": "tool_calls" if step.get("tool_calls") else "stop"}],
                        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}})
                if r == "/flag":
                    if gw.ended:
                        return self._send(409, {"error": "run ended"})
                    if gw.cooldowns > 0:
                        gw.cooldowns -= 1
                        return self._send(429, {"error": "wrong-flag cooldown: wait 1s"},
                                          {"Retry-After": "0"})
                    gw.flags.append(body.get("flag", ""))
                    if body.get("flag") == gw.flag:
                        gw.ended = True
                        return self._send(200, {"correct": True, "points": 250})
                    return self._send(200, {"correct": False, "error": "incorrect flag"})
                if r == "/log":
                    if len(gw.logs) >= 300:
                        return self._send(429, {"error": "log limit"})
                    gw.logs.append(body)
                    return self._send(200, {"ok": True})
                if r == "/give-up":
                    gw.notes.append(str(body.get("message", ""))[:32])
                    gw.ended = True
                    return self._send(200, {"ok": True})
                self._send(404, {"error": "not found"})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/gateway"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
