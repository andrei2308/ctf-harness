"""A mock contest "starter kit" for the adapter drill (CLAUDE_CODE_FINAL.md task 7).

HTTP API on :8080 behind a bearer token (MOCK_TOKEN), plus the challenge's own
TCP service on :31337. Field names are deliberately unlike the skeleton's
guesses. Two flags, both as questions: a MOCK{...} flag found in the file, and
a 4-digit PIN that only the TCP service reveals. Submit answers 200 correct,
400 wrong, 429 when called twice within a second."""
import codecs, json, os, socketserver, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN = os.environ.get("MOCK_TOKEN", "mock-token-123456789")
HTTP_PORT = int(os.environ.get("MOCK_HTTP_PORT", "8080"))
TCP_PORT = int(os.environ.get("MOCK_TCP_PORT", "31337"))
FLAG1, PIN = "MOCK{v4ult_d00r_0p3n}", "4821"
FILE = ("Recovered from the vault controller. The key was stored rot13'd:\n"
        + codecs.encode(FLAG1, "rot13") + "\n").encode()
CHALLENGE = {"slug": "vault-01", "title": "Rusty Vault", "type": "Crypto", "points": 100,
             "body": "An old vault controller. Get the key from its dump, then talk to the console.",
             "attachments": [{"name": "vault.dump", "href": "/api/v1/files/vault.dump"}],
             "endpoint": f"nc 127.0.0.1 {TCP_PORT}",
             "questions": [{"qid": 11, "text": "What is the vault key?", "format": "MOCK{...}"},
                           {"qid": 12, "text": "What is the admin PIN?", "format": "four digits"}]}
ANSWERS = {11: FLAG1, 12: PIN}
solved, last_submit = set(), [0.0]


class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, code, obj=None, raw=None, ctype="application/json", extra=None):
        body = raw if raw is not None else json.dumps(obj).encode()
        self.send_response(code); self.send_header("Content-Type", ctype)
        for k, v in (extra or {}).items(): self.send_header(k, v)
        self.end_headers(); self.wfile.write(body)
    def _auth(self):
        if self.headers.get("Authorization") != f"Bearer {TOKEN}":
            self._send(401, {"error": "bad token"}); return False
        return True
    def do_GET(self):
        if not self._auth(): return
        if self.path == "/api/v1/challenge":
            return self._send(200, {"challenge": CHALLENGE})
        if self.path == "/api/v1/files/vault.dump":
            return self._send(200, raw=FILE, ctype="application/octet-stream",
                              extra={"Content-Disposition": 'attachment; filename="vault.dump"'})
        self._send(404, {"error": "not found"})
    def do_POST(self):
        if not self._auth(): return
        if self.path != "/api/v1/answer":
            return self._send(404, {"error": "not found"})
        now = time.monotonic()
        if now - last_submit[0] < 1.0:
            last_submit[0] = now
            return self._send(429, {"error": "slow down"})
        last_submit[0] = now
        req = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        qid, ans = int(req.get("qid", 0)), str(req.get("answer", ""))
        if ANSWERS.get(qid) == ans:
            solved.add(qid)
            return self._send(200, {"result": "correct", "all_solved": solved == set(ANSWERS)})
        self._send(400, {"result": "incorrect"})


class Console(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b"Vault admin console. Say 'pin please'.\n")
        for line in self.rfile:
            if line.strip().lower() == b"pin please":
                self.wfile.write(f"Admin PIN: {PIN}\n".encode())
            else:
                self.wfile.write(b"?\n")

if __name__ == "__main__":
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    threading.Thread(target=socketserver.ThreadingTCPServer(("127.0.0.1", TCP_PORT), Console).serve_forever,
                     daemon=True).start()
    ThreadingHTTPServer(("127.0.0.1", HTTP_PORT), H).serve_forever()
