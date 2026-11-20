"""Adapter for the AISafe starter kit (DefCamp 2026 Agentic CTF).

Written on 20 November from the kit's README, its starter agent and its local
gateway. What the platform gives a run, and where it lands here:

    GATEWAY_URL, RUN_TOKEN     every call goes to the gateway with X-Run-Token
    /code                      the challenge's files           -> download_files
    TARGETS (host:port,...)    live targets, protocol unknown  -> start_instance
    INSTRUCTIONS               the team's notes for this run   -> description,
                               and `@` lines that steer the harness (below)
    TIME_LIMIT_SECONDS,        the run's budgets               -> bootstrap(),
    COST_LIMIT_CENTS           and GET /health while running   -> seconds_left

    POST /flag {flag}          {"correct": true|false}         -> submit_flag
    POST /give-up {message}    a note of 32 characters         -> finish
    POST /log {event, meta}    the team's live timeline        -> timeline

There is no challenge name, category or description: the platform gives files
and targets only. So the category is guessed from them, and the description is
assembled from the team's notes, the README-like files and a probe of each
target.

STEERING A RUN WITHOUT A NEW UPLOAD: lines of INSTRUCTIONS that start with `@`
are read by the harness and not shown to the model.

    @category rev            route to that specialist (pwn rev crypto web
                             forensics stego mobile blockchain misc)
    @name my-label           name used in logs
    @set CTF_NAME=value      any harness setting, for this run only
    @preflight               first check the model endpoint and print the result
    @check-only              the same, then stop without solving (a cheap first
                             run on the practice challenge)

Everything else in INSTRUCTIONS is given to the model as the team's notes.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path

from ..secrets import register
from .base import Challenge, ChallengeKind, ConnInfo, Platform, PlatformError, SubmitResult

PLATFORM = "harness.platforms.starter_kit:StarterKitPlatform"
# Seconds kept back from the run's time limit for the last submission and the
# give-up note.
RESERVE_SECONDS = 30
NOTE_CHARS = 32
LOG_LIMIT = 300
# Files copied out of /code in full; above this a file is left there and named.
COPY_LIMIT_BYTES = 400 * 1024 * 1024

FLAG_TEXT = (
    "Flag format: flag{ followed by 32 lowercase hex characters and }. The flag is "
    "generated for this run. It can be split across the files and the targets: the "
    "part starting with flag{ comes first, the part ending with } comes last, "
    "hex-only parts go between. A complete flag written in source code may be a "
    "placeholder; the real one is in what the running challenge holds.")
# Worded without the names of techniques: the notes index suggests sections by
# the words of the description, and "reverse shells" here put that section of
# the web notes at the top of every challenge.
RULES_TEXT = (
    "Network: only TCP to the listed targets, and no internet. Inbound connections "
    "to you are impossible, so an exploit has to return its result over a "
    "connection you opened.")

_DIRECTIVE = re.compile(r"^\s*@([a-z][a-z-]*)\b[ \t]*[:=]?[ \t]*(.*)$", re.I)
_TEXT_NAMES = re.compile(r"(?i)^(readme|description|challenge|notes?|hint|task|statement)[^/]*$|\.(txt|md)$")


# --- INSTRUCTIONS -------------------------------------------------------------

def split_instructions(text: str) -> tuple[str, dict]:
    """(notes for the model, directives for the harness) from INSTRUCTIONS."""
    notes, directives = [], {"set": {}}
    for line in (text or "").splitlines():
        m = _DIRECTIVE.match(line)
        if not m:
            notes.append(line)
            continue
        key, value = m.group(1).lower(), m.group(2).strip()
        if key == "set":
            name, _, val = value.partition("=")
            if re.fullmatch(r"CTF_[A-Z0-9_]+", name.strip()):
                directives["set"][name.strip()] = val.strip()
        elif key in ("category", "cat"):
            directives["category"] = value.lower()
        elif key == "name":
            directives["name"] = value
        elif key in ("preflight", "check-only"):
            directives[key] = True
        else:
            notes.append(line)             # not ours: the model may want it
    return "\n".join(notes).strip(), directives


def parse_targets(text: str) -> list[tuple[str, int]]:
    out = []
    for part in (text or "").split(","):
        host, _, port = part.strip().rpartition(":")
        if host and port.isdigit():
            out.append((host.strip("[]"), int(port)))
    return out


def bootstrap(env=os.environ) -> dict[str, str]:
    """Map the platform's variables onto the harness's settings. Called at
    start-up (config_from_env) and a no-op outside a run of this platform.

    Nothing set in contest.env or the real environment is overridden, except by
    an `@set` line of INSTRUCTIONS, which is the team steering this one run."""
    gateway, token = env.get("GATEWAY_URL", "").strip(), env.get("RUN_TOKEN", "").strip()
    if not gateway or not token:
        return {}
    register(token)
    applied: dict[str, str] = {}

    def default(name: str, value: str) -> None:
        if not env.get(name):
            env[name] = applied[name] = value

    default("OPENAI_BASE_URL", gateway.rstrip("/") + "/v1")
    default("OPENAI_API_KEY", "gateway")                 # any key; the token is the header
    default("CTF_MODEL_HEADERS", f"X-Run-Token={token}")
    default("CTF_BACKEND", "openai")
    default("CTF_PLATFORM", PLATFORM)
    default("CTF_FAST_MODEL", "qwen3.8-27b")             # ignored by the gateway
    default("CTF_GATEWAY_STATUS", "1")                   # 400 = too long, 402/409 = stop
    default("CTF_FLAG_PIECES", "1")                      # a flag split across surfaces
    limit = env.get("TIME_LIMIT_SECONDS", "").strip()
    if limit.replace(".", "", 1).isdigit():
        default("CTF_TOTAL_SECONDS", str(max(60, int(float(limit)) - RESERVE_SECONDS)))
    if len(parse_targets(env.get("TARGETS", ""))) > 1:
        default("CTF_TARGET_SCOPE", "any")               # several targets: no one-port guard
    _, directives = split_instructions(env.get("INSTRUCTIONS", ""))
    for name, value in directives["set"].items():
        env[name] = applied[name] = value
    return applied


# --- probing a target ---------------------------------------------------------

def probe_target(host: str, port: int, timeout: float = 4.0) -> dict:
    """What a target speaks: {"proto": "http"|"https"|"tcp"|"down", "info": str}.
    The platform does not say; the kit's advice is HTTP first, raw TCP if that
    fails. A banner the service sends on connect is kept as `info`."""
    request = f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode()

    def talk(wrap=None) -> bytes:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            s = wrap(raw) if wrap else raw
            s.settimeout(1.2)
            try:
                banner = s.recv(400)            # a service that speaks first
            except (socket.timeout, TimeoutError):
                banner = b""
            if banner and not banner.startswith(b"HTTP/"):
                return banner
            s.settimeout(timeout)
            s.sendall(request)
            data = banner
            try:
                while len(data) < 600:
                    chunk = s.recv(600)
                    if not chunk:
                        break
                    data += chunk
            except (socket.timeout, TimeoutError):
                pass
            return data

    try:
        data = talk()
    except OSError as e:
        return {"proto": "down", "info": str(e)[:80]}
    if data.startswith(b"HTTP/"):
        head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
        server = re.search(r"(?im)^(server|x-powered-by):\s*(.+)$", head)
        info = head.splitlines()[0].strip() + (f"; {server.group(0).strip()}" if server else "")
        return {"proto": "http", "info": info[:160]}
    if not data.strip(b"\x00\r\n ") or data[:1] in (b"\x15", b"\x16"):
        try:                                     # nothing readable in clear: TLS?
            ctx = ssl.create_default_context()
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            tls = talk(lambda raw: ctx.wrap_socket(raw, server_hostname=host))
            if tls.startswith(b"HTTP/"):
                return {"proto": "https", "info": tls.split(b"\r\n", 1)[0].decode("latin-1", "replace")[:160]}
        except OSError:
            pass
    text = data.decode("utf-8", "replace").strip()
    return {"proto": "tcp", "info": text[:200]}


# --- guessing the category ----------------------------------------------------

_EXT = {
    "forensics": {".pcap", ".pcapng", ".cap", ".mem", ".raw", ".vmem", ".dmp", ".img", ".dd",
                  ".e01", ".evtx", ".ad1", ".vmdk", ".lime"},
    "stego": {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".wav", ".mp3", ".flac", ".tiff"},
    "mobile": {".apk", ".dex", ".ipa", ".aab"},
    "blockchain": {".sol"},
    "web": {".php", ".html", ".js", ".ts", ".jsx", ".tsx", ".ejs", ".twig", ".jsp", ".aspx"},
}
_CRYPTO_WORDS = re.compile(
    rb"Crypto\.|from Crypto|bytes_to_long|long_to_bytes|getPrime|\bRSA\b|\bAES\b|"
    rb"\bn\s*=\s*\d{20,}|\be\s*=\s*\d+|pow\(|sage\.all|EllipticCurve|\bGF\(", re.I)
_WEB_WORDS = re.compile(rb"flask|django|express\(|fastapi|@app\.route|app\.get\(|<\?php|"
                        rb"require\(['\"]express|http\.createServer|springframework", re.I)
_JAIL_WORDS = re.compile(rb"\beval\(|\bexec\(|__builtins__|blacklist|banned|jail", re.I)


def _is_elf(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            return fh.read(4) == b"\x7fELF"
    except OSError:
        return False


def guess_category(files: list[Path], protos: list[str]) -> str:
    """A category for routing, from the files and from what the targets speak.
    The platform gives none; `@category` in INSTRUCTIONS overrides this."""
    exts = {p.suffix.lower() for p in files}
    for cat in ("mobile", "blockchain", "forensics"):
        if exts & _EXT[cat]:
            return cat
    elf = [p for p in files if _is_elf(p) and not re.search(r"(?i)^(libc|ld)[-.]|\.so(\.|$)", p.name)]
    sample = b""
    for p in files:
        if p.suffix.lower() in (".py", ".sage", ".txt", ".js", ".php", ".rb", ".go", ".c", ".md", ""):
            try:
                sample += p.read_bytes()[:6000]
            except OSError:
                pass
    http = any(p in ("http", "https") for p in protos)
    tcp = any(p == "tcp" for p in protos)
    if elf:
        return "pwn" if (tcp or http) else "rev"
    if _WEB_WORDS.search(sample) or (http and exts & _EXT["web"]):
        return "web"
    if _CRYPTO_WORDS.search(sample):
        return "crypto"
    if tcp and _JAIL_WORDS.search(sample):
        return "pyjail"
    if http:
        return "web"
    if exts and exts <= _EXT["stego"] | {".txt", ".md"} and exts & _EXT["stego"]:
        return "stego"
    if exts & {".pyc", ".jar", ".class", ".exe", ".dll", ".wasm"}:
        return "rev"
    return ""                # the router falls back on the connection's shape


# --- the adapter --------------------------------------------------------------

class StarterKitPlatform(Platform):
    def __init__(self) -> None:
        self.base = os.environ.get("GATEWAY_URL", "").strip().rstrip("/")
        self.token = os.environ.get("RUN_TOKEN", "").strip()
        if not self.base or not self.token:
            raise PlatformError("GATEWAY_URL and RUN_TOKEN are not set: not inside a run")
        register(self.token)
        self.run_id = os.environ.get("RUN_ID", "").strip() or "run"
        self.code = Path(os.environ.get("CTF_CODE_DIR") or "/code")
        self.targets = parse_targets(os.environ.get("TARGETS", ""))
        text = os.environ.get("INSTRUCTIONS", "")
        if not text.strip():
            text = self._instructions_from_gateway()
        self.notes, self.directives = split_instructions(text)
        self._probes: dict[tuple[str, int], dict] | None = None
        self._challenge: Challenge | None = None
        self._log_events = 0
        self._log_failures = 0
        self._ended = ""            # why the run is over, once the gateway said so
        self._solved = False

    # --- gateway --------------------------------------------------------------

    def _call(self, method: str, route: str, body: dict | None = None,
              timeout: float = 20.0) -> tuple[int, object, dict]:
        """(status, parsed body, headers). Raises PlatformError when there was
        no answer at all; every HTTP status is returned for the caller to read."""
        data = json.dumps(body).encode() if body is not None else None
        headers = {"X-Run-Token": self.token, "Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.base + route, data=data, headers=headers,
                                     method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status, raw, hdrs = resp.status, resp.read(), dict(resp.headers)
        except urllib.error.HTTPError as e:
            status, raw, hdrs = e.code, e.read(), dict(e.headers or {})
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise PlatformError(f"{method} {route}: {e}") from e
        text = raw.decode("utf-8", "replace")
        try:
            parsed: object = json.loads(text) if text.strip()[:1] in ("{", "[") else text
        except ValueError:
            parsed = text
        return status, parsed, {k.lower(): v for k, v in hdrs.items()}

    def _instructions_from_gateway(self) -> str:
        try:
            status, body, _ = self._call("GET", "/instructions", timeout=8)
        except PlatformError:
            return ""
        return body if status == 200 and isinstance(body, str) else ""

    def health(self) -> dict | None:
        """{"secondsLeft": n, "centsLeft": n, ...} or None when it cannot be read."""
        try:
            status, body, _ = self._call("GET", "/health", timeout=8)
        except PlatformError:
            return None
        return body if status == 200 and isinstance(body, dict) else None

    def seconds_left(self) -> float | None:
        """Seconds the harness may still use, for the budget to follow: the
        platform adds back time spent waiting for the shared model, so this can
        grow. Raises RunEnded when the cost cap is used up."""
        h = self.health()
        if h is None:
            return None
        cents = h.get("centsLeft")
        floor = float(os.environ.get("CTF_KEEP_CENTS") or 0)
        if isinstance(cents, (int, float)) and cents <= floor:
            from ..scheduler.budget import RunEnded
            self._ended = "out of budget"
            raise RunEnded(f"cost cap reached ({cents} cents left)")
        left = h.get("secondsLeft")
        return max(0.0, float(left) - RESERVE_SECONDS) if isinstance(left, (int, float)) else None

    # --- the challenge --------------------------------------------------------

    def _files(self) -> list[Path]:
        if not self.code.is_dir():
            return []
        return sorted(p for p in self.code.rglob("*") if p.is_file())

    def _probe_all(self) -> dict[tuple[str, int], dict]:
        if self._probes is None:
            self._probes = {t: probe_target(*t) for t in self.targets}
        return self._probes

    def list_challenges(self) -> list[Challenge]:
        if self._challenge is not None:
            return [self._challenge]
        files, probes = self._files(), self._probe_all()
        protos = [p["proto"] for p in probes.values()]
        category = self.directives.get("category") or guess_category(files, protos)
        if any(p in ("http", "https") for p in protos):
            kind = ChallengeKind.WEB
        elif self.targets:
            kind = ChallengeKind.INTERACTIVE
        else:
            kind = ChallengeKind.STATIC
        self._challenge = Challenge(
            id=re.sub(r"[^\w.-]", "_", self.run_id)[:60] or "run",
            name=self.directives.get("name") or f"run {self.run_id}",
            kind=kind, category=category,
            description=self._describe(files, probes),
            flags_required=1,
            meta={"targets": [f"{h}:{p}" for h, p in self.targets],
                  "category_from": "team" if self.directives.get("category") else "guess"})
        return [self._challenge]

    def get_challenge(self, challenge_id: str) -> Challenge:
        return self.list_challenges()[0]

    def _describe(self, files: list[Path], probes: dict) -> str:
        parts = []
        if self.notes:
            parts.append("Your team's notes for this run (follow them):\n" + self.notes[:4096])
        if files:
            lines = [f"{p.relative_to(self.code)} ({p.stat().st_size} bytes)" for p in files[:40]]
            if len(files) > 40:
                lines.append(f"... and {len(files) - 40} more")
            parts.append("Challenge files (copied into your working directory, also in /code):\n"
                         + "\n".join(lines))
            room = 1500
            for p in files:
                if room <= 0 or not _TEXT_NAMES.search(p.name) or p.stat().st_size > 4000:
                    continue
                try:
                    body = p.read_text("utf-8", "replace").strip()
                except OSError:
                    continue
                if body:
                    parts.append(f"{p.relative_to(self.code)} says:\n{body[:room]}")
                    room -= len(body)
        else:
            parts.append("No files were shipped with this challenge.")
        if probes:
            lines = []
            for (host, port), p in probes.items():
                how = {"http": f"HTTP, answers `{p['info']}`: http://{host}:{port}/",
                       "https": f"HTTPS, answers `{p['info']}`: https://{host}:{port}/",
                       "tcp": "raw TCP" + (f", on connect it sends: {p['info']!r}" if p["info"] else
                                           ", silent until it gets input"),
                       "down": f"did not answer a first probe ({p['info']}); try again"}[p["proto"]]
                lines.append(f"{host}:{port} ({how})")
            parts.append("Live targets:\n" + "\n".join(lines))
        else:
            parts.append("No live target: everything needed is in the files.")
        parts += [FLAG_TEXT, RULES_TEXT]
        return "\n\n".join(parts)

    def download_files(self, challenge_id: str, dest: Path) -> list[Path]:
        out: list[Path] = []
        for src in self._files():
            target = Path(dest) / src.relative_to(self.code)
            try:
                if src.stat().st_size > COPY_LIMIT_BYTES:
                    continue                   # stays in /code; the description names it
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, target)
                target.chmod(target.stat().st_mode | 0o600)
                out.append(target)
            except OSError:
                continue
        return out

    def start_instance(self, challenge_id: str) -> ConnInfo:
        if not self.targets:
            return ConnInfo()
        probes = self._probe_all()
        # The first target that speaks HTTP, else the first one.
        pick = next((t for t in self.targets if probes[t]["proto"] in ("http", "https")),
                    self.targets[0])
        host, port = pick
        proto = probes[pick]["proto"]
        url = f"{proto}://{host}:{port}" if proto in ("http", "https") else None
        return ConnInfo(host=host, port=port, url=url,
                        meta={"targets": [f"{h}:{p}" for h, p in self.targets], "proto": proto})

    def get_conn_info(self, challenge_id: str) -> ConnInfo:
        return self.start_instance(challenge_id)

    # --- flags ----------------------------------------------------------------

    def submit_flag(self, challenge_id: str, flag: str) -> SubmitResult:
        if self._ended:
            return SubmitResult(accepted=False, message=f"the run has ended ({self._ended})")
        for _ in range(4):
            status, data, headers = self._call("POST", "/flag", {"flag": flag})
            if status != 429:
                break
            # The team's wrong-flag cooldown: the answer says how long to wait.
            try:
                wait = float(headers.get("retry-after") or 10)
            except ValueError:
                wait = 10.0
            time.sleep(min(30.0, max(1.0, wait)) + 0.5)
        else:
            raise PlatformError("POST /flag: still in the wrong-flag cooldown")
        body = data if isinstance(data, dict) else {}
        if status == 409:
            self._ended = "ended by the platform"
            return SubmitResult(accepted=False, message="the run has ended", raw=body)
        if status in (401, 403) or status >= 500:
            raise PlatformError(f"POST /flag: HTTP {status}: {str(data)[:120]}")
        if body.get("correct") is True:
            self._solved = True
            self._ended = "flag captured"
            return SubmitResult(accepted=True, challenge_solved=True,
                                message=f"correct ({body.get('points', '?')} points)", raw=body)
        return SubmitResult(accepted=False, raw=body,
                            message=str(body.get("error") or f"rejected (HTTP {status})")[:200])

    # --- what the team sees ---------------------------------------------------

    _TOOLS = {"shell": "bash", "python": "python", "http": "http", "read_file": "read_file",
              "submit_flag": "submit_flag"}

    def timeline(self, event: str, tool: str | None = None) -> None:
        """One event on the team's live timeline. Never raises; stops by itself
        at the platform's limit or when the gateway does not take them."""
        if self._ended or self._log_events >= LOG_LIMIT - 5 or self._log_failures >= 3:
            return
        body: dict = {"event": event}
        if tool:
            body["meta"] = {"tool": self._TOOLS.get(tool, "other")}
        try:
            status, _, _ = self._call("POST", "/log", body, timeout=4)
        except PlatformError:
            self._log_failures += 1
            return
        self._log_events += 1
        if status == 409:
            self._ended = self._ended or "ended by the platform"
        elif status != 200:
            self._log_failures += 1

    def on_event(self, payload: dict) -> None:
        """Run-log sink: turn the harness's own events into timeline events."""
        kind = payload.get("kind")
        if kind == "tool.call":
            if self._log_events < LOG_LIMIT - 40:        # keep room for the rest
                self.timeline("tool_use", str(payload.get("tool") or "other"))
        elif kind in ("attempt.start", "challenge.top_rung_restart", "challenge.fresh_context"):
            self.timeline("progress")
        elif kind in ("solver.model_timeout", "solver.model_retry"):
            self.timeline("error")
        elif kind == "challenge.done" and not payload.get("solved"):
            self.timeline("stuck")

    def give_up(self, note: str) -> None:
        """End the run with a note (cut to 32 characters by the platform)."""
        try:
            self._call("POST", "/give-up", {"message": note[:NOTE_CHARS]}, timeout=10)
        except PlatformError:
            pass
        self._ended = self._ended or "gave up"

    def finish(self, summary: dict) -> None:
        """End the run. A solved run has ended already; an unsolved one sends
        the 32-character note, which is all the team sees of it besides the
        timeline (the rules forbid file contents, keys or flag pieces in it)."""
        if self._solved or self._ended.startswith(("flag", "ended")):
            return
        self.give_up(make_note(summary, self._challenge.category if self._challenge else ""))


def make_note(summary: dict, category: str = "") -> str:
    """The give-up note: category, turns, rung, wrong flags, why it stopped.
    Example: `rev 61t r2 w1 time` = rev, 61 turns, reached rung 2, one wrong
    flag, out of time."""
    reason = str(summary.get("reason") or "").lower()
    why = ("cost" if "cost" in reason or "budget (" in reason else
           "time" if "seconds" in reason or "time" in reason else
           "tokens" if "token" in reason else
           "model" if "model error" in reason or "timed out" in reason else
           "ended" if "ended" in reason else
           "stuck" if "stuck" in reason or "stall" in reason or "no new progress" in reason else
           "crash" if "crash" in reason or "error" in reason else "gave up")
    subs = summary.get("submissions") or {}
    wrong = (max(0, int(subs.get("submissions", 0)) - int(subs.get("flags_accepted", 0)))
             if isinstance(subs, dict) else 0)
    turns = summary.get("turns", 0)
    note = f"{category or 'misc'} {turns}t r{summary.get('top_rung', 0)} w{wrong} {why}"
    return note[:NOTE_CHARS]
