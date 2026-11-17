"""Building blocks for writing the contest adapter quickly.

The starter kit's interface is unknown until the contest starts, and the
adapter (harness/platforms/starter_kit.py) has to be written in the first
hour. Everything here is a piece that adapter is likely to need, already
tested, so the hour goes on reading the docs rather than on plumbing. Each
helper encodes something the CyberEDU rehearsal got wrong the first time.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from .base import ConnInfo, PlatformError


class HttpError(PlatformError):
    """A platform call that should be retried: no answer, a 5xx, 408 or 429."""

    def __init__(self, message: str, status: int | None = None, body: str = ""):
        super().__init__(message)
        self.status, self.body = status, body


def _parse(raw: bytes, content_type: str) -> Any:
    text = raw.decode("utf-8", "replace")
    if "json" in content_type or text.lstrip()[:1] in ("{", "["):
        try:
            return json.loads(text)
        except ValueError:
            pass
    return text


def http_json(method: str, url: str, *, body: Any = None, form: dict | None = None,
              headers: dict | None = None, timeout: float = 20.0) -> tuple[int, Any]:
    """One HTTP call. Returns (status, parsed JSON or text).

    The split that matters for flag submission, learned from a flag re-sent 323
    times in rehearsal: a 2xx or a 4xx is the platform's ANSWER and is returned
    for the adapter to read; only a failure to get an answer raises (transport
    error, 5xx, 408, 429), and the submitter retries those with backoff.

    `body` is sent as JSON, `form` as application/x-www-form-urlencoded."""
    hdrs = {"Accept": "application/json", **(headers or {})}
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json")
    elif form is not None:
        data = urllib.parse.urlencode(form).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method.upper())
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, _parse(resp.read(), resp.headers.get("Content-Type", ""))
    except urllib.error.HTTPError as e:
        raw = e.read() if hasattr(e, "read") else b""
        if e.code >= 500 or e.code in (408, 429):
            raise HttpError(f"{method} {url}: HTTP {e.code}", e.code,
                            raw.decode("utf-8", "replace")[:500]) from e
        return e.code, _parse(raw, e.headers.get("Content-Type", "") if e.headers else "")
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise HttpError(f"{method} {url}: {e}") from e


def safe_name(name: str, fallback: str = "file") -> str:
    """A file name safe to create under the work dir. Keep the REAL name and
    extension: they are clues (rehearsal files first arrived as `downloaded_file`)."""
    name = urllib.parse.unquote(str(name or "")).replace("\\", "/").rsplit("/", 1)[-1]
    name = re.sub(r"[^\w.\-+ ()\[\]]", "_", name).strip(" .")
    return name[:200] or fallback


def http_download(url: str, dest: Path, name: str | None = None, *,
                  headers: dict | None = None, timeout: float = 120.0) -> Path:
    """Download one file into `dest` under its real name (from `name`, the
    Content-Disposition header, or the URL path, in that order)."""
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if not name:
                m = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)',
                              resp.headers.get("Content-Disposition", ""))
                name = m.group(1) if m else urllib.parse.urlsplit(url).path
            path = Path(dest) / safe_name(name)
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("wb") as fh:
                while chunk := resp.read(1 << 20):
                    fh.write(chunk)
            return path
    except urllib.error.HTTPError as e:
        raise HttpError(f"GET {url}: HTTP {e.code}", e.code) from e
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise HttpError(f"GET {url}: {e}") from e


_HOSTPORT = r"(\[[0-9a-fA-F:]+\]|[A-Za-z0-9._-]+)"


def parse_address(text: str) -> tuple[str | None, int | None]:
    """(host, port) from the ways a platform writes a service address:

        host:1337            nc host 1337          ncat --ssl host 1337
        http://host:8080/x   https://host          tcp://host:1337
        ssh user@host -p 22  ssh -p 2222 u@host    host 1337

    (None, None) when it is not understood. Treat that as an error in the
    adapter: on ret2win an unread "nc HOST PORT" became "no target", and the
    agent spent its whole run looking for a service it had not been given."""
    t = str(text or "").strip()
    if not t:
        return None, None
    m = re.search(r"\b([a-z][a-z0-9+.-]*)://" + _HOSTPORT + r"(?::(\d{1,5}))?", t, re.I)
    if m:
        default = {"http": 80, "https": 443, "ws": 80, "wss": 443, "ssh": 22, "ftp": 21}
        port = int(m.group(3)) if m.group(3) else default.get(m.group(1).lower())
        return m.group(2).strip("[]"), port
    m = re.search(r"\b(?:nc|ncat|netcat|telnet)\b(?:\s+-\S+)*\s+" + _HOSTPORT + r"\s+(\d{1,5})\b", t, re.I)
    if m:
        return m.group(1).strip("[]"), int(m.group(2))
    if re.match(r"ssh\b", t, re.I):
        host = re.search(r"(?:\S+@)" + _HOSTPORT, t) or re.search(r"\s" + _HOSTPORT + r"\s*$", t)
        port = re.search(r"-p\s*(\d{1,5})\b", t)
        if host:
            return host.group(1).strip("[]"), int(port.group(1)) if port else 22
    m = re.fullmatch(_HOSTPORT + r"(?::|\s+)(\d{1,5})", t)
    if m:
        return m.group(1).strip("[]"), int(m.group(2))
    # Last resort: an IP or dotted name with a port somewhere in a sentence.
    m = re.search(r"(?<![\w.])((?:\d{1,3}\.){3}\d{1,3}|[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+):(\d{1,5})\b", t)
    if m:
        return m.group(1), int(m.group(2))
    return None, None


def conn_from(text: str, *, web: bool | None = None, **meta: Any) -> ConnInfo:
    """A ConnInfo from an address string. `web=True` forces an http:// URL for
    a bare host:port; by default a URL is set only when the text is one.
    Raises PlatformError when the address cannot be read, so the mistake shows
    up at start-up and not as a puzzled agent."""
    host, port = parse_address(text)
    if not host:
        raise PlatformError(f"service address not understood: {text!r}")
    t = str(text).strip()
    url = None
    m = re.search(r"\bhttps?://\S+", t, re.I)
    if m:
        url = m.group(0).rstrip(".,)")
    elif web and port:
        url = f"http://{host}:{port}"
    return ConnInfo(host=host, port=port, url=url, meta=dict(meta))


def describe(description: str = "", *, questions: list | None = None,
             flag_format: str = "", hints: list | None = None) -> str:
    """The text the agent is given as the challenge description.

    Put EVERYTHING a human player would read on the challenge page in here. On
    CyberEDU the answer format ("ctf{sha256(flag)}", "the WPA2 password") was
    not in the description but in a per-flag question, and without it the agent
    solved challenges it could not then submit.

    `questions`: one entry per flag, a string or a dict with any of
    question / description (format) / options / found."""
    parts = [str(description or "").strip()]
    if flag_format:
        parts.append(f"Flag format: {flag_format}")
    if hints:
        parts.append("Tags: " + "; ".join(str(h) for h in hints if h))
    if questions:
        lines = ["Flags to find (one answer each, in order):"]
        for n, q in enumerate(questions, 1):
            if not isinstance(q, dict):
                q = {"question": q}
            line = f"{n}. {str(q.get('question') or 'flag').strip()}"
            if q.get("description"):
                line += f" (format: {str(q['description']).strip()})"
            if q.get("options"):
                line += " Options: " + "; ".join(
                    str(o.get("value", o) if isinstance(o, dict) else o) for o in q["options"])
            if q.get("found"):
                line += " [already solved]"
            lines.append(line)
        parts.append("\n".join(lines))
    return "\n\n".join(p for p in parts if p)
