"""Keep credential values out of what the model and the log see.

The agent's shell gets only PATH, but everything in the container runs as one
user, so a command like `cat /proc/1/environ` can still print the model key or
a platform session cookie. Every tool result passes through `scrub` before it
is recorded, logged or sent to the model, and any known secret value in it is
replaced. This stops accidental exposure (a stuck model trawling /proc); it
does not stop a model that sets out to encode the value. Running the agent's
shell as a separate user would.

Values come from the environment variables below, read when first needed, and
from `register`, for a secret an adapter takes out of the environment.
"""

from __future__ import annotations

import os
from urllib.parse import quote, unquote

SECRET_ENV_VARS = ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN",
                   "CYBEREDU_SESSION_COOKIE", "CYBEREDU_SESSION")
MIN_LEN = 12            # shorter values would redact ordinary text
MARK = "[redacted secret]"

_registered: set[str] = set()


def register(value: str | None) -> None:
    """Add a secret value to scrub, with its URL-encoded and -decoded forms
    (a cookie copied from a browser is URL-encoded; the server may decode it)."""
    if not value:
        return
    for v in (value, unquote(value), quote(value, safe="")):
        if len(v) >= MIN_LEN:
            _registered.add(v)


def _values() -> list[str]:
    for name in SECRET_ENV_VARS:
        register(os.environ.get(name))
    return sorted(_registered, key=len, reverse=True)      # longest first


def scrub_text(text: str | None) -> str | None:
    if not text:
        return text
    for v in _values():
        if v in text:
            text = text.replace(v, MARK)
    return text


def scrub(data: bytes) -> bytes:
    if not data:
        return data
    for v in _values():
        b = v.encode("utf-8", "replace")
        if b in data:
            data = data.replace(b, MARK.encode())
    return data
