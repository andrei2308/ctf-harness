"""Load contest settings from one file.

Every knob the harness has is an environment variable, but in the contest the
organizers start the container, so the values must travel inside the image.
`contest.env` at the repo root is that place: edit it, rebuild, done. Variables
already set in the real environment always win, so `docker run -e ...` and a
local `export` still override the file.

Format: `NAME=value` per line; `#` starts a comment; quotes around the value are
optional. `${OTHER}` in a value is replaced from the environment, which is how a
differently named organizer variable is mapped onto the one the harness reads:

    OPENAI_BASE_URL=${LLM_ENDPOINT}/v1
"""

from __future__ import annotations

import os
import re
from pathlib import Path

DEFAULT_FILE = Path(__file__).resolve().parent.parent / "contest.env"
_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def load_env_file(path: str | os.PathLike | None = None) -> dict[str, str]:
    """Apply the settings file to os.environ without overriding anything already
    set. Returns what it applied. CTF_ENV_FILE picks another file; an empty value
    disables loading. A missing file is not an error."""
    if path is None:
        chosen = os.environ.get("CTF_ENV_FILE")
        if chosen is not None and not chosen.strip():
            return {}
        path = chosen or DEFAULT_FILE
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError:
        return {}
    applied: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        name = name.removeprefix("export ").strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        else:
            value = re.sub(r"\s+#.*$", "", value)       # trailing comment
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) or name in os.environ:
            continue
        value = _VAR.sub(lambda m: os.environ.get(m.group(1), ""), value)
        if value == "":
            continue        # e.g. a mapping whose source variable is not set
        os.environ[name] = value
        applied[name] = value
    return applied
