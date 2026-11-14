"""Size and time limits for one solver, read from the environment.

Tokens and wall-clock are hard-capped and scored, and the model's context window
is not known until the event, so every number that decides how much text reaches
the model (or the log) lives here with a conservative default and a CTF_* knob.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, fields


@dataclass(frozen=True)
class Limits:
    # Bytes of one tool result shown to the model. The full output always goes to
    # the evidence store and, when cut, to a file the model can grep.
    tool_output_bytes: int = 8192
    # Once the transcript passes `history_soft_chars`, tool results older than
    # the newest `keep_recent_results` are cut down to `old_result_chars`.
    keep_recent_results: int = 4
    old_result_chars: int = 600
    history_soft_chars: int = 40_000
    # Past this the middle of the transcript is dropped (replaced by a digest of
    # the actions taken) before the endpoint has a chance to reject the request.
    history_hard_chars: int = 160_000
    # Characters of model text / tool arguments / tool output kept per log event.
    log_text_chars: int = 2000
    # Seconds a tool may never eat into at the end of the time budget, so the
    # loop gets control back to submit and exit cleanly.
    reserve_seconds: float = 20.0
    # Ceiling on any single tool call, whatever timeout the model asks for.
    max_tool_seconds: float = 900.0
    # Size of the notes index placed in the task prompt (0 turns it off). It is
    # re-sent every turn like the rest of the prompt, so keep it an index.
    primer_chars: int = 2500
    # Size of the handover note the model writes before a clean-context restart.
    recap_chars: int = 3000

    @classmethod
    def from_env(cls) -> "Limits":
        """Defaults overridden by CTF_<FIELD_NAME> (e.g. CTF_TOOL_OUTPUT_BYTES).
        A value that does not parse is ignored."""
        kwargs = {}
        for f in fields(cls):
            raw = os.environ.get("CTF_" + f.name.upper(), "").strip()
            if not raw:
                continue
            try:
                kwargs[f.name] = type(f.default)(float(raw))
            except ValueError:
                continue
        return cls(**kwargs)
