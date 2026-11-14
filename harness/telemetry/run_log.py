"""Structured per-run logging.

This is the highest-leverage investment in the whole harness: retries are allowed
and you may update the harness between attempts, so the dev loop *is* the
competition. You can only learn between runs if the logs tell you what each
attempt tried, where it stalled, and what it spent.

Format: one JSON object per line (JSONL), append-only, one file per run. Every
event carries a monotonic sequence number and a wall-clock timestamp. Nothing is
pretty-printed; parsing is trivial and streaming-friendly.

Safety: this logger is used in a context where "everything is logged and
reviewed". It MUST NOT persist secrets. `redact()` scrubs known-sensitive keys
before anything is written. Never log raw credentials, session cookies, or env
that could contain them.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

# Keys whose values are scrubbed anywhere they appear in a logged payload.
_SENSITIVE_KEYS = {
    "cookie", "session", "cyberedu_session", "authorization", "auth",
    "token", "api_key", "apikey", "secret", "password", "passwd",
    "set-cookie", "x-api-key",
}
_REDACTED = "[REDACTED]"


def redact(value: Any) -> Any:
    """Recursively scrub sensitive keys. Defensive: applied to every event."""
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if isinstance(k, str) and k.lower() in _SENSITIVE_KEYS:
                out[k] = _REDACTED
            else:
                out[k] = redact(v)
        return out
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    if is_dataclass(value) and not isinstance(value, type):
        return redact(asdict(value))
    return value


def _jsonable(value: Any) -> Any:
    """Make arbitrary values JSON-serialisable without throwing."""
    try:
        json.dumps(value)
        return value
    except (TypeError, ValueError):
        if is_dataclass(value) and not isinstance(value, type):
            return _jsonable(asdict(value))
        if isinstance(value, dict):
            return {str(k): _jsonable(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [_jsonable(v) for v in value]
        return repr(value)


class RunLog:
    """Append-only JSONL event log for a single harness run.

    Thread-safe: specialist agents run concurrently (fixed-concurrency slots), so
    writes are serialised under a lock. Each event is flushed immediately so a
    killed run (budget/time limit hit mid-attempt) still leaves a complete tail.
    """

    def __init__(self, run_dir: str | os.PathLike, run_id: str | None = None,
                 mirror: bool = False):
        # mirror=True also writes every event to stderr. In the contest the
        # container's filesystem may not come back, but its output stream does;
        # stdout stays free for the final JSON summary.
        self._mirror = mirror
        self.run_dir = Path(run_dir)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.run_id = run_id or time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        self.path = self.run_dir / f"run-{self.run_id}.jsonl"
        self._lock = threading.Lock()
        self._seq = 0
        self._fh = self.path.open("a", encoding="utf-8")
        self.event("run.start", run_id=self.run_id)

    def event(self, kind: str, *, challenge: str | None = None, **fields: Any) -> None:
        """Write one event. `kind` is a dotted name, e.g. 'attempt.start',
        'tool.observe', 'flag.candidate', 'flag.submit', 'budget.tick'."""
        payload = {
            "seq": None,  # filled under lock for a strict order
            "t": round(time.time(), 3),
            "kind": kind,
        }
        if challenge is not None:
            payload["challenge"] = challenge
        payload.update(redact(_jsonable(fields)))
        line = None
        with self._lock:
            self._seq += 1
            payload["seq"] = self._seq
            line = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
            self._fh.write(line + "\n")
            self._fh.flush()
            if self._mirror:
                try:
                    sys.stderr.write(line + "\n")
                    sys.stderr.flush()
                except (OSError, ValueError):
                    pass

    # --- convenience wrappers for the events we query most ------------------

    def attempt_start(self, challenge: str, spec_label: str, rung: int) -> None:
        self.event("attempt.start", challenge=challenge, spec=spec_label, rung=rung)

    def attempt_end(self, challenge: str, outcome: str, reason: str = "") -> None:
        self.event("attempt.end", challenge=challenge, outcome=outcome, reason=reason)

    def observe(self, challenge: str, tool: str, bytes_out: int, truncated: bool = False,
                **extra: Any) -> None:
        """Record a tool result: its size, plus whatever the caller adds (exit
        code, seconds, a capped excerpt of the output). The full bytes stay in
        the attempt's evidence store."""
        self.event("tool.observe", challenge=challenge, tool=tool,
                   bytes=bytes_out, truncated=truncated, **extra)

    def flag_candidate(self, challenge: str, flag_preview: str, grounded: bool, source: str) -> None:
        self.event("flag.candidate", challenge=challenge,
                   flag_preview=flag_preview, grounded=grounded, source=source)

    def flag_submit(self, challenge: str, accepted: bool, already: bool = False) -> None:
        self.event("flag.submit", challenge=challenge, accepted=accepted, already=already)

    def budget_tick(self, phase: str, **counters: Any) -> None:
        self.event("budget.tick", phase=phase, **counters)

    def close(self) -> None:
        with self._lock:
            if not self._fh.closed:
                self._fh.write(json.dumps(
                    {"seq": self._seq + 1, "t": round(time.time(), 3), "kind": "run.end"},
                    separators=(",", ":"),
                ) + "\n")
                self._fh.flush()
                self._fh.close()

    def __enter__(self) -> "RunLog":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
