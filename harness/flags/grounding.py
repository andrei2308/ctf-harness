"""Flag grounding guard — the single most important correctness rule in the harness.

A candidate flag counts ONLY if it traces back to real tool output: bytes the
platform or a tool actually produced (stdout/stderr, a file's contents, a network
response). A `CTF{...}` string the model merely wrote in prose is a confabulation
and submitting it burns a submission (and may carry a penalty). We guard this hard:
the model never hands us a flag; it points at evidence, and we extract from the
evidence.

Mechanism:
  1. Every tool observation is appended to an append-only EvidenceStore as raw
     bytes, tagged with its source. The model's own text is NEVER evidence.
  2. extract_grounded() scans the accumulated evidence for the flag pattern and
     returns only matches found in real output.
  3. verify_candidate() takes a flag the model *claims* and accepts it only if
     that exact string is present verbatim in the evidence.

The flag format is configurable (default CTF{...}); confirm the exact grammar
with organizers. Keep the pattern tight enough to avoid matching chatter but
loose enough for multi-stage/odd flags — tune from real challenges.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field


# Default DefCamp-style flag: CTF{ ... }. The body is intentionally permissive
# (any non-brace run) because flags vary (sha256 hex, words, symbols). Tighten
# per the organizers' confirmed grammar. Case-insensitive prefix is tolerated.
DEFAULT_FLAG_RE = re.compile(rb"CTF\{[^}\r\n]{1,512}\}", re.IGNORECASE)

# The default used at run time. The flag grammar is not confirmed, and both
# `CTF{..}` and prefixed forms such as `DCTF{..}` are plausible, so this captures
# up to 8 alphanumerics glued to the front as `prefix` and the bare form as
# `bare`. A match with a prefix yields BOTH candidates (bare first): one of them
# is right, and which one cannot be told from the bytes alone ("DCTF{x}" vs a
# "CTF{x}" that follows padding in a dump).
VARIANT_FLAG_RE = re.compile(
    rb"(?P<prefix>[A-Za-z0-9]{0,8}?)(?P<bare>CTF\{[^}\r\n]{1,512}\})", re.IGNORECASE)


def flag_pattern() -> re.Pattern[bytes]:
    """The flag pattern for this run. Set CTF_FLAG_REGEX once the organizers
    confirm the format (e.g. `flag\\{[^}]+\\}`); it is then used verbatim, with no
    prefix variants. An invalid regex falls back to the default."""
    raw = os.environ.get("CTF_FLAG_REGEX", "").strip()
    if raw:
        try:
            return re.compile(raw.encode("utf-8"))
        except re.error:
            pass
    return VARIANT_FLAG_RE


def candidates(pattern: re.Pattern[bytes], data: bytes) -> list[bytes]:
    """Every flag candidate `pattern` finds in `data`, in order, de-duplicated."""
    out: list[bytes] = []
    for m in pattern.finditer(data):
        groups = m.groupdict()
        if groups.get("bare") is not None:
            found = [groups["bare"]]
            if groups.get("prefix"):
                found.append(groups["prefix"] + groups["bare"])
        else:
            found = [m.group(0)]
        for raw in found:
            if raw not in out:
                out.append(raw)
    return out


@dataclass
class Evidence:
    """One piece of real tool output."""

    source: str          # e.g. "bash:cat flag", "pwn:recv", "http:GET /", "file:out.bin"
    data: bytes          # raw bytes exactly as produced
    seq: int             # order captured


@dataclass
class GroundedFlag:
    """A flag that was found inside real evidence."""

    flag: str            # decoded flag text (utf-8, errors replaced)
    raw: bytes           # the exact bytes matched
    source: str          # which evidence it came from
    evidence_seq: int


class EvidenceStore:
    """Append-only store of real tool output for one challenge attempt.

    Only bytes that a tool actually emitted go here. Model prose must never be
    added — that is what makes grounding meaningful. Bounded by `max_bytes` to
    keep memory sane on chatty tools; oldest evidence is dropped first, but a
    flag is extracted *as output arrives* (see record()) so truncation can't lose
    a flag that was already seen.
    """

    def __init__(self, pattern: re.Pattern[bytes] | None = None, max_bytes: int = 32 * 1024 * 1024):
        self._pattern = pattern or DEFAULT_FLAG_RE
        self._items: list[Evidence] = []
        self._seq = 0
        self._bytes = 0
        self._max = max_bytes
        # Flags are latched the moment they appear, so trimming the store later
        # never discards a flag we already grounded.
        self._latched: dict[str, GroundedFlag] = {}

    def record(self, source: str, data: bytes | str) -> list[GroundedFlag]:
        """Add one observation. Returns any *newly* grounded flags it contained.

        Also scans across the boundary with the previous chunk from the same
        source so a flag split across two reads is still caught.
        """
        if isinstance(data, str):
            data = data.encode("utf-8", "surrogatepass")
        self._seq += 1
        ev = Evidence(source=source, data=data, seq=self._seq)
        self._items.append(ev)
        self._bytes += len(data)

        found: list[GroundedFlag] = []
        # Scan this chunk plus a small tail of the prior chunk from the same
        # source, to catch a flag straddling the read boundary.
        prior_tail = b""
        for prev in reversed(self._items[:-1]):
            if prev.source == source:
                prior_tail = prev.data[-600:]
                break
        haystack = prior_tail + data
        for raw in candidates(self._pattern, haystack):
            flag = raw.decode("utf-8", "replace")
            if flag not in self._latched:
                gf = GroundedFlag(flag=flag, raw=raw, source=source, evidence_seq=ev.seq)
                self._latched[flag] = gf
                found.append(gf)

        self._trim()
        return found

    def _trim(self) -> None:
        while self._bytes > self._max and len(self._items) > 1:
            dropped = self._items.pop(0)
            self._bytes -= len(dropped.data)

    def grounded_flags(self) -> list[GroundedFlag]:
        """All flags ever found in evidence (latched, order of first sighting)."""
        return list(self._latched.values())

    def contains(self, flag: str) -> GroundedFlag | None:
        """Is this exact flag present in evidence? Used to verify a model claim.

        Checks the latch first (fast path), then does a verbatim scan of live
        evidence in case the flag text doesn't match the configured pattern but
        the model is pointing at something real.
        """
        if flag in self._latched:
            return self._latched[flag]
        needle = flag.encode("utf-8", "surrogatepass")
        for ev in self._items:
            idx = ev.data.find(needle)
            if idx != -1:
                return GroundedFlag(flag=flag, raw=needle, source=ev.source,
                                    evidence_seq=ev.seq)
        return None

    @property
    def total_bytes(self) -> int:
        return self._bytes

    def claims_in(self, text: str) -> list[str]:
        """Flag-shaped strings in model prose, using this store's pattern. These
        are CLAIMS, not evidence; the caller decides what to do with them."""
        return [raw.decode("utf-8", "replace")
                for raw in candidates(self._pattern, text.encode("utf-8", "replace"))]


def extract_grounded(store: EvidenceStore) -> list[GroundedFlag]:
    """All flags that appear in real evidence. Pattern-driven discovery."""
    return store.grounded_flags()


def verify_candidate(store: EvidenceStore, claimed: str) -> GroundedFlag | None:
    """Accept a model-claimed flag ONLY if it is present verbatim in evidence.

    This is the confab guard: return None (reject) for anything the model wrote
    that we cannot find in real tool output. A rejected claim must never be
    submitted.
    """
    claimed = claimed.strip()
    if not claimed:
        return None
    return store.contains(claimed)
