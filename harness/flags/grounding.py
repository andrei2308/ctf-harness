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
import json
import re
from dataclasses import dataclass, field


# Default DefCamp-style flag: CTF{ ... }. The body is intentionally permissive
# (any non-brace run) because flags vary (sha256 hex, words, symbols). Tighten
# per the organizers' confirmed grammar. Case-insensitive prefix is tolerated.
# The body excludes '{' as well as '}': a log line is one long JSON line, and
# with '{' allowed the pattern spanned prose such as "CTF{, flag{, ..." up to
# the next '}' (rehearsal: two junk submissions). Real flags do not nest braces.
DEFAULT_FLAG_RE = re.compile(rb"CTF\{[^{}\r\n]{1,512}\}", re.IGNORECASE)

# The default used at run time. The flag grammar is not confirmed, and both
# `CTF{..}` and prefixed forms such as `DCTF{..}` are plausible, so this captures
# up to 8 alphanumerics glued to the front as `prefix` and the bare form as
# `bare`. A match with a prefix yields BOTH candidates (a letters-only prefix
# first, a prefix with digits last): one of them is right, and which one cannot be told from the bytes alone ("DCTF{x}" vs a
# "CTF{x}" that follows padding in a dump).
VARIANT_FLAG_RE = re.compile(
    rb"(?P<prefix>[A-Za-z0-9]{0,8}?)(?P<bare>CTF\{[^{}\r\n]{1,512}\})", re.IGNORECASE)


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


# "sum" too: DefCamp CTF 2025 states its format as ctf{sha256sum}.
_HASH_HINT = re.compile(r"[A-Za-z0-9_]*\{\s*(sha-?256|sha-?1|md5)(?:sum)?\b", re.IGNORECASE)
_LEN_HINT = re.compile(r"\{\s*\.\{(\d{1,3})\}\s*\}")
_HASH_HEX = {"sha256": 64, "sha-256": 64, "sha1": 40, "sha-1": 40, "md5": 32}


def format_check(text: str):
    """A check for flag bodies, from a format the challenge states, or None.

    "Flag format: DCTF{sha256}" or "ctf{sha256(flag)}" means the body is a
    64-character hex digest. In rehearsal (investigator) the agent's tool output
    contained a planted "DCTF{Try Hard...}" next to the real flag; it was
    grounded, so it went out as a wrong submission. Only hash formats are
    understood; anything else imposes no check."""
    lengths = {_HASH_HEX[m.group(1).lower()] for m in _HASH_HINT.finditer(text or "")}
    pats = [re.compile(rf"[0-9a-fA-F]{{{n}}}") for n in sorted(lengths)]
    # A length stated as a regex, "CTF{.{27}}" (luma-lacks-love): any body of
    # exactly that many characters.
    sized = sorted({int(m.group(1)) for m in _LEN_HINT.finditer(text or "")})
    pats += [re.compile(rf"[^{{}}]{{{n}}}", re.S) for n in sized]
    lengths |= set(sized)
    if not pats:
        return None

    def check(flag: str) -> bool:
        i, j = flag.find("{"), flag.rfind("}")
        body = flag[i + 1:j] if 0 <= i < j else ""
        return any(p.fullmatch(body) for p in pats)
    check.lengths = sorted(lengths)          # for the log
    return check


_BYTE_ESCAPE = re.compile(rb"\\x[0-9a-fA-F]{2}")


def _junk_body(raw: bytes) -> bool:
    """A flag-shaped match that cannot be a flag: an empty or whitespace-only
    body (a placeholder such as "CTF{" + 27 spaces + "}"), or one holding
    printed byte escapes (a Python bytes repr of garbage, "CTF{\\x98\\xb8..}").
    Both went out as wrong submissions on luma-lacks-love."""
    i, j = raw.find(b"{"), raw.rfind(b"}")
    body = raw[i + 1:j] if 0 <= i < j else b""
    return not body.strip() or bool(_BYTE_ESCAPE.search(body))


def candidates(pattern: re.Pattern[bytes], data: bytes) -> list[bytes]:
    """Every flag candidate `pattern` finds in `data`, in order, de-duplicated."""
    out: list[bytes] = []
    for m in pattern.finditer(data):
        groups = m.groupdict()
        if groups.get("bare") is not None:
            found = [groups["bare"]]
            prefix = groups.get("prefix") or b""
            if prefix:
                # Letters glued to the front ("DCTF{", "UNBRK..") are part of
                # the flag far more often than not: try that form first (contest
                # mode on investigator: the bare form went out first and was
                # wrong). Digits are dump padding ("1da00de3CTF{"): bare first.
                if prefix.isalpha():
                    found.insert(0, prefix + groups["bare"])
                else:
                    found.append(prefix + groups["bare"])
        else:
            found = [m.group(0)]
        for raw in found:
            if raw not in out and not _junk_body(raw):
                out.append(raw)
    return out


def _in_command(value: str, cmd: str) -> bool:
    """Does the command text carry `value`? Tool arguments are logged as the
    bare command, or as JSON when there are several (quotes escaped)."""
    if not cmd or not value:
        return False
    return value in cmd or json.dumps(value, ensure_ascii=False)[1:-1] in cmd


@dataclass
class Evidence:
    """One piece of real tool output."""

    source: str          # e.g. "bash:cat flag", "pwn:recv", "http:GET /", "file:out.bin"
    data: bytes          # raw bytes exactly as produced
    seq: int             # order captured
    cmd: str = ""        # the tool arguments that produced it


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

    def __init__(self, pattern: re.Pattern[bytes] | None = None, max_bytes: int = 32 * 1024 * 1024,
                 ignore: frozenset[str] = frozenset(), accept=None):
        self._pattern = pattern or DEFAULT_FLAG_RE
        # A flag-format check (format_check); a candidate it rejects is not
        # latched, so it is never auto-submitted. Rejects are kept for the log.
        self._accept = accept
        self.rejected: list[str] = []
        # Flag-shaped strings known not to be the answer (see flags/decoys.py).
        self._ignore = ignore
        self._items: list[Evidence] = []
        self._seq = 0
        self._bytes = 0
        self._max = max_bytes
        # Flags are latched the moment they appear, so trimming the store later
        # never discards a flag we already grounded.
        self._latched: dict[str, GroundedFlag] = {}

    def record(self, source: str, data: bytes | str, cmd: str = "") -> list[GroundedFlag]:
        """Add one observation. Returns any *newly* grounded flags it contained.

        Also scans across the boundary with the previous chunk from the same
        source so a flag split across two reads is still caught.
        """
        if isinstance(data, str):
            data = data.encode("utf-8", "surrogatepass")
        self._seq += 1
        ev = Evidence(source=source, data=data, seq=self._seq, cmd=cmd)
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
            if flag in self._ignore:
                continue
            if _in_command(flag, cmd):
                # The command carried the value itself: the model's own guess
                # printed back, not evidence (zodiac, pre-freeze: a python
                # list of five spellings and an `echo "ctf{...}"` went out as
                # seven grounded wrong submissions). A command that did not
                # contain it can still ground it later.
                continue
            if self._accept is not None and not self._accept(flag):
                if flag not in self.rejected:
                    self.rejected.append(flag)
                continue
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

    def breaks_stated_format(self, value: str) -> bool:
        """True when `value` is flag-shaped (WORD{...}) and the challenge states
        a format it does not meet. submit_flag skips the flag pattern on purpose
        (it is for answers like a password); a flag-shaped answer still has to
        meet the stated format (metar-station: a planted CTF{try_harder...} went
        out through submit_flag although the format was UNBRK{sha256})."""
        v = value.strip()
        return (self._accept is not None and bool(re.fullmatch(r"[A-Za-z0-9_]*\{.*\}", v, re.S))
                and not self._accept(v))

    def contains_independent(self, value: str) -> GroundedFlag | None:
        """Is `value` in the output of a command that did not itself contain it?
        `echo s3cretpass` proves nothing; aircrack-ng printing it does. Used for
        answers the model submits explicitly (submit_flag)."""
        value = value.strip()
        if not value:
            return None
        needle = value.encode("utf-8", "surrogatepass")
        for ev in self._items:
            if _in_command(value, ev.cmd):
                continue
            if ev.data.find(needle) != -1:
                return GroundedFlag(flag=value, raw=needle, source=ev.source,
                                    evidence_seq=ev.seq)
        return None

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
            if _in_command(flag, ev.cmd):
                continue                    # its own command printed it: a guess
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
        claims = [raw.decode("utf-8", "replace")
                  for raw in candidates(self._pattern, text.encode("utf-8", "replace"))]
        return [c for c in claims if c not in self._ignore]


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
