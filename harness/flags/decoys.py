"""Flags that are known NOT to be the answer.

The image carries flag-shaped strings of its own: the toy flags in tests/ and
fixtures/. The agent's shell can read them, and anything flag-shaped in tool
output is auto-submitted. In rehearsal a stalled model went looking and
submitted every one it found. Wrong flags cost no points, but each is a wasted
submission and a false "found a flag" signal to the model.

`known_decoys()` collects those strings once at start-up; the evidence store
then never latches or submits them. Two deliberate limits:

  * knowledge/ is NOT scanned. A flag in your notes could, rarely, be a real
    answer (a reused challenge), and while wrong flags are free, submitting it
    can only gain.
  * It must not be used when the platform grades against answers on this disk
    (the fixtures rig): there the real flags live in exactly those directories.
"""

from __future__ import annotations

import os
import re
from functools import lru_cache
from pathlib import Path

from .grounding import candidates, flag_pattern

REPO_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_DIRS = ("tests", "fixtures")
_MAX_FILE = 4 * 1024 * 1024
_MAX_TOTAL = 64 * 1024 * 1024


def _scan_roots() -> list[Path]:
    roots = [REPO_ROOT / d for d in _DEFAULT_DIRS]
    roots += sorted(REPO_ROOT.glob("*.md"))      # README / handoff examples
    # Extra places to treat as decoy sources, colon-separated.
    roots += [Path(p) for p in os.environ.get("CTF_DECOY_DIRS", "").split(":") if p.strip()]
    return roots


def collect_decoys(roots: list[Path], pattern: re.Pattern[bytes]) -> frozenset[str]:
    found: set[str] = set()
    total = 0
    for root in roots:
        files = [root] if root.is_file() else (
            sorted(p for p in root.rglob("*") if p.is_file()) if root.is_dir() else [])
        for path in files:
            if "__pycache__" in path.parts:
                continue
            try:
                size = path.stat().st_size
                if size > _MAX_FILE or total + size > _MAX_TOTAL:
                    continue
                data = path.read_bytes()
            except OSError:
                continue
            total += size
            for raw in candidates(pattern, data):
                found.add(raw.decode("utf-8", "replace"))
    return frozenset(found)


@lru_cache(maxsize=4)
def _cached(pattern_src: bytes, flags: int, extra: str) -> frozenset[str]:
    return collect_decoys(_scan_roots(), re.compile(pattern_src, flags))


def known_decoys() -> frozenset[str]:
    """Flag-shaped strings shipped inside the harness's own directories."""
    pat = flag_pattern()
    return _cached(pat.pattern, pat.flags, os.environ.get("CTF_DECOY_DIRS", ""))
