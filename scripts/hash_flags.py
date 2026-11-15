#!/usr/bin/env python3
"""Replace plaintext flags in a fixture suite with their SHA-256.

    python scripts/hash_flags.py <suite-dir>

For every <suite>/<task>/challenge.json, `flag` becomes `flag_sha256` and
`flags` becomes `flags_sha256`; a `flag.txt` is folded in and deleted. The
files platform grades against the hashes, so the agent cannot read the answer
off the disk during a rehearsal. This rewrites the suite in place and cannot be
undone: keep the plaintext flags somewhere the agent cannot reach if you still
need them. Do not run it on the bundled `fixtures/` (the tests use those).
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


def _h(flag: str) -> str:
    return hashlib.sha256(flag.strip().encode("utf-8")).hexdigest()


def main(argv: list[str]) -> int:
    if len(argv) != 1 or not Path(argv[0]).is_dir():
        print(__doc__)
        return 2
    changed = 0
    for cdir in sorted(p for p in Path(argv[0]).iterdir() if p.is_dir()):
        meta_path = cdir / "challenge.json"
        if not meta_path.is_file():
            continue
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        flags: list[str] = []
        if isinstance(meta.get("flags"), list):
            flags = [str(f) for f in meta.pop("flags")]
        elif meta.get("flag") is not None:
            flags = [str(meta.pop("flag"))]
        flag_file = cdir / "flag.txt"
        if not flags and flag_file.is_file():
            flags = [ln for ln in flag_file.read_text(encoding="utf-8").splitlines() if ln.strip()]
        if not flags:
            continue
        if len(flags) == 1:
            meta["flag_sha256"] = _h(flags[0])
        else:
            meta["flags_sha256"] = [_h(f) for f in flags]
        meta_path.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
        flag_file.unlink(missing_ok=True)
        changed += 1
        print(f"hashed {len(flags)} flag(s): {cdir.name}")
    print(f"{changed} challenge(s) updated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
