#!/usr/bin/env python3
"""Copy your notes into knowledge/ctf-notes/ so they are baked into the image.

    python scripts/sync_knowledge.py ../ctf-notes

Only text the agent can use is copied (markdown, scripts, contracts); .git,
caches and binaries are skipped. The destination is replaced on each run and is
git-ignored, so the notes ship in the Docker image without being committed here.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

KEEP = {".md", ".txt", ".rst", ".py", ".sh", ".sol", ".asm", ".sage", ".c", ".js"}
SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv"}


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print(__doc__)
        return 2
    src = Path(argv[0]).resolve()
    if not src.is_dir():
        print(f"not a directory: {src}")
        return 1
    dest = Path(__file__).resolve().parent.parent / "knowledge" / "ctf-notes"
    if dest.exists():
        shutil.rmtree(dest)
    n = size = 0
    for p in sorted(src.rglob("*")):
        if not p.is_file() or p.suffix.lower() not in KEEP:
            continue
        if SKIP_DIRS & set(p.relative_to(src).parts):
            continue
        out = dest / p.relative_to(src)
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(p, out)
        n += 1
        size += p.stat().st_size
    print(f"copied {n} files ({size // 1024} KB) to {dest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
