#!/usr/bin/env python3
"""Copy your notes into knowledge/ctf-notes/ so they are baked into the image.

    python scripts/sync_knowledge.py ../ctf-notes                  # the files as they are on disk
    python scripts/sync_knowledge.py ../ctf-notes --ref harness    # a branch, without checking it out

With --ref the notes are read from that branch (or tag, or commit) of the notes
repository through git, so the working copy stays on whatever branch you are
writing in. `harness` is the branch with the playbooks written for the agent;
`main` stays yours. A branch that only exists on the remote is found as
`origin/<name>` (run `git -C ../ctf-notes fetch` first to have the latest).

Only text the agent can use is copied (markdown, scripts, contracts); .git,
caches and binaries are skipped. The destination is replaced on each run and is
git-ignored, so the notes ship in the Docker image without being committed here.
"""

from __future__ import annotations

import io
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

KEEP = {".md", ".txt", ".rst", ".py", ".sh", ".sol", ".asm", ".sage", ".c", ".js"}
SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv"}
DEST = Path(__file__).resolve().parent.parent / "knowledge" / "ctf-notes"


def _git(src: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(src), *args], capture_output=True)


def export_ref(src: Path, ref: str, into: Path) -> str:
    """Unpack the tree of `ref` into `into`; returns a one-line description of
    the commit used. Raises ValueError when the ref does not exist."""
    for name in (ref, f"origin/{ref}"):
        if _git(src, "rev-parse", "--verify", "--quiet", f"{name}^{{commit}}").returncode == 0:
            break
    else:
        raise ValueError(f"no branch, tag or commit named {ref!r} in {src} "
                         f"(try: git -C {src} fetch)")
    tar = _git(src, "archive", "--format=tar", name)
    if tar.returncode != 0:
        raise ValueError(tar.stderr.decode(errors="replace").strip())
    with tarfile.open(fileobj=io.BytesIO(tar.stdout)) as t:
        t.extractall(into, filter="data")
    what = _git(src, "log", "-1", "--format=%h %s", name).stdout.decode(errors="replace").strip()
    return f"{name} ({what})"


def copy_notes(src: Path, dest: Path) -> tuple[int, int]:
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
    return n, size


def main(argv: list[str], dest: Path = DEST) -> int:
    ref = None
    if "--ref" in argv:
        i = argv.index("--ref")
        if i + 1 >= len(argv):
            print(__doc__)
            return 2
        ref = argv[i + 1]
        argv = argv[:i] + argv[i + 2:]
    if len(argv) != 1:
        print(__doc__)
        return 2
    src = Path(argv[0]).resolve()
    if not src.is_dir():
        print(f"not a directory: {src}")
        return 1
    if ref is None:
        n, size = copy_notes(src, dest)
        branch = _git(src, "rev-parse", "--abbrev-ref", "HEAD").stdout.decode().strip()
        origin = f"the files on disk in {src}" + (f" (branch {branch})" if branch else "")
    else:
        with tempfile.TemporaryDirectory(prefix="notes-") as tmp:
            try:
                origin = export_ref(src, ref, Path(tmp))
            except ValueError as e:
                print(e)
                return 1
            n, size = copy_notes(Path(tmp), dest)
    print(f"copied {n} files ({size // 1024} KB) to {dest}")
    print(f"from: {origin}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
