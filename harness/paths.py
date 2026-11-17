"""Directories the harness writes to, with a fallback.

The contest sandbox is unknown: the image's root filesystem may be read-only,
or the container may run as a user that does not own /opt/ctf-harness. Either
would make the configured work or log directory unusable, and the harness
would die before its first model call, with nothing in the logs to say why.
`writable_dir` tries the configured path, then a fresh temporary directory.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


def writable_dir(path: str | os.PathLike, prefix: str = "ctf-") -> tuple[Path, bool]:
    """(a directory that exists and can be written to, whether it is the one
    asked for). Raises OSError only if no temporary directory works either."""
    want = Path(path)
    try:
        want.mkdir(parents=True, exist_ok=True)
        probe = want / f".w{os.getpid()}"
        probe.write_bytes(b"")
        probe.unlink()
        return want.resolve(), True
    except OSError:
        return Path(tempfile.mkdtemp(prefix=prefix)).resolve(), False
