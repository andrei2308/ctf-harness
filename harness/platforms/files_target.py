"""Files-on-disk (+ optional target) Platform adapter.

A drop-in alternative to the live MCP: challenges are directories on disk. This
is both the local test rig and the fallback runtime shape if the organizers
mount challenges + give a target host/port and a submit hook rather than an MCP.

Layout (root/ = the directory passed in):

    root/
      <challenge_id>/
        challenge.json      # metadata (see below)
        files/              # optional attachments, copied into the work dir
        flag.txt            # optional: local-only expected flag for self-grading

challenge.json:
    {
      "id": "pwn-01", "name": "babyheap",
      "kind": "interactive",            # static|interactive|web|unknown
      "category": "pwn", "points": 500,
      "description": "nc the service and pop a shell",
      "target": {"host": "127.0.0.1", "port": 1337}   # or {"url": "http://..."}
      "flag": "CTF{...}"                # LOCAL ONLY; used to grade submit_flag
    }

`flag`/`flag.txt` make the rig self-grading offline. They are dev-only and must
never appear in anything submitted — they live in your local fixtures, not the
harness. submit_flag compares against them when present; otherwise it reports
"unknown" (accepted=False) so you can wire a real submit hook.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from .base import (Challenge, ChallengeKind, ConnInfo, Platform, PlatformError,
                   SubmitResult)


class FilesTargetPlatform(Platform):
    def __init__(self, root: str | Path, submit_hook=None):
        """`root` holds one directory per challenge. `submit_hook(cid, flag) ->
        SubmitResult` lets you plug a real submit path (a mounted script/endpoint)
        while keeping offline self-grading as the default."""
        self.root = Path(root)
        if not self.root.is_dir():
            raise PlatformError(f"fixtures root not found: {self.root}")
        self._submit_hook = submit_hook
        self._cache: dict[str, tuple[Challenge, dict]] = {}

    def _load(self, cdir: Path) -> tuple[Challenge, dict]:
        meta_path = cdir / "challenge.json"
        meta = {}
        if meta_path.is_file():
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        cid = str(meta.get("id") or cdir.name)
        kind_raw = str(meta.get("kind", "unknown")).lower()
        kind = ChallengeKind(kind_raw) if kind_raw in ChallengeKind._value2member_map_ \
            else ChallengeKind.UNKNOWN
        # A challenge may declare several expected flags (`flags: [...]`) for a
        # multi-flag / staged challenge, or a single `flag`.
        if isinstance(meta.get("flags"), list):
            flags_required = max(1, len(meta["flags"]))
        else:
            flags_required = int(meta.get("flags_required", 1) or 1)
        challenge = Challenge(
            id=cid,
            name=str(meta.get("name", cid)),
            kind=kind,
            category=str(meta.get("category", "")),
            points=meta.get("points"),
            description=str(meta.get("description", "")),
            flags_required=flags_required,
            meta={k: v for k, v in meta.items()
                  if k not in {"flag", "flags"}},  # keep expected flags out of Challenge.meta
        )
        return challenge, meta

    def _dir(self, challenge_id: str) -> Path:
        # challenge_id may differ from dir name; find by id, else by dir name.
        for cdir in self.root.iterdir():
            if not cdir.is_dir():
                continue
            ch, _ = self._cache.get(cdir.name, (None, None)) if cdir.name in self._cache else (None, None)
            if ch and ch.id == challenge_id:
                return cdir
        direct = self.root / challenge_id
        if direct.is_dir():
            return direct
        # Fall back to a scan matching challenge.json id.
        for cdir in self.root.iterdir():
            if cdir.is_dir() and (cdir / "challenge.json").is_file():
                ch, _ = self._load(cdir)
                if ch.id == challenge_id:
                    return cdir
        raise PlatformError(f"unknown challenge: {challenge_id}")

    def list_challenges(self) -> list[Challenge]:
        out: list[Challenge] = []
        for cdir in sorted(self.root.iterdir()):
            if not cdir.is_dir():
                continue
            ch, meta = self._load(cdir)
            self._cache[cdir.name] = (ch, meta)
            out.append(ch)
        return out

    def get_challenge(self, challenge_id: str) -> Challenge:
        ch, meta = self._load(self._dir(challenge_id))
        return ch

    def download_files(self, challenge_id: str, dest: Path) -> list[Path]:
        src = self._dir(challenge_id) / "files"
        dest = Path(dest)
        dest.mkdir(parents=True, exist_ok=True)
        if not src.is_dir():
            return []
        written: list[Path] = []
        for item in src.rglob("*"):
            if item.is_file():
                rel = item.relative_to(src)
                target = dest / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(item, target)
                written.append(target)
        return written

    def start_instance(self, challenge_id: str) -> ConnInfo:
        return self.get_conn_info(challenge_id)

    def get_conn_info(self, challenge_id: str) -> ConnInfo:
        _, meta = self._load(self._dir(challenge_id))
        target = meta.get("target") or {}
        return ConnInfo(
            host=target.get("host"),
            port=target.get("port"),
            url=target.get("url"),
            meta=target,
        )

    def submit_flag(self, challenge_id: str, flag: str) -> SubmitResult:
        if self._submit_hook is not None:
            return self._submit_hook(challenge_id, flag)
        cdir = self._dir(challenge_id)
        _, meta = self._load(cdir)
        # Gather the set of acceptable flags (single or multi-flag).
        expected: set[str] = set()
        if isinstance(meta.get("flags"), list):
            expected = {str(f).strip() for f in meta["flags"]}
        elif meta.get("flag") is not None:
            expected = {str(meta["flag"]).strip()}
        else:
            flag_file = cdir / "flag.txt"
            if flag_file.is_file():
                expected = {ln.strip() for ln in
                            flag_file.read_text(encoding="utf-8").splitlines() if ln.strip()}
        if not expected:
            return SubmitResult(accepted=False, message="no local answer to grade against")
        ok = flag.strip() in expected
        # The adapter is stateless per call; the submitter counts accepted flags
        # against Challenge.flags_required to decide when the challenge is solved.
        return SubmitResult(accepted=ok, message="correct" if ok else "incorrect")
