#!/usr/bin/env python3
"""Convert a public CTF benchmark into the harness's suite layout.

Emits one directory per task:   <out>/<id>/challenge.json  +  <out>/<id>/files/*
so you can run:                 python -m harness.bench --fixtures <out> ...

Supports common layouts (CTFTiny / NYU CTF Bench / InterCode-CTF and generic).
Dataset schemas drift between releases, so field names are best-effort and marked
in PRESETS — verify against the dataset you pulled, and pass --metadata/--flag-key
to override. The converter is defensive: a task it cannot parse is skipped with a
warning rather than aborting the run.

  python scripts/convert_benchmark.py --spec ctftiny --src /path/to/CTFTiny --out suites/ctftiny
  python scripts/convert_benchmark.py --spec generic --src ./tasks --out suites/mine

Run it on your dev machine with the datasets checked out (the agent sandbox has no
internet). Keep datasets + converted suites out of git (large / licensed).
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

# Per-dataset hints. `meta` = candidate metadata filenames; `flag_keys` =
# metadata fields that hold the flag; `cat_keys` = category fields; `desc_keys`;
# `name_keys`. CONFIRM against the actual dataset.
PRESETS = {
    "generic": {
        "meta": ["challenge.json", "task.json", "metadata.json", "info.json"],
        "name_keys": ["name", "title", "challenge"],
        "cat_keys": ["category", "type", "tags"],
        "desc_keys": ["description", "prompt", "statement"],
        "flag_keys": ["flag", "flags", "answer"],
    },
    "ctftiny": {  # NYU-LLM-CTF CTFTiny
        "meta": ["challenge.json", "chal.json", "metadata.json"],
        "name_keys": ["name", "challenge"],
        "cat_keys": ["category", "tags"],
        "desc_keys": ["description", "prompt"],
        "flag_keys": ["flag"],
    },
    "nyu": {  # NYU CTF Bench (CSAW)
        "meta": ["challenge.json", "chal.json"],
        "name_keys": ["name", "challenge"],
        "cat_keys": ["category"],
        "desc_keys": ["description"],
        "flag_keys": ["flag"],
    },
    "intercode": {  # InterCode-CTF (picoCTF-style)
        "meta": ["challenge.json", "task.json", "metadata.json"],
        "name_keys": ["name", "title"],
        "cat_keys": ["category", "tags"],
        "desc_keys": ["description", "prompt"],
        "flag_keys": ["flag"],
    },
}

_KIND_BY_CAT = {
    "pwn": "interactive", "binary": "interactive", "web": "web",
    "rev": "static", "reversing": "static", "crypto": "static",
    "forensic": "static", "forensics": "static", "stego": "static",
    "misc": "static",
}


def _first(d: dict, keys: list[str]):
    for k in keys:
        if isinstance(d, dict) and d.get(k) not in (None, "", []):
            return d[k]
    return None


def _kind(category: str) -> str:
    c = (category or "").lower()
    for key, kind in _KIND_BY_CAT.items():
        if key in c:
            return kind
    return "unknown"


def _load_meta(task_dir: Path, preset: dict) -> dict | None:
    for name in preset["meta"]:
        p = task_dir / name
        if p.is_file():
            try:
                return json.loads(p.read_text(encoding="utf-8", errors="replace"))
            except json.JSONDecodeError:
                return None
    return None


def _flag(meta: dict, task_dir: Path, preset: dict, flag_key: str | None):
    keys = ([flag_key] if flag_key else []) + preset["flag_keys"]
    val = _first(meta, keys) if meta else None
    if val is None:
        for fn in ("flag.txt", "flag"):
            fp = task_dir / fn
            if fp.is_file():
                val = fp.read_text(encoding="utf-8").strip()
                break
    if val is None:
        return None
    return val if isinstance(val, list) else [str(val)]


def convert(src: Path, out: Path, preset: dict, metadata: str | None,
            flag_key: str | None) -> tuple[int, int]:
    out.mkdir(parents=True, exist_ok=True)
    if metadata:
        preset = {**preset, "meta": [metadata] + preset["meta"]}
    written = skipped = 0
    # A task dir = any dir that has a metadata file or a flag file.
    for task_dir in sorted(p for p in src.rglob("*") if p.is_dir()):
        meta = _load_meta(task_dir, preset)
        flags = _flag(meta or {}, task_dir, preset, flag_key)
        if meta is None and flags is None:
            continue
        cid = (str(_first(meta or {}, preset["name_keys"]) or task_dir.name)
               .strip().replace("/", "_").replace(" ", "_"))[:80] or task_dir.name
        category = str(_first(meta or {}, preset["cat_keys"])
                       or task_dir.parent.name or "")
        if isinstance(category, list):
            category = category[0] if category else ""
        description = str(_first(meta or {}, preset["desc_keys"]) or "")
        dest = out / cid
        (dest / "files").mkdir(parents=True, exist_ok=True)

        # Copy attachment files: everything in the task dir except metadata/flag.
        skip_names = set(preset["meta"]) | {"flag.txt", "flag", "docker-compose.yml"}
        for item in task_dir.iterdir():
            if item.is_file() and item.name not in skip_names:
                shutil.copy2(item, dest / "files" / item.name)
        for sub in ("files", "dist", "handout", "public"):
            srcsub = task_dir / sub
            if srcsub.is_dir():
                for f in srcsub.rglob("*"):
                    if f.is_file():
                        rel = f.relative_to(srcsub)
                        (dest / "files" / rel).parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(f, dest / "files" / rel)

        chal = {"id": cid, "name": cid, "kind": _kind(category),
                "category": category, "description": description}
        if flags:
            chal["flags"] = flags
        # A docker-compose => a service; leave a commented hint for the user.
        if (task_dir / "docker-compose.yml").is_file():
            chal["_service_hint"] = ("this task ships a docker-compose.yml — add a "
                                     "\"service\": {cmd, port} or run compose and set "
                                     "\"target\": {host, port} / {url}")
        (dest / "challenge.json").write_text(json.dumps(chal, indent=2), encoding="utf-8")
        written += 1
    return written, skipped


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Convert a CTF benchmark to the suite layout")
    p.add_argument("--spec", choices=list(PRESETS), default="generic")
    p.add_argument("--src", required=True, help="dataset root (checked out locally)")
    p.add_argument("--out", required=True, help="output suite directory")
    p.add_argument("--metadata", help="metadata filename override (e.g. chal.json)")
    p.add_argument("--flag-key", help="metadata field holding the flag")
    a = p.parse_args(argv if argv is not None else sys.argv[1:])
    src = Path(a.src)
    if not src.is_dir():
        print(f"error: src not found: {src}", file=sys.stderr)
        return 2
    written, _ = convert(src, Path(a.out), PRESETS[a.spec], a.metadata, a.flag_key)
    print(f"converted {written} task(s) -> {a.out}")
    if written == 0:
        print("no tasks parsed — check --spec / --metadata / --flag-key against the "
              "dataset's actual layout.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
