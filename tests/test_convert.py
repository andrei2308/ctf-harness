"""Benchmark converter: a dataset task -> the harness suite layout."""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

CONVERTER = Path(__file__).resolve().parent.parent / "scripts" / "convert_benchmark.py"


def test_converts_generic_task_dir():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        # A source dataset: one task dir with metadata + a handout file.
        task = root / "ds" / "pwn" / "babyheap"
        task.mkdir(parents=True)
        (task / "challenge.json").write_text(json.dumps({
            "name": "babyheap", "category": "pwn",
            "description": "nc it", "flag": "CTF{x}"}))
        (task / "vuln").write_text("ELF-ish bytes")

        out = root / "suite"
        r = subprocess.run([sys.executable, str(CONVERTER), "--spec", "generic",
                            "--src", str(root / "ds"), "--out", str(out)],
                           capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        chal = json.loads((out / "babyheap" / "challenge.json").read_text())
        assert chal["category"] == "pwn"
        assert chal["kind"] == "interactive"       # pwn -> interactive
        assert chal["flags"] == ["CTF{x}"]
        assert (out / "babyheap" / "files" / "vuln").is_file()
        # metadata/flag files are not copied as attachments
        assert not (out / "babyheap" / "files" / "challenge.json").exists()
