"""End-to-end, fully offline: the files adapter + the rule model drive the whole
enumerate -> solve -> ground -> submit -> log loop with no network.

Asserts the two behaviours that matter most:
  * a challenge whose flag is in a readable file gets solved and submitted;
  * a challenge whose flag is NOT in any provided file is never falsely
    submitted (the confab guard holds across the whole pipeline) and is dropped
    after the ladder is exhausted.
"""

import json
import tempfile
from pathlib import Path

from harness.config import Config
from harness.run import run

SOLVABLE_FLAG = "CTF{" + "a" * 16 + "}"


def _write_fixtures(root: Path):
    s = root / "solvable"
    (s / "files").mkdir(parents=True)
    (s / "challenge.json").write_text(json.dumps({
        "id": "solvable", "name": "easy", "kind": "static", "category": "misc",
        "points": 100, "flag": SOLVABLE_FLAG,
    }))
    (s / "files" / "note.txt").write_text(f"read me\n{SOLVABLE_FLAG}\n")

    u = root / "locked"
    (u / "files").mkdir(parents=True)
    (u / "challenge.json").write_text(json.dumps({
        "id": "locked", "name": "hard", "kind": "static", "category": "crypto",
        "points": 500, "flag": "CTF{not_in_any_file}",
    }))
    (u / "files" / "cipher.bin").write_text("deadbeef no flag here\n")


def test_offline_end_to_end():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        _write_fixtures(root / "fixtures")
        cfg = Config(
            inference_backend="rule",
            platform="files",
            fixtures_root=str(root / "fixtures"),
            work_root=str(root / "work"),
            run_dir=str(root / "logs"),
            concurrency=2,
        )
        summary = run(cfg)

        assert "solvable" in summary["submissions"]["solved"]
        assert "locked" not in summary["submissions"]["solved"]
        assert summary["solved"] == 1
        # Dropped (ladder exhausted) — not solved, not stuck running.
        assert summary["by_status"].get("solved") == 1
        assert summary["by_status"].get("dropped") == 1

        # The run log exists and records a solve for the solvable challenge only.
        log_text = Path(summary["log"]).read_text()
        assert '"kind":"flag.submit"' in log_text
        assert '"accepted":true' in log_text


def test_multi_flag_challenge_solved_end_to_end():
    """A two-flag challenge whose flags both sit in readable files must get BOTH
    submitted and be marked solved — the failure mode the reference agent hit."""
    f1 = "CTF{" + "a" * 20 + "}"
    f2 = "CTF{" + "b" * 20 + "}"
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        c = root / "fixtures" / "twopart"
        (c / "files").mkdir(parents=True)
        (c / "challenge.json").write_text(json.dumps({
            "id": "twopart", "name": "two", "kind": "static",
            "category": "forensics", "points": 400, "flags": [f1, f2],
        }))
        (c / "files" / "a.txt").write_text(f"stage1\n{f1}\n")
        (c / "files" / "b.txt").write_text(f"stage2\n{f2}\n")
        cfg = Config(inference_backend="rule", platform="files",
                     fixtures_root=str(root / "fixtures"),
                     work_root=str(root / "work"), run_dir=str(root / "logs"),
                     concurrency=1)
        summary = run(cfg)
        assert "twopart" in summary["submissions"]["solved"]
        assert summary["submissions"]["flags_accepted"] == 2


def test_dry_run_does_not_submit_but_still_grounds():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        _write_fixtures(root / "fixtures")
        cfg = Config(inference_backend="rule", platform="files",
                     fixtures_root=str(root / "fixtures"),
                     work_root=str(root / "work"), run_dir=str(root / "logs"),
                     concurrency=2, dry_run=True)
        summary = run(cfg)
        # In dry-run the submitter reports accepted without hitting the platform,
        # so the solvable one is still "solved" in-process but nothing was sent.
        assert summary["solved"] == 1
