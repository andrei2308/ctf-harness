"""Single-challenge production path (solve_one / run_challenge)."""

import json
import tempfile
from pathlib import Path

from harness.config import Config
from harness.single import solve_one

FLAG = "CTF{" + "s" * 16 + "}"


def _one_challenge(root: Path, cid="only", with_flag=True):
    c = root / cid
    (c / "files").mkdir(parents=True)
    meta = {"id": cid, "name": cid, "kind": "static", "category": "misc", "points": 100}
    if with_flag:
        meta["flag"] = FLAG
        (c / "files" / "f.txt").write_text(f"here: {FLAG}\n")
    else:
        meta["flag"] = "CTF{unobtainable}"
        (c / "files" / "f.txt").write_text("no flag here\n")
    (c / "challenge.json").write_text(json.dumps(meta))


def _cfg(root: Path) -> Config:
    return Config(inference_backend="rule", platform="files",
                  fixtures_root=str(root / "fix"), work_root=str(root / "work"),
                  run_dir=str(root / "logs"))


def test_solve_one_solves_the_single_challenge():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "fix").mkdir()
        _one_challenge(root / "fix")
        summary = solve_one(_cfg(root))
        assert summary["challenge"] == "only"
        assert summary["solved"] is True
        assert summary["flags_accepted"] == 1
        assert Path(summary["log"]).exists()


def test_solve_one_picks_named_challenge():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "fix").mkdir()
        _one_challenge(root / "fix", cid="a")
        _one_challenge(root / "fix", cid="b", with_flag=False)
        summary = solve_one(_cfg(root), challenge_id="b")
        assert summary["challenge"] == "b"
        assert summary["solved"] is False          # b's flag is not in its files
        # and nothing was falsely submitted
        assert summary["submissions"]["flags_accepted"] == 0


def test_solve_one_unsolvable_makes_no_false_submission():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "fix").mkdir()
        _one_challenge(root / "fix", with_flag=False)
        summary = solve_one(_cfg(root))
        assert summary["solved"] is False
        assert summary["submissions"]["solved_count"] == 0


def test_task_prompt_is_logged():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "fix").mkdir()
        _one_challenge(root / "fix")
        summary = solve_one(_cfg(root))
        events = [json.loads(l) for l in open(summary["log"])]
        prompts = [e for e in events if e["kind"] == "task.prompt"]
        assert len(prompts) == 1 and "f.txt" in prompts[0]["text"]
