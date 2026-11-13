"""Run-log judge: analyse a real run log into a between-run improvement report."""

import json
import tempfile
from pathlib import Path

from harness.bench import run_benchmark
from harness.config import Config
from harness.judge import analyze_run


def _suite(root: Path):
    good = root / "easy"
    (good / "files").mkdir(parents=True)
    f = "CTF{" + "a" * 12 + "}"
    (good / "challenge.json").write_text(json.dumps(
        {"id": "easy", "name": "easy", "kind": "static", "category": "rev",
         "flag": f}))
    (good / "files" / "n.txt").write_text(f + "\n")
    hard = root / "hard"
    (hard / "files").mkdir(parents=True)
    (hard / "challenge.json").write_text(json.dumps(
        {"id": "hard", "name": "hard", "kind": "static", "category": "crypto",
         "flag": "CTF{unobtainable}"}))
    (hard / "files" / "c.bin").write_text("no flag\n")


def test_judge_reports_structure_and_rates():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        _suite(root / "suite")
        cfg = Config(inference_backend="rule", platform="benchmark",
                     fixtures_root=str(root / "suite"), work_root=str(root / "w"),
                     run_dir=str(root / "l"), concurrency=2)
        summary = run_benchmark(cfg)

        report = analyze_run(summary["log"])
        assert report["challenges"] == 2
        assert report["solved"] == 1
        assert abs(report["solve_rate"] - 0.5) < 1e-3
        assert set(report["per_challenge"]) == {"easy", "hard"}
        assert report["per_challenge"]["easy"]["solved"] is True
        assert report["per_challenge"]["easy"]["progress_score"] == 1.0
        assert report["per_challenge"]["hard"]["solved"] is False
        assert report["per_challenge"]["hard"]["progress_score"] < 1.0
        assert report["by_specialist"].get("rev", {}).get("solved") == 1
        assert report["suggestions"]            # non-empty guidance


def test_judge_flags_found_but_unsubmitted():
    # A hand-made log where a flag grounded but the challenge was never solved.
    with tempfile.TemporaryDirectory() as d:
        log = Path(d) / "run-x.jsonl"
        log.write_text("\n".join(json.dumps(e) for e in [
            {"seq": 1, "t": 1.0, "kind": "run.start"},
            {"seq": 2, "t": 1.1, "kind": "scheduler.prepared", "challenge": "c",
             "specialist": "forensics", "has_target": False, "files": 1},
            {"seq": 3, "t": 1.2, "kind": "attempt.start", "challenge": "c", "rung": 0},
            {"seq": 4, "t": 1.3, "kind": "tool.observe", "challenge": "c",
             "tool": "shell", "bytes": 100},
            {"seq": 5, "t": 1.4, "kind": "flag.candidate", "challenge": "c",
             "grounded": True, "source": "shell:x"},
            {"seq": 6, "t": 1.5, "kind": "flag.submit", "challenge": "c",
             "accepted": False},
            {"seq": 7, "t": 1.6, "kind": "attempt.end", "challenge": "c",
             "outcome": "stalled"},
            {"seq": 8, "t": 1.7, "kind": "scheduler.done", "solved": 0, "budget": {}},
        ]))
        report = analyze_run(log)
        assert report["grounded_but_unsolved"] == ["c"]
        assert any("found a flag but did not submit" in s for s in report["suggestions"])
        assert report["per_challenge"]["c"]["progress_score"] == 0.7
