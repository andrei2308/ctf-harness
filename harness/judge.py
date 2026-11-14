"""Run-log judge — analyse what happened in a run so you can improve the harness
between attempts (the dev loop *is* the competition).

Inspired by CTFJudge / the CTF Competency Index (arXiv:2508.05674): grade each
challenge's trajectory, give partial credit, and surface *where* it failed. This
reads the JSONL run log the harness already writes — no re-run needed — and is
heuristic (offline, deterministic, zero token cost). An optional `--llm` layer
asks a model to diagnose the worst failures and suggest concrete fixes.

    python -m harness.judge runs/logs/run-<id>.jsonl
    python -m harness.judge runs/logs/run-<id>.jsonl --llm --backend openai

Partial-credit ladder (progress score, 0–1): solved=1.0, found-but-not-submitted
flag=0.7, engaged tools but no flag=0.4, only prepared=0.1, never started=0.0.
A challenge that *grounded a flag but is unsolved* is the highest-value fix — it
is a plumbing/submission gap, not a solving gap (the lesson that beat Overmind).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path


def _events(log_path: Path):
    for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line:
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def analyze_run(log_path: str | Path) -> dict:
    log_path = Path(log_path)
    per = defaultdict(lambda: {
        "specialist": None, "attempts": 0, "max_rung": 0, "tools": Counter(),
        "observed_bytes": 0, "grounded": False, "submitted": 0, "accepted": 0,
        "stuck_nudges": 0, "planned": False, "outcomes": [], "fresh_restarts": 0,
        "first_flag_t": None, "has_target": None, "files": None,
    })
    run_start = None
    budget = {}
    solved_from_summary = None

    for ev in _events(log_path):
        kind = ev.get("kind", "")
        if kind == "run.start":
            run_start = ev.get("t")
        c = ev.get("challenge")
        if kind in ("scheduler.prepared", "challenge.prepared") and c:
            per[c]["specialist"] = ev.get("specialist")
            per[c]["has_target"] = ev.get("has_target")
            per[c]["files"] = ev.get("files")
        elif kind == "attempt.start" and c:
            per[c]["attempts"] += 1
            per[c]["max_rung"] = max(per[c]["max_rung"], ev.get("rung", 0))
        elif kind == "attempt.end" and c:
            per[c]["outcomes"].append(ev.get("outcome"))
        elif kind == "tool.observe" and c:
            per[c]["tools"][ev.get("tool", "?")] += 1
            per[c]["observed_bytes"] += ev.get("bytes", 0)
        elif kind == "flag.candidate" and c and ev.get("grounded"):
            per[c]["grounded"] = True
        elif kind == "flag.submit" and c:
            per[c]["submitted"] += 1
            if ev.get("accepted"):
                per[c]["accepted"] += 1
                if per[c]["first_flag_t"] is None and run_start is not None:
                    per[c]["first_flag_t"] = round(ev.get("t", 0) - run_start, 1)
        elif kind == "solver.plan" and c:
            per[c]["planned"] = True
        elif kind == "solver.stuck_nudge" and c:
            per[c]["stuck_nudges"] += 1
        elif kind == "challenge.fresh_context" and c:
            per[c]["fresh_restarts"] += 1
        elif kind == "scheduler.done":
            budget = ev.get("budget", {}) or {}
            solved_from_summary = ev.get("solved")

    pc_tokens = (budget.get("per_challenge") or {})
    challenges = {}
    for c, d in per.items():
        solved = d["accepted"] > 0
        if solved:
            score = 1.0
        elif d["grounded"]:
            score = 0.7
        elif sum(d["tools"].values()) > 0:
            score = 0.4
        elif d["specialist"]:
            score = 0.1
        else:
            score = 0.0
        challenges[c] = {
            "specialist": d["specialist"],
            "solved": solved,
            "progress_score": score,
            "attempts": d["attempts"],
            "max_rung": d["max_rung"],
            "tool_calls": dict(d["tools"]),
            "observed_bytes": d["observed_bytes"],
            "grounded_but_unsolved": d["grounded"] and not solved,
            "submissions": d["submitted"],
            "accepted": d["accepted"],
            "stuck_nudges": d["stuck_nudges"],
            "planned": d["planned"],
            "fresh_restarts": d["fresh_restarts"],
            "seconds_to_first_flag": d["first_flag_t"],
            "last_outcome": d["outcomes"][-1] if d["outcomes"] else None,
            "tokens": (pc_tokens.get(c) or {}).get("tokens"),
        }

    total = len(challenges)
    solved = sum(1 for v in challenges.values() if v["solved"])
    report = {
        "log": str(log_path),
        "challenges": total,
        "solved": solved,
        "solve_rate": round(solved / total, 4) if total else 0.0,
        "mean_progress": round(
            sum(v["progress_score"] for v in challenges.values()) / total, 3) if total else 0.0,
        "grounded_but_unsolved": [c for c, v in challenges.items() if v["grounded_but_unsolved"]],
        "stuck_heavy": [c for c, v in challenges.items() if v["stuck_nudges"] >= 1 and not v["solved"]],
        "by_specialist": _by_specialist(challenges),
        "suggestions": _suggest(challenges),
        "per_challenge": challenges,
    }
    return report


def _by_specialist(challenges: dict) -> dict:
    agg: dict[str, dict] = defaultdict(lambda: {"total": 0, "solved": 0})
    for v in challenges.values():
        s = v["specialist"] or "unknown"
        agg[s]["total"] += 1
        if v["solved"]:
            agg[s]["solved"] += 1
    return dict(agg)


def _suggest(challenges: dict) -> list[str]:
    out = []
    gbu = [c for c, v in challenges.items() if v["grounded_but_unsolved"]]
    if gbu:
        out.append(f"HIGH: {len(gbu)} challenge(s) found a flag but did not submit it "
                   f"({', '.join(gbu)}) — a submission/multi-flag gap, not a solving gap. "
                   "Check flags_required and the submit path.")
    weak = {}
    for v in challenges.values():
        if not v["solved"]:
            s = v["specialist"] or "unknown"
            weak[s] = weak.get(s, 0) + 1
    if weak:
        worst = max(weak, key=weak.get)
        out.append(f"Weakest category: {worst} ({weak[worst]} unsolved) — tune its "
                   "playbook/tools or add knowledge-base notes for it.")
    idle = [c for c, v in challenges.items()
            if not v["solved"] and sum(v["tool_calls"].values()) == 0]
    if idle:
        out.append(f"{len(idle)} challenge(s) ran no tools ({', '.join(idle[:5])}) — "
                   "the agent may be misrouted or lacks a usable tool; check routing/profile.")
    if not out:
        out.append("No systemic issues detected from the log.")
    return out


# --- optional LLM diagnosis -------------------------------------------------

def llm_diagnose(report: dict, config) -> list[str]:
    """Ask a model to diagnose the worst failures and suggest harness/prompt fixes.
    Best-effort; returns [] if no model is available."""
    from .config import make_model_factory
    from .inference.base import Message, ModelSpec, Effort, ModelError
    worst = sorted(report["per_challenge"].items(),
                   key=lambda kv: kv[1]["progress_score"])[:5]
    brief = json.dumps({c: v for c, v in worst}, indent=2)
    try:
        model = make_model_factory(config)(ModelSpec(name=config.fast_model, effort=Effort.MEDIUM,
                                                      max_tokens=1024))
        resp = model.complete([
            Message(role="system", content=(
                "You are a CTF-harness engineer. Given per-challenge run stats, name "
                "the top 3 concrete changes to the harness/prompts/tools that would "
                "most improve solve rate. Be specific and brief.")),
            Message(role="user", content=brief),
        ], [])
        return [resp.text.strip()]
    except (ModelError, Exception):  # noqa: BLE001 - diagnosis is optional
        return []


def _print(report: dict) -> None:
    print(f"\n  Judge: {report['solved']}/{report['challenges']} solved "
          f"({report['solve_rate']*100:.1f}%)  |  mean progress {report['mean_progress']}")
    print("  By specialist:")
    for s, v in sorted(report["by_specialist"].items()):
        print(f"    {s:<12} {v['solved']}/{v['total']}")
    if report["grounded_but_unsolved"]:
        print(f"  ⚠ found-but-unsubmitted: {', '.join(report['grounded_but_unsolved'])}")
    print("  Suggestions:")
    for s in report["suggestions"]:
        print(f"    - {s}")
    for d in report.get("llm_diagnosis", []):
        print("  LLM diagnosis:\n    " + d.replace("\n", "\n    "))


def print_transcript(log_path: str | Path, challenge: str | None = None, out=None) -> int:
    """Replay what the agent did, turn by turn: its text, each command, and a
    capped excerpt of each result. Returns the number of events shown."""
    out = out or sys.stdout
    shown = 0
    for ev in _events(Path(log_path)):
        c = ev.get("challenge")
        if challenge and c != challenge:
            continue
        kind = ev.get("kind", "")
        tag = f"[{c}] " if c and not challenge else ""
        if kind == "attempt.start":
            line = f"=== attempt: {ev.get('spec')} (rung effort {ev.get('rung')})"
        elif kind == "attempt.end":
            line = f"=== end: {ev.get('outcome')} — {ev.get('reason')}"
        elif kind == "solver.plan":
            line = "PLAN  " + str(ev.get("text", "")).strip()
        elif kind == "model.turn":
            line = (f"MODEL #{ev.get('iter')} ({ev.get('tokens_in')} in / "
                    f"{ev.get('tokens_out')} out, {ev.get('seconds')}s)  "
                    + str(ev.get("text", "")).strip())
        elif kind == "tool.call":
            line = f"  $ {ev.get('tool')}: {ev.get('args')}"
        elif kind == "tool.observe":
            head = f"    -> {ev.get('bytes')} bytes, exit {ev.get('exit_code')}, {ev.get('seconds')}s"
            if ev.get("error"):
                head += f", error: {ev['error']}"
            body = str(ev.get("output", "")).rstrip()
            line = head + ("\n" + "\n".join("       " + ln for ln in body.splitlines())
                           if body else "")
        elif kind in ("flag.candidate", "flag.submit", "flag.submit_error",
                      "solver.stuck_nudge", "solver.model_retry",
                      "challenge.top_rung_restart", "challenge.fresh_context",
                      "challenge.budget_stop", "challenge.done"):
            extra = {k: v for k, v in ev.items() if k not in ("seq", "t", "kind", "challenge")}
            line = f"* {kind} {json.dumps(extra, ensure_ascii=False)}"
        else:
            continue
        print(tag + line, file=out)
        shown += 1
    return shown


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="harness.judge", description="Analyse a run log")
    p.add_argument("log", help="path to a run-<id>.jsonl log")
    p.add_argument("--transcript", nargs="?", const="", default=None, metavar="CHALLENGE",
                   help="print the turn-by-turn transcript (optionally for one challenge) and exit")
    p.add_argument("--llm", action="store_true", help="add a model diagnosis of the worst failures")
    p.add_argument("--backend", default="openai")
    a = p.parse_args(argv if argv is not None else sys.argv[1:])
    if a.transcript is not None:
        print_transcript(a.log, a.transcript or None)
        return 0
    report = analyze_run(a.log)
    if a.llm:
        from .config import config_from_env
        cfg = config_from_env()
        cfg.inference_backend = a.backend
        report["llm_diagnosis"] = llm_diagnose(report, cfg)
    out = Path(a.log).with_suffix(".judge.json")
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    _print(report)
    print(f"  Report: {out}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
