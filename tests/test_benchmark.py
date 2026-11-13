"""Benchmark runner + report, and the service-launching platform."""

import json
import socket
import tempfile
import threading
from pathlib import Path

from harness.bench import run_benchmark
from harness.config import Config
from harness.platforms.benchmark import BenchmarkPlatform


def _task(root: Path, cid, category, flag, in_file=True):
    c = root / cid
    (c / "files").mkdir(parents=True)
    meta = {"id": cid, "name": cid, "kind": "static", "category": category,
            "points": 100, "flag": flag}
    (c / "challenge.json").write_text(json.dumps(meta))
    (c / "files" / "note.txt").write_text(f"{flag}\n" if in_file else "nothing\n")


def test_benchmark_report_structure_and_rate():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        suite = root / "suite"
        suite.mkdir()
        _task(suite, "rev1", "rev", "CTF{" + "a" * 12 + "}", in_file=True)
        _task(suite, "cry1", "crypto", "CTF{" + "b" * 12 + "}", in_file=True)
        _task(suite, "hard", "pwn", "CTF{" + "c" * 12 + "}", in_file=False)  # unsolvable offline
        cfg = Config(inference_backend="rule", platform="benchmark",
                     fixtures_root=str(suite), work_root=str(root / "w"),
                     run_dir=str(root / "l"), concurrency=2)
        rep = run_benchmark(cfg)

        assert rep["challenges"] == 3
        assert rep["solved"] == 2                     # two flags are in files
        assert abs(rep["solve_rate"] - 2 / 3) < 1e-3  # solve_rate is rounded to 4 dp
        assert rep["by_category"]["rev"] == {"total": 1, "solved": 1}
        assert rep["by_category"]["pwn"] == {"total": 1, "solved": 0}
        assert len(rep["solves"]) == 2
        assert Path(rep["report"]).exists()
        # report file is valid JSON with the same solve count
        disk = json.loads(Path(rep["report"]).read_text())
        assert disk["solved"] == 2


def test_benchmark_platform_launches_and_tears_down_service():
    # A tiny TCP server that prints a flag, declared as a task service.
    flag = "CTF{" + "svc" * 4 + "}"
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        c = root / "svc01"
        (c / "files").mkdir(parents=True)
        # server.py greets each client with the flag, then closes.
        (c / "files" / "server.py").write_text(
            "import socket,sys\n"
            "p=int(sys.argv[1])\n"
            "s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
            "s.bind(('127.0.0.1',p));s.listen(5)\n"
            "while True:\n"
            "    conn,_=s.accept()\n"
            f"    conn.sendall(b'{flag}\\n');conn.close()\n"
        )
        port = _free_port()
        (c / "challenge.json").write_text(json.dumps({
            "id": "svc01", "name": "svc", "kind": "interactive", "category": "pwn",
            "flag": flag,
            "service": {"cmd": f"python3 server.py {port}", "port": port, "ready_wait": 10},
        }))
        plat = BenchmarkPlatform(str(root))
        try:
            conn = plat.start_instance("svc01")
            assert conn.host == "127.0.0.1" and conn.port == port
            # the service is reachable and serves the flag
            with socket.create_connection((conn.host, conn.port), timeout=5) as s:
                data = s.recv(100)
            assert flag.encode() in data
        finally:
            plat.close()


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p
