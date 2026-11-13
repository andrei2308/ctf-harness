"""Benchmark Platform — run the harness over a local challenge suite.

Extends the files adapter with the one thing benchmarks need that a static file
drop does not: launching a local service for interactive/web tasks. A task's
challenge.json may declare:

    "service": {"cmd": "python3 server.py", "port": 1337, "cwd": "files", "ready_wait": 15}

and start_instance() spawns it, waits for the port, and returns a ConnInfo
pointing at 127.0.0.1:<port>. close() tears every launched service down.

This is the local measurement rig for Cybench / NYU-CTF / InterCode-style suites
(convert each into this layout — see BENCHMARKS.md). It launches the benchmark's
own service commands, so only run it on suites you trust, on your dev machine —
never as the production path.
"""

from __future__ import annotations

import socket
import subprocess
import time
from pathlib import Path

from .base import ConnInfo, PlatformError
from .files_target import FilesTargetPlatform


class BenchmarkPlatform(FilesTargetPlatform):
    def __init__(self, root, submit_hook=None):
        super().__init__(root, submit_hook=submit_hook)
        self._procs: dict[str, subprocess.Popen] = {}

    def start_instance(self, challenge_id: str) -> ConnInfo:
        cdir = self._dir(challenge_id)
        _, meta = self._load(cdir)
        svc = meta.get("service")
        if not svc:
            return super().start_instance(challenge_id)  # target-from-json or empty

        port = int(svc.get("port") or 0)
        if challenge_id in self._procs and self._procs[challenge_id].poll() is None:
            return ConnInfo(host="127.0.0.1", port=port, meta={"launched": True})

        cmd = svc.get("cmd")
        if not cmd or not port:
            raise PlatformError(f"service for {challenge_id} needs cmd and port")
        cwd = cdir / str(svc.get("cwd", "files"))
        if not cwd.is_dir():
            cwd = cdir
        argv = cmd if isinstance(cmd, list) else ["bash", "-lc", cmd]
        try:
            proc = subprocess.Popen(argv, cwd=str(cwd),
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    stdin=subprocess.DEVNULL)
        except OSError as e:
            raise PlatformError(f"failed to launch service for {challenge_id}: {e}") from e
        self._procs[challenge_id] = proc
        self._wait_port("127.0.0.1", port, float(svc.get("ready_wait", 15)))
        return ConnInfo(host="127.0.0.1", port=port, meta={"launched": True})

    def get_conn_info(self, challenge_id: str) -> ConnInfo:
        if challenge_id in self._procs and self._procs[challenge_id].poll() is None:
            _, meta = self._load(self._dir(challenge_id))
            port = int((meta.get("service") or {}).get("port") or 0)
            return ConnInfo(host="127.0.0.1", port=port, meta={"launched": True})
        return super().get_conn_info(challenge_id)

    @staticmethod
    def _wait_port(host: str, port: int, timeout: float) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with socket.create_connection((host, port), timeout=1):
                    return
            except OSError:
                time.sleep(0.25)
        # Not fatal: the solver will get a connection error and can react.

    def close(self) -> None:
        for proc in self._procs.values():
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
        self._procs.clear()
