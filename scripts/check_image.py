#!/usr/bin/env python3
"""Check the built image from the agent's point of view.

    docker run --rm ctf-harness:latest python scripts/check_image.py

Every command runs through LocalExecutor, the same stripped-down shell the agent
gets (PATH only, HOME set to the work dir), so a tool that is installed but not
visible to the agent shows up as a failure here. Exit code is the number of
CRITICAL failures; optional ones are reported but do not fail the check.

A smaller image tier (Dockerfile.slim) leaves tools out on purpose. Those are
listed in scripts/tiers/<tier>.missing and reported as `[ -- ]`, apart from a
tool that is missing because its install failed, which is still `[miss]`:

    docker run --rm ctf-harness:base-core python scripts/check_image.py --strict

With --strict the exit code also counts those unexpected misses.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from harness.agents.tools import LocalExecutor  # noqa: E402

C, O = True, False   # critical / optional


def have(*names: str) -> str:
    """Shell that succeeds only if EVERY name is on PATH. (`command -v a b`
    succeeds when just one of them is.)"""
    return f"for t in {' '.join(names)}; do command -v \"$t\" >/dev/null || exit 1; done"


CHECKS: list[tuple[str, str, bool]] = [
    # --- the agent's python is the venv, with the core libraries ------------
    ("python3 is the venv's", 'test "$(command -v python3)" = /opt/venv/bin/python3', C),
    ("pwntools works", "python3 -c 'from pwn import cyclic, p64, ELF; print(cyclic(16))'", C),
    ("z3 solves", "python3 -c 'import z3; x=z3.Int(\"x\"); s=z3.Solver(); s.add(x*3==12); "
                  "assert s.check()==z3.sat'", C),
    ("pycryptodome", "python3 -c 'from Crypto.Cipher import AES; from Crypto.Util.number "
                     "import long_to_bytes'", C),
    ("gmpy2 / sympy", "python3 -c 'import gmpy2, sympy'", C),
    ("requests", "python3 -c 'import requests'", C),
    ("angr imports", "python3 -c 'import angr'", C),
    ("capstone / unicorn", "python3 -c 'import capstone, unicorn'", O),
    ("scapy", "python3 -c 'import scapy.all'", O),
    ("fpylll (lattices)", "python3 -c 'import fpylll'", O),
    ("web3", "python3 -c 'import web3'", O),
    ("volatility3 module", "python3 -c 'import volatility3'", O),
    # --- rev / pwn ------------------------------------------------------------
    ("gdb runs", "command -v gdb >/dev/null && gdb --batch -ex 'show version' | head -1", C),
    # The gdb tools run `$CTF_GDB --batch --nx`, so check exactly that.
    ("pwndbg loads (as the gdb tools run it)",
     "pwndbg --batch --nx -ex 'pwndbg' 2>&1 | grep -qi checksec", O),
    ("binutils (objdump/readelf/strings)", have("objdump", "readelf", "strings", "file", "xxd"), C),
    ("ROPgadget", "ROPgadget --version", C),
    ("ropper", "ropper --version", O),
    ("checksec", have("checksec"), O),
    ("one_gadget", "one_gadget --version", O),
    ("seccomp-tools", have("seccomp-tools"), O),
    ("pwninit", have("pwninit"), O),
    ("patchelf", "patchelf --version", O),
    ("radare2", "command -v r2 >/dev/null && r2 -v | head -1", O),
    ("ghidra headless", have("analyzeHeadless"), O),
    ("qemu-user", "command -v qemu-aarch64-static || command -v qemu-aarch64", O),
    ("ltrace / strace", have("ltrace", "strace"), O),
    # --- crypto ---------------------------------------------------------------
    ("sage factors", "sage -c 'print(factor(2^64+1))' | grep -q 274177", O),
    # Run it: a wrapper on PATH can point at a script upstream has moved.
    ("RsaCtfTool runs", "RsaCtfTool --help 2>&1 | grep -qi usage", O),
    ("pari-gp", have("gp"), O),
    # --- forensics / stego ----------------------------------------------------
    ("binwalk", have("binwalk"), C),
    ("exiftool", "exiftool -ver", C),
    ("tshark", "command -v tshark >/dev/null && tshark --version | head -1", C),
    ("volatility3 CLI", "command -v vol || command -v vol3 || command -v volatility3", O),
    ("foremost / scalpel", have("foremost", "scalpel"), O),
    ("7z / unrar", "command -v 7z >/dev/null && (command -v unrar || command -v unrar-free)", O),
    ("steghide / stegseek", have("steghide", "stegseek"), O),
    ("zsteg", have("zsteg"), O),
    ("tesseract", "command -v tesseract >/dev/null && tesseract --version 2>&1 | head -1", O),
    ("ffmpeg / sox", have("ffmpeg", "sox"), O),
    # --- cracking -------------------------------------------------------------
    ("john", have("john"), C),
    ("hashcat", have("hashcat"), O),
    ("rockyou.txt", "test -s /usr/share/wordlists/rockyou.txt", O),
    ("seclists", "test -d /usr/share/seclists", O),
    # --- web ------------------------------------------------------------------
    ("curl", "command -v curl >/dev/null && curl --version | head -1", C),
    ("sqlmap", have("sqlmap"), O),
    ("ffuf / gobuster", have("ffuf", "gobuster"), O),
    ("jwt_tool", have("jwt_tool"), O),
    ("nmap / nc / socat", have("nmap", "socat") + " ; command -v nc || command -v netcat", C),
    # --- mobile / blockchain --------------------------------------------------
    ("apktool / jadx", have("apktool", "jadx"), O),
    ("forge / cast (foundry)", "forge --version && cast --version", O),
    ("solc runs with the agent's HOME", "solc --version", O),
    # --- the harness's own tool wrappers, end to end ------------------------
    # A binary being on PATH is not enough: these wrappers had bugs (a dot-dir
    # Ghidra rejects; `python3 -m volatility3`, which has no __main__).
    ("ghidra_decompile tool decompiles",
     "printf 'int win(void){return 1337;}\\nint main(void){return win();}\\n' > g.c "
     "&& gcc -o g g.c && python3 -c 'import pathlib; "
     "from harness.agents.tools import LocalExecutor, ToolContext; "
     "from harness.agents.exttools import GhidraDecompileTool; "
     "c = ToolContext(challenge_id=\"c\", work_dir=pathlib.Path.cwd(), executor=LocalExecutor()); "
     "r = GhidraDecompileTool().run({\"binary\": \"./g\", \"function\": \"win\"}, c); "
     "assert b\"1337\" in r.output or b\"0x539\" in r.output, r.output[-300:]'", O),
    ("volatility tool reaches Volatility",
     "echo junk > m.raw && python3 -c 'import pathlib; "
     "from harness.agents.tools import LocalExecutor, ToolContext; "
     "from harness.agents.exttools import VolatilityTool; "
     "c = ToolContext(challenge_id=\"c\", work_dir=pathlib.Path.cwd(), executor=LocalExecutor()); "
     "r = VolatilityTool().run({\"image\": \"m.raw\", \"plugin\": \"windows.info\"}, c); "
     "assert b\"No module named\" not in r.output and not r.error, (r.error, r.output[-300:]); "
     "assert b\"symbol\" in r.output.lower() or b\"unsatisfied\" in r.output.lower(), r.output[-300:]'", O),
    # --- the harness itself ---------------------------------------------------
    # --- added after the rehearsal (scripts/image_extras.sh) ------------------
    ("ssh client + sshpass", have("ssh", "sshpass"), O),
    ("telnet / ftp", have("telnet", "ftp"), O),
    ("smbclient", have("smbclient"), O),
    ("mysql / psql / redis-cli", have("mysql", "psql", "redis-cli"), O),
    ("sqlite3 CLI", have("sqlite3"), O),
    ("php runs", "php -r 'echo 6*7;' | grep -q 42", O),
    ("ping / ip / ss", have("ping", "ip", "ss"), O),
    ("matplotlib / scipy", "python3 -c 'import matplotlib, scipy'", O),
    # A sandbox that drops NET_RAW must not make nmap unrunnable (file caps).
    # (Only root can drop capabilities; as another user, run nmap directly.)
    ("nmap runs without NET_RAW",
     "if [ \"$(id -u)\" = 0 ]; then capsh --drop=cap_net_raw,cap_net_admin -- -c 'nmap -V'; "
     "else nmap -V; fi 2>&1 | grep -q 'Nmap version'", O),
    ("forge outside /root (works as non-root)",
     "test -x /usr/local/bin/forge && /usr/local/bin/forge --version", O),
    ("node runs", "node -e 'console.log(6*7)' | grep -q 42", O),
    ("32-bit ELF loader", "test -e /lib/ld-linux.so.2", O),
    ("bs4 / jwt / websocket", "python3 -c 'import bs4, jwt, websocket'", O),
    ("Pillow for view_image", "/opt/venv/bin/python -c 'import PIL'", O),
    ("mcp client library", "/opt/venv/bin/python -c 'import mcp'", O),
    ("CyberEDU MCP server (dormant)",
     "/opt/cyberedu-mcp/bin/python -c 'import cyberedu_mcp'", O),
    ("contest.env puts the agent's work dir outside the harness tree",
     "/opt/venv/bin/python -c \"import sys; from harness.config import config_from_env; "
     "w = config_from_env().work_root; "
     "sys.exit(not w.startswith('/') or w.startswith('/opt/ctf-harness'))\"", O),
    ("openai SDK importable by the harness",
     "/opt/venv/bin/python -c 'import openai; print(openai.__version__)'", C),
    ("contest.env is in the image", "test -s /opt/ctf-harness/contest.env", C),
    ("ctf-notes are in the image",
     "test -n \"$(ls /opt/ctf-harness/knowledge/ctf-notes 2>/dev/null)\"", O),
]


def image_tier() -> str:
    """The tier this image was built as: written by Dockerfile.slim's last
    stage; "full" for the main Dockerfile, which writes nothing."""
    try:
        for line in Path("/etc/ctf-image-tier").read_text().splitlines():
            if line.startswith("tier="):
                return line[5:].strip().lower() or "full"
    except OSError:
        pass
    return os.environ.get("CTF_IMAGE_TIER", "").strip().lower() or "full"


def left_out(tier: str) -> set[str]:
    """Labels of the checks this tier is built not to pass."""
    try:
        lines = (ROOT / "scripts" / "tiers" / f"{tier}.missing").read_text().splitlines()
    except OSError:
        return set()
    return {ln.strip() for ln in lines if ln.strip() and not ln.startswith("#")}


def main() -> int:
    strict = "--strict" in sys.argv[1:]
    tier = image_tier()
    by_design = left_out(tier)
    ex = LocalExecutor()
    work = Path(tempfile.mkdtemp(prefix="imgcheck-"))
    failed_critical = failed_optional = skipped = 0
    if tier != "full":
        print(f"image tier: {tier}")
    for label, cmd, critical in CHECKS:
        out, code = ex.run(cmd, work, 180)
        ok = code == 0
        expected = not ok and not critical and label in by_design
        if expected:
            skipped += 1
            print(f"[ -- ] {label}   (left out of the {tier} tier)")
            continue
        if not ok:
            if critical:
                failed_critical += 1
            else:
                failed_optional += 1
        tag = "PASS" if ok else ("FAIL" if critical else "miss")
        line = f"[{tag}] {label}"
        if not ok:
            tail = out.decode("utf-8", "replace").strip().splitlines()[-1:] or [""]
            line += f"   <- exit {code}: {tail[0][:160]}"
        print(line)
    # A profile planted in the work dir (the agent's HOME) must not run on the
    # next command: challenge files are untrusted.
    ex.run("echo 'echo PLANTED' > .profile; cp .profile .bash_profile", work, 10)
    out, _ = ex.run("echo ok", work, 10)
    if b"PLANTED" in out:
        failed_critical += 1
        print("[FAIL] a planted ~/.profile is sourced by the agent shell")
    else:
        print("[PASS] a planted ~/.profile is not sourced")
    total = len(CHECKS) + 1
    summary = (f"\n{total - failed_critical - failed_optional - skipped}/{total} passed; "
               f"{failed_critical} critical failure(s), {failed_optional} optional tool(s) missing")
    if tier != "full":
        summary += (f" that the {tier} tier should have; "
                    f"{skipped} left out of it by design")
    print(summary)
    return failed_critical + (failed_optional if strict else 0)


if __name__ == "__main__":
    raise SystemExit(main())
