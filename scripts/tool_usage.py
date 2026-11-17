#!/usr/bin/env python3
"""Which programs did the agent actually run? Counted from run logs.

    python scripts/tool_usage.py ~/Desktop/ctf-rehearsal            # every *.jsonl below
    python scripts/tool_usage.py logs/ --tier core                  # ...and what a tier lacks

Reads the `tool.call` events of every log, pulls the program names out of shell
commands (and the Python modules out of scripts), and prints for each one how
many challenge runs called it and how many of those runs were solved. With
--tier, the last column says whether the program's name is in that tier's
package list (scripts/tiers/<tier>.conf). That is a comparison of names, not of
the built image: the common cases where a program's package has another name
are known (`7z` comes from `p7zip-full`), an uncommon one shows as "-" and may
be there all the same. Treat "-" as "look", not as "missing".

Evidence for deciding what a smaller image tier may leave out: a tool no run
ever called costs nothing to drop; a tool called in solved runs does.
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
from collections import defaultdict
from pathlib import Path

# Shell words that are not programs worth counting.
_NOISE = set("""
cd echo cat ls head tail grep egrep fgrep sed awk cut tr sort uniq wc printf test true false
export set unset for do done if then else fi while case esac in function return exit sleep
timeout time env xargs find mkdir rm cp mv chmod chown touch ln tee pwd which command type
id whoami date basename dirname read local source bash sh
import from print def class try except with as pass assert lambda None True False
""".split())
_SPLIT = re.compile(r"\|\||&&|[|;&\n]|\$\(|`")
_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
# Tools that are harness wrappers around a program.
_WRAPPERS = {"gdb": "gdb", "gdb_session": "gdb", "ghidra_decompile": "ghidra",
             "volatility": "volatility", "http": "(http tool)",
             "connect": "(service tools)", "send": "(service tools)", "recv": "(service tools)"}
# Python modules worth knowing about, when a command or script imports them.
_MODULES = ("pwn", "angr", "z3", "sage", "Crypto", "gmpy2", "sympy", "fpylll", "scapy",
            "requests", "web3", "PIL", "matplotlib", "scipy", "numpy", "capstone",
            "unicorn", "volatility3", "bs4", "jwt", "websocket", "paramiko", "pytesseract")
_IMPORT = re.compile(r"(?:^|[\s;'\"])(?:from|import)\s+([A-Za-z_][A-Za-z0-9_]*)")


def programs(command: str) -> set[str]:
    """Program names at the start of each simple command in a shell line."""
    found = set()
    for part in _SPLIT.split(command):
        try:
            words = shlex.split(part, comments=True)
        except ValueError:
            words = part.split()
        while words and (_ASSIGN.match(words[0]) or words[0] in ("sudo", "timeout", "time", "env",
                                                                 "nohup", "stdbuf", "xargs")):
            words.pop(0)
            while words and (words[0].startswith("-") or words[0].replace(".", "").isdigit()
                             or re.fullmatch(r"\d+[smh]?", words[0])):
                words.pop(0)
        if not words:
            continue
        name = words[0].rsplit("/", 1)[-1]
        if re.fullmatch(r"[A-Za-z0-9_.+-]{2,40}", name) and name not in _NOISE:
            found.add(name)
    for mod in _IMPORT.findall(command):
        if mod in _MODULES:
            found.add(f"py:{mod}")
    return found


# Programs whose package is named differently, and those every tier has from
# its base layer or its fixed Python set.
_PACKAGE = {
    "strings": "binutils", "objdump": "binutils", "readelf": "binutils", "nm": "binutils",
    "ld": "binutils", "as": "binutils", "7z": "p7zip-full", "7za": "p7zip-full",
    "r2": "radare2", "rabin2": "radare2", "rasm2": "radare2", "nc": "netcat-traditional",
    "netcat": "netcat-traditional", "dig": "dnsutils", "nslookup": "dnsutils",
    "ssh": "openssh-client", "scp": "openssh-client", "pdftotext": "poppler-utils",
    "pdfimages": "poppler-utils", "zbarimg": "zbar-tools", "php": "php-cli",
    "fls": "sleuthkit", "mmls": "sleuthkit", "icat": "sleuthkit", "vol": "volatility3",
    "sage": "sagemath", "upx": "upx-ucl", "gp": "pari-gp", "convert": "imagemagick",
    "identify": "imagemagick", "node": "nodejs", "mysql": "default-mysql-client",
    "psql": "postgresql-client", "redis-cli": "redis-tools", "ping": "iputils-ping",
    "ip": "iproute2", "ss": "iproute2", "hexdump": "bsdextrautils", "unrar": "unrar-free",
    "photorec": "testdisk", "analyzeHeadless": "ghidra", "tesseract": "tesseract-ocr",
    "zip2john": "john", "rar2john": "john", "ssh2john": "john", "pdf2john": "john",
    "solc": "solc-select", "olevba": "oletools", "d2j-dex2jar": "dex2jar",
    "qemu-aarch64-static": "qemu-user-static", "qemu-arm-static": "qemu-user-static",
    "volatility": "volatility3",
}
_ALWAYS = set("""
python3 python pip gcc g++ cc make git curl wget unzip xz tar gzip gunzip base64 base32 od
dd diff cmp nl rev tac seq bc perl openssl-always ROPgadget pwn checksec-py pytest
""".split())


def tier_packages(tier: str) -> set[str]:
    conf = Path(__file__).resolve().parent / "tiers" / f"{tier}.conf"
    text = re.sub(r"#.*", "", conf.read_text())
    words = {w.lower() for w in re.findall(r"[A-Za-z0-9_.+-]+", text)}
    # Pieces switched by a WITH_* setting rather than listed as a package.
    for flag, names in (("WITH_GHIDRA", ["ghidra"]), ("WITH_SAGE", ["sagemath"]),
                        ("WITH_FOUNDRY", ["forge", "cast", "anvil"]),
                        ("WITH_PWNDBG", ["pwndbg"]), ("WITH_RSACTFTOOL", ["rsactftool"]),
                        ("WITH_JWT_TOOL", ["jwt_tool"]), ("WITH_PWNINIT", ["pwninit"])):
        on = re.search(flag + r":=1", text)
        words -= {n for n in names if not on}
        words |= {n for n in names if on}
    return words


def in_tier(prog: str, packages: set[str]) -> bool:
    if prog in _ALWAYS:
        return True
    return _PACKAGE.get(prog, prog).lower() in packages


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("paths", nargs="+", help="log files or directories of *.jsonl")
    ap.add_argument("--tier", help="mark programs not in scripts/tiers/<tier>.conf")
    ap.add_argument("--min", type=int, default=1, help="only programs called in at least N challenges")
    args = ap.parse_args()

    logs: list[Path] = []
    for p in map(Path, args.paths):
        logs += sorted(p.rglob("*.jsonl")) if p.is_dir() else [p]
    if not logs:
        print("no logs found", file=sys.stderr)
        return 1

    used = defaultdict(set)        # program -> {run keys}
    solved_runs: set[tuple] = set()
    runs: set[tuple] = set()
    for log in logs:
        try:
            lines = log.read_text(errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            try:
                e = json.loads(line)
            except ValueError:
                continue
            kind, cid = e.get("kind"), e.get("challenge")
            key = (str(log), cid)
            if kind == "tool.call":
                runs.add(key)
                tool = e.get("tool", "")
                args_ = e.get("args") or e.get("input") or {}
                if tool in _WRAPPERS:
                    used[_WRAPPERS[tool]].add(key)
                # The log holds the bare command, or compact JSON for a call
                # with several arguments.
                if isinstance(args_, str) and args_.startswith("{"):
                    try:
                        args_ = json.loads(args_)
                    except ValueError:
                        pass
                text = " ".join(str(v) for v in args_.values()) if isinstance(args_, dict) else str(args_)
                if tool in ("shell", "write_file"):
                    for prog in programs(text) if tool == "shell" else \
                            {f"py:{m}" for m in _IMPORT.findall(text) if m in _MODULES}:
                        used[prog].add(key)
            elif kind == "challenge.done" and e.get("solved"):
                solved_runs.add(key)

    lacking = tier_packages(args.tier) if args.tier else None
    print(f"{len(logs)} logs, {len(runs)} challenge runs with tool calls, "
          f"{len(solved_runs & runs)} of them solved\n")
    print(f"{'program':28} {'runs':>5} {'solved':>7}" + ("   in tier list?" if lacking is not None else ""))
    rows = sorted(used.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    for prog, keys in rows:
        if len(keys) < args.min:
            continue
        line = f"{prog:28} {len(keys):>5} {len(keys & solved_runs):>7}"
        if lacking is not None and not prog.startswith(("py:", "(")):
            line += "   yes" if in_tier(prog, lacking) else "   -"
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
