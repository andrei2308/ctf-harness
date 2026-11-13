"""Per-category specialists with concrete tool playbooks.

Each specialist supplies a system prompt (a terse playbook naming the tools it
should reach for and when) and a tool profile; the shared Solver loop does the
rest. A per-run capability probe tells each specialist which tools are actually
installed in the image, so it only reaches for what's present.

Routing is by the challenge's category string first (rev / pwn / crypto /
forensics / stego / web / mobile), then falls back to the kind hint and the
connection shape. An unlabelled challenge goes to a broad generalist.

Prompts name real tools but stay terse — token efficiency is scored.
"""

from __future__ import annotations

import abc
from pathlib import Path

from ..platforms.base import Challenge, ChallengeKind, ConnInfo
from .exttools import GdbTool, GhidraDecompileTool, VolatilityTool
from .tools import (HttpTool, ServiceConnectTool, ServiceRecvTool,
                    ServiceSendTool, ShellTool, ToolProfile, WriteFileTool)

_FLAG_CONTRACT = (
    "A flag counts only if it appears in real tool output (file contents, program "
    "stdout, a service reply). Never write a flag you did not observe. Show the "
    "exact output containing it. Multi-flag challenges exist (often staged, e.g. "
    "forensics): after one is accepted, keep going until every flag is in."
)
_EFFICIENCY = (
    "Token/time are hard-capped and scored. One concrete action per step, read "
    "the result, decide; drop a dead line of attack fast. All tools run "
    "non-interactively — supply every input up front; never launch something that "
    "waits at a prompt. No internet: online lookups (factordb, libc.rip) are dead."
)


class Specialist(abc.ABC):
    kind: ChallengeKind = ChallengeKind.UNKNOWN

    @abc.abstractmethod
    def profile(self) -> ToolProfile: ...

    @abc.abstractmethod
    def system_prompt(self) -> str: ...

    def task_prompt(self, challenge: Challenge, work_dir: Path,
                    conn: ConnInfo | None, files: list[Path],
                    available: set[str] | None = None) -> str:
        lines = [f"Challenge: {challenge.name}"]
        if challenge.category:
            lines.append(f"Category: {challenge.category}")
        if challenge.description:
            lines.append(f"Description:\n{challenge.description}")
        if files:
            lines.append(f"Files in your working directory ({work_dir}): "
                         + ", ".join(p.name for p in files))
        if conn and conn.url:
            lines.append(f"Web target: {conn.url}")
        elif conn and conn.host and conn.port:
            lines.append(f"Service target: {conn.host}:{conn.port} (use connect/send/recv).")
        if challenge.flags_required > 1:
            lines.append(f"This challenge requires {challenge.flags_required} flags.")
        if available:
            lines.append("Installed tools detected here: " + ", ".join(sorted(available)) + ".")
        lines.append("Find the flag.")
        return "\n".join(lines)


# Shared tool sets -----------------------------------------------------------
def _base():            # every specialist can run a shell and write scripts
    return [ShellTool(), WriteFileTool()]


class RevSpecialist(Specialist):
    kind = ChallengeKind.STATIC

    def profile(self) -> ToolProfile:
        return ToolProfile("rev", _base() + [GdbTool(), GhidraDecompileTool()])

    def system_prompt(self) -> str:
        return (
            "You are a reverse-engineering specialist. Playbook:\n"
            "- Triage: `file`, `strings -n6`, `checksec`, `nm`, `readelf -a`. UPX-"
            "packed? `upx -d`. Foreign arch (ARM/MIPS)? run/debug under "
            "`qemu-*-static` and `gdb-multiarch`.\n"
            "- Decompile the key function with `ghidra_decompile` (prefer one "
            "function over dumping everything); cross-check in `radare2` (aaa; pdf).\n"
            "- Dynamic: `gdb` in batch (break at the check, inspect state), "
            "`ltrace`/`strace` for calls/syscalls. Emulate opaque byte streams "
            "with `unicorn`; solve constraint/keygen checks with `angr` or `z3`.\n"
            "- .pyc? `uncompyle6`/`decompyle3`. Unknown blobs: `binwalk`, `floss`.\n"
            f"{_FLAG_CONTRACT}\n{_EFFICIENCY}"
        )


class PwnSpecialist(Specialist):
    kind = ChallengeKind.INTERACTIVE

    def profile(self) -> ToolProfile:
        return ToolProfile("pwn", _base() + [
            ServiceConnectTool(), ServiceSendTool(), ServiceRecvTool(), GdbTool()])

    def system_prompt(self) -> str:
        return (
            "You are a binary-exploitation (pwn) specialist. Playbook:\n"
            "- Recon the binary: `checksec` (RELRO/canary/NX/PIE), find the bug "
            "path in `ghidra`/`radare2`. For libc challenges, identify libc and "
            "run `pwninit`/`patchelf`; find gadgets with `ROPgadget`/`ropper` and "
            "`one_gadget`; parse filters with `seccomp-tools`.\n"
            "- Write the exploit as a `pwntools` script (process locally first, "
            "then switch to remote). Debug with `gdb`+pwndbg in batch.\n"
            "- Drive the live service with `connect`/`send`/`recv`; confirm each "
            "primitive (leak → libc base → control) before chaining.\n"
            f"{_FLAG_CONTRACT}\n{_EFFICIENCY}"
        )


class CryptoSpecialist(Specialist):
    kind = ChallengeKind.STATIC

    def profile(self) -> ToolProfile:
        return ToolProfile("crypto", _base())

    def system_prompt(self) -> str:
        return (
            "You are a cryptography specialist. Playbook:\n"
            "- Read the source/params first; identify the scheme. Prefer "
            "**SageMath** (`sage` / `sage -python`) for ECC (discrete_log, "
            "Pohlig-Hellman), lattices/LLL (`fpylll`), and number theory.\n"
            "- RSA: try `RsaCtfTool` (offline attacks only — no factordb), or "
            "hand-roll with `pycryptodome`+`gmpy2`+`sympy` (Wiener, common-modulus, "
            "Hastad, Franklin-Reiter, partial-key via Coppersmith in Sage). Factor "
            "locally with `yafu` (NO internet for factordb).\n"
            "- Classical/XOR: `xortool`, frequency analysis. Padding oracle: a "
            "`pwntools`/`requests` script. Hashes: identify, then `john`/`hashcat`.\n"
            "- Interactive crypto services: script with `pwntools` over the socket.\n"
            f"{_FLAG_CONTRACT}\n{_EFFICIENCY}"
        )


class ForensicsSpecialist(Specialist):
    kind = ChallengeKind.STATIC

    def profile(self) -> ToolProfile:
        return ToolProfile("forensics", _base() + [VolatilityTool()])

    def system_prompt(self) -> str:
        return (
            "You are a forensics & steganography specialist. Playbook:\n"
            "- Identify every input: `file`, `binwalk -e`, `foremost`/`scalpel` to "
            "carve, `exiftool` for metadata, 7z/unzip for archives.\n"
            "- Memory image → **Volatility 3** (`volatility` tool: windows.pslist, "
            "cmdline, filescan/dumpfiles, netscan; linux.* for Linux). Disk image "
            "→ `sleuthkit` (fls/icat), `testdisk`/`photorec`.\n"
            "- PCAP → `tshark` (follow streams, export objects), `scapy`.\n"
            "- Images/audio stego: `zsteg` (PNG/BMP LSB), `steghide`/`stegseek` "
            "(JPEG, crack with rockyou), `outguess`, `stegsnow`; `zbar` for QR; "
            "`sox`/spectrogram and `multimon-ng` for audio. PDFs: `pdf-parser`, "
            "`qpdf`; Office macros: `oletools` (olevba).\n"
            f"{_FLAG_CONTRACT}\n{_EFFICIENCY}"
        )


class WebSpecialist(Specialist):
    kind = ChallengeKind.WEB

    def profile(self) -> ToolProfile:
        return ToolProfile("web", _base() + [HttpTool()])

    def system_prompt(self) -> str:
        return (
            "You are a web-exploitation specialist. The `http` tool is bound to "
            "the target app (other hosts refused); `shell` has curl, `ffuf`/"
            "`feroxbuster`/`gobuster`, `sqlmap`, `nikto`/`whatweb`, `wfuzz`, "
            "`commix`, `jwt_tool`, `flask-unsign`. Playbook:\n"
            "- Map it: fingerprint (`whatweb`), enumerate paths/params (`ffuf`/"
            "`feroxbuster` with SecLists), read cookies/headers.\n"
            "- Attack the implied bug class: SQLi (`sqlmap`), command injection "
            "(`commix`), SSRF/LFI/path-traversal, auth/JWT (`jwt_tool`), Flask "
            "session forging (`flask-unsign`), SSTI, deserialization.\n"
            "- The flag may be in a body, header, a file read via the bug, or the "
            "app DB.\n"
            f"{_FLAG_CONTRACT}\n{_EFFICIENCY}"
        )


class MobileSpecialist(Specialist):
    kind = ChallengeKind.STATIC

    def profile(self) -> ToolProfile:
        return ToolProfile("mobile", _base() + [GhidraDecompileTool()])

    def system_prompt(self) -> str:
        return (
            "You are a mobile (Android/APK) specialist. Playbook:\n"
            "- Decompile with `jadx` (Java/Smali) and unpack with `apktool` "
            "(resources, AndroidManifest, strings.xml); `dex2jar` if needed.\n"
            "- Grep decompiled sources for the flag, secrets, endpoints, crypto "
            "keys, and checks. Native `.so` libraries → `ghidra_decompile`.\n"
            "- Note: dynamic instrumentation (`frida`) needs a device/emulator the "
            "run sandbox lacks — rely on static analysis.\n"
            f"{_FLAG_CONTRACT}\n{_EFFICIENCY}"
        )


class GeneralistSpecialist(Specialist):
    """Fallback for misc / unlabelled challenges: broad toolset, identify first."""

    kind = ChallengeKind.UNKNOWN

    def profile(self) -> ToolProfile:
        return ToolProfile("generalist",
                           _base() + [GdbTool(), GhidraDecompileTool(), VolatilityTool()])

    def system_prompt(self) -> str:
        return (
            "You are a generalist CTF solver for a challenge of unclear type. "
            "First identify what you have: `file`, `strings`, `binwalk`, "
            "`exiftool`. Then treat it as the matching category — a binary "
            "(decompile with `ghidra`/`gdb`), a cipher (SageMath/`pycryptodome`), "
            "a capture or image (`tshark`/`volatility`/`zsteg`), or an encoding "
            "(base64/hex/`CyberChef`-style transforms via `shell`).\n"
            f"{_FLAG_CONTRACT}\n{_EFFICIENCY}"
        )


# Singletons -----------------------------------------------------------------
_REV = RevSpecialist()
_PWN = PwnSpecialist()
_CRYPTO = CryptoSpecialist()
_FORENSICS = ForensicsSpecialist()
_WEB = WebSpecialist()
_MOBILE = MobileSpecialist()
_GENERALIST = GeneralistSpecialist()

# Category keyword -> specialist. First substring match wins (order matters:
# check 'pwn'/'rev' before generic words).
_CATEGORY_RULES: list[tuple[tuple[str, ...], Specialist]] = [
    (("pwn", "exploit", "binary exploit"), _PWN),
    (("rev", "reversing", "reverse"), _REV),
    (("crypto", "cryptography"), _CRYPTO),
    (("forensic", "stego", "steg"), _FORENSICS),
    (("web", "http"), _WEB),
    (("mobile", "android", "apk", "ios"), _MOBILE),
]


def route(challenge: Challenge, conn: ConnInfo | None) -> Specialist:
    """Pick a specialist by category keyword, then by kind/connection shape."""
    cat = (challenge.category or "").lower()
    for keys, spec in _CATEGORY_RULES:
        if any(k in cat for k in keys):
            return spec
    # No category match: use the connection/kind signal.
    if conn and conn.url:
        return _WEB
    if conn and conn.host and conn.port:
        return _PWN
    if challenge.kind == ChallengeKind.WEB:
        return _WEB
    if challenge.kind == ChallengeKind.INTERACTIVE:
        return _PWN
    return _GENERALIST
