"""Per-type specialists: static-file, interactive (pwn), web.

Each specialist supplies a system prompt and a tool profile; the shared Solver
loop does the rest. Tool profiles now include the heavyweight analysis tools
(gdb/pwndbg, Ghidra headless, Volatility) alongside shell — the agent's effective
capability is whatever we bake into the submission image. A per-run capability
probe tells each specialist which tools are actually installed, so it never
reaches for one the image lacks.

Prompts are terse on purpose: token efficiency is scored.
"""

from __future__ import annotations

import abc
from pathlib import Path

from ..platforms.base import Challenge, ChallengeKind, ConnInfo
from .exttools import GdbTool, GhidraDecompileTool, VolatilityTool
from .tools import (HttpTool, ServiceConnectTool, ServiceRecvTool,
                    ServiceSendTool, ShellTool, ToolProfile, WriteFileTool)

_FLAG_CONTRACT = (
    "A flag only counts if it appears in real tool output (a file's contents, a "
    "program's stdout, a service reply). Never write a flag you did not observe; "
    "an invented flag is worthless. When you have the flag, show the exact tool "
    "output that contains it. Some challenges need more than one flag (often "
    "staged, e.g. forensics): after one is accepted, keep going until every flag "
    "is in."
)

_EFFICIENCY = (
    "Token and time are hard-capped and scored. Do not narrate or pad. Each step: "
    "one concrete action, read the result, decide. If a line of attack shows no "
    "progress, abandon it and try another. All tools run non-interactively — a "
    "tool you launch must not wait for a prompt; supply every input up front."
)


class Specialist(abc.ABC):
    kind: ChallengeKind

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
            rels = ", ".join(p.name for p in files)
            lines.append(f"Files in your working directory ({work_dir}): {rels}")
        if conn and conn.url:
            lines.append(f"Web target: {conn.url}")
        elif conn and conn.host and conn.port:
            lines.append(f"Service target: {conn.host}:{conn.port} (use connect/send/recv).")
        if challenge.flags_required > 1:
            lines.append(f"This challenge requires {challenge.flags_required} flags.")
        if available:
            lines.append("Installed analysis tools in this sandbox: "
                         + ", ".join(sorted(available)) + ".")
        lines.append("Find the flag.")
        return "\n".join(lines)


class StaticFileSpecialist(Specialist):
    """Type A: rev, crypto, forensics, stego, misc — files on disk, no service."""

    kind = ChallengeKind.STATIC

    def profile(self) -> ToolProfile:
        return ToolProfile("static", [
            ShellTool(), WriteFileTool(),
            GdbTool(), GhidraDecompileTool(), VolatilityTool(),
        ])

    def system_prompt(self) -> str:
        return (
            "You are a CTF specialist for static-file challenges (reverse "
            "engineering, cryptography, forensics, steganography). Tools: `shell` "
            "(file, strings, binwalk, xxd, objdump, python, etc.), `write_file` "
            "(author scripts), `gdb` (batch debugging/disassembly), "
            "`ghidra_decompile` (decompile a binary to C), and `volatility` "
            "(memory-image forensics).\n"
            f"{_FLAG_CONTRACT}\n{_EFFICIENCY}\n"
            "Fingerprint inputs first (file type, strings, entropy). For large "
            "inputs (binaries, captures, disk images) extract with tools rather "
            "than dumping whole files into reasoning — reading raw bytes wholesale "
            "wastes the token budget. For reversing, prefer `ghidra_decompile` on "
            "the key function over reading raw disassembly."
        )


class InteractiveSpecialist(Specialist):
    """Type B: pwn and interactive challenges — a live service to talk to."""

    kind = ChallengeKind.INTERACTIVE

    def profile(self) -> ToolProfile:
        return ToolProfile("interactive", [
            ShellTool(), WriteFileTool(),
            ServiceConnectTool(), ServiceSendTool(), ServiceRecvTool(),
            GdbTool(),
        ])

    def system_prompt(self) -> str:
        return (
            "You are a CTF specialist for interactive/pwn challenges. Tools: "
            "`connect`/`send`/`recv` for a real session with the target service, "
            "`gdb` for batch analysis of the local binary (checksec, disassembly, "
            "run with crafted input), and `shell`/`write_file` to build and run "
            "exploit scripts (e.g. pwntools) against that target.\n"
            f"{_FLAG_CONTRACT}\n{_EFFICIENCY}\n"
            "If a binary is provided, analyse it first (protections, the "
            "vulnerable path) before interacting. Confirm each primitive (leak, "
            "overflow, write) against the live service before chaining. Prefer a "
            "scripted exploit over hand-typed bytes once you understand the protocol."
        )


class WebSpecialist(Specialist):
    """Type C: web challenges — an HTTP target."""

    kind = ChallengeKind.WEB

    def profile(self) -> ToolProfile:
        return ToolProfile("web", [ShellTool(), WriteFileTool(), HttpTool()])

    def system_prompt(self) -> str:
        return (
            "You are a CTF specialist for web challenges. Tools: `http` (bound to "
            "the target app; other hosts are refused), `shell`, `write_file`. Map "
            "the app first (routes, parameters, cookies, technologies), then probe "
            "for the bug class the challenge implies (injection, auth bypass, "
            "SSRF, deserialization, path traversal, etc.).\n"
            f"{_FLAG_CONTRACT}\n{_EFFICIENCY}\n"
            "The flag may be in a response body, a header, a file you can read "
            "through the bug, or the app database."
        )


_BY_KIND: dict[ChallengeKind, Specialist] = {
    ChallengeKind.STATIC: StaticFileSpecialist(),
    ChallengeKind.INTERACTIVE: InteractiveSpecialist(),
    ChallengeKind.WEB: WebSpecialist(),
}


def route(challenge: Challenge, conn: ConnInfo | None) -> Specialist:
    """Pick a specialist. Uses the platform's kind hint; falls back to signal
    from the connection (a URL => web, a host:port => interactive) and finally to
    static-file, the safest default for an unlabelled file drop."""
    if challenge.kind in _BY_KIND:
        return _BY_KIND[challenge.kind]
    if conn and conn.url:
        return _BY_KIND[ChallengeKind.WEB]
    if conn and conn.host and conn.port:
        return _BY_KIND[ChallengeKind.INTERACTIVE]
    return _BY_KIND[ChallengeKind.STATIC]
