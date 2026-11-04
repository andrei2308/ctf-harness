"""Per-type specialists: static-file, interactive (pwn), web.

Each specialist is thin by design — it supplies a system prompt and a tool
profile; the shared Solver loop does the rest. This mirrors the CAI "one tool
profile per specialist" shape and keeps EnIGMA's interactive ACI (connect/
send/recv) as the reusable pwn/rev piece, while leaving a single place to tune
each category's instructions as real challenges teach us what works.

The prompts are terse on purpose: long preambles burn tokens, and the rules
score token efficiency. They state the contract (flag must come from real
output), the available tools, and category tradecraft — nothing decorative.
"""

from __future__ import annotations

import abc
from pathlib import Path

from ..platforms.base import Challenge, ChallengeKind, ConnInfo
from .tools import (ToolProfile, interactive_profile, static_profile, web_profile)

_FLAG_CONTRACT = (
    "A flag only counts if it appears in real tool output (a file's contents, a "
    "program's stdout, a service reply). Never write a flag you did not observe; "
    "an invented flag is worthless and may cost a submission. When you have the "
    "flag, show the exact tool output that contains it. Some challenges need more "
    "than one flag (often staged, e.g. forensics): after one is accepted, keep "
    "going until every flag is in."
)

_EFFICIENCY = (
    "Token and time are hard-capped and scored. Do not narrate or pad. Each step: "
    "one concrete action, read the result, decide. If a line of attack shows no "
    "progress, abandon it and try another rather than repeating variations."
)


class Specialist(abc.ABC):
    kind: ChallengeKind

    @abc.abstractmethod
    def profile(self) -> ToolProfile: ...

    @abc.abstractmethod
    def system_prompt(self) -> str: ...

    def task_prompt(self, challenge: Challenge, work_dir: Path,
                    conn: ConnInfo | None, files: list[Path]) -> str:
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
            lines.append(f"Service target: {conn.host}:{conn.port} "
                         f"(use connect/send/recv).")
        lines.append("Find the flag.")
        return "\n".join(lines)


class StaticFileSpecialist(Specialist):
    """Type A: rev, crypto, forensics, stego, misc — files on disk, no service."""

    kind = ChallengeKind.STATIC

    def profile(self) -> ToolProfile:
        return static_profile()

    def system_prompt(self) -> str:
        return (
            "You are a CTF specialist for static-file challenges (reverse "
            "engineering, cryptography, forensics, steganography). You have a "
            "`shell` tool (run analysis tools: file, strings, binwalk, xxd, "
            "objdump, python, and any installed RE/forensics tooling) and "
            "`write_file` (author scripts to run via shell).\n"
            f"{_FLAG_CONTRACT}\n{_EFFICIENCY}\n"
            "Start by fingerprinting the inputs (file type, strings, entropy) "
            "before committing to an approach. For large inputs (binaries, packet "
            "captures, disk images) extract with tools — strings, binwalk, tshark, "
            "file carving, targeted greps — rather than dumping whole files into "
            "your reasoning; reading raw bytes wholesale wastes the token budget."
        )


class InteractiveSpecialist(Specialist):
    """Type B: pwn and interactive challenges — a live service to talk to."""

    kind = ChallengeKind.INTERACTIVE

    def profile(self) -> ToolProfile:
        return interactive_profile()

    def system_prompt(self) -> str:
        return (
            "You are a CTF specialist for interactive/pwn challenges. You have "
            "`connect`, `send`, `recv` for a real interactive session with the "
            "target service, plus `shell` and `write_file` to build and run "
            "exploit scripts (e.g. pwntools) locally against that target. "
            "Prefer writing a scripted exploit over hand-typing bytes once you "
            "understand the protocol.\n"
            f"{_FLAG_CONTRACT}\n{_EFFICIENCY}\n"
            "If a binary is provided, analyse it first (protections, the "
            "vulnerable path) before interacting. Confirm each primitive (leak, "
            "overflow, write) against the live service before chaining."
        )


class WebSpecialist(Specialist):
    """Type C: web challenges — an HTTP target."""

    kind = ChallengeKind.WEB

    def profile(self) -> ToolProfile:
        return web_profile()

    def system_prompt(self) -> str:
        return (
            "You are a CTF specialist for web challenges. You have an `http` tool "
            "bound to the target application (other hosts are refused), plus "
            "`shell` and `write_file`. Map the app first (routes, parameters, "
            "cookies, technologies) then probe for the class of bug the "
            "challenge implies (injection, auth bypass, SSRF, deserialization, "
            "path traversal, etc.).\n"
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
