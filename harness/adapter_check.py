"""Check the platform adapter before uploading the image.

    python -m harness.adapter_check                       # read-only
    python -m harness.adapter_check --challenge ID
    python -m harness.adapter_check --submit 'CTF{deliberately_wrong}'

At the contest a broken adapter shows only as "unsolved", with no log to read.
This walks the adapter the way a run does (list, describe, files, service,
routing) and prints exactly what the agent would be told, so a wrong field name
or an unread address is caught in seconds on your own machine.

Nothing is submitted unless --submit is given. Submitting a deliberately wrong
value is worth doing where wrong flags are free: it proves a rejection comes
back as "not accepted" rather than as a crash, or, worse, as accepted.
Exit code: the number of failed checks.
"""

from __future__ import annotations

import argparse
import os
import socket
import sys
import tempfile
from pathlib import Path

from .agents.specialists import route
from .config import config_from_env, make_platform
from .flags.grounding import flag_pattern, format_check
from .platforms.base import ChallengeKind


def stated_flag_examples(text: str) -> list[str]:
    """Flag formats a description states, as matchable examples:
    "MOCK{...}" -> "MOCK{x0x0x0x0}", "format: DCTF{sha256}" -> "DCTF{x0x0x0x0}".
    Bare words in braces only; hints without a '{...}' shape are ignored."""
    import re
    out = []
    for m in re.finditer(r"\b([A-Za-z][A-Za-z0-9_]{0,15})\{[^{}\s]{0,40}\}", text or ""):
        ex = f"{m.group(1)}{{x0x0x0x0}}"
        if ex not in out:
            out.append(ex)
    return out


class _Report:
    def __init__(self, out) -> None:
        self.out, self.failed, self.warned = out, 0, 0

    def line(self, tag: str, text: str) -> None:
        print(f"[{tag}] {text}", file=self.out)

    def ok(self, text: str) -> None:
        self.line("PASS", text)

    def warn(self, text: str) -> None:
        self.warned += 1
        self.line("WARN", text)

    def fail(self, text: str) -> None:
        self.failed += 1
        self.line("FAIL", text)


def check(platform, challenge_id: str | None = None, submit: str | None = None,
          out=None, reach: bool = True) -> int:
    """Run the checks against an adapter instance. Returns the failure count."""
    out = out or sys.stdout
    r = _Report(out)

    try:
        challenges = platform.list_challenges()
    except Exception as e:  # noqa: BLE001 - every adapter failure is a finding
        r.fail(f"list_challenges raised {type(e).__name__}: {e}")
        return r.failed
    if not challenges:
        r.fail("list_challenges returned nothing")
        return r.failed
    r.ok(f"list_challenges: {len(challenges)} challenge(s): "
         + ", ".join(c.id for c in challenges[:8]) + (" …" if len(challenges) > 8 else ""))

    cid = challenge_id or challenges[0].id
    try:
        ch = platform.get_challenge(cid)
    except Exception as e:  # noqa: BLE001
        r.fail(f"get_challenge({cid!r}) raised {type(e).__name__}: {e}")
        return r.failed
    r.ok(f"get_challenge: id={ch.id!r} name={ch.name!r} category={ch.category!r} "
         f"flags_required={ch.flags_required}")
    if not ch.category:
        r.warn("no category: routing will fall back to the connection shape")
    if not ch.description.strip():
        r.warn("empty description: the agent gets no statement, no flag format, no question")

    work = Path(tempfile.mkdtemp(prefix="adapter-check-"))
    files: list[Path] = []
    try:
        files = platform.download_files(cid, work)
        if files:
            r.ok("download_files: " + ", ".join(f"{p.name} ({p.stat().st_size} B)" for p in files))
            for p in files:
                if p.stat().st_size == 0:
                    r.fail(f"{p.name} is empty")
                if p.name.lower() in ("downloaded_file", "file", "download", "attachment"):
                    r.warn(f"{p.name}: generic name; keep the real name and extension")
                try:
                    p.resolve().relative_to(work.resolve())
                except ValueError:
                    r.fail(f"{p} was written outside the work dir")
        else:
            r.ok("download_files: no files")
    except Exception as e:  # noqa: BLE001
        r.fail(f"download_files raised {type(e).__name__}: {e}")

    conn = None
    try:
        conn = platform.start_instance(cid)
        if conn and (conn.host or conn.url):
            r.ok(f"start_instance: host={conn.host} port={conn.port} url={conn.url}")
            if reach and conn.host and conn.port:
                try:
                    socket.create_connection((conn.host, int(conn.port)), timeout=5).close()
                    r.ok(f"the service answers on {conn.host}:{conn.port}")
                except OSError as e:
                    r.warn(f"cannot connect to {conn.host}:{conn.port} from here ({e}); "
                           "fine if it is only reachable from the contest sandbox")
        else:
            r.ok("start_instance: no service (files-only challenge)")
            if ch.kind in (ChallengeKind.INTERACTIVE, ChallengeKind.WEB):
                r.fail(f"the challenge is {ch.kind.value} but no service address came back")
            if not files:
                r.fail("neither files nor a service: the agent has nothing to work on")
    except Exception as e:  # noqa: BLE001
        r.fail(f"start_instance raised {type(e).__name__}: {e}")

    spec = route(ch, conn)
    prof = spec.profile_for(conn)
    r.ok(f"routing: specialist '{prof.name}', tools: {', '.join(t.name for t in prof.tools)}")
    chk = format_check(ch.description)
    r.ok(f"flag pattern: {flag_pattern().pattern.decode()[:90]}"
         + (f"; stated hash format, hex lengths {chk.lengths}" if chk else ""))
    # A stated flag format the pattern cannot match means flags in tool output
    # are never picked up automatically (drill: a kit with MOCK{...} flags and
    # the default CTF{...} pattern). Only submit_flag would get them in.
    for example in stated_flag_examples(ch.description):
        if not flag_pattern().search(example.encode()):
            r.warn(f"the challenge states the format {example!r}, which the flag pattern "
                   f"does not match: set CTF_FLAG_REGEX in contest.env")
    print("\n----- what the agent is told -----", file=out)
    print(spec.task_prompt(ch, work, conn, files), file=out)
    print("----------------------------------\n", file=out)

    if submit is not None:
        try:
            res = platform.submit_flag(cid, submit)
            r.ok(f"submit_flag({submit!r}): accepted={res.accepted} "
                 f"already_solved={res.already_solved} challenge_solved={res.challenge_solved} "
                 f"message={res.message[:120]!r}")
            if res.accepted:
                r.warn("that value was ACCEPTED. If it was meant to be wrong, the adapter "
                       "reports every flag as correct and every run will stop at once")
        except Exception as e:  # noqa: BLE001
            r.fail(f"submit_flag raised {type(e).__name__}: {e} "
                   "(a rejected flag must come back as a result, not an exception)")
    else:
        r.line("SKIP", "submit_flag not exercised (pass --submit VALUE)")

    try:
        platform.close()
    except Exception as e:  # noqa: BLE001
        r.warn(f"close raised {type(e).__name__}: {e}")
    print(f"{r.failed} failed, {r.warned} warning(s)", file=out)
    return r.failed


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="harness.adapter_check", description=__doc__.split("\n\n")[0])
    p.add_argument("--challenge", help="challenge id (default: CTF_CHALLENGE_ID, else the first listed)")
    p.add_argument("--submit", metavar="VALUE", help="also submit VALUE (use a deliberately wrong one)")
    p.add_argument("--no-reach", action="store_true", help="do not try to connect to the service")
    a = p.parse_args(argv if argv is not None else sys.argv[1:])
    config = config_from_env()
    print(f"platform: {config.platform}")
    try:
        platform = make_platform(config)
    except Exception as e:  # noqa: BLE001
        print(f"[FAIL] cannot build the platform: {type(e).__name__}: {e}")
        return 1
    return check(platform, a.challenge or os.environ.get("CTF_CHALLENGE_ID") or None,
                 a.submit, reach=not a.no_reach)


if __name__ == "__main__":
    raise SystemExit(main())
