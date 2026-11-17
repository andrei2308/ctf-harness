"""Preflight: can this harness talk to the model endpoint it is configured for?

    python -m harness.preflight            # uses the same env as a real run

Run it the moment the organizers publish the endpoint, model id and limits, and
again inside the built image. It sends a handful of tiny requests through the
SAME adapter and ladder a run uses and reports, per check, what failed and which
setting fixes it. Costs a few hundred tokens. Exit code 0 means a run can start.
"""

from __future__ import annotations

import os
import sys
import time

from .config import Config, config_from_env, make_model_factory
from .inference.base import Message, ModelError, ToolCall

_TOOL = [{
    "name": "shell",
    "description": "Run a bash command and return its output.",
    "input_schema": {"type": "object",
                     "properties": {"cmd": {"type": "string"}}, "required": ["cmd"]},
}]


def _host(url: str | None) -> str:
    return url.split("//", 1)[-1].split("/", 1)[0] if url else "(SDK default)"


def describe(config: Config) -> list[str]:
    """What the run would use. Never prints a key, only whether one is set."""
    backend = config.inference_backend
    lines = [f"backend        {backend}"]
    if backend == "openai":
        lines += [f"endpoint       {_host(os.environ.get('OPENAI_BASE_URL'))}"
                  f"   (OPENAI_BASE_URL)",
                  f"api key        {'set' if os.environ.get('OPENAI_API_KEY') else 'NOT SET'}"
                  f"   (OPENAI_API_KEY)"]
    elif backend == "anthropic":
        lines += [f"endpoint       {_host(os.environ.get('ANTHROPIC_BASE_URL'))}"
                  f"   (ANTHROPIC_BASE_URL)",
                  f"api key        {'set' if os.environ.get('ANTHROPIC_API_KEY') else 'NOT SET'}"
                  f"   (ANTHROPIC_API_KEY)"]
    lines.append(f"model          {config.fast_model}   (CTF_FAST_MODEL)"
                 + (f", strong: {config.strong_model}" if config.strong_model else ""))
    caps = config.caps
    lines.append(f"token cap      {caps.total_tokens or 'none'}   (CTF_TOTAL_TOKENS)")
    lines.append(f"time cap       {caps.total_seconds or 'none'}   (CTF_TOTAL_SECONDS)")
    return lines


def run(config: Config, model_factory=None) -> list[tuple[str, bool, str]]:
    """Run the checks. Returns (name, passed, detail) per check, in order."""
    factory = model_factory or make_model_factory(config)
    ladder = config.ladder()
    results: list[tuple[str, bool, str]] = []

    def attempt(name, fn, hint=""):
        t0 = time.monotonic()
        try:
            detail = fn()
            results.append((name, True, f"{detail}  [{time.monotonic() - t0:.1f}s]"))
            return True
        except Exception as e:  # noqa: BLE001 - report every failure, never crash
            results.append((name, False, f"{str(e)[:400]}{'  -> ' + hint if hint else ''}"))
            return False

    base = factory(ladder.rung(0).spec)
    sys_msg = Message("system", "You are a connectivity test. Follow instructions exactly.")

    def plain():
        r = base.complete([sys_msg, Message("user", "Reply with the single word: ready")], None)
        if not (r.text or "").strip():
            raise ModelError("the model returned no text")
        plain.usage = r.usage
        return f"reply: {r.text.strip()[:40]!r}"

    if not attempt("1. reach the endpoint and get a reply", plain,
                   "check the base URL, API key and model id"):
        return results

    u = plain.usage
    results.append(("2. token usage is reported", u.input > 0 and u.output > 0,
                    f"input={u.input} output={u.output}"
                    + ("" if u.input > 0 and u.output > 0 else
                       "  -> the endpoint returns no usage, so token caps will never "
                       "trigger; rely on CTF_TOTAL_SECONDS")))

    state: dict = {}

    def tool_call():
        msgs = [sys_msg, Message("user", "Call the shell tool with cmd set to: echo preflight")]
        r = base.complete(msgs, _TOOL)
        if not r.tool_calls:
            raise ModelError(f"no tool call came back (text: {r.text[:120]!r})")
        tc: ToolCall = r.tool_calls[0]
        if tc.name != "shell" or "cmd" not in tc.arguments:
            raise ModelError(f"malformed tool call: {tc.name} {tc.arguments}")
        state["msgs"] = msgs + [Message("assistant", r.text, tool_calls=r.tool_calls)] + [
            Message("tool", "preflight", tool_call_id=c.id, name=c.name) for c in r.tool_calls]
        return f"called {tc.name}({tc.arguments})"

    if attempt("3. the model makes a tool call", tool_call,
               "the endpoint/model must support OpenAI-style tool (function) calling; "
               "the harness cannot work without it"):
        attempt("4. a tool result is accepted back",
                lambda: "reply: %r" % (base.complete(state["msgs"], _TOOL).text or "(tool call)")[:60])

    seen = set()
    for i, rung in enumerate(ladder.rungs):
        key = (rung.spec.name, rung.spec.max_tokens, rung.spec.temperature)
        if key in seen:
            continue
        seen.add(key)
        m = factory(rung.spec)
        attempt(f"5. rung {i}: {rung.spec.name}, max_tokens={rung.spec.max_tokens}, "
                f"temperature={rung.spec.temperature}",
                lambda m=m: "accepted" if m.complete(
                    [sys_msg, Message("user", "Reply with: ok")], None) else "accepted",
                "lower CTF_MAX_OUTPUT_TOKENS to what the model allows")
        m.close()
    def room_to_act():
        # A task that invites some thinking, at rung 0's output cap. A reasoning
        # model that spends the cap on hidden thought returns nothing here.
        r = base.complete([sys_msg, Message("user", (
            "You are starting a reverse-engineering CTF challenge. The working "
            "directory holds `chall` (unknown type) and `output.txt`. Think about "
            "what you need to learn first, then call the shell tool with the ONE "
            "command that tells you the most."))], _TOOL)
        cap = ladder.rung(0).spec.max_tokens
        note = (f"; reasoning model ({r.reasoning_tokens} hidden tokens of {r.usage.output} "
                f"output, cap {cap})" if r.reasoning_tokens else "")
        if r.stop_reason == "length" and not r.tool_calls and not (r.text or "").strip():
            raise ModelError(f"cut off at max_tokens={cap} with nothing produced{note}")
        if not r.tool_calls:
            return f"replied in text without a tool call (the solver nudges this){note}"
        return f"acted within the cap{note}"

    attempt(f"6. the model can act within rung 0's output cap "
            f"({ladder.rung(0).spec.max_tokens})", room_to_act,
            "set CTF_MIN_OUTPUT_TOKENS=8192 or higher; the solver also doubles the "
            "cap after a cut-off turn, but each one wastes a full turn of tokens")

    def sees_images():
        # A 64x64 solid red square. An adapter that learns the model rejects
        # images falls back to text and remembers it; that is the signal here.
        r = base.complete([sys_msg, Message(
            "user", "What colour is the square in the image? Answer with one word.",
            images=(_red_square(),))], None)
        blind = base.spec.name in getattr(type(base), "_no_vision_models", ())
        answer = (r.text or "").strip()[:40]
        if blind:
            raise ModelError("the model rejected image input")
        if "red" not in answer.lower():
            raise ModelError(f"took the image but answered {answer!r}, not 'red'")
        return f"read the image: {answer!r}"

    attempt("7. the model can look at images (view_image)", sees_images,
            "not fatal: view_image falls back to text. Set CTF_VISION=0 to drop the "
            "tool, and expect handwriting, QR-in-photo and stereogram tasks to go slowly")

    base.close()
    return results


def _red_square(side: int = 64) -> str:
    """A solid red PNG as a data: URL, built without Pillow."""
    import base64
    import struct
    import zlib

    def chunk(kind: bytes, data: bytes) -> bytes:
        body = kind + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))

    raw = (b"\x00" + b"\xff\x00\x00" * side) * side
    png = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", side, side, 8, 2, 0, 0, 0))
           + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))
    return "data:image/png;base64," + base64.b64encode(png).decode()


def main(argv: list[str] | None = None) -> int:
    config = config_from_env()
    print("Configuration this run would use:")
    for line in describe(config):
        print("  " + line)
    if config.inference_backend in ("rule", "null"):
        print("\nBackend is the offline rule model: nothing to check. "
              "Set CTF_BACKEND=openai to test a real endpoint.")
        return 0
    print("\nChecks:")
    results = run(config)
    for name, ok, detail in results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}\n         {detail}")
    # Usage reporting and vision are warnings; everything else must pass for a
    # run to work.
    blocking = [r for r in results if not r[1] and not r[0].startswith(("2.", "7."))]
    print("\n" + ("Ready: a run can start." if not blocking
                  else f"NOT ready: {len(blocking)} check(s) failed."))
    return 1 if blocking else 0


if __name__ == "__main__":
    raise SystemExit(main())
