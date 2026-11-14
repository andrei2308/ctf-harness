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
    base.close()
    return results


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
    # Usage reporting is a warning; everything else must pass for a run to work.
    blocking = [r for r in results if not r[1] and not r[0].startswith("2.")]
    print("\n" + ("Ready: a run can start." if not blocking
                  else f"NOT ready: {len(blocking)} check(s) failed."))
    return 1 if blocking else 0


if __name__ == "__main__":
    raise SystemExit(main())
