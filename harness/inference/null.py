"""Offline models for dry-runs and tests — no network, fully deterministic.

Two flavours:
  * ScriptedModel  — returns a fixed list of ModelResponse, one per turn. Lets a
    test drive the exact tool-call / final-answer sequence it wants.
  * RuleModel       — a tiny heuristic agent: when a tool profile exposes a shell
    tool, it lists files and cats small ones, then stops. Enough to exercise the
    full loop (tool call -> observation -> grounding -> submit) against a fixture
    without any real model, so the harness plumbing is testable offline.

Neither is a solver. They exist so the scheduler/grounding/submit/logging path
can run end-to-end with zero external dependencies.
"""

from __future__ import annotations

import itertools

from .base import Effort, Message, Model, ModelResponse, ModelSpec, ToolCall, Usage


class ScriptedModel(Model):
    """Replays a predefined sequence of responses. Raises if it runs dry."""

    def __init__(self, responses: list[ModelResponse], spec: ModelSpec | None = None):
        super().__init__(spec or ModelSpec(name="scripted", effort=Effort.LOW))
        self._responses = list(responses)
        self._i = 0

    def complete(self, messages: list[Message], tools: list[dict] | None = None) -> ModelResponse:
        if self._i >= len(self._responses):
            # Default terminal response so a loop can't spin forever in a test.
            return ModelResponse(text="(script exhausted)", stop_reason="end", spec=self.spec)
        resp = self._responses[self._i]
        self._i += 1
        # Attach a nominal usage so budget accounting has something to meter.
        if resp.usage == Usage():
            resp = ModelResponse(text=resp.text, tool_calls=resp.tool_calls,
                                 usage=Usage(input=50, output=20),
                                 stop_reason=resp.stop_reason or "turn", spec=self.spec)
        return resp


class RuleModel(Model):
    """A no-LLM heuristic that explores files via a shell tool.

    Strategy, in order:
      1. If we have not yet listed files, call the shell tool with a recursive
         listing.
      2. For each regular file seen in a listing, cat it once (small files).
      3. When nothing new to do, stop with a short summary.

    It never fabricates a flag — it only runs tools. Grounding + submit happen
    above it from real observations, exactly as with a real model. Good enough to
    "solve" a fixture whose flag sits in a readable file.
    """

    _ids = itertools.count(1)

    def __init__(self, shell_tool: str = "shell", spec: ModelSpec | None = None,
                 max_files: int = 25):
        super().__init__(spec or ModelSpec(name="rule", effort=Effort.LOW))
        self._shell = shell_tool
        self._listed = False
        self._to_cat: list[str] = []
        self._catted: set[str] = set()
        self._max_files = max_files

    def _call(self, cmd: str) -> ModelResponse:
        return ModelResponse(
            tool_calls=(ToolCall(id=f"c{next(self._ids)}", name=self._shell,
                                 arguments={"cmd": cmd}),),
            usage=Usage(input=80, output=15), stop_reason="tool", spec=self.spec)

    def complete(self, messages: list[Message], tools: list[dict] | None = None) -> ModelResponse:
        # Harvest filenames from the most recent tool observations.
        for m in messages:
            if m.role == "tool" and m.content:
                for line in m.content.splitlines():
                    line = line.strip()
                    if line and "/" in line and line not in self._catted:
                        if line not in self._to_cat and len(self._to_cat) < self._max_files:
                            self._to_cat.append(line)

        if not self._listed:
            self._listed = True
            return self._call("find . -maxdepth 4 -type f 2>/dev/null | head -50")

        while self._to_cat:
            target = self._to_cat.pop(0)
            if target in self._catted:
                continue
            self._catted.add(target)
            return self._call(f"cat -- {target!r} 2>/dev/null | head -c 4096")

        return ModelResponse(text="explored all files; no further actions",
                             usage=Usage(input=40, output=10),
                             stop_reason="end", spec=self.spec)
