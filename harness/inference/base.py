"""Model / inference interface.

Solvers never import a vendor SDK. They receive a `Model` and call `.complete()`.
This lets us wire whatever the organizers provide (OpenAI-compatible, Anthropic,
a local endpoint) without touching solver or scheduler code, and lets the
escalation ladder swap models/effort by swapping the `Model` instance.

Token accounting is reported back on every response so the budget layer can meter
spend precisely (input + output, and cached input separately when the provider
distinguishes it).
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from enum import IntEnum


class Effort(IntEnum):
    """Reasoning-effort rungs, provider-agnostic. Adapters map these onto whatever
    knob the backend exposes (reasoning_effort, thinking budget, temperature, or
    nothing). Ordered so the ladder can compare/step."""

    LOW = 0
    MEDIUM = 1
    HIGH = 2
    MAX = 3


@dataclass(frozen=True)
class ModelSpec:
    """Identifies a model + how hard to make it think.

    `name` is the backend's model id. `effort` is our abstract rung. `max_tokens`
    caps a single response. Everything here is declarative so a ladder rung is
    just data; the actual client is resolved by the inference registry.
    """

    name: str
    effort: Effort = Effort.LOW
    max_tokens: int = 4096
    temperature: float | None = None
    top_p: float | None = None
    # Rough cost weights (per-1k tokens) used only for budget *estimation* and
    # ladder ordering, never billed. Filled from organizer pricing when known.
    cost_in_per_1k: float = 0.0
    cost_out_per_1k: float = 0.0

    def label(self) -> str:
        return f"{self.name}@{self.effort.name.lower()}"


@dataclass
class Usage:
    """Token counts for one call. `cached_in` is a subset of `input` the provider
    served from cache (counted separately because it is usually cheaper and the
    rules care about real spend)."""

    input: int = 0
    output: int = 0
    cached_in: int = 0

    def __add__(self, other: "Usage") -> "Usage":
        return Usage(
            input=self.input + other.input,
            output=self.output + other.output,
            cached_in=self.cached_in + other.cached_in,
        )

    @property
    def billable_in(self) -> int:
        """Input tokens that were *not* cache hits."""
        return max(0, self.input - self.cached_in)


@dataclass(frozen=True)
class ToolCall:
    """A tool invocation the model asked for, normalised across vendors."""

    id: str
    name: str
    arguments: dict


@dataclass(frozen=True)
class ModelResponse:
    """One model turn. Either text, tool calls, or both."""

    text: str = ""
    tool_calls: tuple[ToolCall, ...] = ()
    usage: Usage = field(default_factory=Usage)
    stop_reason: str = ""
    spec: ModelSpec | None = None

    @property
    def wants_tools(self) -> bool:
        return bool(self.tool_calls)


@dataclass(frozen=True)
class Message:
    """A single conversation message. `tool_results` carries observations fed back
    after a tool call; kept structured so grounding can scan real tool output."""

    role: str  # "system" | "user" | "assistant" | "tool"
    content: str = ""
    tool_call_id: str | None = None   # set when role == "tool"
    name: str | None = None           # tool name, when role == "tool"
    # Set on an assistant turn that requested tools. Every backend requires the
    # call to precede its result in the transcript, and without it the model
    # cannot see which command produced which output.
    tool_calls: tuple[ToolCall, ...] = ()


class ModelError(RuntimeError):
    """Recoverable inference failure (rate limit, transient 5xx, overload).

    Adapters raise this so the scheduler can back off / fall back a rung rather
    than killing the attempt. A context-length overflow raises ContextOverflow
    instead so the caller can compact rather than retry blindly."""


class ContextOverflow(ModelError):
    """The request exceeded the model's context window; caller should compact."""


class Model(abc.ABC):
    """A resolved, callable model at a fixed spec."""

    def __init__(self, spec: ModelSpec):
        self.spec = spec

    @abc.abstractmethod
    def complete(
        self,
        messages: list[Message],
        tools: list[dict] | None = None,
    ) -> ModelResponse:
        """Run one turn. `tools` are JSON-schema tool definitions (vendor-neutral);
        the adapter translates to the backend's tool format and normalises any
        tool calls back into ModelResponse.tool_calls."""

    def close(self) -> None:  # pragma: no cover - default no-op
        pass
