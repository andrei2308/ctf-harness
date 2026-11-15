"""OpenAI-compatible Chat Completions adapter.

Covers the common case where the organizers expose an OpenAI-compatible endpoint
(many local servers — vLLM, llama.cpp, LM Studio, TGI — speak this). Lazy-imports
the SDK. Translates our Message/tool types to chat-completions tool-calling and
normalises the function-call + usage back out. base_url/api_key come from env at
run time, never from the submission.
"""

from __future__ import annotations

import json
import os

from .base import (ContextOverflow, Effort, Message, Model, ModelError,
                   ModelResponse, ModelSpec, ToolCall, Usage)

# Some backends accept a reasoning_effort string; map our rung onto it. Harmless
# on backends that ignore unknown fields (we drop it if the call rejects it).
_EFFORT_STR = {Effort.LOW: "low", Effort.MEDIUM: "medium", Effort.HIGH: "high", Effort.MAX: "high"}


_OVERFLOW_PHRASES = (
    "context length", "context_length", "context window", "maximum context",
    "too long", "too many tokens", "reduce the length", "exceeds the model",
    "maximum input length",
)


def is_context_overflow(error_text: str) -> bool:
    """Does this endpoint error mean the request was too big? Matched on specific
    phrases: a bare "context" also appears in unrelated errors ("context deadline
    exceeded" from a proxy), and compacting on those throws history away."""
    msg = error_text.lower()
    return any(p in msg for p in _OVERFLOW_PHRASES)


def _raw_args(arguments: dict):
    """Arguments exactly as the model sent them: unparseable JSON was kept under
    `_raw`, so echo that string back rather than a wrapper it never wrote."""
    if set(arguments) == {"_raw"} and isinstance(arguments["_raw"], str):
        return arguments["_raw"]
    return arguments


class OpenAIModel(Model):
    _mct_models: set[str] = set()             # models that want max_completion_tokens
    _fixed_sampling_models: set[str] = set()  # models that refuse temperature/top_p

    def __init__(self, spec: ModelSpec, *, api_key: str | None = None,
                 base_url: str | None = None, client=None, send_effort: bool = False):
        super().__init__(spec)
        self._client = client
        self._api_key = api_key or os.environ.get("OPENAI_API_KEY") or "not-needed"
        self._base_url = base_url or os.environ.get("OPENAI_BASE_URL")
        self._send_effort = send_effort
        # Learned from the endpoint's own errors (see complete): some models take
        # max_completion_tokens instead of max_tokens, or refuse a temperature.
        self._use_completion_tokens = False
        self._drop_sampling = False

    def _ensure_client(self):
        if self._client is not None:
            return self._client
        try:
            import openai  # noqa: F401
        except ImportError as e:  # pragma: no cover
            raise ModelError("openai SDK not installed; `pip install openai`") from e
        # One request must not hang a slot: the SDK default is 10 minutes with
        # its own retries on top. The solver does the backing off.
        kwargs = {"api_key": self._api_key, "max_retries": 1,
                  "timeout": float(os.environ.get("CTF_MODEL_TIMEOUT") or 300)}
        if self._base_url:
            kwargs["base_url"] = self._base_url
        self._client = openai.OpenAI(**kwargs)
        return self._client

    @staticmethod
    def _to_chat(messages: list[Message]) -> list[dict]:
        out: list[dict] = []
        for m in messages:
            if m.role == "tool":
                out.append({"role": "tool", "tool_call_id": m.tool_call_id or "",
                            "content": m.content})
            elif m.role == "assistant" and m.tool_calls:
                out.append({
                    "role": "assistant", "content": m.content or "",
                    "tool_calls": [{
                        "id": tc.id, "type": "function",
                        "function": {"name": tc.name,
                                     "arguments": json.dumps(_raw_args(tc.arguments))},
                    } for tc in m.tool_calls],
                })
            else:
                out.append({"role": m.role, "content": m.content})
        return out

    @staticmethod
    def _to_tools(tools: list[dict] | None) -> list[dict] | None:
        """Our tool schema is {name, description, input_schema}; wrap into the
        chat-completions {type:function, function:{...parameters}} shape."""
        if not tools:
            return None
        wrapped = []
        for t in tools:
            wrapped.append({
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t.get("description", ""),
                    "parameters": t.get("input_schema", {"type": "object", "properties": {}}),
                },
            })
        return wrapped

    def complete(self, messages: list[Message], tools: list[dict] | None = None) -> ModelResponse:
        client = self._ensure_client()
        kwargs: dict = {
            "model": self.spec.name,
            "messages": self._to_chat(messages),
        }
        cls = type(self)
        use_mct = self._use_completion_tokens or self.spec.name in cls._mct_models
        drop_sampling = self._drop_sampling or self.spec.name in cls._fixed_sampling_models
        kwargs["max_completion_tokens" if use_mct else "max_tokens"] = self.spec.max_tokens
        if not drop_sampling:
            if self.spec.temperature is not None:
                kwargs["temperature"] = self.spec.temperature
            if self.spec.top_p is not None:
                kwargs["top_p"] = self.spec.top_p
        wrapped = self._to_tools(tools)
        if wrapped:
            kwargs["tools"] = wrapped
        if self._send_effort:
            kwargs["reasoning_effort"] = _EFFORT_STR.get(self.spec.effort, "low")

        try:
            resp = client.chat.completions.create(**kwargs)
        except Exception as e:
            text = str(e).lower()
            # Parameter-shape rejections: remember per model and retry once. A new
            # adapter is built per attempt, so the memory lives on the class.
            if "max_completion_tokens" in text and not use_mct:
                cls._mct_models.add(self.spec.name)
                return self.complete(messages, tools)
            if ("temperature" in text or "top_p" in text) and not drop_sampling and (
                    "unsupported" in text or "not support" in text or "only the default" in text):
                cls._fixed_sampling_models.add(self.spec.name)
                return self.complete(messages, tools)
            if is_context_overflow(str(e)):
                raise ContextOverflow(str(e)) from e
            raise ModelError(str(e)) from e

        choice = resp.choices[0]
        msg = choice.message
        tool_calls: list[ToolCall] = []
        for n, tc in enumerate(getattr(msg, "tool_calls", None) or []):
            fn = tc.function
            try:
                args = json.loads(fn.arguments) if fn.arguments else {}
            except (json.JSONDecodeError, TypeError):
                args = {"_raw": fn.arguments}
            if not isinstance(args, dict):
                args = {"_raw": fn.arguments}
            # Some local servers omit the id; the result must still pair with it.
            tool_calls.append(ToolCall(id=tc.id or f"call_{len(messages)}_{n}",
                                       name=fn.name, arguments=args))

        u = getattr(resp, "usage", None)
        cached = 0
        if u is not None:
            details = getattr(u, "prompt_tokens_details", None)
            cached = getattr(details, "cached_tokens", 0) or 0
        usage = Usage(
            input=getattr(u, "prompt_tokens", 0) or 0,
            output=getattr(u, "completion_tokens", 0) or 0,
            cached_in=cached,
        ) if u else Usage()
        reasoning = getattr(getattr(u, "completion_tokens_details", None),
                            "reasoning_tokens", 0) or 0
        if not reasoning:
            # Endpoints that return the reasoning as text instead of a count.
            hidden = getattr(msg, "reasoning_content", None) or getattr(msg, "reasoning", None)
            if isinstance(hidden, str):
                reasoning = len(hidden) // 4
        return ModelResponse(
            text=msg.content or "",
            tool_calls=tuple(tool_calls),
            usage=usage,
            stop_reason=choice.finish_reason or "",
            spec=self.spec,
            reasoning_tokens=int(reasoning),
        )
