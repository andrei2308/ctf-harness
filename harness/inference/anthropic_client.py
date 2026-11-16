"""Anthropic Messages API adapter.

Lazy-imports the SDK so the harness imports fine in environments without it (e.g.
the offline sandbox during unit tests). Translates our vendor-neutral Message /
tool-schema types to the Messages API and normalises tool calls + token usage
back out. Maps our Effort rung onto extended-thinking budget.

The model/endpoint the organizers provide is OPEN; if they hand us an
Anthropic-compatible endpoint, point base_url/api_key at it via env. We never
bake a key into the submission — it is read from the environment at run time.
"""

from __future__ import annotations

import os

from .base import (ContextOverflow, Effort, Message, Model, ModelError,
                   ModelResponse, ModelSpec, ToolCall, Usage)

# Rough thinking-token budget per effort rung. Tuned once real limits are known.
_THINK_BUDGET = {Effort.LOW: 0, Effort.MEDIUM: 4000, Effort.HIGH: 12000, Effort.MAX: 32000}


class AnthropicModel(Model):
    def __init__(self, spec: ModelSpec, *, api_key: str | None = None,
                 base_url: str | None = None, client=None):
        super().__init__(spec)
        self._client = client  # injectable for tests
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self._base_url = base_url or os.environ.get("ANTHROPIC_BASE_URL")

    def _ensure_client(self):
        if self._client is not None:
            return self._client
        try:
            import anthropic  # noqa: F401
        except ImportError as e:  # pragma: no cover
            raise ModelError("anthropic SDK not installed; `pip install anthropic`") from e
        kwargs = {"max_retries": 1,
                  "timeout": float(os.environ.get("CTF_MODEL_TIMEOUT") or 300)}
        if self._api_key:
            kwargs["api_key"] = self._api_key
        if self._base_url:
            kwargs["base_url"] = self._base_url
        self._client = anthropic.Anthropic(**kwargs)
        return self._client

    @staticmethod
    def _split(messages: list[Message]) -> tuple[str, list[dict]]:
        """Pull out the system prompt; convert the rest to Messages API blocks."""
        system_parts: list[str] = []
        api_msgs: list[dict] = []
        for m in messages:
            if m.role == "system":
                system_parts.append(m.content)
            elif m.role == "tool":
                block = {"type": "tool_result", "tool_use_id": m.tool_call_id or "",
                         "content": m.content or "(no output)"}
                # All results for one assistant turn go in a single user message.
                prev = api_msgs[-1] if api_msgs else None
                if (prev and prev["role"] == "user" and isinstance(prev["content"], list)
                        and prev["content"] and prev["content"][0].get("type") == "tool_result"):
                    prev["content"].append(block)
                else:
                    api_msgs.append({"role": "user", "content": [block]})
            elif m.role == "assistant" and m.tool_calls:
                blocks: list[dict] = []
                if m.content:
                    blocks.append({"type": "text", "text": m.content})
                for tc in m.tool_calls:
                    blocks.append({"type": "tool_use", "id": tc.id, "name": tc.name,
                                   "input": tc.arguments})
                api_msgs.append({"role": "assistant", "content": blocks})
            else:
                # The API rejects empty text content.
                text = m.content or "(no text)"
                if m.images:
                    text += ("\n[The image is not shown: this adapter does not send images. "
                             "Inspect it with tools instead.]")
                api_msgs.append({"role": m.role, "content": text})
        return "\n\n".join(p for p in system_parts if p), api_msgs

    def complete(self, messages: list[Message], tools: list[dict] | None = None) -> ModelResponse:
        client = self._ensure_client()
        system, api_msgs = self._split(messages)
        kwargs: dict = {
            "model": self.spec.name,
            "max_tokens": self.spec.max_tokens,
            "messages": api_msgs,
        }
        if system:
            kwargs["system"] = system
        if self.spec.temperature is not None:
            kwargs["temperature"] = self.spec.temperature
        if self.spec.top_p is not None:
            kwargs["top_p"] = self.spec.top_p
        if tools:
            # Our tool schema already matches the Messages API shape
            # (name/description/input_schema); pass through.
            kwargs["tools"] = tools
        budget = _THINK_BUDGET.get(self.spec.effort, 0)
        if budget:
            kwargs["thinking"] = {"type": "enabled", "budget_tokens": budget}

        try:
            resp = client.messages.create(**kwargs)
        except Exception as e:  # pragma: no cover - vendor exceptions
            msg = str(e).lower()
            if "context" in msg and ("long" in msg or "exceed" in msg or "maximum" in msg):
                raise ContextOverflow(str(e)) from e
            raise ModelError(str(e)) from e

        text_parts: list[str] = []
        tool_calls: list[ToolCall] = []
        for block in getattr(resp, "content", []) or []:
            btype = getattr(block, "type", None)
            if btype == "text":
                text_parts.append(getattr(block, "text", ""))
            elif btype == "tool_use":
                tool_calls.append(ToolCall(
                    id=getattr(block, "id", ""),
                    name=getattr(block, "name", ""),
                    arguments=dict(getattr(block, "input", {}) or {}),
                ))
        u = getattr(resp, "usage", None)
        usage = Usage(
            input=getattr(u, "input_tokens", 0) or 0,
            output=getattr(u, "output_tokens", 0) or 0,
            cached_in=getattr(u, "cache_read_input_tokens", 0) or 0,
        ) if u else Usage()
        return ModelResponse(
            text="".join(text_parts),
            tool_calls=tuple(tool_calls),
            usage=usage,
            stop_reason=getattr(resp, "stop_reason", "") or "",
            spec=self.spec,
        )
