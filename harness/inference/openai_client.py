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
import time

from .base import (ContextOverflow, Effort, Message, Model, ModelError,
                   ModelResponse, ModelSpec, ModelTimeout, ToolCall, Usage, is_timeout)

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


def default_headers() -> dict[str, str]:
    """Headers for every model call, from CTF_MODEL_HEADERS (`Name=value`, more
    than one separated by `;`). A gateway that identifies the run by a header
    (AISafe: X-Run-Token) is reached this way."""
    out = {}
    for part in os.environ.get("CTF_MODEL_HEADERS", "").split(";"):
        name, sep, value = part.partition("=")
        if sep and name.strip() and value.strip():
            out[name.strip()] = value.strip()
    return out


class _Busy(Exception):
    """The endpoint asked us to wait (429, or a quick 503) and said how long."""

    def __init__(self, wait: float, text: str):
        super().__init__(text)
        self.wait = wait


def _status(exc: BaseException) -> tuple[int | None, float]:
    """(HTTP status, Retry-After seconds or 0) of an SDK error, when it has them."""
    status = getattr(exc, "status_code", None)
    headers = getattr(getattr(exc, "response", None), "headers", None) or {}
    try:
        retry = float(headers.get("retry-after") or 0)
    except (TypeError, ValueError):
        retry = 0.0
    return (status if isinstance(status, int) else None), retry


_sleep = time.sleep


def _raw_args(arguments: dict):
    """Arguments exactly as the model sent them: unparseable JSON was kept under
    `_raw`, so echo that string back rather than a wrapper it never wrote."""
    if set(arguments) == {"_raw"} and isinstance(arguments["_raw"], str):
        return arguments["_raw"]
    return arguments


class OpenAIModel(Model):
    _no_vision_models: set[str] = set()       # models that rejected image input
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
        # max_retries=0: the SDK retries a TIMEOUT too, which doubles the time a
        # capped request can take. The solver retries with backoff and re-reads
        # the time left before each try.
        kwargs = {"api_key": self._api_key, "max_retries": 0,
                  "timeout": float(os.environ.get("CTF_MODEL_TIMEOUT") or 300)}
        if self._base_url:
            kwargs["base_url"] = self._base_url
        headers = default_headers()
        if headers:
            kwargs["default_headers"] = headers
        self._client = openai.OpenAI(**kwargs)
        return self._client

    @staticmethod
    def _to_chat(messages: list[Message], vision: bool = True) -> list[dict]:
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
            elif m.images and vision:
                out.append({"role": m.role, "content": [{"type": "text", "text": m.content}] + [
                    {"type": "image_url", "image_url": {"url": u}} for u in m.images]})
            elif m.images:
                out.append({"role": m.role, "content": m.content + (
                    "\n[The image is not shown: this model does not accept images. "
                    "Inspect it with tools instead (OCR, rendering it as text, zbarimg).]")})
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
        """One turn. A "busy" answer (429, or a 503 that came back quickly) is
        waited out here for as long as the endpoint asks, up to
        CTF_MODEL_BUSY_WAIT seconds (default 300) and never past the time this
        request was given: on the contest gateway that waiting is not a failure
        and its time is handed back to the run."""
        waited = 0.0
        limit = float(os.environ.get("CTF_MODEL_BUSY_WAIT") or 300)
        while True:
            try:
                return self._complete(messages, tools)
            except _Busy as b:
                room = self.request_timeout
                if waited + b.wait > limit or (room is not None and waited + b.wait >= room - 5):
                    raise ModelError(str(b)) from b
                waited += b.wait
                _sleep(b.wait)

    def _complete(self, messages: list[Message], tools: list[dict] | None = None) -> ModelResponse:
        client = self._ensure_client()
        cls = type(self)
        has_images = any(m.images for m in messages)
        vision = self.spec.name not in cls._no_vision_models
        kwargs: dict = {
            "model": self.spec.name,
            "messages": self._to_chat(messages, vision=vision),
        }
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

        t0 = time.monotonic()
        try:
            extra = {}
            if self.request_timeout is not None:
                extra["timeout"] = min(self.request_timeout,
                                       float(os.environ.get("CTF_MODEL_TIMEOUT") or 300))
            resp = client.chat.completions.create(**kwargs, **extra)
        except Exception as e:
            text = str(e).lower()
            status, retry_after = _status(e)
            if os.environ.get("CTF_GATEWAY_STATUS") == "1" and status in (402, 409):
                # The contest gateway: the run's cost cap is used up (402), or
                # the run has ended (409). Asking again cannot help.
                from ..scheduler.budget import RunEnded
                raise RunEnded("cost cap reached (402)" if status == 402
                               else "the run has ended (409)") from e
            if status == 503 and time.monotonic() - t0 >= 100:
                # The gateway cuts a call at 3 minutes, usually because the
                # model kept reasoning: the same handling as our own timeout.
                raise ModelTimeout(f"503 after {time.monotonic() - t0:.0f}s: {e}") from e
            if status in (429, 503):
                raise _Busy(min(60.0, max(2.0, retry_after or 5.0)),
                            f"{status} busy: {e}") from e
            # Parameter-shape rejections: remember per model and retry once. A new
            # adapter is built per attempt, so the memory lives on the class.
            if "max_completion_tokens" in text and not use_mct:
                cls._mct_models.add(self.spec.name)
                return self._complete(messages, tools)
            if ("temperature" in text or "top_p" in text) and not drop_sampling and (
                    "unsupported" in text or "not support" in text or "only the default" in text):
                cls._fixed_sampling_models.add(self.spec.name)
                return self._complete(messages, tools)
            # A model without vision rejects image parts (seen: glm-5.3 answers
            # 400 "messages.content.type is invalid, allowed values: ['text']").
            # Remember it and resend with the images described in text.
            if has_images and vision and ("image" in text or "content.type" in text
                                          or "content type" in text):
                cls._no_vision_models.add(self.spec.name)
                return self._complete(messages, tools)
            if is_context_overflow(str(e)) or (
                    status == 400 and os.environ.get("CTF_GATEWAY_STATUS") == "1"):
                # The gateway answers 400 for a conversation longer than the
                # model's context, in the provider's words, whatever they are.
                raise ContextOverflow(str(e)) from e
            if is_timeout(e):
                raise ModelTimeout(str(e)) from e
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
