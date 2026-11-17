"""Day-of configurability: the settings file, pluggable platform adapter, and
the model adapter adjusting to an endpoint's parameter rules."""

import os
from types import SimpleNamespace

import pytest

from harness.config import Config, config_from_env, make_platform
from harness.envfile import DEFAULT_FILE, load_env_file
from harness.inference.base import Message, ModelError, ModelSpec
from harness.inference.openai_client import OpenAIModel, is_context_overflow
from harness.platforms.base import PlatformError
from harness.platforms.starter_kit import StarterKitPlatform


def _write(tmp_path, text):
    p = tmp_path / "contest.env"
    p.write_text(text)
    return p


def test_env_file_sets_defaults_but_real_env_wins(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_FAST_MODEL", "from-real-env")
    monkeypatch.delenv("CTF_TOTAL_SECONDS", raising=False)
    monkeypatch.delenv("CTF_FLAG_REGEX", raising=False)
    f = _write(tmp_path, "# comment\nCTF_FAST_MODEL=from-file\n"
                         "CTF_TOTAL_SECONDS=3300   # under the limit\n"
                         'export CTF_FLAG_REGEX="CTF\\{[0-9a-f]{64}\\}"\nnot a setting\n')
    applied = load_env_file(f)
    try:
        assert os.environ["CTF_FAST_MODEL"] == "from-real-env"
        assert applied == {"CTF_TOTAL_SECONDS": "3300",
                           "CTF_FLAG_REGEX": "CTF\\{[0-9a-f]{64}\\}"}
    finally:
        for k in applied:
            os.environ.pop(k, None)


def test_env_file_maps_differently_named_organizer_variables(tmp_path, monkeypatch):
    monkeypatch.setenv("LLM_ENDPOINT", "http://10.0.0.5:8000")
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    f = _write(tmp_path, "OPENAI_BASE_URL=${LLM_ENDPOINT}/v1\nOPENAI_API_KEY=${NOT_PROVIDED}\n")
    applied = load_env_file(f)
    try:
        assert applied == {"OPENAI_BASE_URL": "http://10.0.0.5:8000/v1"}
        assert "OPENAI_API_KEY" not in os.environ      # unset source: leave it unset
    finally:
        os.environ.pop("OPENAI_BASE_URL", None)


def test_config_from_env_reads_the_settings_file(tmp_path, monkeypatch):
    for k in ("CTF_BACKEND", "CTF_FAST_MODEL", "CTF_MAX_OUTPUT_TOKENS"):
        monkeypatch.delenv(k, raising=False)
    f = _write(tmp_path, "CTF_BACKEND=openai\nCTF_FAST_MODEL=qwen\nCTF_MAX_OUTPUT_TOKENS=8192\n")
    monkeypatch.setenv("CTF_ENV_FILE", str(f))
    try:
        cfg = config_from_env()
        assert (cfg.inference_backend, cfg.fast_model, cfg.max_output_tokens) == ("openai", "qwen", 8192)
    finally:
        for k in ("CTF_BACKEND", "CTF_FAST_MODEL", "CTF_MAX_OUTPUT_TOKENS"):
            os.environ.pop(k, None)


def test_env_file_can_be_disabled_and_missing_is_fine(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_ENV_FILE", "")
    assert load_env_file() == {}
    assert load_env_file(tmp_path / "nope.env") == {}


def test_shipped_settings_file_parses_and_only_enables_safe_defaults(monkeypatch):
    for k in ("CTF_BACKEND", "CTF_LOG_MIRROR", "CTF_WORK_ROOT", "CTF_RUN_DIR", "CTF_MODEL_TIMEOUT"):
        monkeypatch.delenv(k, raising=False)
    applied = load_env_file(DEFAULT_FILE)
    try:
        assert applied == {"CTF_BACKEND": "openai", "CTF_LOG_MIRROR": "1",
                           "CTF_WORK_ROOT": "/tmp/ctf-work", "CTF_RUN_DIR": "/var/tmp/ctf-logs",
                           # measured in the final round: GLM p99 turn 132 s
                           "CTF_MODEL_TIMEOUT": "180"}
    finally:
        for k in applied:
            os.environ.pop(k, None)


def test_platform_adapter_loads_by_module_path():
    plat = make_platform(Config(platform="harness.platforms.starter_kit:StarterKitPlatform"))
    assert isinstance(plat, StarterKitPlatform)
    with pytest.raises(PlatformError):            # unfilled skeleton fails loudly, not silently
        plat.list_challenges()
    with pytest.raises(ValueError, match="cannot load platform"):
        make_platform(Config(platform="harness.platforms.nope:Missing"))


class _Client:
    """Fake chat-completions client that rejects given parameters like OpenAI's
    reasoning models do."""
    def __init__(self, reject):
        self.reject, self.sent = reject, []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))
    def _create(self, **kw):
        self.sent.append(kw)
        for name, msg in self.reject.items():
            if name in kw:
                raise RuntimeError(msg)
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="ok", tool_calls=None),
                                     finish_reason="stop")],
            usage=SimpleNamespace(prompt_tokens=3, completion_tokens=1, prompt_tokens_details=None))


def test_adapter_switches_parameters_the_endpoint_rejects():
    OpenAIModel._mct_models.clear()
    OpenAIModel._fixed_sampling_models.clear()
    reject = {
        "max_tokens": "Unsupported parameter: 'max_tokens' is not supported with this "
                      "model. Use 'max_completion_tokens' instead.",
        "temperature": "Unsupported value: 'temperature' does not support 0.2 with this "
                       "model. Only the default (1) value is supported.",
    }
    client = _Client(reject)
    spec = ModelSpec(name="reasoner", max_tokens=4096, temperature=0.2)
    assert OpenAIModel(spec, client=client).complete([Message("user", "hi")]).text == "ok"
    assert len(client.sent) == 3
    assert client.sent[-1]["max_completion_tokens"] == 4096
    assert "max_tokens" not in client.sent[-1] and "temperature" not in client.sent[-1]
    # a fresh adapter for the same model (one is built per attempt) goes straight there
    again = _Client(reject)
    OpenAIModel(spec, client=again).complete([Message("user", "hi")])
    assert len(again.sent) == 1
    OpenAIModel._mct_models.clear()
    OpenAIModel._fixed_sampling_models.clear()


def test_other_endpoint_errors_still_surface():
    client = _Client({"model": "429 rate limit exceeded"})
    with pytest.raises(ModelError, match="429"):
        OpenAIModel(ModelSpec(name="m"), client=client).complete([Message("user", "hi")])
    assert len(client.sent) == 1
    # an oversized max_tokens is a settings problem, not a reason to drop history
    assert not is_context_overflow("max_tokens is too large: 32768. This model supports at most 16384")
