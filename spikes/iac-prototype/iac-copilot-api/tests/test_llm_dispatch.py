"""Adapter tests for services/llm_dispatch.py against static, hand-built
provider response fixtures — no network calls. Covers both the
OpenAI-compatible branch (openai/ollama/foundry/custom) and the Anthropic
branch, plus the neutral-message translation layer between them."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from services.llm_dispatch import _neutral_messages_to_anthropic, call_model


def _fake_openai_response(*, content=None, tool_calls=None):
    message = SimpleNamespace(content=content, tool_calls=tool_calls)
    choice = SimpleNamespace(message=message)
    return SimpleNamespace(choices=[choice])


def _fake_openai_tool_call(id_, name, arguments_json):
    return SimpleNamespace(id=id_, function=SimpleNamespace(name=name, arguments=arguments_json))


class _FakeOpenAIClient:
    def __init__(self, response):
        self._response = response
        self.last_kwargs = None
        self.chat = SimpleNamespace(
            completions=SimpleNamespace(create=self._create)
        )

    def _create(self, **kwargs):
        self.last_kwargs = kwargs
        return self._response


async def test_openai_compatible_text_only_response():
    fake_client = _FakeOpenAIClient(_fake_openai_response(content="hello there"))
    with patch("services.llm_dispatch._get_openai_client", return_value=fake_client):
        result = await call_model(
            [{"role": "user", "content": "hi"}],
            provider_id="openai",
            model_id="gpt-4o-mini",
            api_key="sk-test",
        )
    assert result.text_blocks == ["hello there"]
    assert result.tool_calls == []
    assert result.stop_reason == "end_turn"


async def test_openai_compatible_tool_call_response_parses_arguments():
    tool_call = _fake_openai_tool_call("tc1", "list_skills", "{}")
    fake_client = _FakeOpenAIClient(_fake_openai_response(content=None, tool_calls=[tool_call]))
    with patch("services.llm_dispatch._get_openai_client", return_value=fake_client):
        result = await call_model(
            [{"role": "user", "content": "hi"}],
            provider_id="openai",
            model_id="gpt-4o-mini",
            api_key="sk-test",
            tools=[{"name": "list_skills", "description": "d", "input_schema": {"type": "object", "properties": {}}}],
        )
    assert result.stop_reason == "tool_use"
    assert len(result.tool_calls) == 1
    assert result.tool_calls[0].name == "list_skills"
    assert result.tool_calls[0].input == {}
    # Tools get converted to OpenAI function-calling shape before being sent.
    assert fake_client.last_kwargs["tools"][0]["type"] == "function"
    assert fake_client.last_kwargs["tools"][0]["function"]["name"] == "list_skills"


async def test_ollama_uses_ollama_client_not_openai_client():
    fake_client = _FakeOpenAIClient(_fake_openai_response(content="local reply"))
    with patch("services.llm_dispatch._get_ollama_client", return_value=fake_client) as get_ollama, \
         patch("services.llm_dispatch._get_openai_client") as get_openai:
        result = await call_model(
            [{"role": "user", "content": "hi"}],
            provider_id="ollama",
            base_url="http://localhost:11434",
        )
    get_ollama.assert_called_once()
    get_openai.assert_not_called()
    assert result.text_blocks == ["local reply"]


async def test_foundry_requires_base_url():
    with pytest.raises(ValueError, match="Base URL"):
        await call_model([{"role": "user", "content": "hi"}], provider_id="foundry")


async def test_anthropic_requires_api_key():
    with patch.dict("os.environ", {}, clear=False):
        import os
        os.environ.pop("ANTHROPIC_API_KEY", None)
        with pytest.raises(ValueError, match="Anthropic API key"):
            await call_model([{"role": "user", "content": "hi"}], provider_id="anthropic")


async def test_anthropic_text_and_tool_use_response():
    fake_response = SimpleNamespace(
        is_success=True,
        json=lambda: {
            "content": [
                {"type": "text", "text": "let me check"},
                {"type": "tool_use", "id": "tc1", "name": "run_skill_script", "input": {"name": "dns-lookup"}},
            ],
            "stop_reason": "tool_use",
        },
    )
    fake_async_client = AsyncMock()
    fake_async_client.post = AsyncMock(return_value=fake_response)
    fake_async_client.__aenter__ = AsyncMock(return_value=fake_async_client)
    fake_async_client.__aexit__ = AsyncMock(return_value=False)

    with patch("services.llm_dispatch.httpx.AsyncClient", return_value=fake_async_client):
        result = await call_model(
            [{"role": "user", "content": "hi"}],
            provider_id="anthropic",
            api_key="sk-ant-test",
        )

    assert result.text_blocks == ["let me check"]
    assert result.stop_reason == "tool_use"
    assert len(result.tool_calls) == 1
    assert result.tool_calls[0].name == "run_skill_script"
    assert result.tool_calls[0].input == {"name": "dns-lookup"}


def test_neutral_to_anthropic_translates_all_three_roles():
    neutral = [
        {"role": "user", "content": "hi"},
        {
            "role": "assistant",
            "content": "checking",
            "tool_calls": [{"id": "tc1", "name": "list_skills", "input": {}}],
        },
        {"role": "tool", "tool_call_id": "tc1", "content": '{"ok": true}'},
    ]
    translated = _neutral_messages_to_anthropic(neutral)

    assert translated[0] == {"role": "user", "content": "hi"}

    assert translated[1]["role"] == "assistant"
    assert {"type": "text", "text": "checking"} in translated[1]["content"]
    assert {"type": "tool_use", "id": "tc1", "name": "list_skills", "input": {}} in translated[1]["content"]

    assert translated[2]["role"] == "user"
    assert translated[2]["content"][0]["type"] == "tool_result"
    assert translated[2]["content"][0]["tool_use_id"] == "tc1"
