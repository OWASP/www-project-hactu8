"""Shared multi-provider LLM dispatch — relocates (not rewrites) the provider
branching that used to live separately in `RAGService.chat()` (no tool
support) and `agents/base_agent.py`'s `_call_claude` (Anthropic-only, tool
support). One function, `call_model()`, does both: works across all 5
provider IDs the frontend's `ModelProviderContext` already models
(openai/anthropic/ollama/foundry/custom), and optionally takes `tools`.

Message format is a single neutral shape (OpenAI's own convention, since
most of the ecosystem already converges on it) that every caller uses
regardless of provider:
    {"role": "user", "content": str}
    {"role": "assistant", "content": str | None, "tool_calls": [{"id","name","input"}] | None}
    {"role": "tool", "tool_call_id": str, "content": str}

For OpenAI-compatible providers this is passed through almost unchanged.
For Anthropic, it's translated to/from the blocks-in-content shape the
Anthropic Messages API actually uses.
"""

import json
import os
from typing import Any, Dict, List, Optional

import httpx
import openai
from pydantic import BaseModel

ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"


class ToolCall(BaseModel):
    id: str
    name: str
    input: Dict[str, Any]


class LLMResponse(BaseModel):
    text_blocks: List[str] = []
    tool_calls: List[ToolCall] = []
    stop_reason: str = "end_turn"


def _resolve_model(provider_id: Optional[str], model_id: Optional[str]) -> str:
    if model_id:
        return model_id
    if provider_id in ("ollama", "foundry", "custom"):
        return os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    if provider_id == "anthropic":
        return os.getenv("ANTHROPIC_MODEL", "claude-3.5-sonnet")
    return os.getenv("OPENAI_MODEL", "gpt-4o-mini")


def _get_openai_client(api_key: Optional[str], base_url: Optional[str]) -> openai.OpenAI:
    resolved_key = api_key or os.getenv("OPENAI_API_KEY") or ""
    if base_url:
        return openai.OpenAI(api_key=resolved_key or "local", base_url=base_url)
    return openai.OpenAI(api_key=resolved_key)


def _get_ollama_client(base_url: Optional[str]) -> openai.OpenAI:
    resolved_base = (base_url or os.getenv("OLLAMA_BASE_URL") or "").strip()
    if not resolved_base:
        return openai.OpenAI(api_key="local")
    if not resolved_base.endswith("/v1"):
        resolved_base = f"{resolved_base.rstrip('/')}/v1"
    return openai.OpenAI(api_key="local", base_url=resolved_base)


def _to_openai_tools(tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [
        {
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t["description"],
                "parameters": t["input_schema"],
            },
        }
        for t in tools
    ]


async def _call_openai_compatible(
    messages: List[Dict[str, Any]],
    *,
    provider_id: str,
    model: str,
    api_key: Optional[str],
    base_url: Optional[str],
    system_prompt: str,
    tools: Optional[List[Dict[str, Any]]],
    max_tokens: int,
) -> LLMResponse:
    if provider_id in ("foundry", "custom") and not base_url:
        raise ValueError("Base URL is required for the selected provider")

    client = _get_ollama_client(base_url) if provider_id == "ollama" else _get_openai_client(api_key, base_url)

    full_messages = [{"role": "system", "content": system_prompt}, *messages] if system_prompt else list(messages)

    kwargs: Dict[str, Any] = {
        "model": model,
        "messages": full_messages,
        "temperature": 0.7,
        "max_tokens": max_tokens,
    }
    if tools:
        kwargs["tools"] = _to_openai_tools(tools)
        kwargs["tool_choice"] = "auto"

    response = client.chat.completions.create(**kwargs)
    choice_message = response.choices[0].message

    tool_calls: List[ToolCall] = []
    for tc in choice_message.tool_calls or []:
        try:
            args = json.loads(tc.function.arguments) if tc.function.arguments else {}
        except json.JSONDecodeError:
            args = {}
        tool_calls.append(ToolCall(id=tc.id, name=tc.function.name, input=args))

    text_blocks = [choice_message.content] if choice_message.content else []
    stop_reason = "tool_use" if tool_calls else "end_turn"
    return LLMResponse(text_blocks=text_blocks, tool_calls=tool_calls, stop_reason=stop_reason)


def _neutral_messages_to_anthropic(messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Translate the neutral (OpenAI-shaped) message list into Anthropic's
    blocks-in-content convention."""
    anthropic_messages: List[Dict[str, Any]] = []
    for m in messages:
        role = m["role"]
        if role == "user":
            anthropic_messages.append({"role": "user", "content": m["content"]})
        elif role == "assistant":
            blocks: List[Dict[str, Any]] = []
            if m.get("content"):
                blocks.append({"type": "text", "text": m["content"]})
            for tc in m.get("tool_calls") or []:
                blocks.append({"type": "tool_use", "id": tc["id"], "name": tc["name"], "input": tc["input"]})
            anthropic_messages.append({"role": "assistant", "content": blocks})
        elif role == "tool":
            anthropic_messages.append({
                "role": "user",
                "content": [{"type": "tool_result", "tool_use_id": m["tool_call_id"], "content": m["content"]}],
            })
    return anthropic_messages


async def _call_anthropic(
    messages: List[Dict[str, Any]],
    *,
    model: str,
    api_key: Optional[str],
    system_prompt: str,
    tools: Optional[List[Dict[str, Any]]],
    max_tokens: int,
) -> LLMResponse:
    resolved_key = api_key or os.getenv("ANTHROPIC_API_KEY")
    if not resolved_key:
        raise ValueError("Anthropic API key is not configured")

    payload: Dict[str, Any] = {
        "model": model,
        "max_tokens": max_tokens,
        "messages": _neutral_messages_to_anthropic(messages),
    }
    if system_prompt:
        payload["system"] = system_prompt
    if tools:
        payload["tools"] = tools  # already Anthropic-native {name, description, input_schema}

    headers = {
        "x-api-key": resolved_key,
        "anthropic-version": ANTHROPIC_VERSION,
        "content-type": "application/json",
    }

    async with httpx.AsyncClient(timeout=120.0) as client:
        response = await client.post(ANTHROPIC_API_URL, json=payload, headers=headers)
        if not response.is_success:
            try:
                err_body = response.json()
                err_detail = err_body.get("error", {}).get("message") or str(err_body)
            except Exception:
                err_detail = response.text or f"HTTP {response.status_code}"
            raise ValueError(f"Claude API {response.status_code}: {err_detail}")
        data = response.json()

    content_blocks = data.get("content", [])
    text_blocks = [b["text"] for b in content_blocks if b.get("type") == "text"]
    tool_calls = [
        ToolCall(id=b["id"], name=b["name"], input=b.get("input", {}))
        for b in content_blocks if b.get("type") == "tool_use"
    ]
    return LLMResponse(text_blocks=text_blocks, tool_calls=tool_calls, stop_reason=data.get("stop_reason", "end_turn"))


async def call_model(
    messages: List[Dict[str, Any]],
    *,
    provider_id: Optional[str] = None,
    model_id: Optional[str] = None,
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
    system_prompt: str = "",
    tools: Optional[List[Dict[str, Any]]] = None,
    max_tokens: int = 1024,
) -> LLMResponse:
    """Send `messages` (neutral shape, see module docstring) to whichever
    provider/model is configured, optionally with `tools` (Anthropic-native
    {name, description, input_schema} shape — converted internally for
    OpenAI-compatible providers). Returns a normalized LLMResponse regardless
    of provider."""
    resolved_provider = (provider_id or "openai").lower()
    resolved_model = _resolve_model(resolved_provider, model_id)

    if resolved_provider in ("openai", "ollama", "foundry", "custom"):
        return await _call_openai_compatible(
            messages,
            provider_id=resolved_provider,
            model=resolved_model,
            api_key=api_key,
            base_url=base_url,
            system_prompt=system_prompt,
            tools=tools,
            max_tokens=max_tokens,
        )
    if resolved_provider == "anthropic":
        return await _call_anthropic(
            messages,
            model=resolved_model,
            api_key=api_key,
            system_prompt=system_prompt,
            tools=tools,
            max_tokens=max_tokens,
        )
    raise ValueError(f"Unsupported model provider: {resolved_provider}")
