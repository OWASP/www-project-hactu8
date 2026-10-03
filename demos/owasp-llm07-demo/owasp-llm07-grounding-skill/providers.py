"""providers.py — optional real-model backends for HACTU8 demo labs.

Shared by every demo and copied unchanged into each skill folder (like web/).
Ported from AgenticGoat's providers.py, so the env vars match that repo.
Standard library only.

Backends (selected per demo with ``<PREFIX>_BACKEND``; model with ``<PREFIX>_MODEL``):

  stub        default. The demo's own deterministic stub model. No network.
  ollama      local. OLLAMA_HOST (default http://localhost:11434).
  llamacpp    local llama.cpp server. LLAMACPP_HOST (default http://localhost:8080).
  openrouter  remote. OPENROUTER_API_KEY required. The key is sent only in the
              Authorization header, never logged and never placed in a prompt.

Safety and cost limits, applied to every non-stub call:

  LAB_MAX_CALLS      calls per process before the provider refuses (default 200)
  LAB_MAX_TOKENS     max output tokens requested per call (default 400)
  <PROVIDER>_TIMEOUT per-call HTTP timeout in seconds (default 120), with
                     LAB_HTTP_TIMEOUT as the shared fallback

Choosing a remote backend means lab prompts, including the demo's payloads,
leave the machine. The stub and the local backends keep everything on the host.
"""

from __future__ import annotations

import json
import os
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import List, Optional

BACKENDS = ("stub", "ollama", "llamacpp", "openrouter")
DEFAULT_MODELS = {
    "ollama": "llama3.2:3b",
    "llamacpp": "local",
    "openrouter": "meta-llama/llama-3.2-3b-instruct",
}
_ALLOWED_URL_SCHEMES = ("http://", "https://")


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        return default


def http_timeout(specific_env: str, default: float = 120.0) -> float:
    raw = os.environ.get(specific_env) or os.environ.get("LAB_HTTP_TIMEOUT")
    try:
        return float(raw) if raw else default
    except ValueError:
        return default


def _urlopen(req: urllib.request.Request, *, timeout: float):
    """urlopen restricted to http(s), so a stray file:// host is never opened."""
    if not req.full_url.lower().startswith(_ALLOWED_URL_SCHEMES):
        raise ValueError(f"refusing to open non-HTTP(S) URL: {req.full_url!r}")
    return urllib.request.urlopen(req, timeout=timeout)  # noqa: S310 (scheme allowlisted)


@dataclass
class Message:
    role: str      # "system" | "user" | "assistant"
    content: str


class _ProviderKey:
    """A secret that never prints itself."""

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "<ProviderKey ****>"

    __str__ = __repr__


class Provider:
    name = "base"

    def __init__(self) -> None:
        self._calls = 0
        self._lock = threading.Lock()
        self.max_calls = _int_env("LAB_MAX_CALLS", 200)
        self.max_tokens = _int_env("LAB_MAX_TOKENS", 400)

    def _count_call(self) -> None:
        with self._lock:
            if self._calls >= self.max_calls:
                raise RuntimeError(
                    f"{self.name}: LAB_MAX_CALLS={self.max_calls} reached for this "
                    "process. Restart the lab or raise the limit.")
            self._calls += 1

    def chat(self, messages: List[Message], *, model: str = "") -> str:
        raise NotImplementedError

    def _post(self, url: str, payload: dict, headers: dict, timeout: float) -> dict:
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", **headers})
        with _urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())


class OllamaProvider(Provider):
    name = "ollama"

    def __init__(self) -> None:
        super().__init__()
        self.host = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
        self.timeout = http_timeout("OLLAMA_TIMEOUT")

    def chat(self, messages: List[Message], *, model: str = "") -> str:
        self._count_call()
        model = model or DEFAULT_MODELS["ollama"]
        try:
            data = self._post(f"{self.host}/api/chat", {
                "model": model,
                "messages": [{"role": m.role, "content": m.content} for m in messages],
                "stream": False,
                "options": {"num_predict": self.max_tokens},
            }, {}, self.timeout)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise RuntimeError(
                    f"ollama has no model {model!r}; run `ollama pull {model}` or pass "
                    "an exact tag from `ollama list` (e.g. llama3.2:3b)") from None
            raise
        return data.get("message", {}).get("content", "")


class LlamaCppProvider(Provider):
    name = "llamacpp"

    def __init__(self) -> None:
        super().__init__()
        self.host = os.environ.get("LLAMACPP_HOST", "http://localhost:8080").rstrip("/")
        self.timeout = http_timeout("LLAMACPP_TIMEOUT")

    def chat(self, messages: List[Message], *, model: str = "") -> str:
        self._count_call()
        data = self._post(f"{self.host}/v1/chat/completions", {
            "model": model or DEFAULT_MODELS["llamacpp"],
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "max_tokens": self.max_tokens,
            "stream": False,
        }, {}, self.timeout)
        return data["choices"][0]["message"]["content"] or ""


class OpenRouterProvider(Provider):
    name = "openrouter"

    def __init__(self) -> None:
        super().__init__()
        raw = os.environ.get("OPENROUTER_API_KEY", "").strip()
        if not raw:
            raise RuntimeError(
                "OpenRouter selected but OPENROUTER_API_KEY is not set. Export it "
                "in your shell; never hard-code it or pass it through a prompt.")
        self._key = _ProviderKey(raw)
        self.timeout = http_timeout("OPENROUTER_TIMEOUT")

    def chat(self, messages: List[Message], *, model: str = "") -> str:
        self._count_call()
        payload = {
            "model": model or DEFAULT_MODELS["openrouter"],
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "max_tokens": self.max_tokens,
        }
        # Defence in depth: the request body must never carry the key.
        if self._key.reveal() in json.dumps(payload):
            raise RuntimeError("refusing to send: provider key found in request body")
        data = self._post("https://openrouter.ai/api/v1/chat/completions", payload,
                          {"Authorization": f"Bearer {self._key.reveal()}"}, self.timeout)
        return data["choices"][0]["message"]["content"] or ""


def get_provider(name: str) -> Optional[Provider]:
    """Return the provider for ``name``, or None for the demo's own stub."""
    name = (name or "stub").strip().lower()
    if name == "stub":
        return None
    if name == "ollama":
        return OllamaProvider()
    if name == "llamacpp":
        return LlamaCppProvider()
    if name == "openrouter":
        return OpenRouterProvider()
    raise ValueError(f"unknown backend {name!r}; use one of {', '.join(BACKENDS)}")


def describe(name: str, model: str) -> str:
    """Short label for logs and the console, e.g. 'openrouter:meta-llama/...'."""
    name = (name or "stub").lower()
    if name == "stub":
        return "stub"
    return f"{name}:{model or DEFAULT_MODELS.get(name, '')}"
