"""One swappable interface for the language model.

The model receives invoice context and explanation facts, including amounts and
current limits, without banking credentials or tools. Callers validate its text;
the model cannot change policy or execute money operations.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Protocol

from airwallex_client import make_opener
from config import Settings, require_https

_OPENER = make_opener()  # no redirects: the API key must only ever go to the configured host


class LLMError(RuntimeError):
    pass


class LLMClient(Protocol):
    name: str

    def complete(self, *, system: str, user: str, max_tokens: int = 500) -> str: ...


def _post_json(url: str, headers: dict, body: dict, timeout: float) -> dict:
    require_https(url, "LLM endpoint")
    req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), method="POST")
    for key, value in headers.items():
        req.add_header(key, value)
    req.add_header("content-type", "application/json")
    try:
        with _OPENER.open(req, timeout=timeout) as resp:  # nosec B310: https-only (checked above), no redirects
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read()[:300].decode("utf-8", "replace")
        raise LLMError(f"HTTP {exc.code}: {detail}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise LLMError(f"network error: {exc}") from exc


class AnthropicClient:
    def __init__(self, api_key: str, model: str, *, timeout: float = 30.0,
                 base_url: str = "https://api.anthropic.com"):
        self._api_key = api_key
        self.model = model
        self.timeout = timeout
        self.base_url = base_url.rstrip("/")
        self.name = f"anthropic:{model}"

    def __repr__(self) -> str:
        return f"AnthropicClient(model={self.model!r})"

    def complete(self, *, system: str, user: str, max_tokens: int = 500) -> str:
        data = _post_json(
            f"{self.base_url}/v1/messages",
            {"x-api-key": self._api_key, "anthropic-version": "2023-06-01"},
            {"model": self.model, "max_tokens": max_tokens, "system": system,
             "messages": [{"role": "user", "content": user}]},
            self.timeout,
        )
        text = "".join(block.get("text", "") for block in data.get("content", [])
                       if block.get("type") == "text")
        if not text.strip():
            raise LLMError(f"empty response (stop_reason={data.get('stop_reason')})")
        return text


class OpenAICompatibleClient:
    def __init__(self, api_key: str, model: str, *, base_url: str, timeout: float = 30.0):
        self._api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.name = f"openai-compatible:{model}"

    def __repr__(self) -> str:
        return f"OpenAICompatibleClient(model={self.model!r}, base_url={self.base_url!r})"

    def complete(self, *, system: str, user: str, max_tokens: int = 500) -> str:
        data = _post_json(
            f"{self.base_url}/chat/completions",
            {"Authorization": f"Bearer {self._api_key}"},
            {"model": self.model, "max_tokens": max_tokens,
             "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]},
            self.timeout,
        )
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMError("unexpected response shape") from exc


def make_llm(settings: Settings) -> LLMClient | None:
    """None means 'no model configured': callers fall back to deterministic code."""
    provider = settings.llm_provider
    if provider == "rules":
        return None
    if provider in {"auto", "anthropic"} and settings.anthropic_api_key:
        return AnthropicClient(settings.anthropic_api_key, settings.llm_model)
    if provider in {"auto", "openai"} and settings.openai_api_key:
        if settings.llm_model.startswith("claude"):
            if provider == "openai":
                raise LLMError("LLM_PROVIDER=openai needs LLM_MODEL set to a model that endpoint serves")
            return None
        return OpenAICompatibleClient(settings.openai_api_key, settings.llm_model,
                                      base_url=settings.openai_base_url)
    if provider in {"anthropic", "openai"}:
        raise LLMError(f"LLM_PROVIDER={provider} but no API key is set for it")
    return None
