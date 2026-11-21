"""
FalseAlarm — OpenAI-compatible AI provider.

Works with any endpoint that speaks the OpenAI Chat Completions API: OpenAI
itself, local gateways (LiteLLM, vLLM, Ollama's ``/v1``, 9router, …), and
proxies. Configured entirely from environment variables so no key is ever
written to disk:

    LLM_API_KEY    bearer token (also accepts OPENAI_API_KEY)
    LLM_API_BASE   base URL incl. /v1, e.g. http://192.168.10.103:20128/v1
                   (also accepts OPENAI_API_BASE / OPENAI_BASE_URL)
    FALSEALARM_LLM model spec "<provider>/<model>" or "<model>",
                   e.g. openai/Combo1   (also accepts LLM_MODEL / OPENAI_MODEL)
"""

from __future__ import annotations

import json
import os

import aiohttp

from .base_provider import AIProvider

DEFAULT_BASE = "https://api.openai.com/v1"
DEFAULT_MODEL = "gpt-4o-mini"


def _first_env(*names: str) -> str | None:
    for name in names:
        value = os.environ.get(name)
        if value:
            return value.strip()
    return None


def parse_model_spec(spec: str | None) -> tuple[str | None, str | None]:
    """Split ``provider/model`` into (provider, model). ``openai/Combo1`` ->
    ("openai", "Combo1"); a bare ``Combo1`` -> (None, "Combo1")."""
    if not spec:
        return None, None
    spec = spec.strip()
    if "/" in spec:
        provider, model = spec.split("/", 1)
        return provider.strip() or None, model.strip() or None
    return None, spec


class OpenAIProvider(AIProvider):
    """Chat Completions provider for any OpenAI-compatible endpoint."""

    def __init__(self, api_key: str | None = None, model: str | None = None, base_url: str | None = None):
        key = api_key or _first_env("LLM_API_KEY", "OPENAI_API_KEY") or ""
        super().__init__(key)
        _, spec_model = parse_model_spec(_first_env("FALSEALARM_LLM"))
        self.model = model or spec_model or _first_env("LLM_MODEL", "OPENAI_MODEL") or DEFAULT_MODEL
        base = base_url or _first_env("LLM_API_BASE", "OPENAI_API_BASE", "OPENAI_BASE_URL") or DEFAULT_BASE
        self.base_url = base.rstrip("/")

    @classmethod
    def is_configured(cls) -> bool:
        """True when the environment points at a custom/OpenAI-compatible LLM."""
        return bool(_first_env("LLM_API_BASE", "OPENAI_API_BASE", "OPENAI_BASE_URL", "FALSEALARM_LLM")
                    or _first_env("LLM_API_KEY", "OPENAI_API_KEY"))

    @property
    def endpoint(self) -> str:
        return f"{self.base_url}/chat/completions"

    async def analyze(self, data: dict, prompt: str) -> str:
        data_str = json.dumps(data, indent=2, default=str)[:50000]
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": "You are a professional penetration tester and bug bounty hunter."},
                {"role": "user", "content": f"{prompt}\n\nScan Data:\n```json\n{data_str}\n```"},
            ],
            "temperature": 0.2,
            "max_tokens": 4096,
        }
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        timeout = aiohttp.ClientTimeout(total=120)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(self.endpoint, headers=headers, json=payload) as resp:
                    text = await resp.text()
                    if resp.status != 200:
                        return f"❌ LLM API error (status {resp.status}) at {self.endpoint}: {text[:500]}"
                    try:
                        result = json.loads(text)
                        return result["choices"][0]["message"]["content"]
                    except (ValueError, KeyError, IndexError):
                        return f"❌ Unexpected LLM response: {text[:500]}"
        except aiohttp.ClientError as exc:
            return f"❌ Network error contacting {self.endpoint}: {exc}"
