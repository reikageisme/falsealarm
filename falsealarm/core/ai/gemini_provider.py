"""
FalseAlarm — Gemini AI Provider
"""

import json
import os

import aiohttp

from .base_provider import AIProvider


class GeminiProvider(AIProvider):
    """Google Gemini AI Provider implementation using aiohttp."""

    DEFAULT_MODEL = "gemini-3.1-pro-preview"

    def __init__(self, api_key: str, model: str | None = None):
        super().__init__(api_key)
        # Model can be overridden per-call or via the GEMINI_MODEL env var,
        # so a retired model ID never hard-blocks AI triage.
        self.model = model or os.environ.get("GEMINI_MODEL") or self.DEFAULT_MODEL
        self.base_url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"

    async def analyze(self, data: dict, prompt: str) -> str:
        """Analyze the scan data using Gemini."""
        url = f"{self.base_url}?key={self.api_key}"

        # Summarize data to avoid blowing up the context window
        # We'll just convert it to a formatted JSON string for the AI
        data_str = json.dumps(data, indent=2)[:50000] # Limit to ~50k chars for safety

        full_prompt = f"{prompt}\n\nScan Data:\n```json\n{data_str}\n```"

        payload = {
            "contents": [{
                "parts": [{"text": full_prompt}]
            }],
            "generationConfig": {
                "temperature": 0.2,
                "topK": 40,
                "topP": 0.95,
                "maxOutputTokens": 4096,
            }
        }

        headers = {
            "Content-Type": "application/json"
        }

        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(url, headers=headers, json=payload) as response:
                    if response.status != 200:
                        error_text = await response.text()
                        return f"❌ Gemini API Error (Status {response.status}): {error_text}"

                    result = await response.json()

                    try:
                        text = result["candidates"][0]["content"]["parts"][0]["text"]
                        return text
                    except (KeyError, IndexError):
                        return f"❌ Failed to parse Gemini response: {result}"

            except Exception as e:
                return f"❌ Network error while contacting Gemini: {e}"
