"""Tests for the OpenAI-compatible AI provider configured via env vars."""

import asyncio

import pytest

from falsealarm.core.ai.openai_provider import OpenAIProvider, parse_model_spec

ENV_KEYS = ["LLM_API_KEY", "LLM_API_BASE", "FALSEALARM_LLM", "LLM_MODEL",
            "OPENAI_API_KEY", "OPENAI_API_BASE", "OPENAI_BASE_URL", "OPENAI_MODEL"]


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for k in ENV_KEYS:
        monkeypatch.delenv(k, raising=False)


@pytest.mark.parametrize("spec,expected", [
    ("openai/Combo1", ("openai", "Combo1")),
    ("Combo1", (None, "Combo1")),
    ("anthropic/claude-3", ("anthropic", "claude-3")),
    ("", (None, None)),
    (None, (None, None)),
])
def test_parse_model_spec(spec, expected):
    assert parse_model_spec(spec) == expected


def test_configured_from_falsealarm_llm_env(monkeypatch):
    monkeypatch.setenv("FALSEALARM_LLM", "openai/Combo1")
    monkeypatch.setenv("LLM_API_KEY", "key-9router")
    monkeypatch.setenv("LLM_API_BASE", "http://192.168.10.103:20128/v1")
    assert OpenAIProvider.is_configured()
    p = OpenAIProvider()
    assert p.model == "Combo1"
    assert p.base_url == "http://192.168.10.103:20128/v1"
    assert p.endpoint == "http://192.168.10.103:20128/v1/chat/completions"
    assert p.api_key == "key-9router"


def test_not_configured_when_env_absent():
    assert OpenAIProvider.is_configured() is False


def test_openai_env_aliases(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-x")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("OPENAI_MODEL", "gpt-4o")
    p = OpenAIProvider()
    assert p.api_key == "sk-x" and p.model == "gpt-4o"
    assert p.base_url == "https://api.example.com/v1"


def test_analyze_posts_to_chat_completions(monkeypatch):
    import json as _json
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    captured = {}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            captured["body"] = _json.loads(self.rfile.read(length))
            captured["auth"] = self.headers.get("Authorization")
            captured["path"] = self.path
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(_json.dumps(
                {"choices": [{"message": {"content": "# Report\nLooks fine."}}]}).encode())

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    monkeypatch.setenv("LLM_API_BASE", f"http://127.0.0.1:{port}/v1")
    monkeypatch.setenv("LLM_API_KEY", "secret-token")
    monkeypatch.setenv("FALSEALARM_LLM", "openai/Combo1")

    try:
        out = asyncio.run(OpenAIProvider().analyze({"x": 1}, "Analyze."))
        assert "Looks fine" in out
        assert captured["path"] == "/v1/chat/completions"
        assert captured["auth"] == "Bearer secret-token"
        assert captured["body"]["model"] == "Combo1"
        assert len(captured["body"]["messages"]) == 2
    finally:
        server.shutdown()
