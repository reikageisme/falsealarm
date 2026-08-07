from types import SimpleNamespace

import pytest

from falsealarm.modules.headers_ssl import HeadersSSLModule
from falsealarm.modules.wayback import WaybackModule


class StubLogger:
    def debug(self, *_args, **_kwargs):
        pass

    def warning(self, *_args, **_kwargs):
        pass

    def info(self, *_args, **_kwargs):
        pass

    def error(self, *_args, **_kwargs):
        pass


class StubEngine:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0

    async def get(self, *_args, **_kwargs):
        self.calls += 1
        return self.responses.pop(0)


@pytest.mark.asyncio
async def test_http_header_scan_reports_redirect_instead_of_missing_hsts():
    engine = StubEngine([
        {
            "status": 301,
            "headers": {"Location": "https://example.com/"},
            "error": None,
        }
    ])
    module = HeadersSSLModule(
        engine=engine,
        db=None,
        config=SimpleNamespace(),
        logger=StubLogger(),
    )

    result = await module.run("http://example.com")

    assert result.data == [
        {
            "type": "https_redirect",
            "target": "http://example.com",
            "status": 301,
            "location": "https://example.com/",
            "secure": True,
        }
    ]


@pytest.mark.asyncio
async def test_wayback_retries_rate_limit(monkeypatch):
    engine = StubEngine([
        {"status": 429, "headers": {"Retry-After": "1"}, "error": None},
        {
            "status": 200,
            "headers": {},
            "body": '[["original","mimetype","timestamp"],["https://example.com/admin","text/html","20200101"]]',
            "error": None,
        },
    ])
    module = WaybackModule(
        engine=engine,
        db=None,
        config=SimpleNamespace(),
        logger=StubLogger(),
    )

    async def no_sleep(_seconds):
        return None

    monkeypatch.setattr("falsealarm.modules.wayback.asyncio.sleep", no_sleep)
    result = await module.run("example.com")

    assert engine.calls == 2
    assert result.stats["retries"] == 1
    assert result.stats["api_status"] == 200
    assert result.data[0]["url"] == "https://example.com/admin"
