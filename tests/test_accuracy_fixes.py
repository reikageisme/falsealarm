"""Regression tests for the DNS, http/https de-duplication and Wayback fixes."""

import asyncio

from falsealarm.core.config import ScanConfig
from falsealarm.core.scheduler import dedupe_http_targets
from falsealarm.modules.dns_enum import DNSEnumModule
from falsealarm.modules.wayback import WaybackModule

# --------------------------------------------------------------------------- #
# DNS: the pipeline hands modules URLs, DNS needs a hostname
# --------------------------------------------------------------------------- #

def test_dns_hostname_normalisation():
    assert DNSEnumModule._hostname("https://aceda.id.vn") == "aceda.id.vn"
    assert DNSEnumModule._hostname("https://www.Example.com:8443/a") == "www.example.com"
    assert DNSEnumModule._hostname("example.com/path") == "example.com"
    assert DNSEnumModule._hostname("example.com:53") == "example.com"
    assert DNSEnumModule._hostname("sub.example.com.") == "sub.example.com"


# --------------------------------------------------------------------------- #
# http/https de-duplication
# --------------------------------------------------------------------------- #

def _item(url, status=200, redirect="", sim="h"):
    return {"url": url, "status": status, "redirect": redirect, "alive": True, "sim_hash": sim}


def test_http_redirecting_to_https_is_dropped():
    items = [_item("http://a.com", 301, "https://a.com/", "x"), _item("https://a.com", 200, sim="y")]
    assert dedupe_http_targets(items) == ["https://a.com"]


def test_http_serving_identical_page_is_dropped():
    items = [_item("http://a.com", 200, sim="same"), _item("https://a.com", 200, sim="same")]
    assert dedupe_http_targets(items) == ["https://a.com"]


def test_http_with_distinct_content_is_kept():
    # Plain-HTTP serving different content is a real, separate surface.
    items = [_item("http://a.com", 200, sim="one"), _item("https://a.com", 200, sim="two")]
    assert dedupe_http_targets(items) == ["http://a.com", "https://a.com"]


def test_http_only_host_is_kept():
    assert dedupe_http_targets([_item("http://b.com")]) == ["http://b.com"]


def test_off_host_redirect_is_dropped():
    items = [_item("http://c.com", 302, "https://login.other.net/")]
    assert dedupe_http_targets(items) == []


def test_same_host_path_redirect_is_kept():
    items = [_item("https://d.com", 302, "https://d.com/home")]
    assert dedupe_http_targets(items) == ["https://d.com"]


def test_dead_entries_ignored():
    assert dedupe_http_targets([{"url": "http://e.com", "alive": False}]) == []


# --------------------------------------------------------------------------- #
# Wayback: bounded CDX query
# --------------------------------------------------------------------------- #

class _FakeEngine:
    def __init__(self):
        self.urls = []

    async def get(self, url, **kwargs):
        self.urls.append(url)
        return {"status": 200, "body": "[]", "headers": {}, "error": None}


class _Log:
    def __getattr__(self, name):
        return lambda *a, **k: None


def test_wayback_query_is_limited_and_filtered():
    engine = _FakeEngine()
    cfg = ScanConfig(target="https://example.com", wayback_limit=1234)
    module = WaybackModule(engine=engine, db=None, config=cfg, logger=_Log())
    asyncio.run(module.run("https://example.com"))
    url = engine.urls[0]
    assert "limit=1234" in url
    assert "filter=statuscode:200" in url
    assert "*.example.com" in url
