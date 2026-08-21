"""Regression tests for the bug fixes applied during the hardening pass."""

import asyncio

from falsealarm.core.config import ScanConfig
from falsealarm.core.diff import KEY_FIELDS, diff_module_results
from falsealarm.core.engine import AsyncEngine
from falsealarm.core.scheduler import ScanScheduler
from falsealarm.modules.cors import CORSModule


def test_adaptive_rate_flag_reaches_limiter():
    """BUG-1: --adaptive-rate must actually enable adaptive throttling."""
    async def _check():
        engine = AsyncEngine(ScanConfig(target="example.com", adaptive_rate=True))
        await engine.start()
        try:
            assert engine._rate_limiter.adaptive is True
        finally:
            await engine.close()

    asyncio.run(_check())

    async def _check_off():
        engine = AsyncEngine(ScanConfig(target="example.com", adaptive_rate=False))
        await engine.start()
        try:
            assert engine._rate_limiter.adaptive is False
        finally:
            await engine.close()

    asyncio.run(_check_off())


def test_portscan_promotes_all_nondefault_web_ports():
    """BUG-2: 8000/8008/8888 were dropped; 80/443 stay covered by the root probe."""
    scheduler = ScanScheduler.__new__(ScanScheduler)
    data = [
        {"target": "example.com", "port": 80},
        {"target": "example.com", "port": 443},
        {"target": "example.com", "port": 8000},
        {"target": "example.com", "port": 8080},
        {"target": "example.com", "port": 8443},
        {"target": "example.com", "port": 8888},
    ]
    promoted = scheduler._extract_downstream_targets("portscan", data)
    assert "http://example.com:8000" in promoted
    assert "http://example.com:8080" in promoted
    assert "http://example.com:8888" in promoted
    assert "https://example.com:8443" in promoted
    # Default ports stay out (already probed as the root target).
    assert "http://example.com:80" not in promoted
    assert "https://example.com:443" not in promoted


def test_cors_bypass_origins_are_wellformed():
    """BUG-3: origins must be built from the hostname, not the full URL."""
    origins = CORSModule._bypass_origins("example.com")
    assert "https://example.com.evil.com" in origins   # suffix bypass
    assert "https://evil-example.com" in origins        # prefix bypass
    # No malformed origin carrying a scheme inside the host part.
    assert all("http://example.com." not in o for o in origins)
    assert "https://evilexample.com" not in origins


def test_diff_portscan_key_includes_target():
    """BUG-5: identical ports on different hosts must not collide."""
    assert KEY_FIELDS["portscan"] == ("target", "port")
    old = [{"target": "a.com", "port": 80}]
    new = [{"target": "a.com", "port": 80}, {"target": "b.com", "port": 80}]
    delta = diff_module_results("portscan", old, new)
    assert delta["new"] == [{"target": "b.com", "port": 80}]
    assert delta["removed"] == []
