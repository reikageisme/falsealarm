"""Tests for scope guard, layered config, auth headers and body capping."""

import textwrap

from falsealarm.core.config import ScanConfig
from falsealarm.core.scope import ScopeGuard

# --------------------------------------------------------------------------- #
# Scope guard
# --------------------------------------------------------------------------- #

def test_scope_include_covers_subdomains():
    g = ScopeGuard(include=["example.com"])
    assert g.allows("https://example.com/a")
    assert g.allows("https://api.example.com")
    assert not g.allows("https://evil.com")
    assert not g.allows("https://notexample.com")  # suffix must be on a dot boundary


def test_scope_wildcard_and_exclude():
    g = ScopeGuard(include=["*.example.com"], exclude=["admin.example.com"])
    assert g.allows("https://api.example.com")
    assert not g.allows("https://admin.example.com")  # exclude wins


def test_scope_cidr():
    g = ScopeGuard(include=["10.0.0.0/8"])
    assert g.allows("http://10.1.2.3")
    assert not g.allows("http://192.168.0.1")


def test_scope_url_prefix():
    g = ScopeGuard(include=["https://example.com/api"])
    assert g.allows("https://example.com/api/v1/users")
    assert not g.allows("https://example.com/admin")


def test_scope_inactive_allows_everything():
    g = ScopeGuard()
    assert not g.active
    assert g.allows("https://anything.test")
    assert g.filter(["https://a.test", "https://b.test"]) == ["https://a.test", "https://b.test"]


def test_exclude_only_blocks_listed():
    g = ScopeGuard(exclude=["*.internal"])
    assert g.active
    assert g.allows("https://public.com")
    assert not g.allows("https://db.internal")


# --------------------------------------------------------------------------- #
# Layered config
# --------------------------------------------------------------------------- #

def test_layered_later_wins_and_ignores_none():
    cfg = ScanConfig.layered(
        {"rate": 10, "threads": 5},
        {"rate": 50},
        {"rate": None, "threads": 100},  # None is ignored, 100 wins
    )
    assert cfg.rate == 50 and cfg.threads == 100


def test_read_profile_named_and_flat(tmp_path):
    named = tmp_path / "profiles.yaml"
    named.write_text(textwrap.dedent("""
        default:
          rate: 20
        stealth:
          rate: 5
          proxy: socks5://127.0.0.1:9050
    """))
    assert ScanConfig.read_profile(str(named), "stealth")["rate"] == 5
    assert ScanConfig.read_profile(str(named), "default")["rate"] == 20

    flat = tmp_path / "flat.yaml"
    flat.write_text("rate: 7\nthreads: 3\n")
    assert ScanConfig.read_profile(str(flat), "default")["rate"] == 7


def test_read_profile_missing_optional_returns_empty(tmp_path):
    assert ScanConfig.read_profile(str(tmp_path / "nope.yaml"), "default", required=False) == {}


def test_config_validation_rejects_bad_values():
    import pytest

    with pytest.raises(ValueError):
        ScanConfig(target="x", max_body=10).validate()
    with pytest.raises(ValueError):
        ScanConfig(target="x", parallel=0).validate()
    with pytest.raises(ValueError):
        ScanConfig(target="x", severity=["bogus"]).validate()


# --------------------------------------------------------------------------- #
# Auth headers
# --------------------------------------------------------------------------- #

def test_header_dict_parses_headers_and_cookie():
    cfg = ScanConfig(
        headers=["Authorization: Bearer abc", "X-Env: staging", "malformed-no-colon"],
        cookie="session=xyz; role=admin",
    )
    h = cfg.header_dict()
    assert h["Authorization"] == "Bearer abc"
    assert h["X-Env"] == "staging"
    assert h["Cookie"] == "session=xyz; role=admin"
    assert "malformed-no-colon" not in h


def test_cookie_merges_with_cookie_header():
    cfg = ScanConfig(headers=["Cookie: a=1"], cookie="b=2")
    assert cfg.header_dict()["Cookie"] == "a=1; b=2"
