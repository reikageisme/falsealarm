from types import SimpleNamespace

from falsealarm.core.scheduler import ScanScheduler
from falsealarm.core.utils import canonical_url
from falsealarm.modules.dirfuzz import is_baseline_match
from falsealarm.modules.js_analysis import JSAnalysisModule


def test_canonical_url_removes_default_ports_and_fragments():
    assert canonical_url("HTTP://Example.COM:80/#section") == "http://example.com"
    assert canonical_url("https://Example.COM:443/") == "https://example.com"
    assert canonical_url("https://example.com:8443/api") == "https://example.com:8443/api"


def test_scheduler_only_forwards_live_http_targets_and_deduplicates():
    scheduler = ScanScheduler.__new__(ScanScheduler)
    data = [
        {"url": "https://example.com", "alive": True},
        {"url": "https://example.com:443/", "alive": True},
        {"url": "http://example.com:8080", "alive": False},
    ]

    assert scheduler._extract_downstream_targets("httpprobe", data) == [
        "https://example.com"
    ]


def test_portscan_only_adds_non_default_web_ports():
    scheduler = ScanScheduler.__new__(ScanScheduler)
    data = [
        {"target": "example.com", "port": 80},
        {"target": "example.com", "port": 443},
        {"target": "example.com", "port": 8080},
        {"target": "example.com", "port": 8443},
    ]

    assert scheduler._extract_downstream_targets("portscan", data) == [
        "http://example.com:8080",
        "https://example.com:8443",
    ]


def test_dirfuzz_baseline_filter_handles_cloudflare_style_error_pages():
    assert is_baseline_match(403, 6572, 403, 6550, 100)
    assert not is_baseline_match(200, 30298, 403, 6550, 100)
    assert not is_baseline_match(404, 1200, 404, 1200, 50)


def test_js_analysis_defaults_to_same_origin_assets():
    module = JSAnalysisModule.__new__(JSAnalysisModule)
    module.config = SimpleNamespace(include_third_party_js=False)
    html = """
        <script src="/assets/app.js"></script>
        <script src="https://cdn.example.net/vendor.js"></script>
    """

    assert module._extract_js_urls(html, "https://example.com") == [
        "https://example.com/assets/app.js"
    ]


def test_js_endpoint_normalization_rejects_third_party_and_noise():
    assert JSAnalysisModule._normalize_endpoint(
        "/api/users?id=1", "https://example.com"
    ) == "https://example.com/api/users?id=1"
    assert JSAnalysisModule._normalize_endpoint(
        "https://tracker.example.net/event", "https://example.com"
    ) is None
    assert JSAnalysisModule._normalize_endpoint(
        '//cdn.example.net/app.js', "https://example.com"
    ) is None
