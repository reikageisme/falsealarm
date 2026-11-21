"""The fingerprint must only advertise Accept-Encoding values aiohttp can decode."""

import falsealarm.core.fingerprint as fp


def test_never_advertises_zstd_in_either_mode():
    for brotli_ok in (True, False):
        for value in fp._encoding_values(brotli_ok):
            assert "zstd" not in value


def test_br_only_when_brotli_available():
    assert any("br" in v for v in fp._encoding_values(True))
    assert all("br" not in v for v in fp._encoding_values(False))


def test_gzip_deflate_always_present():
    for brotli_ok in (True, False):
        values = fp._encoding_values(brotli_ok)
        assert values and all("gzip" in v and "deflate" in v for v in values)


def test_active_list_matches_runtime_brotli_support():
    advertises_br = any("br" in v for v in fp._ACCEPT_ENCODING_VALUES)
    assert advertises_br == fp._brotli_available()
