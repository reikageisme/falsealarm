from falsealarm.core.diff import diff_module_results, diff_scan_results


def test_diff_module_results_detects_new_item():
    old_data = [{"domain": "a.example.com"}]
    new_data = [{"domain": "a.example.com"}, {"domain": "b.example.com"}]

    diff = diff_module_results("subdomain", old_data, new_data)

    assert diff["new"] == [{"domain": "b.example.com"}]
    assert diff["removed"] == []


def test_diff_module_results_detects_removed_item():
    old_data = [{"port": 80}, {"port": 443}]
    new_data = [{"port": 80}]

    diff = diff_module_results("portscan", old_data, new_data)

    assert diff["new"] == []
    assert diff["removed"] == [{"port": 443}]


def test_diff_module_results_no_changes():
    data = [{"url": "https://example.com/admin"}]
    diff = diff_module_results("dirfuzz", data, data)
    assert diff["new"] == []
    assert diff["removed"] == []


def test_diff_scan_results_only_includes_changed_modules():
    old_results = {
        "subdomain": {"data": [{"domain": "a.example.com"}]},
        "portscan": {"data": [{"port": 80}]},
    }
    new_results = {
        "subdomain": {"data": [{"domain": "a.example.com"}, {"domain": "new.example.com"}]},
        "portscan": {"data": [{"port": 80}]},  # unchanged
    }

    diff = diff_scan_results(old_results, new_results)

    assert "subdomain" in diff
    assert diff["subdomain"]["new"] == [{"domain": "new.example.com"}]
    assert "portscan" not in diff  # no changes -> omitted


def test_diff_scan_results_handles_unknown_module_via_fallback_key():
    # Modules not in KEY_FIELDS fall back to hashing the whole item.
    old_results = {"custom_module": {"data": [{"foo": "bar"}]}}
    new_results = {"custom_module": {"data": [{"foo": "bar"}, {"foo": "baz"}]}}

    diff = diff_scan_results(old_results, new_results)

    assert diff["custom_module"]["new"] == [{"foo": "baz"}]
