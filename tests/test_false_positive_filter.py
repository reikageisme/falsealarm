"""Regression tests for the false-positive / catch-all defences.

These pin the fixes for the "soft-200 storm" seen against SPA / WAF-fronted
targets that answer every path with HTTP 200 — the exact failure mode a tool
called *FalseAlarm* must not have.
"""

import glob
import os

import yaml

from falsealarm.modules.dirfuzz import DirFuzzModule, is_baseline_match
from falsealarm.modules.vulnscan import evaluate_matchers

TEMPLATES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "falsealarm", "data", "templates"
)


def test_drop_catch_all_removes_soft200_storm():
    """A target that 200s most paths with a near-constant size is a catch-all."""
    results = []
    for i in range(230):
        results.append({"status": 200, "length": 5861 if i % 3 else 5494})
    results += [
        {"status": 301, "length": 536},   # real redirect — keep
        {"status": 403, "length": 900},    # forbidden — keep
        {"status": 200, "length": 210},    # rare-sized 200 outlier — keep
    ]
    kept, dropped = DirFuzzModule._drop_catch_all(results, tested=299)
    assert dropped >= 230
    kept_statuses = {r["status"] for r in kept}
    assert 301 in kept_statuses and 403 in kept_statuses
    assert {"status": 200, "length": 210} in kept


def test_drop_catch_all_leaves_legit_sites_alone():
    """A handful of real 200 directories must never be treated as a catch-all."""
    results = [{"status": 200, "length": 4000 + i} for i in range(12)]
    results.append({"status": 301, "length": 300})
    kept, dropped = DirFuzzModule._drop_catch_all(results, tested=300)
    assert dropped == 0
    assert kept == results


def test_is_baseline_match_ignores_404_baseline():
    """A 404 baseline is not a catch-all and must never filter real hits."""
    assert is_baseline_match(200, 500, baseline_status=404, baseline_length=0, tolerance=50) is False
    assert is_baseline_match(200, 500, baseline_status=200, baseline_length=500, tolerance=50) is True


def test_shipped_templates_require_and_condition():
    """Every shipped template must AND status with content, so a bare 200
    (a catch-all) cannot trigger a critical/high finding on its own."""
    files = glob.glob(os.path.join(TEMPLATES_DIR, "*.yaml"))
    assert files, "no templates found"
    catch_all_body = "<!doctype html><html lang=vi><title>Some App</title>ordinary page</html>"
    for f in files:
        data = yaml.safe_load(open(f, encoding="utf-8"))
        assert data.get("matchers-condition") == "and", f"{f} must set matchers-condition: and"
        for req in data.get("requests", []):
            fired = evaluate_matchers(
                req.get("matchers", []),
                status=200,
                body=catch_all_body,
                matchers_condition="and",
            )
            assert not fired, f"{data.get('id')} still fires on a plain 200 catch-all page"


def test_drop_catch_all_absolute_cluster_below_ratio():
    """8080 regression: a big same-size 200 cluster is a catch-all even when it
    sits below the overall-ratio gate (one catch-all size was already filtered
    per-request, so the leaked size is only a small fraction of the wordlist)."""
    results = [{"status": 200, "length": 5494} for _ in range(50)]
    results += [
        {"status": 301, "length": 536},
        {"status": 200, "length": 12698},  # real sitemap.xml
        {"status": 200, "length": 1937},   # real robots.txt
    ]
    kept, dropped = DirFuzzModule._drop_catch_all(results, tested=299)  # 50/299 = 16.7%
    assert dropped == 50
    assert sorted(r["length"] for r in kept if r["status"] == 200) == [1937, 12698]
