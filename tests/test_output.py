import json

import pytest

from falsealarm.core.output import OutputManager


@pytest.mark.asyncio
async def test_export_does_not_mutate_scan_results(tmp_path):
    scan_results = {"dns": {"data": [{"target": "example.com"}]}}

    await OutputManager.export(scan_results, str(tmp_path / "results.json"), "json")

    assert "_module" not in scan_results["dns"]["data"][0]


@pytest.mark.asyncio
async def test_export_sarif_maps_vulnerability_fields(tmp_path):
    destination = tmp_path / "results.sarif"
    scan_results = {
        "vulnscan": {
            "data": [
                {
                    "vuln_id": "exposed-env",
                    "name": "Exposed environment file",
                    "severity": "high",
                    "url": "https://example.com/.env",
                }
            ]
        }
    }

    await OutputManager.export(scan_results, str(destination), "sarif")

    document = json.loads(destination.read_text(encoding="utf-8"))
    run = document["runs"][0]
    assert document["version"] == "2.1.0"
    assert run["tool"]["driver"]["rules"][0]["id"] == "exposed-env"
    assert run["results"][0]["level"] == "error"
    assert run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "https://example.com/.env"


@pytest.mark.asyncio
async def test_export_empty_sarif_still_creates_valid_report(tmp_path):
    destination = tmp_path / "empty.sarif"

    await OutputManager.export({}, str(destination), "sarif")

    document = json.loads(destination.read_text(encoding="utf-8"))
    assert document["runs"][0]["results"] == []
