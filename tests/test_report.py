import pytest

from falsealarm.core.report import PentestReport


def test_report_builds_attack_surface_and_manual_queue():
    results = {
        "httpprobe": {
            "data": [
                {"url": "https://example.com", "status": 200, "title": "Example", "alive": True}
            ]
        },
        "tech": {
            "data": [
                {"technologies": [{"name": "Nginx"}, {"name": "Vue.js"}]}
            ]
        },
        "js_analysis": {
            "data": [
                {"endpoints": ["/api/users"], "secrets": [{"type": "JWT Token"}]}
            ]
        },
        "vulnscan": {
            "data": [
                {"name": "Exposed .env", "severity": "critical", "url": "https://example.com/.env"}
            ]
        },
    }

    report = PentestReport.render("example.com", results)

    assert "Live HTTP services | 1" in report
    assert "`Nginx`" in report
    assert "`/api/users`" in report
    assert "CRITICAL" in report
    assert "Potential client-side secret" in report
    assert "Manual testing queue" in report


@pytest.mark.asyncio
async def test_report_export_creates_parent_directories(tmp_path):
    destination = tmp_path / "reports" / "pentest.md"

    await PentestReport.export("example.com", {}, str(destination))

    assert destination.exists()
    assert "No automated vulnerability finding" in destination.read_text(encoding="utf-8")
