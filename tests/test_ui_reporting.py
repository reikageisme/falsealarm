"""Tests for the unified findings model, terminal UI and HTML report."""

from rich.console import Console
from typer.testing import CliRunner

from falsealarm.core.engine import EngineStats
from falsealarm.core.findings import collect_findings, severity_at_least, worst_severity
from falsealarm.core.html_report import HTMLReport
from falsealarm.core.ui import ScanDashboard, finding_line, print_module_views, print_summary

RESULTS = {
    "httpprobe": {"data": [
        {"url": "https://example.com/a/very/long/path/that/must/not/be/truncated/in/the/terminal/view",
         "status": 200, "title": "Home", "server": "nginx", "content_length": 2048, "alive": True},
    ]},
    "vulnscan": {"data": [
        {"vuln_id": "laravel-env", "name": "Laravel env", "severity": "high", "url": "https://example.com/.env",
         "extracted": ["APP_KEY=base64:abc"]},
        {"vuln_id": "nginx-version", "name": "Nginx version", "severity": "info", "url": "https://example.com"},
        {"vuln_id": "laravel-env", "name": "Laravel env", "severity": "high", "url": "https://example.com:443/.env"},
    ]},
    "cors": {"data": [
        {"type": "cors_vulnerability", "target": "https://example.com", "acao": "https://evil.com", "acac": "true",
         "vulnerability": "Arbitrary Origin Reflection with Credentials"},
        {"type": "cors_info", "target": "https://example.com"},
    ]},
    "openredirect": {"data": [
        {"type": "open_redirect", "url": "https://example.com/?next=x", "parameter": "next", "location": "https://evil"},
    ]},
    "js_analysis": {"data": [
        {"type": "js_analysis", "source": "https://example.com/app.js",
         "secrets": [{"type": "AWS Access Key", "value": "AKIAABCDEFGHIJKLMNOP"}], "endpoints": ["/api/v1"]},
    ]},
}


def _console(width: int = 120) -> Console:
    return Console(record=True, width=width, force_terminal=False, color_system=None)


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #

def test_collect_findings_normalises_sorts_and_dedupes():
    findings = collect_findings(RESULTS)
    sev = [f.severity for f in findings]
    assert sev == sorted(sev, key=lambda s: ["critical", "high", "medium", "low", "info", "unknown"].index(s))
    # Default port duplicate of the .env finding collapses into one.
    assert sum(1 for f in findings if f.finding_id == "laravel-env") == 1
    modules = {f.module for f in findings}
    assert {"vulnscan", "cors", "openredirect", "js_analysis"} <= modules
    # Secrets are masked in evidence, never printed in full.
    secret = next(f for f in findings if f.module == "js_analysis")
    assert "AKIAABCDEFGHIJKLMNOP" not in " ".join(secret.evidence)
    assert worst_severity(findings) == "high"


def test_severity_threshold():
    assert severity_at_least("critical", "high")
    assert severity_at_least("high", "high")
    assert not severity_at_least("medium", "high")
    assert not severity_at_least("unknown", "info")


# --------------------------------------------------------------------------- #
# Terminal UI
# --------------------------------------------------------------------------- #

def test_finding_line_is_single_copyable_line():
    f = collect_findings(RESULTS)[0]
    text = finding_line(f).plain
    assert "\n" not in text
    assert f.location in text and f.severity in text


def test_module_views_never_truncate_urls():
    console = _console(80)
    print_module_views(console, RESULTS)
    out = console.export_text()
    flat = out.replace("\n", "").replace(" ", "")
    assert "truncated/in/the/terminal/view" in flat
    assert "…" not in out.split("Live HTTP services")[1].split("\n\n")[0]
    # vulnscan output lives in the findings table, not a raw dump.
    assert "vuln_id" not in out


def test_summary_lists_findings_and_outputs():
    stats = EngineStats()
    stats.requests, stats.errors = 1200, 3
    console = _console()
    findings = print_summary(console, "https://example.com", RESULTS, stats, ["out.json"], 12.5, "fa_1")
    out = console.export_text()
    assert "summary" in out and "out.json" in out and "1,200 requests" in out
    assert "Laravel env" in out and "HIGH" in out
    assert len(findings) == 5


def test_dashboard_renders_progress_and_counts():
    stats = EngineStats()
    stats.requests = 500
    stats.statuses[200] = 480
    stats.statuses[404] = 20
    console = _console()
    dash = ScanDashboard(console, lambda: stats)
    dash.set_stage("vulnscan", "https://example.com")
    dash.set_task("templates", 200)
    dash.advance(50)
    dash.add_finding("high")
    console.print(dash)
    out = console.export_text()
    assert "vulnscan" in out and "50/200 templates" in out
    assert "500 req" in out and "2xx 480" in out and "1 high" in out


def test_logger_has_no_dashboard_when_not_a_tty():
    from falsealarm.core.logger import FalseAlarmLogger

    logger = FalseAlarmLogger()
    logger.start_dashboard(lambda: None)  # stdout is captured -> not interactive
    assert logger.dashboard is None
    logger.task("x", 10)  # no-ops must not raise
    logger.advance()


# --------------------------------------------------------------------------- #
# HTML report
# --------------------------------------------------------------------------- #

def test_html_report_escapes_attacker_controlled_values():
    evil = {
        "httpprobe": {"data": [{"url": "http://t/", "status": 200, "alive": True,
                                "title": "<img src=x onerror=alert(1)>"}]},
        "vulnscan": {"data": [{"vuln_id": '"><script>alert(2)</script>', "name": "<b>x</b>", "severity": "high",
                               "url": "http://t/\"><svg onload=alert(3)>",
                               "extracted": ["</code><script>alert(4)</script>"]}]},
    }
    page = HTMLReport.render("t<script>", evil)
    assert page.count("<script>") == 1  # only the report's own filter script
    assert "onerror=alert(1)>" not in page
    assert "<svg" not in page
    assert "&lt;img src=x onerror=alert(1)&gt;" in page
    assert "Content-Security-Policy" in page


def test_html_report_contains_counts_and_sections(tmp_path):
    out = tmp_path / "r" / "report.html"
    HTMLReport.export("https://example.com", RESULTS, str(out))
    page = out.read_text(encoding="utf-8")
    assert 'data-sev="high"' in page and "Laravel env" in page
    assert "Live HTTP services" in page
    assert "Open ports" not in page  # empty sections are omitted


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def test_fail_on_rejects_unknown_severity():
    from falsealarm.cli import app

    result = CliRunner().invoke(app, ["scan", "-u", "http://127.0.0.1:9", "--fail-on", "severe"])
    assert result.exit_code != 0
    assert "fail-on" in result.output
