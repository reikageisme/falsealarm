"""Pentest-oriented attack-surface reporting."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from falsealarm.core.findings import collect_findings
from falsealarm.core.utils import canonical_url, get_timestamp


class PentestReport:
    """Turn raw module results into a concise handoff for manual testing."""

    @staticmethod
    def _items(results: dict[str, Any], module: str) -> list[dict[str, Any]]:
        value = results.get(module, {})
        if isinstance(value, dict) and isinstance(value.get("data"), list):
            return [item for item in value["data"] if isinstance(item, dict)]
        return []

    @classmethod
    def render(cls, target: str, results: dict[str, Any]) -> str:
        live_by_url: dict[str, dict[str, Any]] = {}
        for item in cls._items(results, "httpprobe"):
            if item.get("alive") and item.get("url"):
                normalized = canonical_url(str(item["url"]))
                live_by_url.setdefault(normalized, {**item, "url": normalized})
        live = list(live_by_url.values())
        subdomains = {
            str(item.get("domain", "")).lower().rstrip(".")
            for item in cls._items(results, "subdomain")
            if item.get("domain")
        }
        ports = {
            (str(item.get("target", "")).lower(), item.get("port"))
            for item in cls._items(results, "portscan")
            if item.get("port")
        }
        edge_ports = any(
            item.get("network_context") == "cdn_edge"
            for item in cls._items(results, "portscan")
        )
        directories = cls._items(results, "dirfuzz")
        historical = cls._items(results, "wayback")
        js_results = cls._items(results, "js_analysis")
        technologies = cls._items(results, "tech")

        endpoints: set[str] = set()
        for item in directories + historical:
            if item.get("url"):
                endpoints.add(canonical_url(str(item["url"])))
        for item in js_results:
            endpoints.update(canonical_url(str(value)) for value in item.get("endpoints", []) if value)

        tech_names = []
        for item in technologies:
            tech_names.extend(str(t.get("name")) for t in item.get("technologies", []) if t.get("name"))

        findings = collect_findings(results)
        severity_counts = Counter(f.severity for f in findings)

        lines = [
            f"# FalseAlarm pre-pentest report — {target}",
            "",
            f"Generated: `{get_timestamp()}`",
            "",
            "> Automated reconnaissance is evidence collection, not proof that a target is secure. Validate findings manually and stay within the agreed scope.",
            "",
            "## Attack-surface summary",
            "",
            "| Signal | Count |",
            "|---|---:|",
            f"| Live HTTP services | {len(live)} |",
            f"| Discovered subdomains | {len(subdomains)} |",
            f"| Open ports | {len(ports)} |",
            f"| Technologies | {len(set(tech_names))} |",
            f"| Candidate endpoints | {len(endpoints)} |",
            f"| Automated findings | {len(findings)} |",
            "",
            "## Prioritized findings",
            "",
        ]
        if findings:
            lines.extend(["| Severity | Finding | Location | Evidence |", "|---|---|---|---|"])
            for f in findings:
                def esc(text: str) -> str:
                    return text.replace("|", "\\|").replace("\n", " ")
                evidence = ", ".join(f.evidence[:3])
                if f.detail:
                    evidence = f"{f.detail}; {evidence}" if evidence else f.detail
                lines.append(f"| {f.severity.upper()} | {esc(f.title)} | {esc(f.location)} | {esc(evidence)} |")
        else:
            lines.append("No automated vulnerability finding was produced. This does not replace manual testing.")

        lines.extend(["", "## Live services", ""])
        if live:
            for item in live:
                lines.append(f"- `{item.get('url')}` — HTTP {item.get('status')} — {item.get('title') or 'no title'}")
        else:
            lines.append("- No live HTTP service recorded.")

        lines.extend(["", "## Technology fingerprint", ""])
        lines.append(", ".join(f"`{name}`" for name in sorted(set(tech_names))) or "No technology signature matched.")

        lines.extend(["", "## Candidate entry points", ""])
        if endpoints:
            for endpoint in sorted(endpoints)[:200]:
                lines.append(f"- `{endpoint}`")
            if len(endpoints) > 200:
                lines.append(f"- … {len(endpoints) - 200} additional endpoints omitted from this concise report")
        else:
            lines.append("- No endpoint was extracted by directory, archive, or JavaScript analysis.")

        lines.extend([
            "",
            "## Manual testing queue",
            "",
            "1. Confirm scope and ownership for every discovered host, IP, and third-party service.",
            "2. Walk authenticated and unauthenticated workflows through an intercepting proxy; record roles, cookies, parameters, APIs, and state transitions.",
            "3. Prioritize authorization and object-level access testing on API and administrative endpoints.",
            "4. Validate every exposed secret, unusual redirect, 401/403 path, backup file, and historical endpoint without exceeding scope.",
            "5. Test session management, authentication recovery, input validation, file handling, and business-logic abuse manually.",
            "6. Re-run with `--diff` after remediation or deployment to isolate attack-surface changes.",
            "",
            "## Coverage notes",
            "",
            f"Modules with recorded output: {', '.join(sorted(k for k, v in results.items() if isinstance(v, dict) and v.get('data')) ) or 'none'}.",
            f"Finding severities: {', '.join(f'{key}={value}' for key, value in sorted(severity_counts.items())) or 'none'}.",
        ])
        if edge_ports:
            lines.append(
                "Port results were observed on a CDN/WAF edge and do not confirm that the origin exposes those services."
            )
        return "\n".join(lines) + "\n"

    @classmethod
    async def export(cls, target: str, results: dict[str, Any], filepath: str) -> None:
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(cls.render(target, results), encoding="utf-8")
