"""
Unified findings model.

Every module reports in its own shape (``vulnscan`` items, CORS records,
missing headers, leaked JS secrets …). This module normalises them into one
``Finding`` list so the terminal summary, the Markdown/HTML reports and the
``--fail-on`` CI gate all agree on what was found and how severe it is.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from falsealarm.core.utils import canonical_url

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info", "unknown")
SEVERITY_RANK = {sev: i for i, sev in enumerate(SEVERITY_ORDER)}


def normalise_severity(value: Any) -> str:
    sev = str(value or "unknown").strip().lower()
    return sev if sev in SEVERITY_RANK else "unknown"


def severity_at_least(severity: str, threshold: str) -> bool:
    """True when *severity* is as bad as or worse than *threshold*."""
    return SEVERITY_RANK[normalise_severity(severity)] <= SEVERITY_RANK[normalise_severity(threshold)]


@dataclass(frozen=True)
class Finding:
    severity: str
    title: str
    location: str
    module: str
    finding_id: str = ""
    evidence: tuple[str, ...] = field(default_factory=tuple)
    detail: str = ""

    @property
    def rank(self) -> int:
        return SEVERITY_RANK.get(self.severity, len(SEVERITY_ORDER))

    def key(self) -> tuple:
        return (self.severity, self.finding_id or self.title, self.location)

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "title": self.title,
            "location": self.location,
            "module": self.module,
            "id": self.finding_id,
            "evidence": list(self.evidence),
            "detail": self.detail,
        }


def _items(results: dict[str, Any], module: str) -> list[dict[str, Any]]:
    value = results.get(module, {})
    if isinstance(value, dict) and isinstance(value.get("data"), list):
        return [item for item in value["data"] if isinstance(item, dict)]
    return []


def _loc(value: Any) -> str:
    text = str(value or "")
    return canonical_url(text) if "://" in text else text


def finding_from_vuln(item: dict[str, Any]) -> Finding:
    evidence = tuple(str(v) for v in (item.get("extracted") or [])[:5])
    detail = str(item.get("matcher_name") or "")
    classification = item.get("classification") or {}
    if isinstance(classification, dict) and classification.get("cve-id"):
        cve = classification["cve-id"]
        cve = ", ".join(cve) if isinstance(cve, list) else str(cve)
        detail = f"{detail} {cve}".strip() if cve.lower() not in str(item.get("vuln_id", "")).lower() else detail
    return Finding(
        severity=normalise_severity(item.get("severity")),
        title=str(item.get("name") or item.get("vuln_id") or "Template match"),
        location=_loc(item.get("url")),
        module="vulnscan",
        finding_id=str(item.get("vuln_id") or ""),
        evidence=evidence,
        detail=detail,
    )


def collect_findings(results: dict[str, Any]) -> list[Finding]:
    """Normalise one scan's module results into a sorted, de-duplicated list."""
    found: list[Finding] = []

    for item in _items(results, "vulnscan"):
        found.append(finding_from_vuln(item))

    for item in _items(results, "cors"):
        if item.get("type") == "cors_vulnerability":
            found.append(Finding(
                "high", str(item.get("vulnerability") or "CORS misconfiguration"), _loc(item.get("target")),
                "cors", "cors-misconfig",
                evidence=(f"ACAO: {item.get('acao')}", f"ACAC: {item.get('acac')}"),
            ))

    for item in _items(results, "openredirect"):
        if item.get("type") == "open_redirect":
            found.append(Finding(
                "medium", f"Open redirect via '{item.get('parameter')}'", _loc(item.get("url")),
                "openredirect", "open-redirect", evidence=(f"Location: {item.get('location')}",),
            ))

    for item in _items(results, "graphql"):
        if item.get("introspection"):
            found.append(Finding(
                "medium", "GraphQL introspection enabled", _loc(item.get("url")), "graphql", "graphql-introspection",
            ))

    for item in _items(results, "js_analysis"):
        for secret in item.get("secrets") or []:
            value = str(secret.get("value", ""))
            masked = value[:6] + "…" if len(value) > 8 else value
            found.append(Finding(
                "high", f"Potential client-side secret: {secret.get('type', 'unknown')}",
                _loc(item.get("source")) or "JavaScript asset",
                "js_analysis", "js-secret", evidence=(masked,) if masked else (),
            ))

    for item in _items(results, "ssl"):
        missing = item.get("missing_headers") or []
        if item.get("type") == "security_headers" and missing:
            found.append(Finding(
                "low", f"Missing security headers ({len(missing)})", _loc(item.get("target")),
                "ssl", "missing-security-headers", evidence=tuple(str(m) for m in missing),
            ))
        if item.get("type") == "ssl_certificate" and item.get("valid") is False:
            found.append(Finding(
                "medium", "Invalid TLS certificate", _loc(item.get("target")), "ssl", "tls-invalid",
                detail=str(item.get("error") or ""),
            ))

    unique: dict[tuple, Finding] = {}
    for f in found:
        unique.setdefault(f.key(), f)
    return sorted(unique.values(), key=lambda f: (f.rank, f.title, f.location))


def severity_counts(findings: Iterable[Finding]) -> Counter:
    return Counter(f.severity for f in findings)


def worst_severity(findings: Iterable[Finding]) -> str | None:
    ranked = sorted(findings, key=lambda f: f.rank)
    return ranked[0].severity if ranked else None
