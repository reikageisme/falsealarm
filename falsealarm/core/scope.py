"""
Scope guard.

Bug-bounty and pentest work is bounded by a scope. This keeps a scan — and
especially the pipeline's auto-discovered downstream targets (subdomains,
redirects, JS endpoints) — from ever touching a host the operator did not
authorise. A target is in scope when it matches at least one include rule (or
no include rules were given) and matches no exclude rule.

Rule syntax (any of):
    example.com            exact host (and its sub-hosts: api.example.com)
    *.example.com          wildcard host
    10.0.0.0/8             CIDR range (matches target IPs in the range)
    https://example.com/api URL prefix (scheme+host+path)
"""

from __future__ import annotations

import fnmatch
import ipaddress
from urllib.parse import urlparse


def _host_of(target: str) -> str:
    if "://" in target:
        return (urlparse(target).hostname or "").lower()
    return target.split("/")[0].split(":")[0].lower()


class ScopeGuard:
    def __init__(self, include: list[str] | None = None, exclude: list[str] | None = None):
        self.include = [r.strip() for r in (include or []) if r.strip()]
        self.exclude = [r.strip() for r in (exclude or []) if r.strip()]

    @property
    def active(self) -> bool:
        return bool(self.include or self.exclude)

    def _match_rule(self, target: str, rule: str) -> bool:
        host = _host_of(target)
        # URL-prefix rule
        if "://" in rule:
            return target.rstrip("/").startswith(rule.rstrip("/"))
        # CIDR rule
        if "/" in rule:
            try:
                net = ipaddress.ip_network(rule, strict=False)
                return ipaddress.ip_address(host) in net
            except ValueError:
                return False
        rule = rule.lower()
        # Wildcard host
        if rule.startswith("*."):
            return host == rule[2:] or host.endswith(rule[1:]) or fnmatch.fnmatch(host, rule)
        if "*" in rule:
            return fnmatch.fnmatch(host, rule)
        # Bare host: exact or any sub-host (example.com covers api.example.com)
        return host == rule or host.endswith("." + rule)

    def allows(self, target: str) -> bool:
        if not target:
            return False
        if any(self._match_rule(target, r) for r in self.exclude):
            return False
        if self.include:
            return any(self._match_rule(target, r) for r in self.include)
        return True

    def filter(self, targets: list[str]) -> list[str]:
        return [t for t in targets if self.allows(t)]
