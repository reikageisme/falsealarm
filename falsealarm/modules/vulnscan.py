"""
vulnscan — nuclei-compatible template scanner.

Runs FalseAlarm's bundled templates and/or any nuclei template directory
(``--templates ~/nuclei-templates``) through the shared AsyncEngine, so rate
limiting, proxies, User-Agent rotation and adaptive backoff all apply.
"""

import asyncio
import os
from typing import Any

from falsealarm.core.templates import TemplateExecutor, TemplateFilter, load_templates
from falsealarm.core.templates.matchers import build_response_context, extract_all, match_all
from falsealarm.core.utils import get_data_path
from falsealarm.modules.base import BaseModule, ModuleResult


def evaluate_matchers(
    matchers: list[dict],
    status: int,
    body: str,
    matchers_condition: str = "or",
    headers: dict | None = None,
) -> bool:
    """Evaluate matcher blocks against a response (pure, no I/O).

    Thin wrapper over the nuclei-compatible matcher engine, kept for
    backwards compatibility with earlier FalseAlarm releases and tests.
    """
    ctx = build_response_context(status, body, headers)
    return match_all(matchers, ctx, matchers_condition).matched


def run_extractors(extractors: list[dict], body: str, headers: dict | None = None) -> list[str]:
    """Pull values out of a response for evidence in the finding."""
    ctx = build_response_context(200, body, headers)
    values, _ = extract_all(extractors, ctx)
    return values


# Loading ~10k nuclei templates takes seconds; do it once per process and
# reuse it for every target in a multi-target scan.
_TEMPLATE_CACHE: dict[tuple, Any] = {}


def resolve_template_paths(config) -> list[str]:
    paths = [p for p in (getattr(config, "templates", None) or []) if p]
    if not paths:
        return [str(get_data_path("templates"))]
    resolved = []
    for p in paths:
        if p in ("bundled", "builtin", "default"):
            resolved.append(str(get_data_path("templates")))
        else:
            resolved.append(os.path.expanduser(p))
    return resolved


def load_for_config(config):
    paths = resolve_template_paths(config)
    tfilter = TemplateFilter.build(
        tags=getattr(config, "template_tags", None),
        exclude_tags=getattr(config, "exclude_tags", None),
        severities=getattr(config, "severity", None),
        ids=getattr(config, "template_ids", None),
        exclude_ids=getattr(config, "exclude_template_ids", None),
    )
    key = (tuple(paths), repr(tfilter))
    if key not in _TEMPLATE_CACHE:
        _TEMPLATE_CACHE[key] = load_templates(paths, tfilter)
    return _TEMPLATE_CACHE[key]


class VulnScanModule(BaseModule):
    name = "vulnscan"
    description = "Nuclei-compatible YAML template vulnerability scanner"

    async def run(self, target: str) -> ModuleResult:
        self._start_timer()
        results: list[dict[str, Any]] = []
        stats: dict[str, Any] = {"templates_loaded": 0, "vulns_found": 0, "requests_sent": 0}

        if not target.startswith("http"):
            target = f"http://{target}"
        target = target.rstrip("/")

        report = load_for_config(self.config)
        stats["templates_loaded"] = report.loaded
        stats["templates_unsupported"] = sum(report.unsupported.values())
        stats["templates_invalid"] = len(report.invalid)

        if not report.templates:
            self.logger.warning(f"No usable templates found ({report.summary()})")
            return self._make_result(target, results, stats)

        self.logger.info(f"Templates: {report.summary()}")
        self.logger.info(f"Running {report.loaded} templates against {target}...")

        executor = TemplateExecutor(self.engine, concurrency=self.config.threads)
        sem = asyncio.Semaphore(max(1, self.config.threads))

        async def run_one(template):
            async with sem:
                try:
                    return await executor.run(template, target)
                except Exception as exc:  # one broken template must not abort the scan
                    self.logger.debug(f"Template {template.id} failed: {exc}")
                    return []

        for findings in await asyncio.gather(*(run_one(t) for t in report.templates)):
            for item in findings:
                results.append(item)
                self.logger.success(
                    f"[{item['severity'].upper()}] {item['name']} ({item['vuln_id']}) at {item['url']}"
                )

        stats["vulns_found"] = len(results)
        stats["requests_sent"] = executor.requests_sent
        stats["cache_hits"] = executor.cache_hits
        stats["request_errors"] = executor.errors
        return self._make_result(target, results, stats)
