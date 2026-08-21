import asyncio
import os
import re
from typing import Any
from urllib.parse import urlparse

import yaml

from falsealarm.core.utils import get_data_path
from falsealarm.modules.base import BaseModule, ModuleResult


def _part_text(part: str, body: str, headers: dict | None) -> str:
    """Return the response text a matcher should search, based on 'part'."""
    header_blob = ""
    if headers:
        header_blob = "\n".join(f"{k}: {v}" for k, v in headers.items())
    if part == "header":
        return header_blob
    if part == "all":
        return f"{header_blob}\n{body}"
    return body  # default: body


def evaluate_matchers(
    matchers: list[dict],
    status: int,
    body: str,
    matchers_condition: str = "or",
    headers: dict | None = None,
) -> bool:
    """Evaluate a template's matcher blocks against a response.

    Supported matcher types:
    - ``status``: response status is in the given list.
    - ``word``: substring match (``words``); ``part`` selects body/header/all.
    - ``regex``: regular-expression match (``regex``); ``part`` selects target.

    Each matcher's own ``condition`` (and/or) governs its value list; the
    per-matcher results are then combined with ``matchers_condition``. Any
    matcher may set ``negative: true`` to invert its own result.

    Pure function (no I/O) so it can be unit-tested directly.
    """
    matcher_results = []
    for matcher in matchers:
        m_type = matcher.get("type", "")
        m_condition = matcher.get("condition", "or")
        part = matcher.get("part", "body")
        result = False

        if m_type == "status":
            result = status in matcher.get("status", [])

        elif m_type == "word":
            text = _part_text(part, body, headers)
            hits = [w in text for w in matcher.get("words", [])]
            result = (all(hits) if hits else False) if m_condition == "and" else any(hits)

        elif m_type == "regex":
            text = _part_text(part, body, headers)
            patterns = matcher.get("regex", [])
            hits = []
            for pat in patterns:
                try:
                    hits.append(re.search(pat, text) is not None)
                except re.error:
                    hits.append(False)
            result = (all(hits) if hits else False) if m_condition == "and" else any(hits)

        else:
            # Unknown matcher type: don't silently treat as a pass.
            result = False

        if matcher.get("negative"):
            result = not result
        matcher_results.append(result)

    if not matcher_results:
        return False
    if matchers_condition == "and":
        return all(matcher_results)
    return any(matcher_results)


def run_extractors(extractors: list[dict], body: str, headers: dict | None = None) -> list[str]:
    """Pull values out of a response for evidence in the finding.

    Supported extractor types:
    - ``regex``: collect regex matches (group 1 if present) from the part.
    - ``kval``: collect the values of the named response headers.
    """
    found: list[str] = []
    for ex in extractors or []:
        ex_type = ex.get("type", "regex")
        part = ex.get("part", "body")
        if ex_type == "regex":
            text = _part_text(part, body, headers)
            for pat in ex.get("regex", []):
                try:
                    for m in re.finditer(pat, text):
                        found.append(m.group(1) if m.groups() else m.group(0))
                except re.error:
                    continue
        elif ex_type == "kval" and headers:
            lowered = {k.lower(): v for k, v in headers.items()}
            for key in ex.get("kval", []):
                if key.lower() in lowered:
                    found.append(f"{key}: {lowered[key.lower()]}")
    # De-duplicate while preserving order.
    return list(dict.fromkeys(found))


class VulnScanModule(BaseModule):
    name = "vulnscan"
    description = "YAML-based Vulnerability Detection Engine"

    async def run(self, target: str) -> ModuleResult:
        self._start_timer()
        results: list[dict[str, Any]] = []
        stats = {"templates_loaded": 0, "vulns_found": 0, "requests_sent": 0}

        if not target.startswith("http"):
            target = f"http://{target}"

        # Ensure trailing slash removed for clean urljoin
        if target.endswith("/"):
            target = target[:-1]

        # Load templates
        templates_dir = get_data_path("templates")
        template_files = []

        if os.path.exists(templates_dir):
            for root, _, files in os.walk(templates_dir):
                for file in files:
                    if file.endswith((".yaml", ".yml")):
                        template_files.append(os.path.join(root, file))

        if not template_files:
            self.logger.warning(f"No YAML templates found in {templates_dir}")
            return self._make_result(target, results, stats)

        templates = []
        for t_file in template_files:
            try:
                with open(t_file, "r", encoding="utf-8") as f:
                    template_data = yaml.safe_load(f)
                    if template_data and "id" in template_data and "requests" in template_data:
                        templates.append(template_data)
                        stats["templates_loaded"] += 1
            except Exception as e:
                self.logger.error(f"Failed to load template {t_file}: {e}")

        self.logger.info(f"Loaded {stats['templates_loaded']} vulnerability templates. Scanning {target}...")

        sem = asyncio.Semaphore(self.config.threads)

        async def execute_template(template: dict):
            vulns = []
            # Top-level condition combining multiple matcher blocks together
            # (separate from each matcher's own internal 'condition' field,
            # which only applies to that matcher's own list of values).
            matchers_condition = template.get("matchers-condition", "or")

            # Placeholder values available to templates.
            parsed = urlparse(target)
            placeholders = {
                "{{BaseURL}}": target,
                "{{RootURL}}": f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme else target,
                "{{Hostname}}": parsed.netloc or target,
                "{{Host}}": parsed.hostname or target,
            }

            def expand(text: str) -> str:
                for key, value in placeholders.items():
                    text = text.replace(key, value)
                return text

            for req in template.get("requests", []):
                method = req.get("method", "GET")
                path = req.get("path", "/")

                # Dynamic placeholder support in path
                if any(k in path for k in placeholders):
                    test_url = expand(path)
                else:
                    test_url = target + path

                headers = {k: expand(str(v)) for k, v in req.get("headers", {}).items()}
                matchers = req.get("matchers", [])
                extractors = req.get("extractors", [])

                async with sem:
                    stats["requests_sent"] += 1
                    try:
                        response = await self.engine.request(
                            method=method,
                            url=test_url,
                            headers=headers,
                            allow_redirects=False
                        )

                        if response.get("error"):
                            continue

                        status = response.get("status", 0)
                        body = response.get("body", "")
                        resp_headers = response.get("headers", {})

                        matched = evaluate_matchers(
                            matchers, status, body, matchers_condition, headers=resp_headers
                        )

                        if matched:
                            vuln_info = template.get("info", {})
                            item = {
                                "vuln_id": template.get("id"),
                                "name": vuln_info.get("name", "Unknown"),
                                "severity": vuln_info.get("severity", "info"),
                                "url": test_url,
                            }
                            extracted = run_extractors(extractors, body, resp_headers)
                            if extracted:
                                item["extracted"] = extracted
                            vulns.append(item)
                            stats["vulns_found"] += 1
                            self.logger.success(f"Vulnerability Found: {item['name']} [{item['severity'].upper()}] at {test_url}")

                    except Exception:
                        pass
            return vulns

        tasks = [execute_template(t) for t in templates]
        responses = await asyncio.gather(*tasks)

        for r in responses:
            if r:
                results.extend(r)

        return self._make_result(target, results, stats)
