"""
ssti — server-side template injection detection (query params and forms).

Injects arithmetic payloads in each major template engine's syntax and reports
only when the server evaluates two different products. It is a detector; a
confirmed hit should be explored with tplmap for RCE.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

from falsealarm.core.injection.forms import _FormParser
from falsealarm.core.injection.ssti import SSTIDetector
from falsealarm.modules.base import BaseModule, ModuleResult


class SSTIModule(BaseModule):
    name = "ssti"
    description = "Server-side template injection detection (params, forms)"

    async def run(self, target: str) -> ModuleResult:
        self._start_timer()
        results: list[dict[str, Any]] = []
        stats = {"params_tested": 0, "forms_tested": 0, "vulnerable": 0}

        if not target.startswith("http"):
            target = f"http://{target}"

        baseline = await self.engine.get(target)
        if baseline.get("error"):
            self.logger.debug(f"ssti: baseline failed for {target}: {baseline.get('error')}")
            return self._make_result(target, results, stats)

        parsed = urlparse(target)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        for name, _value in params:
            stats["params_tested"] += 1
            found = await self._test_query_param(parsed, params, name)
            if found:
                results.append(found)
                stats["vulnerable"] += 1

        if "<form" in (baseline.get("body") or "").lower():
            forms = _FormParser()
            try:
                forms.feed(baseline.get("body", ""))
            except Exception:
                forms.forms = []
            for form in forms.forms:
                await self._test_form(target, form, results, stats)

        return self._make_result(target, results, stats)

    async def _test_query_param(self, parsed, params, name):
        baseline = await self.engine.get(urlunparse(parsed))
        detector = SSTIDetector(baseline)

        async def send(payload: str) -> dict:
            injected = [(k, (payload if k == name else v)) for k, v in params]
            url = urlunparse(parsed._replace(query=urlencode(injected)))
            return await self.engine.get(url)

        result = await detector.probe(send)
        if result:
            result.parameter = name
            result.where = "query"
            result.extra["url"] = urlunparse(parsed._replace(query=""))
            self.logger.finding_hook(result)
            return result.to_dict()
        return None

    async def _test_form(self, page_url, form, results, stats):
        action = urljoin(page_url, form.action) if form.action else page_url
        stats["forms_tested"] += 1

        async def submit(fields: dict) -> dict:
            if form.method == "post":
                return await self.engine.post(action, data=fields, allow_redirects=False)
            sep = "&" if urlparse(action).query else "?"
            return await self.engine.get(f"{action}{sep}{urlencode(fields)}", allow_redirects=False)

        for field_name, field_type in form.types.items():
            if field_type in ("submit", "button", "image", "file", "checkbox", "radio", "hidden"):
                continue
            base_fields = dict(form.fields)
            baseline = await submit(base_fields)
            if baseline.get("error"):
                continue
            detector = SSTIDetector(baseline)

            async def send(payload: str, _f=field_name, _base=base_fields) -> dict:
                fields = dict(_base)
                fields[_f] = payload
                return await submit(fields)

            result = await detector.probe(send)
            if result:
                result.parameter = field_name
                result.where = "body" if form.method == "post" else "query"
                result.extra["url"] = action
                result.extra["method"] = form.method.upper()
                self.logger.finding_hook(result)
                results.append(result.to_dict())
                stats["vulnerable"] += 1

