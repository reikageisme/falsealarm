"""
sqli — SQL injection detection (query params, POST bodies, and login forms).

What it does:
  * Enumerates injectable parameters from the URL query string, and — when the
    page is an HTML form — from the form fields.
  * Runs error-, boolean- and time-based detection on each, re-verifying every
    hit so single-response flukes never become findings.
  * Detects classic ``' OR '1'='1`` authentication bypass on login forms.

What it is NOT: an exploitation/dump tool. Confirmed findings should be handed
to sqlmap for extraction. This keeps FalseAlarm a fast, safe detector that fits
a daily recon pipeline.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

from falsealarm.core.injection.body import get_path as _get
from falsealarm.core.injection.forms import INTERESTING, _FormParser
from falsealarm.core.sqli.detector import LoginProbe, SQLiDetector, detect_auth_bypass
from falsealarm.modules.base import BaseModule, ModuleResult


class SQLiModule(BaseModule):
    name = "sqli"
    description = "SQL injection detection (params, forms, login auth-bypass)"

    async def run(self, target: str) -> ModuleResult:
        self._start_timer()
        results: list[dict[str, Any]] = []
        stats = {"params_tested": 0, "forms_tested": 0, "vulnerable": 0, "login_forms": 0}

        if not target.startswith("http"):
            target = f"http://{target}"

        techniques = self._techniques()
        time_delay = int(getattr(self.config, "sqli_delay", 5) or 5)

        # 0) Explicit request body (-d/--data): inject SQL into each field.
        if getattr(self.config, "data", None):
            await self._test_body(target, results, stats, techniques, time_delay)
            return self._make_result(target, results, stats)

        baseline = await self.engine.get(target)
        if baseline.get("error"):
            self.logger.debug(f"sqli: baseline request failed for {target}: {baseline.get('error')}")
            return self._make_result(target, results, stats)

        # 1) Query-string parameters -------------------------------------
        parsed = urlparse(target)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        for name, value in params:
            if not (INTERESTING.search(name) or value):
                continue
            stats["params_tested"] += 1
            found = await self._test_query_param(parsed, params, name, techniques, time_delay)
            if found:
                results.append(found)
                stats["vulnerable"] += 1

        # 2) Forms on the page -------------------------------------------
        if "<form" in (baseline.get("body") or "").lower():
            forms = _FormParser()
            try:
                forms.feed(baseline.get("body", ""))
            except Exception:
                forms.forms = []
            for form in forms.forms:
                await self._test_form(target, form, results, stats, techniques, time_delay)

        return self._make_result(target, results, stats)

    async def _test_body(self, target, results, stats, techniques, time_delay):
        """Inject SQL payloads into each field of an explicit request body."""
        from falsealarm.core.injection.body import (
            field_label,
            leaf_paths,
            parse_body,
            serialize,
            set_path,
        )

        method = (getattr(self.config, "method", None) or "POST").upper()
        kind, obj = parse_body(self.config.data)
        extra_headers = self.config.header_dict()
        paths = leaf_paths(obj) if kind == "json" else [(k,) for k in obj]

        async def send_body(path, payload: str) -> dict:
            original = _get(obj, path) if kind == "json" else obj.get(path[0], "")
            mutated = set_path(obj, path, f"{original}{payload}") if kind == "json" else {**obj, path[0]: f"{original}{payload}"}
            body, ctype = serialize(kind, mutated)
            headers = {**extra_headers, "Content-Type": ctype}
            return await self.engine.request(method, target, data=body.encode("utf-8", "surrogateescape"),
                                             headers=headers, allow_redirects=False)

        baseline = await send_body(paths[0] if paths else (), "") if paths else await self.engine.get(target)
        for path in paths:
            stats["params_tested"] += 1
            detector = SQLiDetector(baseline, time_delay=time_delay)

            async def send(payload: str, _p=path) -> dict:
                return await send_body(_p, payload)

            result = await detector.probe_parameter(send, techniques)
            if result:
                result.parameter = field_label(path)
                result.where = "body"
                result.extra["url"] = target
                result.extra["method"] = method
                self.logger.finding_hook(result)
                results.append(result.to_dict())
                stats["vulnerable"] += 1

    # ------------------------------------------------------------------ #
    def _techniques(self) -> tuple[str, ...]:
        raw = getattr(self.config, "sqli_techniques", None)
        if raw:
            picked = tuple(t.strip().lower() for t in raw if t.strip() in ("error", "boolean", "time"))
            if picked:
                return picked
        # Time-based is slow and noisy; include it only on deeper profiles.
        if getattr(self.config, "depth", "normal") in ("deep", "insane"):
            return ("error", "boolean", "time")
        return ("error", "boolean")

    async def _test_query_param(self, parsed, params, name, techniques, time_delay):
        baseline = await self.engine.get(urlunparse(parsed))
        detector = SQLiDetector(baseline, time_delay=time_delay)

        async def send(payload: str) -> dict:
            injected = [(k, (v + payload if k == name else v)) for k, v in params]
            url = urlunparse(parsed._replace(query=urlencode(injected)))
            return await self.engine.get(url)

        result = await detector.probe_parameter(send, techniques)
        if result:
            result.parameter = name
            result.where = "query"
            result.extra["url"] = urlunparse(parsed._replace(query=""))
            self.logger.finding_hook(result)
            return result.to_dict()
        return None

    async def _test_form(self, page_url, form, results, stats, techniques, time_delay):
        action = urljoin(page_url, form.action) if form.action else page_url
        stats["forms_tested"] += 1

        async def submit(fields: dict) -> dict:
            if form.method == "post":
                return await self.engine.post(action, data=fields, allow_redirects=False)
            query = urlencode(fields)
            sep = "&" if urlparse(action).query else "?"
            return await self.engine.get(f"{action}{sep}{query}", allow_redirects=False)

        # Login form: try auth bypass first — it is the highest-value check.
        if form.is_login:
            stats["login_forms"] += 1
            user_f, pass_f = form.user_field(), form.pass_field()
            if user_f and pass_f:
                base_fields = dict(form.fields)

                async def login_submit(username: str, password: str) -> dict:
                    fields = dict(base_fields)
                    fields[user_f] = username
                    fields[pass_f] = password
                    return await submit(fields)

                bypass = await detect_auth_bypass(LoginProbe(submit=login_submit))
                if bypass:
                    bypass.extra["url"] = action
                    bypass.parameter = user_f
                    self.logger.finding_hook(bypass)
                    results.append(bypass.to_dict())
                    stats["vulnerable"] += 1

        # Error/boolean/time injection on each meaningful field.
        for field_name, field_type in form.types.items():
            if field_type in ("submit", "button", "image", "file", "checkbox", "radio"):
                continue
            base_fields = dict(form.fields)
            baseline = await submit(base_fields)
            if baseline.get("error"):
                continue
            detector = SQLiDetector(baseline, time_delay=time_delay)

            async def send(payload: str, _f=field_name, _base=base_fields) -> dict:
                fields = dict(_base)
                fields[_f] = (_base.get(_f) or "x") + payload
                return await submit(fields)

            result = await detector.probe_parameter(send, techniques)
            if result:
                result.parameter = field_name
                result.where = "body" if form.method == "post" else "query"
                result.extra["url"] = action
                result.extra["method"] = form.method.upper()
                self.logger.finding_hook(result)
                results.append(result.to_dict())
                stats["vulnerable"] += 1
