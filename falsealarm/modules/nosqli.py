"""
nosqli — NoSQL injection detection (operator injection, JS boolean, auth-bypass).

Rewrites ``id=1`` into MongoDB operator form (``id[$ne]=1`` / ``id[$eq]=1``) and
compares responses, appends ``$where`` JS boolean payloads, watches for NoSQL
driver errors, and tries operator-based login bypass. Detection only.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

from falsealarm.core.injection.forms import INTERESTING, _FormParser
from falsealarm.core.injection.nosqli import (
    NoSQLiDetector,
    NoSQLLoginProbe,
    detect_nosql_auth_bypass,
)
from falsealarm.modules.base import BaseModule, ModuleResult


class NoSQLiModule(BaseModule):
    name = "nosqli"
    description = "NoSQL injection detection (operator injection, login bypass)"

    async def run(self, target: str) -> ModuleResult:
        self._start_timer()
        results: list[dict[str, Any]] = []
        stats = {"params_tested": 0, "forms_tested": 0, "login_forms": 0, "vulnerable": 0}

        if not target.startswith("http"):
            target = f"http://{target}"

        # 0) Explicit request body (-d/--data): operator injection + JSON login bypass.
        if getattr(self.config, "data", None):
            await self._test_body(target, results, stats)
            return self._make_result(target, results, stats)

        baseline = await self.engine.get(target)
        if baseline.get("error"):
            self.logger.debug(f"nosqli: baseline failed for {target}: {baseline.get('error')}")
            return self._make_result(target, results, stats)

        parsed = urlparse(target)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        for name, value in params:
            if not (INTERESTING.search(name) or value):
                continue
            stats["params_tested"] += 1
            found = await self._test_query_param(parsed, params, name, value)
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

    async def _test_body(self, target, results, stats):
        """Operator injection on each JSON/form field, plus JSON login bypass."""
        from falsealarm.core.injection.body import (
            credential_fields,
            field_label,
            get_path,
            leaf_paths,
            looks_like_login,
            parse_body,
            serialize,
            set_path,
        )
        from falsealarm.core.injection.nosqli import detect_json_login_bypass

        method = (getattr(self.config, "method", None) or "POST").upper()
        kind, obj = parse_body(self.config.data)
        extra_headers = self.config.header_dict()
        paths = leaf_paths(obj) if kind == "json" else [(k,) for k in obj]

        async def submit(mutated) -> dict:
            body, ctype = serialize(kind, mutated)
            headers = {**extra_headers, "Content-Type": ctype}
            return await self.engine.request(method, target, data=body.encode("utf-8", "surrogateescape"),
                                             headers=headers, allow_redirects=False)

        # Login auth-bypass (SQL tautology + NoSQL operator objects) first.
        if looks_like_login(kind, obj):
            stats["login_forms"] += 1
            user_p, pass_p = credential_fields(kind, obj)
            if user_p and pass_p:
                async def login_submit(user_val, pass_val) -> dict:
                    mutated = set_path(set_path(obj, user_p, user_val), pass_p, pass_val)
                    return await submit(mutated)

                bypass = await detect_json_login_bypass(login_submit, user_p, pass_p)
                if bypass:
                    bypass.extra["url"] = target
                    bypass.extra["method"] = method
                    self.logger.finding_hook(bypass)
                    results.append(bypass.to_dict())
                    stats["vulnerable"] += 1

        # Operator injection on each field: field=orig -> field={$ne: orig}.
        for path in paths:
            stats["params_tested"] += 1
            original = get_path(obj, path)
            baseline = await submit(obj)
            detector = NoSQLiDetector(baseline)

            def op_sender(operator):
                async def _send(_payload: str, _p=path, _op=operator) -> dict:
                    return await submit(set_path(obj, _p, {_op: original}))
                return _send

            result = await detector.operator_injection(op_sender("$ne"), op_sender("$eq"))
            if result:
                result.parameter = field_label(path)
                result.where = "body"
                result.extra["url"] = target
                result.extra["method"] = method
                self.logger.finding_hook(result)
                results.append(result.to_dict())
                stats["vulnerable"] += 1

    async def _test_query_param(self, parsed, params, name, value):
        baseline = await self.engine.get(urlunparse(parsed))
        detector = NoSQLiDetector(baseline)

        async def send(payload: str) -> dict:
            injected = [(k, (v + payload if k == name else v)) for k, v in params]
            return await self.engine.get(urlunparse(parsed._replace(query=urlencode(injected))))

        def operator_sender(op: str):
            async def _send(_payload: str) -> dict:
                # id=1 -> id[$ne]=1 (drop the plain key, add the operator key).
                injected = [(k, v) for k, v in params if k != name]
                injected.append((f"{name}[{op}]", value))
                return await self.engine.get(urlunparse(parsed._replace(query=urlencode(injected))))
            return _send

        result = (
            await detector.error_based(send)
            or await detector.operator_injection(operator_sender("$ne"), operator_sender("$eq"))
            or await detector.js_boolean(send)
        )
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

        if form.is_login:
            stats["login_forms"] += 1
            user_f, pass_f = form.user_field(), form.pass_field()
            if user_f and pass_f:
                base_fields = {k: v for k, v in form.fields.items() if k not in (user_f, pass_f)}

                async def login_submit(fields: dict) -> dict:
                    return await submit({**base_fields, **fields})

                bypass = await detect_nosql_auth_bypass(
                    NoSQLLoginProbe(submit=login_submit, user_field=user_f, pass_field=pass_f)
                )
                if bypass:
                    bypass.extra["url"] = action
                    bypass.extra["method"] = form.method.upper()
                    self.logger.finding_hook(bypass)
                    results.append(bypass.to_dict())
                    stats["vulnerable"] += 1
