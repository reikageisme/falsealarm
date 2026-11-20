"""
Execute loaded templates against one target through FalseAlarm's AsyncEngine.

The executor is deliberately engine-agnostic: it only needs an object with an
``async request(method, url, headers=..., data=..., allow_redirects=...,
max_redirects=...)`` coroutine returning FalseAlarm's response dict. That keeps
rate limiting, proxies and fingerprinting in one place and makes the executor
trivial to unit-test with a fake engine.
"""

from __future__ import annotations

import asyncio
import itertools
import random
import string
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, urlparse

from falsealarm.core.templates.dsl import UnresolvedVariable, expand
from falsealarm.core.templates.loader import HTTPRequest, Template
from falsealarm.core.templates.matchers import build_response_context, extract_all, match_all

MAX_PAYLOAD_COMBINATIONS = 1000
# Headers aiohttp computes itself; forwarding stale raw values breaks requests.
_HOP_HEADERS = {"content-length", "transfer-encoding", "connection"}


_URL_SAFE = ":/?#[]@!$&'()*+,;=%~"


def safe_url(url: str) -> str:
    """Percent-encode only characters that are illegal on the wire.

    Existing escapes (``%2e``) and reserved characters are kept verbatim so
    traversal/encoding payloads reach the server exactly as the template wrote them.
    """
    return quote(url, safe=_URL_SAFE)


@dataclass
class PreparedRequest:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    allow_redirects: bool = False
    max_redirects: int = 10

    def cache_key(self) -> tuple:
        return (
            self.method, self.url, tuple(sorted(self.headers.items())), self.body,
            self.allow_redirects, self.max_redirects,
        )


def _randstr(n: int = 27) -> str:
    return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(n))


def target_variables(target: str) -> dict[str, Any]:
    """Placeholders nuclei derives from the input URL."""
    if "://" not in target:
        target = f"http://{target}"
    target = target.rstrip("/")
    p = urlparse(target)
    scheme = p.scheme or "http"
    port = p.port or (443 if scheme == "https" else 80)
    path = p.path or ""
    return {
        "BaseURL": target,
        "RootURL": f"{scheme}://{p.netloc}",
        "Hostname": p.netloc,
        "Host": p.hostname or p.netloc,
        "FQDN": p.hostname or p.netloc,
        "Port": str(port),
        "Path": path,
        "File": path.rsplit("/", 1)[-1] if "/" in path else "",
        "Scheme": scheme,
        "DN": p.hostname or "",
        "SD": "",
    }


def _payload_sets(req: HTTPRequest) -> list[dict[str, str]]:
    if not req.payloads:
        return [{}]
    keys = list(req.payloads)
    lists = [req.payloads[k] for k in keys]
    if req.attack == "clusterbomb":
        combos = itertools.islice(itertools.product(*lists), MAX_PAYLOAD_COMBINATIONS)
    else:  # batteringram / pitchfork: walk the lists in lockstep
        combos = itertools.islice(zip(*lists), MAX_PAYLOAD_COMBINATIONS)
    return [dict(zip(keys, combo)) for combo in combos]


def parse_raw_request(raw: str, ctx: dict[str, Any], merge_path: bool = True) -> PreparedRequest:
    """Parse a nuclei ``raw:`` request (already expanded) into a PreparedRequest."""
    text = raw.replace("\r\n", "\n").lstrip("\n")
    # Leading "@timeout: 10s" style annotations are engine hints; ignore them.
    lines = text.split("\n")
    while lines and lines[0].startswith("@"):
        lines.pop(0)
    if not lines or not lines[0].strip():
        raise ValueError("empty raw request")

    request_line = lines[0].strip().split(" ")
    if len(request_line) < 2:
        raise ValueError(f"bad request line: {lines[0]!r}")
    method, target = request_line[0].upper(), request_line[1]

    headers: dict[str, str] = {}
    idx = 1
    while idx < len(lines) and lines[idx].strip() != "":
        line = lines[idx]
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
        idx += 1
    body = "\n".join(lines[idx + 1:]) if idx < len(lines) else ""
    body = body.rstrip("\n")
    if body and "\r\n" in raw:
        body = body.replace("\n", "\r\n")

    if target.startswith(("http://", "https://")):
        url = target
    else:
        base_path = ctx.get("Path", "").rstrip("/") if merge_path else ""
        if not target.startswith("/"):
            target = "/" + target
        url = f"{ctx['RootURL']}{base_path}{target}"

    clean: dict[str, str] = {}
    for k, v in headers.items():
        lk = k.lower()
        if lk in _HOP_HEADERS:
            continue
        if lk == "host" and v in (ctx.get("Hostname"), ctx.get("Host")):
            continue  # aiohttp sets the correct Host itself
        clean[k] = v
    return PreparedRequest(method=method, url=safe_url(url), headers=clean, body=body)


def build_requests(req: HTTPRequest, ctx: dict[str, Any]) -> list[tuple[PreparedRequest, dict[str, str]]]:
    """Expand one request block into concrete requests (with payload values)."""
    out: list[tuple[PreparedRequest, dict[str, str]]] = []
    strict = not req.skip_variables_check
    for payload in _payload_sets(req):
        local = {**ctx, **payload}
        try:
            if req.raw:
                for raw in req.raw:
                    prepared = parse_raw_request(expand(raw, local, strict), local, not req.disable_path_automerge)
                    prepared.allow_redirects = req.redirects
                    prepared.max_redirects = req.max_redirects
                    out.append((prepared, payload))
            else:
                headers = {k: expand(v, local, strict) for k, v in req.headers.items()}
                body = expand(req.body, local, strict) if req.body else ""
                for path in req.paths:
                    url = expand(path, local, strict)
                    if not url.startswith(("http://", "https://")):
                        # Legacy FalseAlarm templates use bare paths ("/.env").
                        url = ctx["BaseURL"] + (url if url.startswith("/") else "/" + url)
                    out.append(
                        (
                            PreparedRequest(
                                method=req.method, url=safe_url(url), headers=headers, body=body,
                                allow_redirects=req.redirects, max_redirects=req.max_redirects,
                            ),
                            payload,
                        )
                    )
        except (UnresolvedVariable, ValueError):
            continue
    return out


class TemplateExecutor:
    """Runs templates against a single target, sharing a response cache."""

    def __init__(self, engine: Any, concurrency: int = 25, cache_size: int = 4096, oast: Any = None):
        self.engine = engine
        self.sem = asyncio.Semaphore(max(1, concurrency))
        self._cache: dict[tuple, asyncio.Future] = {}
        self._cache_size = cache_size
        self.requests_sent = 0
        self.cache_hits = 0
        self.errors = 0
        # Out-of-band (interactsh) session; set only when OAST templates run.
        self.oast = oast
        # Deferred OAST matcher evaluations, resolved after a final poll.
        self.oast_pending: list[dict] = []

    async def _send(self, prepared: PreparedRequest) -> dict:
        key = prepared.cache_key()
        cacheable = prepared.method in ("GET", "HEAD") and not prepared.body
        if cacheable and key in self._cache:
            self.cache_hits += 1
            return await self._cache[key]

        loop = asyncio.get_running_loop()
        fut: asyncio.Future = loop.create_future()
        if cacheable and len(self._cache) < self._cache_size:
            self._cache[key] = fut
        response: dict = {"url": prepared.url, "status": 0, "headers": {}, "body": "", "error": "cancelled"}
        try:
            async with self.sem:
                self.requests_sent += 1
                kwargs: dict[str, Any] = {
                    "headers": prepared.headers,
                    "allow_redirects": prepared.allow_redirects,
                    "raw_url": True,
                }
                if prepared.allow_redirects:
                    kwargs["max_redirects"] = prepared.max_redirects
                if prepared.body:
                    kwargs["data"] = prepared.body.encode("utf-8", errors="surrogateescape")
                response = await self.engine.request(prepared.method, prepared.url, **kwargs)
        except Exception as exc:  # never let one template kill the scan
            response = {"url": prepared.url, "status": 0, "headers": {}, "body": "", "error": str(exc)}
        finally:
            # Always resolve the shared future so concurrent waiters never hang.
            if not fut.done():
                fut.set_result(response)
        return response

    def _uses_oast(self, req: Any) -> bool:
        for m in req.matchers:
            if str(m.get("part", "")).startswith("interactsh"):
                return True
            if m.get("type") == "dsl" and any("interactsh" in str(d) for d in m.get("dsl", [])):
                return True
        return False

    async def run(self, template: Template, target: str) -> list[dict]:
        base = target_variables(target)
        ctx: dict[str, Any] = dict(base)
        ctx["randstr"] = _randstr()
        for i in range(1, 6):
            ctx[f"randstr_{i}"] = _randstr()

        # OAST: hand this template run a unique interactsh callback hostname.
        oast_uid = ""
        if template.needs_oast and self.oast is not None and self.oast.client.available:
            host, oast_uid = self.oast.register(template.id)
            ctx["interactsh-url"] = host

        # Template variables may reference each other and target placeholders.
        for key, value in template.variables.items():
            try:
                ctx[key] = expand(str(value), ctx, strict=True)
            except UnresolvedVariable:
                ctx[key] = str(value)

        findings: list[dict] = []
        seen: set[tuple] = set()
        counter = 0  # global request index -> body_1, body_2 ...

        for req in template.requests:
            last_ctx: dict[str, Any] | None = None
            stop = False
            gate_passed = False
            # A block whose matchers are all internal is a precondition for
            # the rest of the template: if it never matches, stop here.
            is_gate = bool(req.matchers) and all(m.get("internal") for m in req.matchers)
            for prepared, payload in build_requests(req, ctx):
                response = await self._send(prepared)
                if response.get("error"):
                    self.errors += 1
                    continue
                counter += 1
                resp_ctx = build_response_context(
                    int(response.get("status") or 0),
                    response.get("body") or "",
                    response.get("headers") or {},
                    float(response.get("elapsed") or 0.0),
                    prepared.url,
                )
                # History for later requests / req-condition: body_1, status_code_1 ...
                for k, v in resp_ctx.items():
                    ctx[f"{k}_{counter}"] = v
                eval_ctx = {**ctx, **payload, **resp_ctx, "host": urlparse(prepared.url).hostname or ""}

                values, dynamic = extract_all(req.extractors, eval_ctx)
                ctx.update(dynamic)
                eval_ctx.update(dynamic)
                last_ctx = eval_ctx

                if req.req_condition:
                    continue  # matchers run once the whole block has been sent

                # OAST matchers can only be judged after a poll; defer them.
                if oast_uid and self._uses_oast(req):
                    self.oast_pending.append({
                        "template": template, "uid": oast_uid, "eval_ctx": dict(eval_ctx),
                        "req": req, "url": prepared.url, "payload": dict(payload),
                    })
                    continue

                outcome = match_all(req.matchers, eval_ctx, req.matchers_condition)
                if outcome.matched:
                    gate_passed = True
                reportable = outcome.reportable or (not req.matchers and bool(values))
                if reportable:
                    self._record(findings, seen, template, prepared.url, outcome.names, values, payload)
                if outcome.matched and (req.stop_at_first_match or template.stop_at_first_match):
                    if reportable:
                        stop = True
                    break

            if req.req_condition and last_ctx is not None:
                outcome = match_all(req.matchers, last_ctx, req.matchers_condition)
                gate_passed = gate_passed or outcome.matched
                if outcome.reportable:
                    values, _ = extract_all(req.extractors, last_ctx)
                    self._record(
                        findings, seen, template, str(last_ctx.get("matched", target)), outcome.names, values, {}
                    )
            if stop or (is_gate and not gate_passed):
                break
        return findings

    async def resolve_oast(self, poll_wait: float = 6.0) -> list[dict]:
        """After all templates ran, poll for OAST interactions and judge the
        deferred interactsh matchers. Returns any new findings."""
        if not self.oast_pending or self.oast is None:
            return []
        # Give slow DNS/HTTP callbacks time to land, then sweep.
        await asyncio.sleep(max(0.0, poll_wait))
        await self.oast.collect()

        findings: list[dict] = []
        seen: set[tuple] = set()
        for entry in self.oast_pending:
            hits = self.oast.hits_for(entry["uid"])
            if not hits:
                continue
            protocols = ",".join(sorted({h.protocol for h in hits if h.protocol}))
            ctx = dict(entry["eval_ctx"])
            ctx["interactsh_protocol"] = protocols
            ctx["interactsh_request"] = hits[0].raw_request
            ctx["interactsh_interactions"] = [h.to_dict() for h in hits]
            req = entry["req"]
            outcome = match_all(req.matchers, ctx, req.matchers_condition)
            if outcome.matched and outcome.reportable:
                values, _ = extract_all(req.extractors, ctx)
                evidence = f"{protocols or 'oast'} interaction from {hits[0].remote_address or 'target'}"
                self._record(findings, seen, entry["template"], entry["url"], outcome.names,
                             values + [evidence], entry["payload"])
        self.oast_pending.clear()
        return findings

    @staticmethod
    def _record(
        findings: list[dict],
        seen: set[tuple],
        template: Template,
        url: str,
        names: list[str],
        values: list[str],
        payload: dict[str, str],
    ) -> None:
        key = (template.id, url, tuple(names))
        if key in seen:
            return
        seen.add(key)
        info = template.info
        item: dict[str, Any] = {
            "vuln_id": template.id,
            "name": template.name,
            "severity": template.severity,
            "url": url,
            "template": template.path,
        }
        if names:
            item["matcher_name"] = ", ".join(names)
        if values:
            item["extracted"] = values[:20]
        if payload:
            item["payload"] = payload
        tags = sorted(template.tags)
        if tags:
            item["tags"] = tags
        if info.get("description"):
            item["description"] = str(info["description"]).strip()[:500]
        refs = info.get("reference")
        if refs:
            item["reference"] = refs if isinstance(refs, list) else [str(refs)]
        classification = info.get("classification")
        if isinstance(classification, dict):
            item["classification"] = {
                k: v for k, v in classification.items() if k in ("cve-id", "cwe-id", "cvss-score", "cvss-metrics", "epss-score")
            }
        if info.get("remediation"):
            item["remediation"] = str(info["remediation"]).strip()[:500]
        findings.append(item)
