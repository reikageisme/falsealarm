"""
Matcher and extractor evaluation against an HTTP response context.

A *response context* is a flat dict of DSL variables built from one response
(``body``, ``header``, ``status_code``, ``content_type`` …). Matchers and
extractors only ever read from it, which keeps them pure and unit-testable.
"""

from __future__ import annotations

import binascii
import json
import re
from dataclasses import dataclass, field
from typing import Any

from falsealarm.core.templates.dsl import compile_regex, evaluate, evaluate_bool, expand

# Part aliases used by nuclei templates.
_PART_ALIASES = {"all": "response", "raw": "response", "all_headers": "header", "status": "status_code"}


def header_text(status: int, headers: dict | None) -> str:
    lines = [f"HTTP/1.1 {status}"] if status else []
    for k, v in (headers or {}).items():
        lines.append(f"{k}: {v}")
    return "\r\n".join(lines)


def build_response_context(
    status: int,
    body: str,
    headers: dict | None = None,
    elapsed: float = 0.0,
    url: str = "",
) -> dict[str, Any]:
    """Build the DSL variables exposed for one HTTP response."""
    headers = headers or {}
    htext = header_text(status, headers)
    ctx: dict[str, Any] = {}
    for k, v in headers.items():
        ctx[k.lower().replace("-", "_")] = v
    content_length = len(body)
    for k, v in headers.items():
        if k.lower() == "content-length":
            try:
                content_length = int(v)
            except ValueError:
                pass
    ctx.update(
        {
            "body": body,
            "header": htext,
            "all_headers": htext,
            "response": f"{htext}\r\n\r\n{body}",
            "status_code": status,
            "content_length": content_length,
            "duration": elapsed,
            "matched": url,
        }
    )
    return ctx


def _part(ctx: dict[str, Any], part: str) -> str:
    part = (part or "body").strip()
    key = _PART_ALIASES.get(part, part)
    value = ctx.get(key)
    if value is None:
        return ""
    return value if isinstance(value, str) else str(value)


def _combine(hits: list[bool], condition: str) -> bool:
    if not hits:
        return False
    return all(hits) if condition == "and" else any(hits)


def match_one(matcher: dict, ctx: dict[str, Any]) -> bool:
    """Evaluate one matcher block (including ``negative``) against *ctx*."""
    m_type = matcher.get("type", "")
    condition = str(matcher.get("condition", "or")).lower()
    part = matcher.get("part", "body")
    case_insensitive = bool(matcher.get("case-insensitive"))
    result = False

    if m_type == "status":
        status = ctx.get("status_code", 0)
        result = status in [int(s) for s in matcher.get("status", []) if str(s).lstrip("-").isdigit()]

    elif m_type == "size":
        size = ctx.get("content_length", 0)
        result = size in [int(s) for s in matcher.get("size", []) if str(s).isdigit()]

    elif m_type == "word":
        text = _part(ctx, part)
        words = [expand(str(w), ctx, strict=False) for w in matcher.get("words", [])]
        if matcher.get("encoding") == "hex":
            words = [binascii.unhexlify(w).decode("latin-1", errors="replace") for w in words]
        if case_insensitive:
            text = text.lower()
            words = [w.lower() for w in words]
        result = _combine([w in text for w in words], condition)

    elif m_type == "regex":
        text = _part(ctx, part)
        flags = re.IGNORECASE if case_insensitive else 0
        hits = []
        for pat in matcher.get("regex", []):
            try:
                hits.append(compile_regex(str(pat), flags).search(text) is not None)
            except re.error:
                hits.append(False)
        result = _combine(hits, condition)

    elif m_type == "binary":
        data = _part(ctx, part).encode("utf-8", errors="surrogateescape")
        hits = []
        for hexval in matcher.get("binary", []):
            try:
                hits.append(binascii.unhexlify(str(hexval)) in data)
            except (binascii.Error, ValueError):
                hits.append(False)
        result = _combine(hits, condition)

    elif m_type == "dsl":
        result = _combine([evaluate_bool(str(e), ctx) for e in matcher.get("dsl", [])], condition)

    else:
        # Unknown matcher type: never treat as a pass.
        return False

    if matcher.get("negative"):
        result = not result
    return result


@dataclass
class MatchOutcome:
    matched: bool = False      # the matcher set as a whole passed
    reportable: bool = False   # ...and it should produce a finding
    names: list[str] = field(default_factory=list)


def match_all(matchers: list[dict], ctx: dict[str, Any], condition: str = "or") -> MatchOutcome:
    """Evaluate matcher blocks with nuclei semantics.

    ``internal: true`` matchers are gates (e.g. "page is 200 before we try the
    exploit request"): they take part in the decision but never produce a
    finding on their own.
    """
    if not matchers:
        return MatchOutcome()
    is_and = str(condition).lower() == "and"
    hits = [match_one(m, ctx) for m in matchers]
    matched = all(hits) if is_and else any(hits)
    if not matched:
        return MatchOutcome()
    public = [(m, hit) for m, hit in zip(matchers, hits) if not m.get("internal")]
    reportable = bool(public) if is_and else any(hit for _, hit in public)
    names = [str(m["name"]) for m, hit in public if hit and m.get("name")]
    return MatchOutcome(matched=True, reportable=reportable, names=names if reportable else [])


# --------------------------------------------------------------------------- #
# Extractors
# --------------------------------------------------------------------------- #

_JQ_TOKEN = re.compile(r'\.(?:([A-Za-z_][\w-]*)|\["([^"]+)"\])|\[(\d*)\]')


def _jq(data: Any, expr: str) -> list[Any]:
    """Tiny subset of jq: ``.a.b``, ``.a[]``, ``.a[0]``, ``.["k"]`` and ``|``."""
    current = [data]
    for stage in expr.split("|"):
        stage = stage.strip()
        if stage in (".", ""):
            continue
        pos = 0
        while pos < len(stage):
            m = _JQ_TOKEN.match(stage, pos)
            if not m:
                return []  # unsupported jq syntax -> no extraction
            key, quoted, index = m.group(1), m.group(2), m.group(3)
            nxt: list[Any] = []
            for item in current:
                if key is not None or quoted is not None:
                    k = key if key is not None else quoted
                    if isinstance(item, dict) and k in item:
                        nxt.append(item[k])
                elif index == "":
                    if isinstance(item, list):
                        nxt.extend(item)
                    elif isinstance(item, dict):
                        nxt.extend(item.values())
                else:
                    if isinstance(item, list) and int(index) < len(item):
                        nxt.append(item[int(index)])
            current = nxt
            pos = m.end()
    return current


def _stringify(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, separators=(",", ":"))


def extract_one(extractor: dict, ctx: dict[str, Any]) -> list[str]:
    e_type = extractor.get("type", "regex")
    part = extractor.get("part", "body")
    found: list[str] = []

    if e_type == "regex":
        text = _part(ctx, part)
        group = int(extractor.get("group", 0) or 0)
        flags = re.IGNORECASE if extractor.get("case-insensitive") else 0
        for pat in extractor.get("regex", []):
            try:
                for m in compile_regex(str(pat), flags).finditer(text):
                    try:
                        found.append(m.group(group))
                    except IndexError:
                        found.append(m.group(0))
            except re.error:
                continue

    elif e_type == "kval":
        lowered = {str(k).lower().replace("-", "_"): v for k, v in ctx.items() if isinstance(v, (str, int))}
        for key in extractor.get("kval", []):
            norm = str(key).lower().replace("-", "_")
            if norm in lowered and norm not in ("body", "response", "header", "all_headers"):
                found.append(str(lowered[norm]))

    elif e_type == "json":
        try:
            data = json.loads(_part(ctx, part))
        except ValueError:
            return []
        for expr in extractor.get("json", []):
            found.extend(_stringify(v) for v in _jq(data, str(expr)) if v is not None)

    elif e_type == "dsl":
        for expr in extractor.get("dsl", []):
            try:
                value = evaluate(str(expr), ctx)
            except Exception:
                continue
            if value not in (None, "", False):
                found.append(str(value))

    # xpath (and anything unknown) is ignored at runtime.
    return [v for v in dict.fromkeys(found) if v != ""]


def extract_all(extractors: list[dict], ctx: dict[str, Any]) -> tuple[list[str], dict[str, str]]:
    """Run extractors. Returns (reportable values, named dynamic variables)."""
    reported: list[str] = []
    dynamic: dict[str, str] = {}
    for ex in extractors or []:
        values = extract_one(ex, ctx)
        if not values:
            continue
        if ex.get("name"):
            dynamic[str(ex["name"])] = values[0]
        if not ex.get("internal"):
            reported.extend(values)
    return list(dict.fromkeys(reported)), dynamic
