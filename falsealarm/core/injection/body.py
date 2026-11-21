"""
Request-body helpers for injecting into JSON and form bodies.

Used when a target is tested with an explicit request body (``-d/--data``),
e.g. a JSON login API ``POST /api/auth/login {"email":..,"password":..}``.
Enumerates the leaf fields, mutates one at a time, and serialises the body back
with the right content type, so the sqli/nosqli detectors can drive it through
their normal ``send(payload)`` interface.
"""

from __future__ import annotations

import copy
import json
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode

CREDENTIAL_USER = re.compile(r"user|email|login|account|phone|mobile|name|identifier", re.I)
CREDENTIAL_PASS = re.compile(r"pass|pwd|secret|credential", re.I)


def parse_body(raw: str) -> tuple[str, Any]:
    """Return ("json", obj) or ("form", dict). Falls back to form."""
    raw = (raw or "").strip()
    if raw[:1] in ("{", "["):
        try:
            return "json", json.loads(raw)
        except ValueError:
            pass
    return "form", dict(parse_qsl(raw, keep_blank_values=True))


def leaf_paths(obj: Any, prefix: tuple = ()) -> list[tuple]:
    """Paths to string/number leaves in a JSON structure (skips bool/null)."""
    out: list[tuple] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.extend(leaf_paths(v, prefix + (k,)))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out.extend(leaf_paths(v, prefix + (i,)))
    elif isinstance(obj, (str, int, float)) and not isinstance(obj, bool):
        out.append(prefix)
    return out


def get_path(obj: Any, path: tuple) -> Any:
    cur = obj
    for key in path:
        cur = cur[key]
    return cur


def set_path(obj: Any, path: tuple, value: Any) -> Any:
    """Return a deep copy of *obj* with *path* set to *value*."""
    clone = copy.deepcopy(obj)
    cur = clone
    for key in path[:-1]:
        cur = cur[key]
    if path:
        cur[path[-1]] = value
    return clone


def field_label(path: tuple) -> str:
    return ".".join(str(p) for p in path) if path else "body"


def serialize(kind: str, obj: Any) -> tuple[Any, str]:
    """Return (body, content_type) ready for the HTTP engine."""
    if kind == "json":
        return json.dumps(obj), "application/json"
    return urlencode({str(k): ("" if v is None else str(v)) for k, v in obj.items()}), \
        "application/x-www-form-urlencoded"


def credential_fields(kind: str, obj: Any) -> tuple[tuple | None, tuple | None]:
    """Best-effort (user_path, pass_path) for a login body."""
    paths = leaf_paths(obj) if kind == "json" else [(k,) for k in obj]
    user = next((p for p in paths if CREDENTIAL_USER.search(str(p[-1]))), None)
    passwd = next((p for p in paths if CREDENTIAL_PASS.search(str(p[-1]))), None)
    return user, passwd


def looks_like_login(kind: str, obj: Any) -> bool:
    _, passwd = credential_fields(kind, obj)
    return passwd is not None
