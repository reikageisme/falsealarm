"""
Shared helpers for injection modules: parameter heuristics and HTML form
parsing (used by sqli, ssti and nosqli).
"""

from __future__ import annotations

import re
from html.parser import HTMLParser

# Parameter names worth injecting even when the app echoes nothing.
INTERESTING = re.compile(r"id|user|name|email|search|q|query|cat|page|sort|order|file|key|token|num|code", re.I)


class _Form:
    def __init__(self, action: str, method: str):
        self.action = action
        self.method = method.lower() or "get"
        self.fields: dict[str, str] = {}
        self.types: dict[str, str] = {}

    @property
    def is_login(self) -> bool:
        return "password" in self.types.values() or any(
            re.search(r"pass|pwd", n, re.I) for n in self.fields
        )

    def user_field(self) -> str | None:
        for name in self.fields:
            if re.search(r"user|email|login|name|account", name, re.I):
                return name
        # Fall back to the first non-password, non-hidden text field.
        for name, typ in self.types.items():
            if typ not in ("password", "hidden", "submit", "checkbox"):
                return name
        return next(iter(self.fields), None)

    def pass_field(self) -> str | None:
        for name, typ in self.types.items():
            if typ == "password" or re.search(r"pass|pwd", name, re.I):
                return name
        return None


class _FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms: list[_Form] = []
        self._cur: _Form | None = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._cur = _Form(a.get("action", ""), a.get("method", "get"))
            self.forms.append(self._cur)
        elif tag in ("input", "textarea", "select") and self._cur is not None:
            name = a.get("name")
            if name:
                self._cur.fields[name] = a.get("value", "")
                self._cur.types[name] = a.get("type", "text").lower()

    def handle_endtag(self, tag):
        if tag == "form":
            self._cur = None


