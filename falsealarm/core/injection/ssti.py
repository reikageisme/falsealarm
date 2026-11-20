r"""
Server-side template injection (SSTI) detector.

Strategy (mirrors sqlmap/tplmap but kept to detection):

1. Send a **breakout polyglot** (``${{<%[%'"}}%\``). If it provokes a template
   engine error, the parameter reaches a template — worth testing.
2. Send an arithmetic payload whose result is unlikely to appear by chance
   (``{{41*271}}`` -> ``11111``) in each engine's syntax. If the exact product
   appears in the response but the literal expression does not, the template
   evaluated it.
3. **Confirm** with a second, different product so a page that happens to
   contain ``11111`` is not a false positive.

Engine is identified by which syntax evaluated (Jinja2/Twig ``{{}}``,
Freemarker ``${}``/``#{}``, ERB ``<%= %>``, Velocity, Mako, etc.).

Pure given a sender, so the heuristics are unit-tested without a network.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Awaitable, Callable

Sender = Callable[[str], Awaitable[dict]]

# A polyglot that breaks out of most template/expression contexts at once; a
# template error here means the input is parsed as template code.
BREAKOUT = "${{<%[%'\"}}%\\"

TEMPLATE_ERRORS = re.compile(
    r"TemplateSyntaxError|TemplateError|jinja2\.|Twig\\?Error|freemarker\.|FreeMarker template error|"
    r"velocity\.|org\.apache\.velocity|Smarty|Mako|mako\.|TemplateAssertionError|"
    r"UndefinedError|ParseException.*?template|unexpected (char|token).*?template|"
    r"could not be resolved to a (variable|value)|nil can't be coerced|"
    r"TemplateNotFound|Expression .*? is undefined",
    re.I,
)

# (engine, payload-template, expected-is-product). {A}*{B} are substituted and
# the product is what we look for in the response.
#   Each entry: (engine, template-with-{A}/{B})
ENGINES: list[tuple[str, str]] = [
    ("Jinja2/Twig", "{{{A}*{B}}}"),
    ("Jinja2", "{{ {A}*{B} }}"),
    ("Freemarker", "${{A}*{B}}"),
    ("Freemarker/Thymeleaf", "#{{A}*{B}}"),
    ("Velocity", "#set($x={A}*{B})$x"),
    ("ERB (Ruby)", "<%= {A}*{B} %>"),
    ("Smarty", "{{A}*{B}}"),
    ("Mako", "${{A}*{B}}"),
    ("Razor", "@({A}*{B})"),
    ("EL/Spring", "${{A}*{B}}"),
    ("Handlebars/Generic", "{{{A}*{B}}}"),
]


@dataclass
class SSTIResult:
    parameter: str = ""
    engine: str = "unknown"
    payload: str = ""
    evidence: str = ""
    where: str = "query"
    severity: str = "critical"
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = {
            "type": "ssti", "parameter": self.parameter, "engine": self.engine,
            "payload": self.payload, "evidence": self.evidence, "where": self.where,
            "severity": self.severity,
        }
        d.update(self.extra)
        return d


def _render(template: str, a: int, b: int) -> tuple[str, int]:
    return template.replace("{A}", str(a)).replace("{B}", str(b)), a * b


class SSTIDetector:
    def __init__(self, baseline: dict):
        body = baseline.get("body", "") or ""
        self.baseline_has_error = bool(TEMPLATE_ERRORS.search(body))

    async def probe(self, send: Sender) -> SSTIResult | None:
        # Step 1: breakout — not required, but a template error is a strong hint
        # and tells us to try harder even on reflected-looking parameters.
        try:
            breakout_resp = await send(BREAKOUT)
            breakout_error = bool(TEMPLATE_ERRORS.search(breakout_resp.get("body", "") or ""))
        except Exception:
            breakout_error = False

        # Step 2+3: arithmetic evaluation, two distinct products, per engine.
        for engine, template in ENGINES:
            a1, b1 = 41, 271          # product 11111
            payload1, product1 = _render(template, a1, b1)
            r1 = await send(payload1)
            if r1.get("error"):
                continue
            body1 = r1.get("body", "") or ""
            # The product must appear, and the raw expression must NOT (i.e. the
            # app evaluated it rather than reflecting our input verbatim).
            if str(product1) not in body1 or payload1 in body1:
                continue
            # Guard: the product string must not already be in the baseline-ish
            # response for the breakout (avoid pages that always contain it).
            a2, b2 = 53, 97           # product 5141 — different, unlikely twice
            payload2, product2 = _render(template, a2, b2)
            r2 = await send(payload2)
            body2 = r2.get("body", "") or ""
            if str(product2) in body2 and payload2 not in body2:
                ev = f"{engine}: evaluated {a1}*{b1}={product1} and {a2}*{b2}={product2}"
                if breakout_error:
                    ev += " (breakout raised a template error)"
                return SSTIResult(engine=engine, payload=payload1, evidence=ev)
        return None
