"""Tests for the SSTI and NoSQLi detectors (no network: fake senders)."""

import asyncio
import re

from falsealarm.core.findings import collect_findings, finding_from_injection
from falsealarm.core.injection.nosqli import (
    NoSQLiDetector,
    NoSQLLoginProbe,
    detect_nosql_auth_bypass,
    match_nosql_error,
)
from falsealarm.core.injection.ssti import SSTIDetector


def _run(coro):
    return asyncio.run(coro)


# --------------------------------------------------------------------------- #
# SSTI
# --------------------------------------------------------------------------- #

def test_ssti_jinja_evaluated():
    det = SSTIDetector({"status": 200, "body": "Hello guest"})

    async def send(payload):
        # Evaluate {{ a*b }} like a vulnerable Jinja2 app.
        m = re.search(r"\{\{\s*(\d+)\*(\d+)\s*\}\}", payload)
        body = f"Hello {int(m.group(1)) * int(m.group(2))}" if m else f"Hello {payload}"
        return {"status": 200, "body": body}

    result = _run(det.probe(send))
    assert result is not None and "Jinja" in result.engine


def test_ssti_reflected_but_not_evaluated_is_not_flagged():
    det = SSTIDetector({"status": 200, "body": "Hello guest"})

    async def send(payload):
        return {"status": 200, "body": f"Hello {payload}"}  # reflects verbatim, no eval

    assert _run(det.probe(send)) is None


def test_ssti_page_containing_product_by_chance_not_flagged():
    # Page always contains 11111 but never evaluates the second product.
    det = SSTIDetector({"status": 200, "body": "order 11111"})

    async def send(payload):
        return {"status": 200, "body": "order 11111 " + payload}

    assert _run(det.probe(send)) is None


def test_ssti_erb_engine_detected():
    det = SSTIDetector({"status": 200, "body": "x"})

    async def send(payload):
        m = re.search(r"<%=\s*(\d+)\*(\d+)\s*%>", payload)
        if m:
            return {"status": 200, "body": str(int(m.group(1)) * int(m.group(2)))}
        return {"status": 200, "body": payload}

    result = _run(det.probe(send))
    assert result is not None and "ERB" in result.engine


# --------------------------------------------------------------------------- #
# NoSQLi
# --------------------------------------------------------------------------- #

def test_nosql_error_signatures():
    assert match_nosql_error("MongoError: E11000 duplicate key")
    assert match_nosql_error("CastError: Cast to ObjectId failed")
    assert not match_nosql_error("<html>normal page</html>")


def test_nosql_operator_injection_detected():
    base = "Results: Alice"
    det = NoSQLiDetector({"status": 200, "body": base})

    async def ne(_):
        return {"status": 200, "body": "Results: Bob, Carol, Dave, Eve"}  # $ne -> other rows

    async def eq(_):
        return {"status": 200, "body": base}  # $eq -> same as baseline

    result = _run(det.operator_injection(ne, eq))
    assert result is not None and result.technique == "operator"


def test_nosql_operator_no_false_positive_when_stable():
    base = "Results: static content that never varies at all"
    det = NoSQLiDetector({"status": 200, "body": base})

    async def same(_):
        return {"status": 200, "body": base}

    assert _run(det.operator_injection(same, same)) is None


def test_nosql_error_based():
    det = NoSQLiDetector({"status": 200, "body": "ok"})

    async def send(payload):
        if "'" in payload or "{" in payload:
            return {"status": 500, "body": "MongoServerError: unterminated string literal"}
        return {"status": 200, "body": "ok"}

    result = _run(det.error_based(send))
    assert result is not None and result.technique == "error"


def test_nosql_auth_bypass():
    async def submit(fields):
        user_ops = [k for k in fields if k.startswith("user[$")]
        pass_ops = [k for k in fields if k.startswith("pass[$")]
        # Only $ne / $gt / $regex bypass; $eq to a bogus value fails.
        bypass_ops = [k for k in user_ops + pass_ops if any(op in k for op in ("$ne", "$gt", "$regex"))]
        if len(bypass_ops) >= 2:
            return {"status": 200, "body": "Welcome to your dashboard and account overview"}
        return {"status": 200, "body": "Login failed: invalid credentials"}

    result = _run(detect_nosql_auth_bypass(
        NoSQLLoginProbe(submit=submit, user_field="user", pass_field="pass")))
    assert result is not None and result.technique == "auth-bypass"


def test_nosql_auth_bypass_not_flagged_when_safe():
    async def submit(fields):
        if fields.get("user") == "admin" and fields.get("pass") == "secret":
            return {"status": 200, "body": "Welcome dashboard"}
        return {"status": 200, "body": "Login failed: invalid credentials"}

    result = _run(detect_nosql_auth_bypass(
        NoSQLLoginProbe(submit=submit, user_field="user", pass_field="pass")))
    assert result is None


# --------------------------------------------------------------------------- #
# Findings integration
# --------------------------------------------------------------------------- #

def test_injection_findings_titles():
    ssti = finding_from_injection({"type": "ssti", "engine": "Twig", "parameter": "q",
                                   "url": "http://t/", "payload": "{{41*271}}", "where": "query"})
    assert ssti.severity == "critical" and "template injection" in ssti.title.lower() and "Twig" in ssti.title

    nosql = finding_from_injection({"type": "nosqli", "technique": "auth-bypass", "parameter": "user",
                                    "url": "http://t/login", "payload": "user[$ne]=", "where": "login"})
    assert "NoSQL injection auth-bypass" in nosql.title

    results = {"ssti": {"data": [ssti.to_dict() if hasattr(ssti, "to_dict") else {
        "type": "ssti", "engine": "Twig", "parameter": "q", "url": "http://t/", "payload": "x"}]}}
    assert len(collect_findings(results)) == 1
