"""Tests for the SQL injection detector and module (no network: fake engines)."""

import asyncio

import pytest

from falsealarm.core.injection.forms import _FormParser
from falsealarm.core.sqli.detector import LoginProbe, SQLiDetector, detect_auth_bypass
from falsealarm.core.sqli.signatures import match_dbms_error

# --------------------------------------------------------------------------- #
# Error signatures
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("body,dbms", [
    ("You have an error in your SQL syntax; check the manual that corresponds to your MySQL", "MySQL"),
    ("Unclosed quotation mark after the character string", "Microsoft SQL Server"),
    ("PostgreSQL ERROR: unterminated quoted string at or near", "PostgreSQL"),
    ("Warning: pg_query(): query failed", "PostgreSQL"),
    ("ORA-01756: quoted string not properly terminated", "Oracle"),
    ('near "foo": syntax error', "SQLite"),
    ("just a normal page with no database error", None),
])
def test_error_signatures(body, dbms):
    assert match_dbms_error(body) == dbms


# --------------------------------------------------------------------------- #
# Detector (fake sender)
# --------------------------------------------------------------------------- #

def _run(coro):
    return asyncio.run(coro)


def test_error_based_detection():
    baseline = {"status": 200, "body": "<html>Product Widget</html>"}
    det = SQLiDetector(baseline)

    async def send(payload):
        if payload.count("'") % 2 == 1:  # unbalanced quote -> DB error
            return {"status": 500, "body": "SQL syntax; check the manual that corresponds to your MySQL server", "elapsed": 0}
        return {"status": 200, "body": "<html>Product Widget</html>", "elapsed": 0}

    result = _run(det.probe_parameter(send, ("error",)))
    assert result is not None and result.technique == "error" and result.dbms == "MySQL"


def test_boolean_based_detection():
    base = "<html>Product: Widget Pro, price $9.99, in stock across our stores</html>"
    det = SQLiDetector({"status": 200, "body": base})

    async def send(payload):
        if "1=2" in payload or "'1'='2" in payload:
            return {"status": 200, "body": "<html>Product not found</html>", "elapsed": 0}
        return {"status": 200, "body": base, "elapsed": 0}

    result = _run(det.probe_parameter(send, ("boolean",)))
    assert result is not None and result.technique == "boolean"


def test_boolean_no_false_positive_when_page_is_stable():
    base = "<html>static page, same for everything</html>"
    det = SQLiDetector({"status": 200, "body": base})

    async def send(payload):
        return {"status": 200, "body": base, "elapsed": 0}  # never changes

    assert _run(det.probe_parameter(send, ("boolean",))) is None


def test_time_based_requires_confirmation():
    det = SQLiDetector({"status": 200, "body": "ok"}, time_delay=2)

    async def send(payload):
        import re
        m = re.search(r"SLEEP\((\d+)\)|DELAY '0:0:(\d+)'|PG_SLEEP\((\d+)\)|RECEIVE_MESSAGE\('a',(\d+)\)", payload)
        secs = next((int(g) for g in (m.groups() if m else ()) if g), 0)
        return {"status": 200, "body": "ok", "elapsed": float(secs)}

    result = _run(det.probe_parameter(send, ("time",)))
    assert result is not None and result.technique == "time"


def test_time_based_ignores_uniformly_slow_server():
    det = SQLiDetector({"status": 200, "body": "ok"}, time_delay=2)

    async def send(payload):
        return {"status": 200, "body": "ok", "elapsed": 9.0}  # everything is slow

    # A decoy with no sleep is also slow -> not injectable.
    assert _run(det.probe_parameter(send, ("time",))) is None


def test_error_not_reported_when_baseline_already_errors():
    # App that always shows a DB error must not be flagged as newly injectable.
    det = SQLiDetector({"status": 200, "body": "ORA-00933: SQL command not properly ended"})

    async def send(payload):
        return {"status": 200, "body": "ORA-00933: SQL command not properly ended", "elapsed": 0}

    assert _run(det.probe_parameter(send, ("error",))) is None


# --------------------------------------------------------------------------- #
# Auth bypass
# --------------------------------------------------------------------------- #

def test_auth_bypass_detected_and_verified():
    async def submit(username, password):
        tu = username.upper().replace('"', "'")
        if "OR '1'='1" in tu or "OR 1=1" in tu or (username == "admin" and password == "secret"):
            return {"status": 200, "body": "Welcome to your dashboard and account overview"}
        return {"status": 200, "body": "Login failed: invalid username or password"}

    result = _run(detect_auth_bypass(LoginProbe(submit=submit)))
    assert result is not None and result.technique == "auth-bypass"


def test_auth_bypass_not_flagged_when_login_is_safe():
    async def submit(username, password):
        if username == "admin" and password == "secret":
            return {"status": 200, "body": "Welcome dashboard"}
        return {"status": 200, "body": "Login failed: invalid credentials"}

    assert _run(detect_auth_bypass(LoginProbe(submit=submit))) is None


def test_auth_bypass_handles_redirect_success():
    async def submit(username, password):
        if "OR '1'='1" in username.upper().replace('"', "'"):
            return {"status": 302, "body": "", "elapsed": 0}
        return {"status": 200, "body": "invalid login", "elapsed": 0}

    result = _run(detect_auth_bypass(LoginProbe(submit=submit)))
    assert result is not None and "redirect" in result.evidence


# --------------------------------------------------------------------------- #
# Form parsing
# --------------------------------------------------------------------------- #

def test_form_parser_identifies_login_form():
    html = """
    <form method="POST" action="/auth/login">
      <input type="text" name="email">
      <input type="password" name="pass">
      <input type="hidden" name="csrf" value="tok">
      <button type="submit">Go</button>
    </form>
    """
    parser = _FormParser()
    parser.feed(html)
    assert len(parser.forms) == 1
    form = parser.forms[0]
    assert form.is_login and form.method == "post"
    assert form.user_field() == "email" and form.pass_field() == "pass"
    assert form.fields["csrf"] == "tok"
