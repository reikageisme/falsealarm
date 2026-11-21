"""Tests for request-body (JSON/form) injection and JSON login auth-bypass."""

import asyncio
import json

from falsealarm.core.injection.body import (
    credential_fields,
    leaf_paths,
    looks_like_login,
    parse_body,
    serialize,
    set_path,
)
from falsealarm.core.injection.nosqli import detect_json_login_bypass

# --------------------------------------------------------------------------- #
# Body helpers
# --------------------------------------------------------------------------- #

def test_parse_json_and_form():
    kind, obj = parse_body('{"email":"a","password":"b"}')
    assert kind == "json" and obj == {"email": "a", "password": "b"}
    kind, obj = parse_body("email=a&password=b")
    assert kind == "form" and obj == {"email": "a", "password": "b"}


def test_leaf_paths_nested():
    obj = {"user": {"email": "a", "age": 5}, "tags": ["x", "y"], "ok": True}
    paths = leaf_paths(obj)
    assert ("user", "email") in paths
    assert ("user", "age") in paths
    assert ("tags", 0) in paths
    assert ("ok",) not in paths  # bool skipped


def test_set_path_deep_copy():
    obj = {"a": {"b": 1}}
    out = set_path(obj, ("a", "b"), 99)
    assert out == {"a": {"b": 99}} and obj == {"a": {"b": 1}}  # original untouched


def test_set_path_with_operator_object():
    obj = {"email": "x", "password": "y"}
    out = set_path(obj, ("email",), {"$ne": None})
    assert out == {"email": {"$ne": None}, "password": "y"}


def test_credential_fields_and_login_detection():
    kind, obj = parse_body('{"email":"a","password":"b"}')
    user, passwd = credential_fields(kind, obj)
    assert user == ("email",) and passwd == ("password",)
    assert looks_like_login(kind, obj)
    kind, obj = parse_body('{"q":"search"}')
    assert not looks_like_login(kind, obj)


def test_serialize_json_and_form():
    body, ctype = serialize("json", {"a": {"$ne": None}})
    assert json.loads(body) == {"a": {"$ne": None}} and ctype == "application/json"
    body, ctype = serialize("form", {"a": "1", "b": "2"})
    assert ctype == "application/x-www-form-urlencoded" and "a=1" in body


# --------------------------------------------------------------------------- #
# JSON login auth-bypass
# --------------------------------------------------------------------------- #

def _run(coro):
    return asyncio.run(coro)


def test_json_bypass_via_nosql_operator():
    async def submit(user_val, pass_val):
        # Vulnerable: an operator object matches a user.
        if isinstance(user_val, dict) or isinstance(pass_val, dict):
            return {"status": 200, "body": '{"success":true,"token":"jwt"}'}
        return {"status": 401, "body": '{"message":"invalid email or password"}'}

    result = _run(detect_json_login_bypass(submit, ("email",), ("password",)))
    assert result is not None and result.technique == "auth-bypass"
    assert result.to_dict()["type"] == "nosqli"


def test_json_bypass_via_sql_tautology_reported_as_sqli():
    async def submit(user_val, pass_val):
        if isinstance(user_val, str) and "OR '1'='1" in user_val:
            return {"status": 200, "body": '{"success":true,"token":"jwt","dashboard":1}'}
        return {"status": 401, "body": '{"message":"invalid email or password"}'}

    result = _run(detect_json_login_bypass(submit, ("email",), ("password",)))
    assert result is not None
    assert result.to_dict()["type"] == "sqli"  # tautology -> SQL, not NoSQL


def test_json_bypass_not_flagged_when_safe():
    async def submit(user_val, pass_val):
        # Rejects non-strings and never bypasses.
        if not isinstance(user_val, str) or not isinstance(pass_val, str):
            return {"status": 401, "body": '{"message":"invalid email or password"}'}
        if user_val == "admin@x.com" and pass_val == "secret":
            return {"status": 200, "body": '{"success":true}'}
        return {"status": 401, "body": '{"message":"invalid email or password"}'}

    assert _run(detect_json_login_bypass(submit, ("email",), ("password",))) is None


def test_json_bypass_requires_control_to_fail():
    # A server that "succeeds" for everything must not be flagged (control check).
    async def submit(user_val, pass_val):
        return {"status": 200, "body": '{"success":true,"token":"x"}'}

    assert _run(detect_json_login_bypass(submit, ("email",), ("password",))) is None
