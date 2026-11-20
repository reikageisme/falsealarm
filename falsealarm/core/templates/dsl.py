"""
Safe evaluator for the nuclei template DSL.

Nuclei expressions (``dsl:`` matchers, ``{{...}}`` placeholders, ``dsl``
extractors) use a govaluate-style syntax::

    status_code == 200 && contains(body, "admin") && !contains(header, "nginx")

This module translates that syntax into a Python expression, parses it with
``ast`` and evaluates it with a strict whitelist: only literals, names from the
supplied context, arithmetic/comparison/boolean operators and calls to the
helper functions defined below. There is no attribute access, no subscripting
of arbitrary objects and no builtins, so third-party templates cannot execute
code through an expression.
"""

from __future__ import annotations

import ast
import base64
import binascii
import functools
import hashlib
import html
import json
import keyword
import random
import re
import string
import time
import urllib.parse
import warnings
from collections.abc import Callable
from typing import Any


class DSLError(Exception):
    """Raised when an expression cannot be translated or evaluated."""


# --------------------------------------------------------------------------- #
# Regex cache: templates reuse the same patterns across thousands of targets.
# --------------------------------------------------------------------------- #

@functools.lru_cache(maxsize=8192)
def compile_regex(pattern: str, flags: int = 0) -> re.Pattern:
    # Third-party templates trigger FutureWarnings (nested sets etc.); they are
    # not actionable for the operator, so keep the scan output clean.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return re.compile(pattern, flags)


# --------------------------------------------------------------------------- #
# Helper functions (subset of projectdiscovery/dsl)
# --------------------------------------------------------------------------- #

def _s(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def _b(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    return _s(value).encode("utf-8", errors="surrogateescape")


def _regex(pattern: Any, text: Any) -> bool:
    try:
        return compile_regex(_s(pattern)).search(_s(text)) is not None
    except re.error:
        return False


def _mmh3(value: Any) -> str:
    try:
        import mmh3  # optional dependency: falsealarm[favicon]
    except ImportError as exc:  # pragma: no cover - depends on environment
        raise DSLError("mmh3 is not installed (pip install falsealarm[favicon])") from exc
    return str(mmh3.hash(_b(value)))


def _base64_py(value: Any) -> str:
    # Python's base64.encodebytes (newline every 76 chars) — what Shodan uses
    # for favicon hashes.
    return base64.encodebytes(_b(value)).decode("ascii")


def _parse_version(text: str) -> tuple:
    text = text.strip().lstrip("vV")
    parts: list = []
    for chunk in re.split(r"[.\-+_]", text):
        m = re.match(r"(\d+)(.*)", chunk)
        if m:
            parts.append((int(m.group(1)), m.group(2)))
        elif chunk:
            parts.append((-1, chunk))
    # Normalise trailing zeros so 1.0 == 1.0.0
    while parts and parts[-1] == (0, ""):
        parts.pop()
    return tuple(parts)


def _compare_versions(version: Any, *constraints: Any) -> bool:
    current = _parse_version(_s(version))
    if not current:
        return False
    for raw in constraints:
        for constraint in _s(raw).split(","):
            constraint = constraint.strip()
            if not constraint:
                continue
            m = re.match(r"^(<=|>=|==|!=|<|>|=)?\s*(.+)$", constraint)
            if not m:
                return False
            op, ver = m.group(1) or "==", _parse_version(m.group(2))
            ok = {
                "<": current < ver, "<=": current <= ver, ">": current > ver,
                ">=": current >= ver, "==": current == ver, "=": current == ver,
                "!=": current != ver,
            }[op]
            if not ok:
                return False
    return True


def _rand_chars(alphabet: str, n: Any = 8) -> str:
    return "".join(random.choice(alphabet) for _ in range(int(n)))


def _rand_base(n: Any = 8, charset: Any = "") -> str:
    return _rand_chars(_s(charset) or string.ascii_letters + string.digits, n)


def _rand_int(lo: Any = 0, hi: Any = 2**31 - 1) -> int:
    return random.randint(int(lo), int(hi))


def _to_number(value: Any) -> float | int:
    text = _s(value).strip()
    try:
        return int(text)
    except ValueError:
        try:
            return float(text)
        except ValueError:
            return 0


def _hex_decode(value: Any) -> str:
    try:
        return binascii.unhexlify(_s(value)).decode("latin-1")
    except (binascii.Error, ValueError):
        return ""


def _base64_decode(value: Any) -> str:
    text = _s(value)
    text += "=" * (-len(text) % 4)
    try:
        return base64.b64decode(text).decode("latin-1")
    except (binascii.Error, ValueError):
        return ""


def _json_minify(value: Any) -> str:
    try:
        return json.dumps(json.loads(_s(value)), separators=(",", ":"))
    except ValueError:
        return _s(value)


def _json_prettify(value: Any) -> str:
    try:
        return json.dumps(json.loads(_s(value)), indent=4)
    except ValueError:
        return _s(value)


def _date_time(fmt: Any = "%Y-%m-%d", ts: Any = None) -> str:
    t = time.gmtime(int(ts)) if ts is not None else time.gmtime()
    f = _s(fmt)
    # nuclei accepts both strftime-like (%Y) and Go-like (YYYY) layouts.
    for go, py in (("YYYY", "%Y"), ("MM", "%m"), ("DD", "%d"), ("HH", "%H"), ("mm", "%M"), ("ss", "%S")):
        f = f.replace(go, py)
    return time.strftime(f, t)


def _to_unix_time(value: Any) -> int:
    text = _s(value).strip()
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            import calendar
            return calendar.timegm(time.strptime(text, fmt))
        except ValueError:
            continue
    return int(_to_number(text))


def _hash(algo: str) -> Callable[[Any], str]:
    return lambda value: hashlib.new(algo, _b(value)).hexdigest()


def _hmac(algo: Any, data: Any, secret: Any) -> str:
    import hmac as _hmac_mod
    return _hmac_mod.new(_b(secret), _b(data), _s(algo)).hexdigest()


def _replace_regex(text: Any, pattern: Any, repl: Any) -> str:
    try:
        return compile_regex(_s(pattern)).sub(_s(repl), _s(text))
    except re.error:
        return _s(text)


def _padding(text: Any, pad: Any, length: Any, mode: Any = "suffix") -> str:
    text, pad, length = _s(text), _s(pad) or " ", int(length)
    if len(text) >= length:
        return text
    filler = (pad * length)[: length - len(text)]
    return filler + text if _s(mode) == "prefix" else text + filler


def _unsupported(name: str) -> Callable[..., Any]:
    def _fn(*_args: Any) -> Any:
        raise DSLError(f"DSL function '{name}' is not supported")
    return _fn


FUNCTIONS: dict[str, Callable[..., Any]] = {
    # matching
    "contains": lambda h, n: _s(n) in _s(h),
    "contains_all": lambda h, *ns: all(_s(n) in _s(h) for n in ns),
    "contains_any": lambda h, *ns: any(_s(n) in _s(h) for n in ns),
    "starts_with": lambda h, *ps: any(_s(h).startswith(_s(p)) for p in ps),
    "startswith": lambda h, *ps: any(_s(h).startswith(_s(p)) for p in ps),
    "ends_with": lambda h, *ps: any(_s(h).endswith(_s(p)) for p in ps),
    "endswith": lambda h, *ps: any(_s(h).endswith(_s(p)) for p in ps),
    "line_starts_with": lambda h, *ps: any(line.startswith(_s(p)) for line in _s(h).splitlines() for p in ps),
    "line_ends_with": lambda h, *ps: any(line.endswith(_s(p)) for line in _s(h).splitlines() for p in ps),
    "regex": _regex,
    "compare_versions": _compare_versions,
    "equals_any": lambda v, *xs: any(_s(v) == _s(x) for x in xs),
    # strings
    "len": lambda v: len(v) if isinstance(v, (list, tuple)) else len(_s(v)),
    "to_lower": lambda v: _s(v).lower(),
    "tolower": lambda v: _s(v).lower(),
    "to_upper": lambda v: _s(v).upper(),
    "toupper": lambda v: _s(v).upper(),
    "to_string": _s,
    "tostring": _s,
    "to_number": _to_number,
    "concat": lambda *vs: "".join(_s(v) for v in vs),
    "join": lambda sep, *vs: _s(sep).join(_s(v) for v in vs),
    "replace": lambda t, old, new: _s(t).replace(_s(old), _s(new)),
    "replace_regex": _replace_regex,
    "remove_bad_chars": lambda t, cut: "".join(c for c in _s(t) if c not in _s(cut)),
    "trim": lambda t, cut=" ": _s(t).strip(_s(cut)),
    "trim_left": lambda t, cut=" ": _s(t).lstrip(_s(cut)),
    "trim_right": lambda t, cut=" ": _s(t).rstrip(_s(cut)),
    "trim_prefix": lambda t, p: _s(t)[len(_s(p)):] if _s(t).startswith(_s(p)) else _s(t),
    "trim_suffix": lambda t, p: _s(t)[: -len(_s(p))] if _s(p) and _s(t).endswith(_s(p)) else _s(t),
    "trim_space": lambda t: _s(t).strip(),
    "repeat": lambda t, n: _s(t) * int(n),
    "reverse": lambda t: _s(t)[::-1],
    "split": lambda t, sep=",", n=-1: _s(t).split(_s(sep), int(n)),
    "hex_to_dec": lambda v: int(_s(v), 16),
    "dec_to_hex": lambda v: format(int(v), "x"),
    "to_unix_time": lambda v: _to_unix_time(v),
    "substr": lambda t, a, b=None: _s(t)[int(a): (int(b) if b is not None else None)],
    "padding": _padding,
    "strip_slashes": lambda t: _s(t).replace("\\", ""),
    "json_minify": _json_minify,
    "json_prettify": _json_prettify,
    # encoding
    "base64": lambda v: base64.b64encode(_b(v)).decode("ascii"),
    "base64_py": _base64_py,
    "base64_decode": _base64_decode,
    "url_encode": lambda v: urllib.parse.quote(_s(v), safe=""),
    "urlencode": lambda v: urllib.parse.quote(_s(v), safe=""),
    "url_decode": lambda v: urllib.parse.unquote(_s(v)),
    "urldecode": lambda v: urllib.parse.unquote(_s(v)),
    "hex_encode": lambda v: binascii.hexlify(_b(v)).decode("ascii"),
    "hex_decode": _hex_decode,
    "html_escape": lambda v: html.escape(_s(v)),
    "html_unescape": lambda v: html.unescape(_s(v)),
    # hashing
    "md5": _hash("md5"),
    "sha1": _hash("sha1"),
    "sha256": _hash("sha256"),
    "sha512": _hash("sha512"),
    "mmh3": _mmh3,
    "hmac": _hmac,
    # randomness / time
    "rand_base": _rand_base,
    "randbase": _rand_base,
    "rand_char": lambda charset="": _rand_base(1, charset),
    "rand_int": _rand_int,
    "rand_text_alpha": lambda n=8, bad="": _rand_chars("".join(c for c in string.ascii_letters if c not in _s(bad)), n),
    "rand_text_alphanumeric": lambda n=8, bad="": _rand_chars(
        "".join(c for c in string.ascii_letters + string.digits if c not in _s(bad)), n
    ),
    "rand_text_numeric": lambda n=8, bad="": _rand_chars("".join(c for c in string.digits if c not in _s(bad)), n),
    "unix_time": lambda offset=0: int(time.time()) + int(offset),
    "date_time": _date_time,
}

# Functions that exist in nuclei but need infrastructure we don't ship.
for _name in ("generate_java_gadget", "generate_jwt", "zip", "gzip", "gzip_decode", "inflate", "deflate",
              "aes_gcm", "aes_cbc", "ip_format", "resolve", "print_debug", "xor",
              # wait_for would block the shared asyncio event loop.
              "wait_for"):
    FUNCTIONS.setdefault(_name, _unsupported(_name))


# --------------------------------------------------------------------------- #
# Translation: govaluate syntax -> Python expression
# --------------------------------------------------------------------------- #

def _decode_string(raw: str) -> str:
    """Decode a DSL string literal body.

    Templates in the wild write regexes both as ``"\\d+"`` and ``"\\\\d+"``;
    nuclei accepts both, so we only collapse the escapes that change meaning
    (``\\\\``, quotes, n/r/t) and keep every other backslash verbatim.
    """
    out = []
    i = 0
    while i < len(raw):
        ch = raw[i]
        if ch == "\\" and i + 1 < len(raw):
            nxt = raw[i + 1]
            if nxt in "\\\"'":
                out.append(nxt)
            elif nxt == "n":
                out.append("\n")
            elif nxt == "r":
                out.append("\r")
            elif nxt == "t":
                out.append("\t")
            else:
                out.append(ch + nxt)
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


_LITERALS = {"true": "True", "false": "False", "nil": "None"}
_KW_PREFIX = "__kw_"


def _map_identifier(word: str) -> str:
    if word in _LITERALS:
        return _LITERALS[word]
    if word in ("True", "False", "None"):
        return word
    if keyword.iskeyword(word) or keyword.issoftkeyword(word):
        # Template variables may be named like Python keywords ("pass", "in").
        return _KW_PREFIX + word
    return word


@functools.lru_cache(maxsize=16384)
def translate(expr: str) -> str:
    """Translate a nuclei/govaluate expression into Python source."""
    out: list[str] = []
    i, n = 0, len(expr)
    while i < n:
        ch = expr[i]
        if ch in "\"'`":
            j = i + 1
            buf = []
            while j < n and expr[j] != ch:
                if expr[j] == "\\" and j + 1 < n:
                    buf.append(expr[j: j + 2])
                    j += 2
                    continue
                buf.append(expr[j])
                j += 1
            if j >= n:
                raise DSLError(f"unterminated string in expression: {expr!r}")
            body = "".join(buf)
            out.append(repr(body if ch == "`" else _decode_string(body)))
            i = j + 1
            continue
        two = expr[i: i + 2]
        if two == "&&":
            out.append(" and ")
            i += 2
        elif two == "||":
            out.append(" or ")
            i += 2
        elif two in ("=~", "!~"):
            raise DSLError("regex operators (=~, !~) are not supported; use regex()")
        elif two in ("!=", "==", "<=", ">="):
            out.append(f" {two} ")
            i += 2
        elif ch == "!":
            out.append(" not ")
            i += 1
        elif ch in "?:":
            raise DSLError("ternary expressions are not supported")
        elif ch.isalpha() or ch == "_":
            j = i
            while j < n and (expr[j].isalnum() or expr[j] == "_"):
                j += 1
            word = expr[i:j]
            out.append(_map_identifier(word))
            i = j
        elif ch in "\r\n\t":
            out.append(" ")
            i += 1
        else:
            out.append(ch)
            i += 1
    return "".join(out).strip()


# --------------------------------------------------------------------------- #
# Whitelisted AST evaluator
# --------------------------------------------------------------------------- #

_BINOPS: dict[type, Callable[[Any, Any], Any]] = {
    ast.Add: lambda a, b: (_s(a) + _s(b)) if isinstance(a, str) or isinstance(b, str) else a + b,
    ast.Sub: lambda a, b: a - b,
    ast.Mult: lambda a, b: a * b,
    ast.Div: lambda a, b: a / b,
    ast.Mod: lambda a, b: a % b,
    ast.BitAnd: lambda a, b: a & b,
    ast.BitOr: lambda a, b: a | b,
    ast.BitXor: lambda a, b: a ^ b,
}


def _cmp_operand(a: Any, b: Any) -> tuple[Any, Any]:
    # Compare numbers numerically even if one side came from a header string.
    if isinstance(a, (int, float)) and isinstance(b, str):
        return a, _to_number(b)
    if isinstance(b, (int, float)) and isinstance(a, str):
        return _to_number(a), b
    return a, b


_CMPOPS: dict[type, Callable[[Any, Any], bool]] = {
    ast.Eq: lambda a, b: a == b,
    ast.NotEq: lambda a, b: a != b,
    ast.Lt: lambda a, b: a < b,
    ast.LtE: lambda a, b: a <= b,
    ast.Gt: lambda a, b: a > b,
    ast.GtE: lambda a, b: a >= b,
}


@functools.lru_cache(maxsize=16384)
def _parse(expr: str) -> ast.AST:
    try:
        return ast.parse(translate(expr), mode="eval").body
    except SyntaxError as exc:
        raise DSLError(f"invalid expression {expr!r}: {exc.msg}") from exc


class _Missing(Exception):
    pass


def _eval(node: ast.AST, ctx: dict[str, Any]) -> Any:
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        name = node.id[len(_KW_PREFIX):] if node.id.startswith(_KW_PREFIX) else node.id
        if name in ctx:
            return ctx[name]
        if node.id in ("True", "False", "None"):
            return {"True": True, "False": False, "None": None}[node.id]
        raise _Missing(node.id)
    if isinstance(node, ast.BoolOp):
        if isinstance(node.op, ast.And):
            result: Any = True
            for value in node.values:
                result = _eval(value, ctx)
                if not result:
                    return result
            return result
        result = False
        for value in node.values:
            result = _eval(value, ctx)
            if result:
                return result
        return result
    if isinstance(node, ast.UnaryOp):
        operand = _eval(node.operand, ctx)
        if isinstance(node.op, ast.Not):
            return not operand
        if isinstance(node.op, ast.USub):
            return -operand
        if isinstance(node.op, ast.UAdd):
            return +operand
        raise DSLError("unsupported unary operator")
    if isinstance(node, ast.BinOp):
        op = _BINOPS.get(type(node.op))
        if op is None:
            raise DSLError("unsupported binary operator")
        return op(_eval(node.left, ctx), _eval(node.right, ctx))
    if isinstance(node, ast.Compare):
        left = _eval(node.left, ctx)
        for op_node, comparator in zip(node.ops, node.comparators):
            right = _eval(comparator, ctx)
            op = _CMPOPS.get(type(op_node))
            if op is None:
                raise DSLError("unsupported comparison")
            a, b = _cmp_operand(left, right)
            try:
                if not op(a, b):
                    return False
            except TypeError:
                return False
            left = right
        return True
    if isinstance(node, ast.Call):
        if not isinstance(node.func, ast.Name) or node.keywords:
            raise DSLError("only plain helper calls are allowed")
        fn = FUNCTIONS.get(node.func.id)
        if fn is None:
            raise DSLError(f"unknown DSL function '{node.func.id}'")
        args = [_eval(a, ctx) for a in node.args]
        try:
            return fn(*args)
        except DSLError:
            raise
        except Exception as exc:
            raise DSLError(f"{node.func.id}() failed: {exc}") from exc
    raise DSLError(f"unsupported syntax: {type(node).__name__}")


def evaluate(expr: str, ctx: dict[str, Any]) -> Any:
    """Evaluate a DSL expression. Raises DSLError on bad syntax or unknown names."""
    try:
        return _eval(_parse(expr.strip()), ctx)
    except _Missing as exc:
        raise DSLError(f"unresolved variable '{exc.args[0]}'") from exc
    except RecursionError as exc:
        raise DSLError("expression too deep") from exc


def evaluate_bool(expr: str, ctx: dict[str, Any]) -> bool:
    """Evaluate a DSL matcher. Any error is a non-match (never a false positive)."""
    try:
        return bool(evaluate(expr, ctx))
    except (DSLError, ZeroDivisionError, ValueError, TypeError):
        return False


_PLACEHOLDER = re.compile(r"\{\{(.+?)\}\}", re.S)


class UnresolvedVariable(Exception):
    """A ``{{...}}`` placeholder could not be resolved."""


def expand(text: str, ctx: dict[str, Any], strict: bool = True) -> str:
    """Replace ``{{name}}`` / ``{{func(args)}}`` placeholders in *text*.

    With ``strict`` an unresolvable placeholder raises UnresolvedVariable so the
    caller can skip the request (as nuclei does); otherwise it is left as-is.
    """
    if "{{" not in text:
        return text

    def _sub(m: re.Match) -> str:
        inner = m.group(1).strip()
        if inner in ctx:
            return _s(ctx[inner])
        try:
            return _s(evaluate(inner, ctx))
        except (DSLError, ZeroDivisionError, ValueError, TypeError) as exc:
            if strict:
                raise UnresolvedVariable(inner) from exc
            return m.group(0)

    # Two passes: variables may expand into further placeholders.
    for _ in range(2):
        text = _PLACEHOLDER.sub(_sub, text)
        if "{{" not in text:
            break
    return text
