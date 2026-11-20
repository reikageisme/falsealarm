"""Tests for the nuclei-compatible template engine (DSL, loader, executor)."""

import asyncio
import textwrap

import pytest
import yaml

from falsealarm.core.templates import TemplateExecutor, TemplateFilter, load_templates
from falsealarm.core.templates.dsl import DSLError, evaluate, evaluate_bool, expand
from falsealarm.core.templates.executor import build_requests, parse_raw_request, safe_url, target_variables
from falsealarm.core.templates.loader import UnsupportedTemplate, parse_template
from falsealarm.core.templates.matchers import build_response_context, extract_one, match_all

# --------------------------------------------------------------------------- #
# DSL
# --------------------------------------------------------------------------- #

CTX = {
    "body": "Welcome admin, version 2.4.49",
    "status_code": 200,
    "header": "HTTP/1.1 200\r\nServer: Apache",
    "content_type": "text/html",
}


@pytest.mark.parametrize(
    "expr,expected",
    [
        ('status_code == 200 && contains(body, "admin")', True),
        ('!contains(body, "admin")', False),
        ("!contains(tolower(body), '<html')", True),
        ('contains_all(body, "admin", "version") || false', True),
        ('contains_any(body, "x", "y")', False),
        ('regex("version [0-9.]+", body)', True),
        ('regex("\\\\d+\\\\.\\\\d+", body)', True),  # double-escaped style
        ('regex("\\d+\\.\\d+", body)', True),  # single-escaped style
        ("len(body) > 10 && status_code != 404", True),
        ('status_code == "200"', True),  # numeric/string comparison
        ('compare_versions("2.4.49", "<= 2.4.50", ">= 2.4.0")', True),
        ('compare_versions("2.4.51", "<= 2.4.50")', False),
        ('contains(body, "true")', False),  # keyword inside a string is untouched
        ("md5(\"a\") == '0cc175b9c0f1b6a831c399e269772661'", True),
        ('to_lower(content_type) == "text/html"\n&& true', True),
    ],
)
def test_dsl_expressions(expr, expected):
    assert evaluate_bool(expr, CTX) is expected


def test_dsl_unknown_variable_is_non_match():
    assert evaluate_bool("missing_var == 1", CTX) is False
    with pytest.raises(DSLError):
        evaluate("missing_var == 1", CTX)


@pytest.mark.parametrize(
    "expr",
    [
        "__import__('os').system('id')",
        "body.__class__",
        "[x for x in body]",
        "(lambda: 1)()",
        "open('/etc/passwd')",
        "body[0]",
    ],
)
def test_dsl_rejects_unsafe_syntax(expr):
    with pytest.raises(DSLError):
        evaluate(expr, CTX)


def test_dsl_python_keyword_variable_names():
    assert evaluate('"Password: " + pass', {"pass": "x"}) == "Password: x"


def test_expand_placeholders():
    ctx = {"BaseURL": "http://t", "name": "Ab"}
    assert expand("{{BaseURL}}/{{to_lower(name)}}", ctx) == "http://t/ab"
    assert len(expand("{{rand_base(6)}}", ctx)) == 6


def test_expand_strict_raises_on_unresolved():
    from falsealarm.core.templates.dsl import UnresolvedVariable

    with pytest.raises(UnresolvedVariable):
        expand("{{BaseURL}}/{{csrf}}", {"BaseURL": "http://t"})
    assert expand("{{csrf}}", {}, strict=False) == "{{csrf}}"


# --------------------------------------------------------------------------- #
# Matchers / extractors
# --------------------------------------------------------------------------- #

def _ctx(status=200, body="", headers=None):
    return build_response_context(status, body, headers or {})


def test_internal_matcher_gates_but_does_not_report():
    matchers = [{"type": "status", "status": [200], "internal": True}]
    outcome = match_all(matchers, _ctx(), "or")
    assert outcome.matched is True
    assert outcome.reportable is False


def test_and_condition_with_internal_and_public_matchers():
    matchers = [
        {"type": "status", "status": [200], "internal": True},
        {"type": "word", "words": ["secret"], "name": "leak"},
    ]
    outcome = match_all(matchers, _ctx(body="a secret"), "and")
    assert outcome.reportable and outcome.names == ["leak"]


def test_word_matcher_case_insensitive_and_named_header_part():
    ctx = _ctx(headers={"Content-Type": "Text/HTML"})
    m = {"type": "word", "part": "content_type", "words": ["text/html"], "case-insensitive": True}
    assert match_all([m], ctx).matched


def test_size_and_binary_matchers():
    ctx = _ctx(body="PK\x03\x04rest")
    assert match_all([{"type": "size", "size": [8]}], ctx).matched
    assert match_all([{"type": "binary", "binary": ["504b0304"]}], ctx).matched


def test_regex_extractor_group_and_json_extractor():
    ctx = _ctx(body='{"user": {"name": "bob", "roles": ["a", "b"]}}')
    assert extract_one({"type": "json", "json": [".user.name"]}, ctx) == ["bob"]
    assert extract_one({"type": "json", "json": [".user.roles[]"]}, ctx) == ["a", "b"]
    ctx = _ctx(body="token=abc123;")
    assert extract_one({"type": "regex", "regex": ["token=([a-z0-9]+)"], "group": 1}, ctx) == ["abc123"]


def test_kval_extractor_reads_headers():
    ctx = _ctx(headers={"X-Powered-By": "PHP/8.1"})
    assert extract_one({"type": "kval", "kval": ["x_powered_by"]}, ctx) == ["PHP/8.1"]


# --------------------------------------------------------------------------- #
# Loader
# --------------------------------------------------------------------------- #

def _write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(textwrap.dedent(text))
    return path


NUCLEI_TEMPLATE = """
id: demo-exposure
info:
  name: Demo exposure
  severity: high
  tags: exposure,config
http:
  - method: GET
    path:
      - "{{BaseURL}}/.env"
      - "{{BaseURL}}/api/.env"
    matchers-condition: and
    matchers:
      - type: word
        words: ["DB_PASSWORD="]
      - type: status
        status: [200]
"""


def test_loader_parses_nuclei_and_legacy(tmp_path):
    _write(tmp_path, "nuclei.yaml", NUCLEI_TEMPLATE)
    _write(
        tmp_path,
        "legacy.yaml",
        """
        id: legacy
        info: {name: Legacy, severity: low}
        matchers-condition: and
        requests:
          - method: GET
            path: /.git/config
            matchers:
              - type: status
                status: [200]
              - type: word
                words: ["[core]"]
        """,
    )
    report = load_templates([str(tmp_path)])
    assert report.loaded == 2
    legacy = next(t for t in report.templates if t.id == "legacy")
    assert legacy.requests[0].matchers_condition == "and"
    assert legacy.requests[0].paths == ["/.git/config"]


@pytest.mark.parametrize(
    "extra,reason",
    [
        ("flow: http(1) && http(2)\n", "flow"),
        ("dns:\n  - name: '{{FQDN}}'\n", "protocol-dns"),
    ],
)
def test_loader_rejects_unsupported(extra, reason):
    data = yaml.safe_load(NUCLEI_TEMPLATE + extra)
    with pytest.raises(UnsupportedTemplate) as exc:
        parse_template(data, "x.yaml", NUCLEI_TEMPLATE + extra)
    assert str(exc.value) == reason


def test_loader_rejects_interactsh():
    text = NUCLEI_TEMPLATE.replace("DB_PASSWORD=", "{{interactsh-url}}")
    with pytest.raises(UnsupportedTemplate):
        parse_template(yaml.safe_load(text), "x.yaml", text)


def test_filter_by_tag_severity_and_default_excludes(tmp_path):
    _write(tmp_path, "a.yaml", NUCLEI_TEMPLATE)
    _write(tmp_path, "b.yaml", NUCLEI_TEMPLATE.replace("demo-exposure", "dos-one").replace("exposure,config", "dos"))
    assert load_templates([str(tmp_path)], TemplateFilter.build()).loaded == 1  # dos excluded by default
    assert load_templates([str(tmp_path)], TemplateFilter.build(tags="dos")).loaded == 1
    assert load_templates([str(tmp_path)], TemplateFilter.build(severities="critical")).loaded == 0


def test_payload_file_resolved_relative_to_template(tmp_path):
    (tmp_path / "words.txt").write_text("/a\n/b\n")
    sub = tmp_path / "http"
    sub.mkdir()
    text = NUCLEI_TEMPLATE.replace(
        '      - "{{BaseURL}}/.env"\n      - "{{BaseURL}}/api/.env"\n',
        '      - "{{BaseURL}}{{p}}"\n    payloads:\n      p: words.txt\n',
    )
    _write(sub, "t.yaml", text)
    report = load_templates([str(sub)])
    assert report.templates[0].requests[0].payloads == {"p": ["/a", "/b"]}


# --------------------------------------------------------------------------- #
# Request building
# --------------------------------------------------------------------------- #

def test_raw_request_parsing_merges_path_and_drops_host():
    ctx = target_variables("http://example.com:8080/app")
    raw = "POST /login HTTP/1.1\nHost: example.com:8080\nContent-Type: application/json\n\n{\"a\": 1}\n"
    req = parse_raw_request(raw, ctx)
    assert req.method == "POST"
    assert req.url == "http://example.com:8080/app/login"
    assert "Host" not in req.headers
    assert req.headers["Content-Type"] == "application/json"
    assert req.body == '{"a": 1}'


def test_safe_url_keeps_encoded_traversal():
    url = "http://t/cgi-bin/.%2e/.%2e/etc/passwd?q=<x y>"
    assert safe_url(url) == "http://t/cgi-bin/.%2e/.%2e/etc/passwd?q=%3Cx%20y%3E"


def test_clusterbomb_and_pitchfork_payloads():
    data = yaml.safe_load(
        textwrap.dedent(
            """
            id: p
            info: {name: p, severity: info}
            http:
              - method: GET
                path: ["{{BaseURL}}/{{a}}/{{b}}"]
                attack: clusterbomb
                payloads:
                  a: ["1", "2"]
                  b: ["x", "y"]
                matchers: [{type: status, status: [200]}]
            """
        )
    )
    t = parse_template(data, "p.yaml")
    ctx = target_variables("http://t")
    assert len(build_requests(t.requests[0], ctx)) == 4
    t.requests[0].attack = "pitchfork"
    urls = [r.url for r, _ in build_requests(t.requests[0], ctx)]
    assert urls == ["http://t/1/x", "http://t/2/y"]


# --------------------------------------------------------------------------- #
# Executor (fake engine)
# --------------------------------------------------------------------------- #

class FakeEngine:
    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    async def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        path = url.split("://", 1)[1].split("/", 1)[1] if "/" in url.split("://", 1)[1] else ""
        status, body, headers = self.routes.get((method, "/" + path), (404, "not found", {}))
        return {"url": url, "status": status, "body": body, "headers": headers, "error": None, "elapsed": 0.01}


def _run(template_text, routes, target="http://t"):
    data = yaml.safe_load(textwrap.dedent(template_text))
    template = parse_template(data, "t.yaml", template_text)
    engine = FakeEngine(routes)
    executor = TemplateExecutor(engine, concurrency=5)
    return asyncio.run(executor.run(template, target)), engine, executor


def test_executor_multi_step_with_dynamic_extractor():
    template = """
    id: csrf-flow
    info: {name: CSRF flow, severity: medium}
    http:
      - method: GET
        path: ["{{BaseURL}}/login"]
        extractors:
          - type: regex
            name: token
            group: 1
            internal: true
            regex: ['name="csrf" value="([^"]+)"']
      - raw:
          - |
            POST /login HTTP/1.1
            Host: {{Hostname}}

            csrf={{token}}&user=admin
        matchers:
          - type: dsl
            dsl: ['status_code_2 == 302 && contains(body_1, "csrf")']
    """
    routes = {
        ("GET", "/login"): (200, '<input name="csrf" value="tok123">', {}),
        ("POST", "/login"): (302, "", {"Location": "/home"}),
    }
    findings, engine, _ = _run(template, routes)
    assert [f["vuln_id"] for f in findings] == ["csrf-flow"]
    post = [c for c in engine.calls if c[0] == "POST"][0]
    assert post[2]["data"] == b"csrf=tok123&user=admin"


def test_executor_skips_request_with_unresolved_variable():
    template = """
    id: needs-token
    info: {name: Needs token, severity: high}
    http:
      - method: GET
        path: ["{{BaseURL}}/a"]
        extractors:
          - type: regex
            name: token
            internal: true
            regex: ["never-there-([0-9]+)"]
      - method: GET
        path: ["{{BaseURL}}/b?t={{token}}"]
        matchers: [{type: status, status: [200]}]
    """
    routes = {("GET", "/a"): (200, "nothing", {}), ("GET", "/b"): (200, "ok", {})}
    findings, engine, _ = _run(template, routes)
    assert findings == []
    assert all("/b" not in c[1] for c in engine.calls)


def test_executor_internal_gate_stops_template():
    template = """
    id: gated
    info: {name: Gated, severity: high}
    http:
      - method: GET
        path: ["{{BaseURL}}/wp-login.php"]
        matchers: [{type: word, words: [WordPress], internal: true}]
      - method: GET
        path: ["{{BaseURL}}/"]
        matchers: [{type: status, status: [200]}]
    """
    findings, engine, _ = _run(template, {("GET", "/"): (200, "home", {})})
    assert findings == []
    assert len(engine.calls) == 1


def test_executor_stop_at_first_match_and_payload_reporting():
    template = """
    id: first
    info: {name: First, severity: low}
    http:
      - method: GET
        path: ["{{BaseURL}}{{p}}"]
        payloads:
          p: ["/x", "/info.php", "/phpinfo.php"]
        stop-at-first-match: true
        matchers: [{type: word, words: ["PHP Version"]}]
    """
    routes = {("GET", "/info.php"): (200, "PHP Version", {}), ("GET", "/phpinfo.php"): (200, "PHP Version", {})}
    findings, engine, _ = _run(template, routes)
    assert len(findings) == 1
    assert findings[0]["payload"] == {"p": "/info.php"}
    assert len(engine.calls) == 2


def test_executor_caches_identical_get_requests():
    template = """
    id: t{n}
    info: {{name: T, severity: info}}
    http:
      - method: GET
        path: ["{{{{BaseURL}}}}/"]
        matchers: [{{type: word, words: [nginx], part: header}}]
    """
    data = [yaml.safe_load(textwrap.dedent(template.format(n=i))) for i in range(3)]
    templates = [parse_template(d, f"t{i}.yaml") for i, d in enumerate(data)]
    engine = FakeEngine({("GET", "/"): (200, "", {"Server": "nginx"})})
    executor = TemplateExecutor(engine)

    async def go():
        return await asyncio.gather(*(executor.run(t, "http://t") for t in templates))

    results = asyncio.run(go())
    assert all(len(r) == 1 for r in results)
    assert len(engine.calls) == 1
    assert executor.cache_hits == 2


def test_bundled_templates_still_load():
    from falsealarm.core.utils import get_data_path

    report = load_templates([str(get_data_path("templates"))])
    assert report.loaded == 4 and not report.invalid
