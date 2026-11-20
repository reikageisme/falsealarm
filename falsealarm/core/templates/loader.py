"""
Template loader: reads FalseAlarm and nuclei YAML templates into one model.

Two dialects are accepted:

* **nuclei** (``http:`` or the older ``requests:`` key, per-request
  ``matchers-condition``, ``path`` lists, ``raw`` requests, ``payloads`` …)
* **legacy FalseAlarm** (``requests:`` with a single ``path`` string and a
  top-level ``matchers-condition``) — kept for backwards compatibility.

Templates that need features we cannot honour (OAST/interactsh, non-HTTP
protocols, ``flow:`` scripting, headless browsers, xpath …) are *not* silently
run with partial logic — they are reported as unsupported with a reason, so a
scan never produces findings from a half-understood template.
"""

from __future__ import annotations

import os
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import yaml

try:  # libyaml is ~10x faster when loading thousands of templates
    _Loader = yaml.CSafeLoader  # type: ignore[attr-defined]
except AttributeError:  # pragma: no cover - depends on build
    _Loader = yaml.SafeLoader

SEVERITIES = ("info", "low", "medium", "high", "critical", "unknown")

# Protocol sections nuclei supports that this engine does not (yet) execute.
UNSUPPORTED_PROTOCOLS = (
    "dns", "file", "network", "tcp", "headless", "ssl", "websocket", "whois",
    "code", "javascript", "workflows", "workflow",
)

SUPPORTED_MATCHERS = {"word", "regex", "status", "size", "binary", "dsl"}
SUPPORTED_EXTRACTORS = {"regex", "kval", "json", "dsl", "xpath"}  # xpath is skipped at runtime

# Tags excluded unless explicitly requested (mirrors nuclei's default ignore list).
DEFAULT_EXCLUDE_TAGS = ("dos", "fuzz")

MAX_PAYLOAD_LINES = 5000


@dataclass
class HTTPRequest:
    method: str = "GET"
    paths: list[str] = field(default_factory=list)
    raw: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    matchers: list[dict] = field(default_factory=list)
    matchers_condition: str = "or"
    extractors: list[dict] = field(default_factory=list)
    redirects: bool = False
    max_redirects: int = 10
    stop_at_first_match: bool = False
    payloads: dict[str, list[str]] = field(default_factory=dict)
    attack: str = "batteringram"
    req_condition: bool = False
    skip_variables_check: bool = False
    disable_path_automerge: bool = False


@dataclass
class Template:
    id: str
    path: str
    info: dict[str, Any]
    requests: list[HTTPRequest] = field(default_factory=list)
    variables: dict[str, Any] = field(default_factory=dict)
    stop_at_first_match: bool = False
    dialect: str = "nuclei"

    @property
    def name(self) -> str:
        return str(self.info.get("name") or self.id)

    @property
    def severity(self) -> str:
        sev = str(self.info.get("severity") or "unknown").lower().strip()
        return sev if sev in SEVERITIES else "unknown"

    @property
    def tags(self) -> set[str]:
        return _as_set(self.info.get("tags"))

    @property
    def authors(self) -> set[str]:
        return _as_set(self.info.get("author"))


class UnsupportedTemplate(Exception):
    """The template is valid but uses features this engine cannot execute."""


class InvalidTemplate(Exception):
    """The file is not a usable template."""


@dataclass
class LoadReport:
    templates: list[Template] = field(default_factory=list)
    unsupported: Counter = field(default_factory=Counter)
    invalid: list[tuple[str, str]] = field(default_factory=list)
    filtered: int = 0
    files_seen: int = 0

    @property
    def loaded(self) -> int:
        return len(self.templates)

    def summary(self) -> str:
        skipped = sum(self.unsupported.values())
        return (
            f"{self.loaded} loaded, {skipped} unsupported, {len(self.invalid)} invalid, "
            f"{self.filtered} filtered out ({self.files_seen} files)"
        )


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _as_set(value: Any) -> set[str]:
    if not value:
        return set()
    if isinstance(value, str):
        items: Iterable[Any] = value.split(",")
    elif isinstance(value, (list, tuple, set)):
        items = value
    else:
        items = [value]
    return {str(v).strip().lower() for v in items if str(v).strip()}


def _as_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _resolve_payload_file(name: str, template_dir: Path) -> Path | None:
    candidate = Path(name)
    if candidate.is_absolute():
        return candidate if candidate.is_file() else None
    # nuclei resolves payload files relative to the template, then to the
    # templates root (e.g. "helpers/wordlists/x.txt"): walk up the tree.
    for base in (template_dir, *template_dir.parents):
        path = base / candidate
        if path.is_file():
            return path
    return None


def _load_payloads(raw: Any, template_dir: Path) -> dict[str, list[str]]:
    if not raw:
        return {}
    if not isinstance(raw, dict):
        raise InvalidTemplate("payloads must be a mapping")
    payloads: dict[str, list[str]] = {}
    for key, value in raw.items():
        if isinstance(value, list):
            payloads[str(key)] = [str(v) for v in value]
        elif isinstance(value, str):
            if "\n" in value:
                payloads[str(key)] = [line for line in value.splitlines() if line]
                continue
            path = _resolve_payload_file(value, template_dir)
            if path is None:
                raise UnsupportedTemplate("payload-file-missing")
            with open(path, encoding="utf-8", errors="replace") as fh:
                lines = [line.rstrip("\r\n") for line in fh if line.strip()]
            payloads[str(key)] = lines[:MAX_PAYLOAD_LINES]
        else:
            payloads[str(key)] = [str(value)]
    return payloads


def _check_matchers(matchers: list[dict]) -> None:
    for m in matchers:
        if not isinstance(m, dict):
            raise InvalidTemplate("matcher must be a mapping")
        m_type = m.get("type", "")
        if m_type not in SUPPORTED_MATCHERS:
            raise UnsupportedTemplate(f"matcher-{m_type or 'missing'}")
        part = str(m.get("part", ""))
        if part.startswith("interactsh"):
            raise UnsupportedTemplate("interactsh")


def _check_extractors(extractors: list[dict]) -> None:
    for e in extractors:
        if not isinstance(e, dict):
            raise InvalidTemplate("extractor must be a mapping")
        e_type = e.get("type", "regex")
        if e_type not in SUPPORTED_EXTRACTORS:
            raise UnsupportedTemplate(f"extractor-{e_type}")


def _normalise_request(block: dict, top_condition: str, template_dir: Path, legacy: bool) -> HTTPRequest:
    if not isinstance(block, dict):
        raise InvalidTemplate("request block must be a mapping")

    paths = [str(p) for p in _as_list(block.get("path"))]
    raw = [str(r) for r in _as_list(block.get("raw"))]
    if not paths and not raw:
        raise InvalidTemplate("request has neither path nor raw")
    if block.get("race") or block.get("pipeline"):
        # Race/pipelined requests depend on timing guarantees aiohttp can't give.
        raise UnsupportedTemplate("race-pipeline")

    matchers = _as_list(block.get("matchers"))
    extractors = _as_list(block.get("extractors"))
    _check_matchers(matchers)
    _check_extractors(extractors)

    # Legacy FalseAlarm templates put matchers-condition at the top level.
    condition = block.get("matchers-condition") or (top_condition if legacy else "or")

    attack = str(block.get("attack") or "batteringram").lower()
    if attack not in {"batteringram", "pitchfork", "clusterbomb"}:
        raise UnsupportedTemplate(f"attack-{attack}")

    return HTTPRequest(
        method=str(block.get("method") or "GET").upper(),
        paths=paths,
        raw=raw,
        headers={str(k): str(v) for k, v in (block.get("headers") or {}).items()},
        body=str(block.get("body") or ""),
        matchers=matchers,
        matchers_condition=str(condition).lower(),
        extractors=extractors,
        redirects=bool(block.get("redirects") or block.get("host-redirects")),
        max_redirects=int(block.get("max-redirects") or 10),
        stop_at_first_match=bool(block.get("stop-at-first-match")),
        payloads=_load_payloads(block.get("payloads"), template_dir),
        attack=attack,
        req_condition=bool(block.get("req-condition")),
        skip_variables_check=bool(block.get("skip-variables-check")),
        disable_path_automerge=bool(block.get("disable-path-automerge")),
    )


def parse_template(data: Any, path: str, source_text: str = "") -> Template:
    """Turn a parsed YAML document into a Template (or raise)."""
    if not isinstance(data, dict) or "id" not in data:
        raise InvalidTemplate("missing id")
    info = data.get("info")
    if not isinstance(info, dict):
        raise InvalidTemplate("missing info block")

    for proto in UNSUPPORTED_PROTOCOLS:
        if proto in data:
            raise UnsupportedTemplate(f"protocol-{proto}")
    if "flow" in data:
        raise UnsupportedTemplate("flow")
    if data.get("self-contained"):
        raise UnsupportedTemplate("self-contained")
    if "interactsh" in source_text:
        raise UnsupportedTemplate("interactsh")

    legacy = "http" not in data
    blocks = data.get("http") if not legacy else data.get("requests")
    blocks = _as_list(blocks)
    if not blocks:
        raise InvalidTemplate("no http requests")

    template_dir = Path(path).parent
    top_condition = str(data.get("matchers-condition") or "or")
    requests = [_normalise_request(b, top_condition, template_dir, legacy) for b in blocks]
    if not any(r.matchers or r.extractors for r in requests):
        raise InvalidTemplate("template has no matchers or extractors")

    variables = data.get("variables") or {}
    if not isinstance(variables, dict):
        raise InvalidTemplate("variables must be a mapping")

    return Template(
        id=str(data["id"]),
        path=path,
        info=info,
        requests=requests,
        variables={str(k): v for k, v in variables.items()},
        stop_at_first_match=bool(data.get("stop-at-first-match")),
        dialect="falsealarm" if legacy and "matchers-condition" in data else "nuclei",
    )


def load_template_file(path: str) -> Template:
    with open(path, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    try:
        data = yaml.load(text, Loader=_Loader)  # noqa: S506 - CSafeLoader/SafeLoader only
    except yaml.YAMLError as exc:
        raise InvalidTemplate(f"yaml error: {exc}") from exc
    return parse_template(data, path, text)


def iter_template_files(paths: Iterable[str]) -> Iterable[str]:
    for entry in paths:
        entry = os.path.expanduser(str(entry))
        if os.path.isfile(entry):
            if entry.endswith((".yaml", ".yml")):
                yield entry
            continue
        if not os.path.isdir(entry):
            continue
        for root, dirs, files in os.walk(entry):
            # Skip VCS metadata, CI config and helper payload directories.
            dirs[:] = sorted(d for d in dirs if not d.startswith(".") and d not in {"helpers", "profiles"})
            for name in sorted(files):
                if name.endswith((".yaml", ".yml")):
                    yield os.path.join(root, name)


@dataclass
class TemplateFilter:
    tags: set[str] = field(default_factory=set)
    exclude_tags: set[str] = field(default_factory=set)
    severities: set[str] = field(default_factory=set)
    exclude_severities: set[str] = field(default_factory=set)
    ids: set[str] = field(default_factory=set)
    exclude_ids: set[str] = field(default_factory=set)
    authors: set[str] = field(default_factory=set)

    @classmethod
    def build(
        cls,
        tags: Any = None,
        exclude_tags: Any = None,
        severities: Any = None,
        exclude_severities: Any = None,
        ids: Any = None,
        exclude_ids: Any = None,
        authors: Any = None,
        use_default_excludes: bool = True,
    ) -> "TemplateFilter":
        f = cls(
            tags=_as_set(tags),
            exclude_tags=_as_set(exclude_tags),
            severities=_as_set(severities),
            exclude_severities=_as_set(exclude_severities),
            ids=_as_set(ids),
            exclude_ids=_as_set(exclude_ids),
            authors=_as_set(authors),
        )
        if use_default_excludes:
            # Explicitly requested tags always win over the default excludes.
            f.exclude_tags |= set(DEFAULT_EXCLUDE_TAGS) - f.tags
        return f

    def accepts(self, t: Template) -> bool:
        tid = t.id.lower()
        if self.ids and tid not in self.ids:
            return False
        if tid in self.exclude_ids:
            return False
        if self.severities and t.severity not in self.severities:
            return False
        if t.severity in self.exclude_severities:
            return False
        tags = t.tags
        if self.tags and not (tags & self.tags):
            return False
        if tags & self.exclude_tags:
            return False
        if self.authors and not (t.authors & self.authors):
            return False
        return True


def load_templates(paths: Iterable[str], template_filter: TemplateFilter | None = None) -> LoadReport:
    """Load every template under *paths*, applying *template_filter*."""
    report = LoadReport()
    seen_ids: set[str] = set()
    for file_path in iter_template_files(paths):
        report.files_seen += 1
        try:
            template = load_template_file(file_path)
        except UnsupportedTemplate as exc:
            report.unsupported[str(exc)] += 1
            continue
        except (InvalidTemplate, ValueError, TypeError) as exc:
            report.invalid.append((file_path, str(exc)))
            continue
        except OSError as exc:
            report.invalid.append((file_path, f"read error: {exc}"))
            continue
        if template_filter and not template_filter.accepts(template):
            report.filtered += 1
            continue
        if template.id in seen_ids:
            continue
        seen_ids.add(template.id)
        report.templates.append(template)
    return report
