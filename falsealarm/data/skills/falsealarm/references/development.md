# Developing FalseAlarm

Read this reference when changing the Python orchestrator/modules, scan
pipeline, vulnerability templates, outputs, persistence, or Go dirfuzz worker.

## Architecture and contracts

- `falsealarm/cli.py`: Typer commands and configuration assembly.
- `falsealarm/core/config.py`: `ScanConfig` fields and validation.
- `falsealarm/core/engine.py`: shared HTTP session, proxy/fingerprint, retry,
  delay, and rate limiting. HTTP modules should use this engine.
- `falsealarm/core/scheduler.py`: module discovery, DAG traversal, persistence,
  downstream target propagation, resume, and Gemini triage.
- `falsealarm/core/pipeline.py`: aliases, dependency graph, depth profiles, and
  entry points.
- `falsealarm/modules/`: discovered scan modules.
- `falsealarm/data/templates/`: YAML vulnerability templates.
- `engine-go/dirfuzz.go`: optional NDJSON-producing fast worker.

SQLite records scans, module results, and progress. The scheduler instantiates
modules as `module_class(engine=..., db=..., config=..., logger=...)` and calls
`await module.run(target)`.

## Add or change a scan module

Follow the real `BaseModule` contract:

```python
from falsealarm.modules.base import BaseModule, ModuleResult


class ExampleModule(BaseModule):
    name = "example"
    description = "Short user-visible description"

    async def run(self, target: str) -> ModuleResult:
        self._start_timer()
        response = await self.engine.get(target)
        findings: list[dict] = []
        if not response.get("error"):
            # Build evidence-backed findings.
            pass
        return self._make_result(target, findings, {"requests_sent": 1})
```

The file under `falsealarm/modules/` is auto-discovered when it imports cleanly.
Also update the following when applicable:

- `PipelineManager.depth_profiles` if the module belongs in a built-in profile.
- `PipelineManager.graph` and scheduler downstream-target extraction if it
  consumes or produces pipeline targets.
- `falsealarm/modules/__init__.py` and `falsealarm/__init__.py` if the class is
  part of the public Python API.
- Focused discovery, result-shape, error, and boundary-condition tests.

Keep result `data` as a list of dictionaries with stable identity fields. If a
module participates in scan diffs, add stable keys to `KEY_FIELDS` in
`falsealarm/core/diff.py`. Avoid raw `aiohttp` calls inside HTTP modules: using
the shared engine preserves the user's rate, proxy, delay, fingerprint, retry,
and adaptive-backoff settings.

## Add a vulnerability template

Templates require a top-level `id` and `requests`. Current request support is
HTTP method, path, and headers. Available placeholders are `{{BaseURL}}`,
`{{RootURL}}`, `{{Hostname}}`, and `{{Host}}`.

Matchers support:

- `status` with a `status` list;
- `word` with `words`;
- `regex` with `regex` patterns;
- `condition: and|or` within one matcher's value list;
- top-level `matchers-condition: and|or` across matcher blocks;
- `part: body|header|all` for word/regex checks;
- `negative: true` to invert a matcher.

Extractors support regex matches and `kval` response-header values. Prefer an
`and` combination of status plus a distinctive body/header signal to avoid
false positives. Add matcher/extractor unit tests for new semantics; adding a
single data template usually needs a fixture or focused test proving both a
positive and a near-miss response.

## Change the Go worker

Keep stdout strictly one JSON object per line because Python parses it as
NDJSON. Send diagnostics to stderr. Preserve the flags consumed by
`DirFuzzModule` (`-u`, `-w`, `-t`, `-timeout`, plus proxy/rate/User-Agent), and
keep Python fallback behavior equivalent where practical. Test from
`engine-go/` with `go test ./...` and build the platform binary.

## Validate changes

Install development dependencies once:

```powershell
python -m pip install -e . -r requirements-dev.txt
```

Run focused tests first, then the repository checks:

```powershell
python -m pytest -q
python -m compileall -q falsealarm
ruff check falsealarm tests
mypy falsealarm
Push-Location engine-go
go test ./...
go build -o dirfuzz-engine.exe dirfuzz.go
Pop-Location
```

CI treats mypy as advisory but requires Ruff, Python tests/compile on Windows
and Linux with Python 3.10 and 3.13, plus Go test/build. If Go is unavailable
and the change does not touch the worker or its integration, state that limit;
do not imply Go validation ran.

Before finishing, run `python -m falsealarm modules` to catch discovery/import
failures and `python -m falsealarm scan --help` after CLI changes. For network
logic, prefer deterministic local fixtures or stub engines; do not test against
an external target merely for convenience.
