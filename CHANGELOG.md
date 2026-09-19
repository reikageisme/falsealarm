# Changelog

All notable changes to FalseAlarm are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.6] - 2026-09-19

### Added
- **Bundled FalseAlarm agent skill.** The wheel and source distribution now
  include scoped operating, troubleshooting, extension, and testing guidance
  for AI coding agents.
- **`falsealarm install-skill`.** Installs the bundled skill for Codex, Claude,
  a project-local `.agents/skills` directory, or a custom destination. Existing
  installations require an explicit `--force` update.

### Changed
- The repository skill now points to the packaged canonical copy, preventing
  the development and PyPI versions from drifting apart.

### Fixed
- **Global `--version`.** `falsealarm --version` now reports the package
  version instead of being rejected as an unknown root option.

## [1.0.5] - 2026-09-14

### Fixed
- **AI triage actually ships the model fix now.** The `gemini-3.1-pro-preview`
  default and `GEMINI_MODEL` override were intended for 1.0.4 but did not make
  it into that build, which still called the retired `gemini-1.5-pro` and
  returned a 404 under `--ai-triage`. This release contains the corrected
  provider.

## [1.0.4] - 2026-09-14

### Fixed
- **AI triage no longer points at a retired model.** The Gemini provider
  defaulted to `gemini-1.5-pro`, which the Gemini API no longer serves, so
  `--ai-triage` returned a 404 instead of an analysis. The default is now
  `gemini-3.1-pro-preview`.

### Added
- **`GEMINI_MODEL` environment variable.** Overrides the triage model without
  touching code (e.g. `GEMINI_MODEL=gemini-3.8-flash` for cheaper, faster
  triage).

## [1.0.3] - 2026-09-11

### Fixed
- **Deterministic catch-all detection via response-body signatures.** A catch-all
  page served at randomly varying sizes (an SPA behind a CDN) could still leak
  bogus 200 hits when the baseline probes happened to sample only one size.
  `dirfuzz` now matches hits against the catch-all's *structural* body signature
  (stable across sizes), so one probe recognises every variant; the statistical
  net also fires on any implausibly crowded same-size 200 cluster.

## [1.0.2] - 2026-09-11

### Fixed
- **Hardened catch-all detection against multi-size soft-404 pages.** SPAs that
  echo the requested path into their fallback page serve the "not found" page at
  several different sizes; `dirfuzz` now calibrates its baseline from multiple
  probes (so it learns *every* catch-all size and survives a single blocked
  probe) and the statistical safety net triggers sooner, so those pages no
  longer leak bogus directory hits.

## [1.0.1] - 2026-09-11

### Fixed
- **Eliminated soft-200 / catch-all false positives.** Targets that answer
  every path with HTTP 200 (SPAs, WAF/CDN edges) no longer produce a storm of
  bogus directory hits: `dirfuzz` now detects a catch-all statistically and
  drops indistinguishable 200s while keeping redirects, 403s, and rare-sized
  outliers — even when the up-front baseline probe is blocked.
- **Bundled vulnerability templates now AND their matchers.** `.env`,
  `.git/config`, AWS-keys and CVE-2021-41773 set `matchers-condition: and`, so a
  bare 200 response can no longer trigger a critical/high finding on a catch-all
  page.

## [1.0.0] - 2026-09-11

First stable release. FalseAlarm is a polyglot (Python + Go), fully
asynchronous web-reconnaissance framework with a modular auto-discovery
architecture, a nuclei-style YAML vulnerability engine, and optional LLM triage.

### Added
- **Async core engine** (`aiohttp` + `asyncio`) with connection pooling,
  token-bucket rate limiting (per-host + adaptive back-off), request
  fingerprint/User-Agent rotation, and HTTP/SOCKS5 proxy orchestration with
  up-front proxy-pool health checks.
- **Polyglot fuzzing** — a Go/`fasthttp` `dirfuzz` engine streaming NDJSON,
  with a graceful fallback to the Python fuzzer when the binary is absent.
- **13 recon modules**: `dns`, `subdomain`, `httpprobe`, `tech`, `dirfuzz`,
  `js_analysis`, `cors`, `portscan`, `websocket`, `vulnscan`, `favicon`,
  `graphql`, `openredirect` — each runnable in isolation or orchestrated as a
  DAG pipeline via `-A`.
- **YAML vulnerability templates** (regex / header / negative matchers +
  extractors) with a starter template set.
- **Pipe mode** (`--pipe`): reads targets from stdin, streams NDJSON to stdout,
  logs to stderr — composes with `subfinder`, `httpx`, `jq`, etc.
- **Scan monitoring**: `--diff` between runs + `--notify` (Discord / Slack /
  Telegram) to alert only on new assets, ports, or findings.
- **Output formats**: JSON, JSONL/NDJSON, SARIF (GitHub Code Scanning), and a
  Markdown pentester handoff report.
- **AI triage** (`--ai-triage`) via Gemini / OpenAI / Anthropic providers.
- **State tracking** in WAL-mode SQLite, with `--resume` for interrupted scans.
- Cross-platform prebuilt Go engine binaries and PyPI / Docker (GHCR) release
  automation; CI across Linux + Windows on Python 3.10 and 3.13.

### Fixed
- `--adaptive-rate` now actually reaches the rate limiter (the flag was
  previously dropped, so adaptive throttling never engaged).
- Port-scan results on non-default web ports (8000/8008/8080/8443/8888) are now
  promoted into the downstream pipeline instead of being silently dropped.
- CORS bypass origins are built from the hostname, producing well-formed
  suffix/prefix bypass payloads (`https://host.evil.com`, `https://evil-host`).
- Scan-diff keys port findings by `(target, port)`, so identical ports on
  different hosts no longer collide.
- The Go fuzzing engine honours the same `--proxy`, rate limit, and User-Agent
  as the Python core, closing an IP-leak when scanning through a proxy chain.

### Removed
- Dropped the unmaintained `pyjsparser` dependency (it broke `pip install` on
  modern setuptools and contributed nothing — regex handling covers JS scanning).

[1.0.6]: https://github.com/reikageisme/falsealarm/releases/tag/v1.0.6
[1.0.5]: https://github.com/reikageisme/falsealarm/releases/tag/v1.0.5
[1.0.4]: https://github.com/reikageisme/falsealarm/releases/tag/v1.0.4
[1.0.3]: https://github.com/reikageisme/falsealarm/releases/tag/v1.0.3
[1.0.2]: https://github.com/reikageisme/falsealarm/releases/tag/v1.0.2
[1.0.1]: https://github.com/reikageisme/falsealarm/releases/tag/v1.0.1
[1.0.0]: https://github.com/reikageisme/falsealarm/releases/tag/v1.0.0
