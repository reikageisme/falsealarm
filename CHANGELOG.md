# Changelog

All notable changes to FalseAlarm are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[1.0.0]: https://github.com/reikageisme/falsealarm/releases/tag/v1.0.0
