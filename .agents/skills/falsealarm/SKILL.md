---
name: falsealarm
description: Knowledge and commands for the FalseAlarm async web reconnaissance framework (Python + Go).
---

# FalseAlarm Knowledge Base

FalseAlarm is an Advanced Async Web Reconnaissance Framework combining a Python `asyncio` orchestrator with a high-performance Go (`fasthttp`) worker engine.

## Core Architecture
- **Language**: Python 3.10+ (Orchestrator) & Go 1.20+ (High-speed Fuzzing Engine)
- **CLI Framework**: `typer` and `rich`
- **Module System**: Auto-discovery plugin architecture. Custom modules are placed in `falsealarm/modules/` and must inherit from `BaseModule`.
- **Concurrency**: `asyncio` and `aiohttp` for Python, `fasthttp` for Go.

## Important Commands
- **Install for Development**: 
  ```bash
  python3 -m venv .venv
  source .venv/bin/activate
  pip install -e .
  ```
- **Compile Go Engine**: `python -m falsealarm build-engine`
- **CLI Entry Point**: `falsealarm`
  - *Comprehensive Scan*: `falsealarm scan -u <url> -A`
  - *Targeted Scan (e.g. DNS + technology)*: `falsealarm scan -u <url> -m dns,tech`
  - *High-Speed Directory Fuzzing*: `falsealarm scan -u <url>/FUZZ -m dirfuzz -t 100 -w common.txt`

## Development Guidelines
- Always use `asyncio` for new Python modules.
- Ensure new modules inherit from `BaseModule`.
- Utilize environment variables (via `.env`) for AI API keys (Gemini, OpenAI, Anthropic) for AI Triage integration.
