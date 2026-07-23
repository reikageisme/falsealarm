<div align="center">
  <picture>
    <source srcset="assets/Falsealarm.png" media="(prefers-color-scheme: dark)">
    <source srcset="assets/Falsealarm.png" media="(prefers-color-scheme: light)">
    <img src="assets/Falsealarm.png" alt="FalseAlarm Logo" width="600" style="image-rendering: -webkit-optimize-contrast; image-rendering: crisp-edges;">
  </picture>

  <br/>
  <h1>🛡️ FalseAlarm: Advanced Async Web Reconnaissance Framework</h1>
  <p><strong>An out-of-the-box, Polyglot (Python + Go) & AI-Ready Attack Surface Mapping Engine.</strong></p>

  <p>
    <a href="https://pypi.org/project/falsealarm/"><img src="https://img.shields.io/badge/pypi-v1.0.0--dev-2563eb?style=for-the-badge&logo=pypi&logoColor=white" alt="PyPI version" /></a>
    <a href="https://github.com/reikageisme/falsealarm/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-16a34a.svg?style=for-the-badge" alt="license" /></a>
    <a href="https://github.com/reikageisme/falsealarm/stargazers"><img src="https://img.shields.io/github/stars/reikageisme/falsealarm?style=for-the-badge&color=eab308" alt="stars" /></a>
    <a href="https://github.com/reikageisme/falsealarm/network/members"><img src="https://img.shields.io/github/forks/reikageisme/falsealarm?style=for-the-badge&color=blue" alt="forks" /></a>
    <a href="https://github.com/reikageisme/falsealarm/issues"><img src="https://img.shields.io/github/issues/reikageisme/falsealarm?style=for-the-badge&color=e67e22" alt="open issues" /></a>
    <img src="https://img.shields.io/badge/python-3.10+-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python Version">
    <img src="https://img.shields.io/badge/go-1.20+-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go Version">
  </p>

  <p>
    <em>Developed by <a href="https://github.com/reikageisme">ReiKage (reikageisme)</a> & The Open Source InfoSec Community.</em>
  </p>

  <a href="#-philosophy--the-problem-it-solves">Philosophy</a> •
  <a href="#-core-features">Features</a> •
  <a href="#-module-ecosystem">Modules</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-usage-guide">Usage</a> •
  <a href="#-ai-triage-integration">AI Triage</a> •
  <a href="#-license">License</a>
</div>

---

## 🎯 Philosophy & The Problem It Solves

Traditional scanning tools are inherently flawed for modern web architectures. They operate synchronously, consume excessive memory, and lack the heuristic intelligence required to bypass Next-Gen Web Application Firewalls (WAFs). 

**FalseAlarm** was engineered from the ground up to solve this. By combining a Python `asyncio` orchestrator with a high-performance **Go (fasthttp)** worker engine, dynamic YAML vulnerability templates, and intelligent plugin auto-discovery, FalseAlarm allows Pentesters and Bug Bounty Hunters to map vast attack surfaces at blistering speeds with streaming real-time NDJSON feedback.

## ⚡ Core Features

### 🚀 Polyglot & High-Performance Engine
* **Python Orchestrator + Native Go Engine:** High-speed directory and parameter fuzzing powered by `fasthttp` in Go, with real-time NDJSON line-by-line streaming.
* **Full Asynchronous I/O:** Built on `aiohttp` and `asyncio`, capable of sustaining thousands of concurrent connections with minimal CPU footprint.
* **Token Bucket Rate Limiting:** Millisecond-precision traffic control with automatic HTTP 429 backoff handling.
* **Auto-Discovery Plugin Architecture:** Drop any custom `.py` module inheriting `BaseModule` into `falsealarm/modules/` for instant execution without touching core code.

### 🕵️‍♂️ Stealth & Evasion
* **Proxy Orchestration:** Native support for chained HTTP and SOCKS5 proxies (e.g., Tor network) with automatic node health checks.
* **Dynamic Fingerprinting:** Automated rotation of `User-Agent`, TLS handshakes, and HTTP headers to spoof legitimate traffic profiles.
* **Smart Catch-All & Baseline Calibration:** Heuristic analysis to calculate response baselines, filtering out wildcard DNS and soft-404 traps.

### 🧠 Intelligence & State Management
* **Multi-Target & CIDR Support:** Scan individual URLs (`-u`), input lists (`-iL targets.txt`), or full IP network blocks (`192.168.1.0/24`).
* **YAML Configuration Profiles:** Save and reuse scan presets (`falsealarm scan -c profile.yaml -p stealth`).
* **AI-Ready Triage:** Direct integration with LLMs (Gemini / Anthropic / OpenAI) to automatically parse scan results and prioritize high-impact vulnerabilities.
* **SQLite State Tracking:** Non-blocking WAL-mode SQLite database with automatic retry timeouts for scan history and state persistence.

---

## 🧩 Module Ecosystem

FalseAlarm's architecture is strictly modular with dynamic plugin discovery. Each component can run in isolation or orchestrated together via the `-A` (All) flag.

| Module Core | Tactical Capability | OPSEC Level | Status |
|-------------|---------------------|-------------|:------:|
| `dns` | Deep Record Enumeration (A, AAAA, MX, NS, TXT, SOA, AXFR, SPF, DMARC) | Passive/Active | ✅ |
| `subdomain` | Multi-source Subdomain Enumeration (crt.sh, TLS certs, DNS brute) | Active | ✅ |
| `httpprobe` | Liveness Probing + Similarity Hashing for false positive reduction | Active | ✅ |
| `techdetect` | Fingerprinting (CMS, Frameworks, WAF, CDN) via Headers & DOM | Active | ✅ |
| `dirfuzz` | Polyglot (Go + Python) High-Speed Path/Directory Fuzzing (NDJSON Streaming) | Aggressive | ✅ |
| `js_analysis` | JavaScript AST Parsing for hidden API endpoints & hardcoded secrets | Active | ✅ |
| `cors` | Strict CORS Misconfiguration Analysis & Exploit Verification | Active | ✅ |
| `portscan` | Async TCP/UDP Port Scanner (Nmap alternative for L7 chains) | Aggressive | ✅ |
| `websocket` | WebSocket (WS/WSS) Discovery & Message Fuzzing | Active | ✅ |
| `vulnscan` | Next-Gen YAML-based Vulnerability Detection Engine (CVEs, Cloud Keys, Misconfigs) | Aggressive | ✅ |

---

## 📦 Installation

FalseAlarm is designed to be deployed rapidly across diverse penetration testing environments.

### Option 1: Standard Development Install (Recommended)
```bash
git clone https://github.com/reikageisme/falsealarm.git
cd falsealarm
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# Compile high-speed Go Fuzzing engine
python -m falsealarm build-engine
```

### Option 2: Isolated Global Install (via pipx)
```bash
pipx install git+https://github.com/reikageisme/falsealarm.git
```

### Option 3: Docker Deployment
```bash
docker pull reikageisme/falsealarm:latest
docker run -it --rm reikageisme/falsealarm scan -u example.com -A
```

---

## 💻 Usage Guide

The FalseAlarm CLI is built for speed and intuition.

### 🔍 Standard Reconnaissance
```bash
# 1. Comprehensive mapping (All modules)
falsealarm scan -u example.com -A

# 2. Targeted modular scan (DNS and Tech only)
falsealarm scan -u example.com -m dns,techdetect

# 3. Multi-target file or CIDR range scan
falsealarm scan -iL targets.txt -q
falsealarm scan -u 192.168.1.0/24 -m portscan,httpprobe

# 4. Quick mode (Bypasses heavy fuzzing for rapid overview)
falsealarm scan -u example.com -q
```

### 🥷 Stealth & High-Speed Fuzzing
```bash
# Rate limited with Tor network proxy and randomized headers
falsealarm scan -u example.com -A -r 15 -t 20 --proxy socks5://127.0.0.1:9050 --random-agent

# High-intensity Go-accelerated Directory Fuzzing
falsealarm scan -u http://example.com/FUZZ -m dirfuzz -t 100 -w common.txt
```

### 📊 Data Management & Profiles
```bash
# Load scan parameters from a YAML profile
falsealarm scan -c profile.yaml -p stealth

# Export results to JSON for CI/CD pipelines
falsealarm scan -u example.com -A -o results.json -f json

# List historical scans
falsealarm list-scans
```

---

## 🤖 AI Triage Integration

FalseAlarm introduces an AI Triage layer. By hooking into Gemini / OpenAI / Anthropic LLMs, the framework automatically analyzes scan outputs, filters out noise, and highlights chained exploit paths.

**Setup `.env` configuration:**
```bash
echo -e 'OPENAI_API_KEY="sk-1234"\nANTHROPIC_API_KEY=""\nOLLAMA=""\nPROMPT_TOOLKIT_NO_CPR=1\nCAI_STREAM=false' > .env
```

**Execute scan with AI Triage:**
```bash
falsealarm scan -u example.com -A --ai-triage
```

---

## 🐍 Python API Integration

FalseAlarm is fully extensible. You can import its async core directly into your own security orchestration scripts.

```python
import asyncio
from falsealarm.core.config import ScanConfig
from falsealarm.core.engine import AsyncEngine
from falsealarm.modules.techdetect import TechDetectModule

async def automate_recon():
    # 1. Define scanning parameters
    config = ScanConfig(
        target="example.com",
        modules=["techdetect"],
        threads=20,
        timeout=10
    )
    
    # 2. Initialize the asynchronous networking core
    engine = AsyncEngine(config)
    
    # 3. Instantiate and execute the specific module
    module = TechDetectModule(config, engine)
    results = await module.run()
    
    print(f"[+] Discovered Technologies: {results}")
    await engine.close()

if __name__ == "__main__":
    asyncio.run(automate_recon())
```

---

## 📜 License

Copyright (c) 2026 **ReiKage (`reikageisme`)** & FalseAlarm Security Engine Contributors.

This project is licensed under the **MIT License**. Permission is hereby granted to use, copy, modify, merge, publish, distribute, and sublicense this software for any lawful security research or penetration testing purpose.

---

## ⚖️ Legal Disclaimer & Ethics

FalseAlarm is an offensive security tool designed strictly for authorized penetration testing, academic research, and lawful bug bounty programs.

Executing Layer 7 reconnaissance and fuzzing attacks against infrastructure without explicit, written authorization is illegal. The developers assume zero liability for any misuse, damage, or legal consequences resulting from the deployment of this tool.

*Hack ethically. Stay authorized.*
