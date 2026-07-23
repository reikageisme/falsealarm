<div align="center">
  <picture>
    <source srcset="assets/Falsealarm.png" media="(prefers-color-scheme: dark)">
    <source srcset="assets/Falsealarm.png" media="(prefers-color-scheme: light)">
    <img src="assets/Falsealarm.png" alt="FalseAlarm Logo" width="600" style="image-rendering: -webkit-optimize-contrast; image-rendering: crisp-edges;">
  </picture>

  <br/>
  <h1>🛡️ FalseAlarm: Advanced Async Web Reconnaissance Framework</h1>
  <p><strong>An out-of-the-box, AI-Ready Attack Surface Mapping Engine for Modern Hackers.</strong></p>

  <p>
    <a href="https://pypi.org/project/falsealarm/"><img src="https://img.shields.io/badge/pypi-v1.0.0--dev-2563eb?style=for-the-badge&logo=pypi&logoColor=white" alt="PyPI version" /></a>
    <a href="https://github.com/reikageisme/falsealarm/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-16a34a.svg?style=for-the-badge" alt="license" /></a>
    <a href="https://github.com/reikageisme/falsealarm/stargazers"><img src="https://img.shields.io/github/stars/reikageisme/falsealarm?style=for-the-badge&color=eab308" alt="stars" /></a>
    <a href="https://github.com/reikageisme/falsealarm/network/members"><img src="https://img.shields.io/github/forks/reikageisme/falsealarm?style=for-the-badge&color=blue" alt="forks" /></a>
    <a href="https://github.com/reikageisme/falsealarm/issues"><img src="https://img.shields.io/github/issues/reikageisme/falsealarm?style=for-the-badge&color=e67e22" alt="open issues" /></a>
    <img src="https://img.shields.io/badge/python-3.10+-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python Version">
  </p>

  <p>
    <em>Developed with rigorous standards by <a href="https://github.com/reikageisme">ReiKage</a> & The Open Source InfoSec Community.</em>
  </p>

  <a href="#-philosophy">Philosophy</a> •
  <a href="#-core-features">Features</a> •
  <a href="#-module-ecosystem">Modules</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-usage-guide">Usage</a> •
  <a href="#-ai-triage-integration">AI Triage</a>
</div>

---

## 🎯 Philosophy & The Problem It Solves

Traditional scanning tools are inherently flawed for modern web architectures. They operate synchronously, consume excessive memory, and lack the heuristic intelligence required to bypass Next-Gen Web Application Firewalls (WAFs). 

**FalseAlarm** was engineered from the ground up to solve this. By leveraging a highly optimized `asyncio` networking core combined with dynamic YAML-based vulnerability templates and intelligent module scheduling, FalseAlarm allows Pentesters and Bug Bounty Hunters to map vast attack surfaces at blistering speeds while remaining stealthy.

## ⚡ Core Features

### 🚀 High-Performance Engine
* **Full Asynchronous I/O:** Built entirely on `aiohttp` and `asyncio`, capable of sustaining thousands of concurrent connections with minimal CPU footprint.
* **Token Bucket Rate Limiting:** Millisecond-precision traffic control to prevent target DoS and bypass strict rate-limiting WAF rules.
* **Smart Concurrency:** Dynamic thread pool adjustment based on network latency and target responsiveness.

### 🕵️‍♂️ Stealth & Evasion
* **Proxy Orchestration:** Native support for chained HTTP and SOCKS5 proxies (e.g., Tor network) with automatic node health checks.
* **Dynamic Fingerprinting:** Automated rotation of `User-Agent`, TLS handshakes, and HTTP headers to spoof legitimate traffic profiles.
* **Catch-all Detection:** Heuristic analysis to identify and filter out wildcard DNS and soft-404 traps.

### 🧠 Intelligence & State Management
* **AI-Ready Triage:** Direct integration with Google Gemini LLM to automatically parse scan results and prioritize high-impact vulnerabilities.
* **SQLite State Tracking:** Seamlessly pause, resume, and historically query scans without losing a single byte of data.
* **Rich Data Export:** Generate beautiful terminal UIs, parseable JSON, structured CSV, or styled HTML executive reports.

---

## 🧩 Module Ecosystem

FalseAlarm's architecture is strictly modular. Each component can run in isolation or orchestrated together via the `-A` (All) flag.

| Module Core | Tactical Capability | OPSEC Level | Status |
|-------------|---------------------|-------------|:------:|
| `dns` | Deep Record Enumeration (A, AAAA, MX, NS, TXT, SOA, AXFR, SPF, DMARC) | Passive/Active | ✅ |
| `subdomain` | Multi-source Subdomain Enumeration (crt.sh, TLS certs, DNS brute) | Active | ✅ |
| `httpprobe` | Liveness Probing + Similarity Hashing for false positive reduction | Active | ✅ |
| `techdetect` | Fingerprinting (CMS, Frameworks, WAF, CDN) via Headers & DOM | Active | ✅ |
| `dirfuzz` | High-Speed Path/Directory Bruteforcing (Catch-all aware) | Aggressive | ✅ |
| `js_analysis` | JavaScript AST Parsing for hidden API endpoints & hardcoded secrets | Active | ✅ |
| `cors` | Strict CORS Misconfiguration Analysis & Exploit Verification | Active | ✅ |
| `portscan` | Async TCP/UDP Port Scanner (Nmap alternative for L7 chains) | Aggressive | ✅ |
| `websocket` | WebSocket (WS/WSS) Discovery & Message Fuzzing | Active | ✅ |
| `vulnscan` | Next-Gen YAML-based Vulnerability Detection Engine | Aggressive | ✅ |

---

## 📦 Installation

FalseAlarm is designed to be deployed rapidly across diverse penetration testing environments.

### Option 1: Standard Development Install (Recommended)
```bash
git clone [https://github.com/reikageisme/falsealarm.git](https://github.com/reikageisme/falsealarm.git)
cd falsealarm
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
