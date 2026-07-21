<p align="center">
  <picture>
    <source srcset="assets/Falsealarm.png" media="(prefers-color-scheme: dark)">
    <source srcset="assets/Falsealarm.png" media="(prefers-color-scheme: light)">
    <img src="assets/Falsealarm.png" alt="FalseAlarm Logo" width="600" style="image-rendering: -webkit-optimize-contrast; image-rendering: crisp-edges;">
  </picture>
</p>

<p align="center">
  <strong>An out-of-the-box, AI-Ready Reconnaissance Framework for Modern Hackers.</strong><br/>
  <sub>Traditional scanning tools are slow, synchronous, and easily blocked. FalseAlarm utilizes asynchronous I/O, dynamic YAML Vuln templates, and intelligent module scheduling to blast through targets with immense speed while evading WAFs. Built for Pentesters, Bug Bounty Hunters & CTF Players.</sub>
</p>

<p align="center">
  Developed by <a href="https://github.com/reikageisme">reikageisme</a>
</p>

<p align="center">
  <a href="#-installation">Quick Start</a> •
  <a href="#-usage">CLI Usage</a> •
  <a href="#-modules">Modules</a> •
  <a href="#-using-as-a-python-library">Python API</a>
</p>

<p align="center">
  <a href="https://pypi.org/project/falsealarm/"><img src="https://img.shields.io/badge/pypi-v1.0.0--dev-2563eb?style=flat-square" alt="PyPI version" /></a>
  <a href="https://github.com/reikageisme/falsealarm/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-16a34a.svg?style=flat-square" alt="license" /></a>
  <a href="https://github.com/reikageisme/falsealarm/stargazers"><img src="https://img.shields.io/github/stars/reikageisme/falsealarm?style=flat-square&color=eab308" alt="stars" /></a>
  <a href="https://github.com/reikageisme/falsealarm/issues"><img src="https://img.shields.io/github/issues/reikageisme/falsealarm?style=flat-square&color=e67e22" alt="open issues" /></a>
  <a href="https://github.com/reikageisme/falsealarm/pulls"><img src="https://img.shields.io/github/issues-pr/reikageisme/falsealarm?style=flat-square&color=9b59b6" alt="open PRs" /></a>
  <img src="https://img.shields.io/badge/python-3.10+-blue?style=flat-square" alt="Python Version">
</p>

---

## ⚡ Features

- **Full Async Engine** — Built on `aiohttp` + `asyncio` for maximum throughput
- **Token Bucket Rate Limiting** — Millisecond-precision rate control to avoid overloading targets
- **SQLite State Management** — Pause/resume scans, query historical results
- **Proxy Rotation** — HTTP and SOCKS5 proxy support with automatic health checks
- **Request Fingerprinting** — Randomized User-Agent and headers
- **Beautiful CLI** — Rich terminal UI with progress bars, colored output, and nmap-style flags
- **Multiple Export Formats** — JSON, CSV, and styled HTML reports

## 📦 Modules

| Module | Description | Status |
|--------|-------------|--------|
| `dns` | DNS Record Enumeration (A, AAAA, MX, NS, TXT, SOA, SRV, CAA, AXFR, SPF, DKIM, DMARC) | ✅ |
| `subdomain` | Subdomain Enumeration (crt.sh, DNS brute-force) | ✅ |
| `httpprobe` | HTTP Probing + Similarity Hashing for false positive detection | ✅ |
| `techdetect` | Technology Detection (CMS, frameworks, WAF, CDN) | ✅ |
| `headers` | Security Headers Analysis | ✅ |
| `ssl` | SSL/TLS Certificate & Cipher Analysis | ✅ |
| `dirfuzz` | Directory/Path Bruteforcing | ✅ |
| `js_analysis` | JavaScript AST Analysis (API endpoints, secrets) | ✅ |
| `wayback` | Wayback Machine URL Discovery | ✅ |
| `cors` | CORS Misconfiguration Detection | ✅ |
| `portscan` | Async TCP Port Scanner | ✅ |
| `websocket` | WebSocket Discovery & Analysis | ✅ |
| `vulnscan` | YAML-based Vulnerability Detection Engine (Next-Gen) | ✅ |

## 🚀 Installation

```bash
# 1. Clone the repository
git clone https://github.com/reikageisme/falsealarm.git
cd falsealarm

# 2. Install in development mode
pip install -e .

# (Optional) Install requirements directly
pip install -r requirements.txt
```

### 🔄 Updating
If you already have FalseAlarm installed and want to fetch the latest features without deleting the folder, run:
```bash
cd falsealarm
git pull origin main
pip install -e .
```

## 🧠 AI Configuration
To unlock the true power of **AI Triage** (Milestone 3), you need to provide a Google Gemini API Key. You can easily do this by creating a `.env` file in your working directory. 

Run the following command to generate the `.env` file:
```bash
echo -e 'GEMINI_API_KEY="your_api_key_here"' > .env
```
FalseAlarm will automatically detect and load this key during runtime.

## 💻 Usage

```bash
# Basic scan — all modules (shorthand)
falsealarm -u example.com -A

# Or explicitly using the scan subcommand
falsealarm scan -u example.com -A

# DNS enumeration only
falsealarm scan -u example.com -m dns

# Quick scan (fast modules only)
falsealarm scan -u example.com -q

# With rate limiting and proxy
falsealarm scan -u example.com -A -r 10 --proxy socks5://127.0.0.1:9050

# Vulnerability Scanning using YAML Templates
falsealarm scan -u example.com -m vulnscan

# Export results to JSON
falsealarm -u example.com -A -o results.json -f json

# Run all modules and execute an AI Triage analysis at the end!
falsealarm -u example.com -A --ai-triage

# Resume a previous scan
falsealarm scan --resume fa_20260721_204512

# List saved scans
falsealarm list-scans

# Silent mode (save to file without printing to terminal)
falsealarm -u example.com -m dns -o report.txt --silent

# Verbose mode (debug info)
falsealarm -u example.com -m dns -v
```

## ⚙️ CLI Options

```
Usage: falsealarm [scan] [OPTIONS] -u <TARGET>

Scan Options:
  -u, --url          Target URL or domain [required]
  -m, --module       Specific module(s), comma-separated
  -A, --all          Run all available modules
  -q, --quick        Quick scan (fast modules only)

Performance:
  -t, --threads      Concurrent tasks [default: 50]
  -r, --rate         Max requests/second [default: 30]
  --timeout          Request timeout in seconds [default: 10]
  --delay            Delay between requests in ms [default: 0]

Proxy & Stealth:
  --proxy            Proxy URL (http:// or socks5://)
  --proxy-file       File containing proxy list
  --random-agent     Rotate User-Agent randomly

Output:
  -o, --output       Save output to file
  -f, --format       Output format: table/json/csv/txt [default: txt]
  --silent           Only show results, no banner/progress
  -v, --verbose      Show debug information

State:
  --resume           Resume scan by ID
  --list-scans       List saved scans

Info:
  -h, --help         Show help
  --version          Show version
```

## 🐍 Using as a Python Library

FalseAlarm exposes its core components allowing you to build custom scripts or integrate it into other tools:

```python
import asyncio
from falsealarm import AsyncEngine, ScanConfig, SubdomainModule, TechDetectModule

async def main():
    # Configure the scan
    config = ScanConfig(
        target="example.com",
        modules=["subdomain", "tech"],
        threads=20
    )
    
    # Initialize engine
    engine = AsyncEngine(config)
    
    # Run a specific module manually
    tech_module = TechDetectModule(config, engine)
    results = await tech_module.run()
    
    print(results)
    await engine.close()

if __name__ == "__main__":
    asyncio.run(main())
```

## 🏗️ Architecture

```
falsealarm/
├── falsealarm/
│   ├── __init__.py           # Package info + banner
│   ├── __main__.py           # python -m falsealarm
│   ├── cli.py                # Typer CLI entry point
│   ├── core/
│   │   ├── engine.py         # Async HTTP engine (aiohttp)
│   │   ├── rate_limiter.py   # Token Bucket rate limiter
│   │   ├── scheduler.py      # Module orchestrator
│   │   ├── db.py             # SQLite state manager
│   │   ├── fingerprint.py    # Request header randomizer
│   │   ├── proxy.py          # Proxy rotation manager
│   │   ├── config.py         # ScanConfig dataclass
│   │   ├── logger.py         # Rich terminal logger
│   │   ├── output.py         # Export (JSON/CSV/HTML)
│   │   └── utils.py          # Shared utilities
│   ├── modules/
│   │   ├── base.py           # BaseModule abstract class
│   │   ├── dns_enum.py       # DNS Enumeration module
│   │   └── vulnscan.py       # YAML VulnScan module
│   └── data/
│       ├── user_agents.txt   # Browser UA strings
│       ├── tech_signatures.json
│       ├── templates/        # VulnScan YAML signatures
│       │   └── env-exposure.yaml
│       └── wordlists/
│           ├── common_dirs.txt
│           └── subdomains_top1k.txt
├── pyproject.toml
├── requirements.txt
├── LICENSE
└── README.md
```

## ⚠️ Legal Disclaimer

**FalseAlarm is designed for authorized security testing only.**

Only use this tool on systems you have explicit permission to test. Unauthorized scanning or testing of systems you do not own or have permission to test is illegal and unethical.

The developers of FalseAlarm assume no liability for misuse of this tool.

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
