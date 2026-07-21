<p align="center">
  <picture>
    <source srcset="assets/Falsealarm.png" media="(prefers-color-scheme: dark)">
    <source srcset="assets/Falsealarm.png" media="(prefers-color-scheme: light)">
    <img src="assets/Falsealarm.png" alt="FalseAlarm Logo" width="600" style="image-rendering: -webkit-optimize-contrast; image-rendering: crisp-edges;">
  </picture>
</p>

<p align="center">
  <strong>An advanced, async-driven Layer 7 Reconnaissance Engine.</strong><br/>
  <sub>Traditional scanning tools are slow, synchronous, and easily blocked. FalseAlarm utilizes asynchronous I/O and intelligent module scheduling to blast through targets with immense speed while fingerprinting bypasses, WAFs, and attack surfaces. Built for Pentesters, Bug Bounty Hunters & CTF Players.</sub>
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

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/reikageisme/falsealarm.git
cd falsealarm

# Install in development mode
pip install -e .

# Or install dependencies directly
pip install -r requirements.txt
```

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

# Export results to TXT (Default)
falsealarm -u example.com -A -o report.txt

# Export HTML report
falsealarm -u example.com -A -o report.html -f html

# Export results to JSON
falsealarm -u example.com -A -o results.json -f json

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
  -f, --format       Output format: table/json/csv/html/txt [default: txt]
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
│   │   └── dns_enum.py       # DNS Enumeration module
│   └── data/
│       ├── user_agents.txt   # Browser UA strings
│       ├── tech_signatures.json
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
