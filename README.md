# FalseAlarm

<p align="center">
  <strong>🔍 Async Web Reconnaissance Engine</strong><br>
  <em>For Pentesters, Bug Bounty Hunters & CTF Players</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-blue?style=flat-square" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="MIT License">
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20windows%20%7C%20macos-lightgrey?style=flat-square" alt="Platform">
  <img src="https://img.shields.io/badge/version-1.0.0-purple?style=flat-square" alt="Version 1.0.0">
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
| `dirfuzz` | Directory/Path Bruteforcing | 🔜 Phase 3 |
| `js_analysis` | JavaScript AST Analysis (API endpoints, secrets) | 🔜 Phase 3 |
| `wayback` | Wayback Machine URL Discovery | 🔜 Phase 3 |
| `cors` | CORS Misconfiguration Detection | 🔜 Phase 3 |
| `portscan` | Async TCP Port Scanner | 🔜 Phase 4 |
| `websocket` | WebSocket Discovery & Analysis | 🔜 Phase 4 |

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/falsealarm.git
cd falsealarm

# Install in development mode
pip install -e .

# Or install dependencies directly
pip install -r requirements.txt
```

## 💻 Usage

```bash
# Basic scan — all modules
falsealarm -u example.com -A

# DNS enumeration only
falsealarm -u example.com -m dns

# Quick scan (fast modules only)
falsealarm -u example.com -q

# With rate limiting and proxy
falsealarm -u example.com -A -r 10 --proxy socks5://127.0.0.1:9050

# Export results to JSON
falsealarm -u example.com -A -o results.json -f json

# Export HTML report
falsealarm -u example.com -A -o report.html -f html

# Resume a previous scan
falsealarm --resume fa_20260721_204512

# List saved scans
falsealarm list-scans

# Silent mode (results only)
falsealarm -u example.com -m dns --silent

# Verbose mode (debug info)
falsealarm -u example.com -m dns -v
```

## ⚙️ CLI Options

```
Usage: falsealarm [OPTIONS] -u <TARGET>

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
  -f, --format       Output format: table/json/csv/html [default: table]
  --silent           Only show results, no banner/progress
  -v, --verbose      Show debug information

State:
  --resume           Resume scan by ID
  --list-scans       List saved scans

Info:
  -h, --help         Show help
  --version          Show version
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
