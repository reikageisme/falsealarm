"""
FalseAlarm terminal UI: live dashboard, finding lines, result views, summary.

Design rules:

* **Signal first.** Findings are printed the moment they are confirmed, as one
  coloured line (like nuclei), and summarised by severity at the end.
* **Never truncate what you'd copy.** URLs fold instead of being cut with "…".
* **Degrade cleanly.** No TTY (CI, ``> file``, ``--pipe``) means no live
  region, no spinners, no ANSI unless ``FORCE_COLOR`` is set.
"""

from __future__ import annotations

import time
from collections import Counter, deque
from collections.abc import Callable, Iterable
from typing import Any

from rich import box
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.progress_bar import ProgressBar
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

from falsealarm.core.findings import SEVERITY_ORDER, Finding, collect_findings

# --------------------------------------------------------------------------- #
# Theme
# --------------------------------------------------------------------------- #

SEVERITY_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "bold yellow",
    "low": "bold green",
    "info": "bold cyan",
    "unknown": "dim",
}
SEVERITY_DOT = {"critical": "red", "high": "red", "medium": "yellow", "low": "green", "info": "cyan", "unknown": "white"}


def severity_badge(severity: str) -> Text:
    sev = severity if severity in SEVERITY_STYLE else "unknown"
    return Text(f" {sev.upper():<8}", style=SEVERITY_STYLE[sev]) if sev == "critical" else Text(
        f"{sev.upper():<8}", style=SEVERITY_STYLE[sev]
    )


def status_text(status: Any) -> Text:
    try:
        code = int(status)
    except (TypeError, ValueError):
        return Text(str(status or "-"), style="dim")
    style = "green" if code < 300 else "cyan" if code < 400 else "yellow" if code < 500 else "red"
    return Text(str(code), style=f"bold {style}")


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"


def human_duration(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    m, s = divmod(seconds, 60)
    if m < 60:
        return f"{m}m{s:02d}s"
    h, m = divmod(m, 60)
    return f"{h}h{m:02d}m"


def finding_line(f: Finding) -> Text:
    """One-line, copy-friendly finding (nuclei style)."""
    line = Text()
    line.append("[", style="dim")
    line.append(f.severity, style=SEVERITY_STYLE.get(f.severity, "dim"))
    line.append("] ", style="dim")
    if f.finding_id:
        line.append(f"[{f.finding_id}] ", style="bold")
    line.append(f.title, style="white")
    line.append("  ")
    line.append(f.location, style="underline")
    if f.detail:
        line.append(f"  [{f.detail}]", style="magenta")
    if f.evidence:
        shown = ", ".join(e if len(e) <= 60 else e[:57] + "…" for e in f.evidence[:3])
        line.append(f"  [{shown}]", style="green")
    return line


# --------------------------------------------------------------------------- #
# Live dashboard
# --------------------------------------------------------------------------- #

class ScanDashboard:
    """Bottom-of-screen live status: stage, progress, throughput, findings."""

    def __init__(self, console: Console, stats_source: Callable[[], Any] | None = None):
        self.console = console
        self.stats_source = stats_source
        self.stage = "starting"
        self.target = ""
        self.task_label = ""
        self.task_total = 0
        self.task_done = 0
        self.findings: Counter = Counter()
        self.modules_done = 0
        self.started = time.monotonic()
        self._spinner = Spinner("dots", style="bold red")
        self._samples: deque = deque(maxlen=64)  # (monotonic time, request count)
        self._live: Live | None = None

    # -- lifecycle -------------------------------------------------------- #
    def start(self) -> None:
        if self._live is None:
            self._live = Live(
                self, console=self.console, refresh_per_second=8, transient=True, redirect_stdout=False,
                redirect_stderr=False,
            )
            self._live.start()

    def stop(self) -> None:
        if self._live is not None:
            self._live.stop()
            self._live = None

    # -- updates ---------------------------------------------------------- #
    def set_stage(self, stage: str, target: str = "") -> None:
        self.stage, self.target = stage, target
        self.task_label, self.task_total, self.task_done = "", 0, 0

    def set_task(self, label: str, total: int) -> None:
        self.task_label, self.task_total, self.task_done = label, max(0, int(total)), 0

    def advance(self, n: int = 1) -> None:
        self.task_done = min(self.task_total or self.task_done + n, self.task_done + n)

    def add_finding(self, severity: str) -> None:
        self.findings[severity] += 1

    def current_rps(self, requests: int) -> float:
        """Requests/second over the last ~3 seconds (not the whole-scan average)."""
        now = time.monotonic()
        self._samples.append((now, requests))
        while len(self._samples) > 2 and now - self._samples[0][0] > 3.0:
            self._samples.popleft()
        t0, r0 = self._samples[0]
        return (requests - r0) / (now - t0) if now - t0 >= 0.5 else 0.0

    # -- rendering -------------------------------------------------------- #
    def __rich__(self) -> Group:
        elapsed = time.monotonic() - self.started
        head = Table.grid(padding=(0, 1))
        head.add_column(no_wrap=True)
        head.add_column(no_wrap=True)
        head.add_column(ratio=1, no_wrap=True, overflow="ellipsis")
        head.add_column(no_wrap=True, justify="right")
        stage = Text(self.stage, style="bold cyan")
        if self.task_label and not self.task_total:
            stage.append(f" · {self.task_label}…", style="cyan")
        target = Text(self.target, style="dim")
        head.add_row(self._spinner, stage, target, Text(human_duration(elapsed), style="dim"))

        rows: list[Any] = [head]
        if self.task_total:
            bar = Table.grid(padding=(0, 1))
            bar.add_column(width=2)
            bar.add_column(ratio=1)
            bar.add_column(no_wrap=True)
            pct = self.task_done / self.task_total if self.task_total else 0
            bar.add_row(
                "",
                ProgressBar(total=self.task_total, completed=self.task_done, complete_style="red", finished_style="green"),
                Text(f"{self.task_done:,}/{self.task_total:,} {self.task_label} ({pct:.0%})", style="dim"),
            )
            rows.append(bar)

        line = Text("  ")
        stats = self.stats_source() if self.stats_source else None
        if stats is not None:
            line.append(f"{stats.requests:,} req", style="bold")
            line.append(f" · {self.current_rps(stats.requests):,.0f}/s", style="dim")
            if stats.errors:
                line.append(f" · {stats.errors:,} err", style="yellow")
            buckets: Counter = Counter()
            for code, count in stats.statuses.items():
                buckets[f"{code // 100}xx"] += count
            for bucket, style in (("2xx", "green"), ("3xx", "cyan"), ("4xx", "yellow"), ("5xx", "red")):
                if buckets.get(bucket):
                    line.append(f" · {bucket} {buckets[bucket]:,}", style=style)
            line.append("   ")
        if self.findings:
            for sev in SEVERITY_ORDER:
                if self.findings.get(sev):
                    line.append("● ", style=SEVERITY_DOT[sev])
                    line.append(f"{self.findings[sev]} {sev}  ", style="bold" if sev in ("critical", "high") else "")
        else:
            line.append("no findings yet", style="dim")
        rows.append(line)
        return Group(*rows)


# --------------------------------------------------------------------------- #
# Header
# --------------------------------------------------------------------------- #

def _short_path(path: str) -> str:
    """'/home/me/.falsealarm/nuclei-templates/http/cves' -> '…/http/cves'."""
    parts = [p for p in str(path).replace("\\", "/").split("/") if p]
    return str(path) if len(parts) <= 2 else "…/" + "/".join(parts[-2:])


def scan_header(console: Console, target: str, modules: list[str], config: Any, scan_id: str, waf: str | None) -> None:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="dim", no_wrap=True)
    grid.add_column()
    grid.add_row("target", Text(target, style="bold"))
    grid.add_row("modules", Text(" ".join(modules), style="cyan"))
    tuning = f"{config.rate} req/s · {config.threads} threads · {config.timeout}s timeout · profile {config.depth}"
    if getattr(config, "adaptive_rate", False):
        tuning += " · adaptive"
    if getattr(config, "proxy", None):
        tuning += f" · proxy {config.proxy}"
    grid.add_row("tuning", tuning)
    templates = getattr(config, "templates", None)
    if templates and "vulnscan" in modules:
        grid.add_row("templates", ", ".join(_short_path(t) for t in templates))
    if waf:
        grid.add_row("waf/cdn", Text(f"{waf} — results may be filtered at the edge", style="yellow"))
    grid.add_row("scan id", Text(scan_id, style="dim"))
    console.print(Panel(grid, box=box.ROUNDED, border_style="red", title="[bold]scan[/bold]", title_align="left",
                        expand=False))


# --------------------------------------------------------------------------- #
# Module result views (assets, not findings)
# --------------------------------------------------------------------------- #

MAX_ROWS = 40
_NOISY_KEYS = {"sim_hash", "template", "description", "reference", "classification", "remediation", "_module",
               "network_context", "serialNumber", "version", "body"}


def _table(title: str, *columns: tuple[str, dict]) -> Table:
    t = Table(title=title, title_justify="left", title_style="bold", box=box.SIMPLE_HEAD, header_style="dim",
              show_edge=False, pad_edge=False, expand=False)
    for name, opts in columns:
        t.add_column(name, **opts)
    return t


_URL = {"overflow": "fold", "ratio": 3, "min_width": 20}


def _short(value: Any, n: int = 60) -> str:
    text = ", ".join(map(str, value)) if isinstance(value, (list, tuple, set)) else str(value if value is not None else "")
    return text if len(text) <= n else text[: n - 1] + "…"


def _view_httpprobe(items: list[dict]) -> Table:
    t = _table("Live HTTP services", ("status", {"no_wrap": True}), ("url", _URL), ("title", {"ratio": 2}),
               ("server", {}), ("size", {"justify": "right", "no_wrap": True}))
    for i in items:
        if i.get("alive") is False:
            continue
        t.add_row(status_text(i.get("status")), i.get("url", ""), _short(i.get("title"), 50),
                  _short(i.get("server"), 30), human_bytes(i.get("content_length") or 0))
    return t


def _view_tech(items: list[dict]) -> Table:
    t = _table("Technology", ("target", _URL), ("stack", {"ratio": 3}))
    for i in items:
        techs = i.get("technologies") or []
        stack = Text()
        for n, tech in enumerate(techs):
            if n:
                stack.append(" · ", style="dim")
            stack.append(str(tech.get("name", "?")), style="bold")
            if tech.get("version"):
                stack.append(f" {tech['version']}", style="green")
            if tech.get("category"):
                stack.append(f" ({tech['category']})", style="dim")
        t.add_row(str(i.get("target", "")), stack)
    return t


def _view_dirfuzz(items: list[dict]) -> Table:
    t = _table("Discovered paths", ("status", {"no_wrap": True}), ("url", _URL),
               ("size", {"justify": "right", "no_wrap": True}))
    for i in sorted(items, key=lambda x: (x.get("status", 0), x.get("url", ""))):
        t.add_row(status_text(i.get("status")), str(i.get("url", "")), human_bytes(i.get("length") or 0))
    return t


def _view_subdomain(items: list[dict]) -> Table:
    t = _table("Subdomains", ("domain", {"overflow": "fold"}), ("source", {"style": "dim"}))
    for i in sorted(items, key=lambda x: str(x.get("domain"))):
        t.add_row(str(i.get("domain", "")), str(i.get("source", "")))
    return t


_SERVICE = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3", 111: "rpc",
            135: "msrpc", 139: "netbios", 143: "imap", 443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
            1433: "mssql", 1521: "oracle", 1723: "pptp", 3306: "mysql", 3389: "rdp", 5432: "postgres",
            5900: "vnc", 6379: "redis", 8000: "http-alt", 8008: "http-alt", 8080: "http-proxy", 8443: "https-alt",
            8888: "http-alt", 9200: "elasticsearch", 11211: "memcached", 27017: "mongodb"}


def _view_portscan(items: list[dict]) -> Table:
    t = _table("Open ports", ("host", {}), ("port", {"justify": "right", "style": "bold"}), ("service", {}),
               ("note", {"style": "dim"}))
    for i in sorted(items, key=lambda x: (str(x.get("target")), x.get("port", 0))):
        note = f"edge: {i['edge_provider']}" if i.get("edge_provider") else ""
        t.add_row(str(i.get("target", "")), str(i.get("port", "")), _SERVICE.get(int(i.get("port") or 0), "?"), note)
    return t


def _view_dns(items: list[dict]) -> Table:
    t = _table("DNS records", ("type", {"style": "bold", "no_wrap": True}), ("name", {}), ("value", {"overflow": "fold"}),
               ("ttl", {"justify": "right", "style": "dim"}))
    for i in items:
        t.add_row(str(i.get("type", "")), str(i.get("name", "")), str(i.get("value", "")), str(i.get("ttl", "")))
    return t


def _view_js(items: list[dict]) -> Table:
    t = _table("JavaScript analysis", ("source", _URL), ("endpoints", {"justify": "right"}),
               ("secrets", {"style": "bold red"}))
    for i in items:
        secrets = sorted({str(s.get("type")) for s in i.get("secrets") or []})
        t.add_row(str(i.get("source", "")), str(len(i.get("endpoints") or [])), ", ".join(secrets))
    return t


def _view_wayback(items: list[dict]) -> Table:
    t = _table("Archived URLs", ("url", _URL))
    for i in items:
        t.add_row(str(i.get("url", "")))
    return t


def _view_ssl(items: list[dict]) -> Table:
    t = _table("TLS & headers", ("check", {"no_wrap": True}), ("target", _URL), ("result", {"ratio": 3}))
    for i in items:
        kind = i.get("type")
        if kind == "security_headers":
            missing = i.get("missing_headers") or []
            res = Text(f"{len(i.get('headers_found') or {})} present", style="green")
            if missing:
                res.append(f" · {len(missing)} missing", style="yellow")
            t.add_row("headers", str(i.get("target", "")), res)
        elif kind == "ssl_certificate":
            if i.get("valid"):
                t.add_row("certificate", str(i.get("target", "")),
                          Text(f"{i.get('issuer')} · expires {i.get('valid_to')}", style="green"))
            else:
                t.add_row("certificate", str(i.get("target", "")), Text(str(i.get("error", "invalid")), style="red"))
        elif kind == "https_redirect":
            ok = i.get("secure")
            t.add_row("https redirect", str(i.get("target", "")),
                      Text("yes" if ok else "no — plain HTTP served", style="green" if ok else "yellow"))
    return t


def _view_favicon(items: list[dict]) -> Table:
    t = _table("Favicon hashes", ("url", _URL), ("mmh3 (shodan)", {"style": "bold"}), ("sha256", {"style": "dim"}))
    for i in items:
        mmh3 = str(i.get("mmh3") or "—")
        t.add_row(str(i.get("url", "")), mmh3, str(i.get("sha256", ""))[:16] + "…")
    return t


def _view_generic(title: str, items: list[dict]) -> Table | None:
    keys: list[str] = []
    for i in items:
        for k in i:
            if k not in _NOISY_KEYS and k not in keys:
                keys.append(k)
    keys = keys[:6]
    if not keys:
        return None
    t = _table(title, *[(k, _URL if k in ("url", "target", "source") else {"overflow": "fold"}) for k in keys])
    for i in items:
        t.add_row(*[_short(i.get(k), 80) for k in keys])
    return t


VIEWS: dict[str, Callable[[list[dict]], Table]] = {
    "httpprobe": _view_httpprobe,
    "tech": _view_tech,
    "dirfuzz": _view_dirfuzz,
    "subdomain": _view_subdomain,
    "portscan": _view_portscan,
    "dns": _view_dns,
    "js_analysis": _view_js,
    "wayback": _view_wayback,
    "ssl": _view_ssl,
    "favicon": _view_favicon,
}
# Modules whose output is fully represented in the findings table.
FINDING_ONLY = {"vulnscan", "openredirect", "sqli", "ssti", "nosqli"}


def print_module_views(console: Console, results: dict[str, Any]) -> None:
    for module, payload in results.items():
        if module in FINDING_ONLY or not isinstance(payload, dict):
            continue
        items = [i for i in payload.get("data") or [] if isinstance(i, dict)]
        if not items:
            continue
        shown, hidden = items[:MAX_ROWS], max(0, len(items) - MAX_ROWS)
        view = VIEWS.get(module)
        table = view(shown) if view else _view_generic(module, shown)
        if table is None or not table.row_count:
            continue
        console.print(table)
        if hidden:
            console.print(Text(f"  … {hidden:,} more {module} rows — export with -o results.json", style="dim"))
        console.print()


# --------------------------------------------------------------------------- #
# Summary
# --------------------------------------------------------------------------- #

def _severity_bar(counts: Counter) -> Text:
    text = Text()
    total = sum(counts.values())
    if not total:
        return Text("no findings", style="dim")
    for sev in SEVERITY_ORDER:
        n = counts.get(sev, 0)
        if not n:
            continue
        text.append(f" {n} {sev} ", style=SEVERITY_STYLE[sev] if sev == "critical" else f"reverse {SEVERITY_DOT[sev]}")
        text.append(" ")
    return text


def findings_table(findings: Iterable[Finding], limit: int = 50) -> Table:
    t = Table(box=box.SIMPLE_HEAD, header_style="dim", show_edge=False, pad_edge=False, expand=True)
    t.add_column("severity", no_wrap=True)
    t.add_column("finding", ratio=3, overflow="fold")
    t.add_column("location", ratio=4, overflow="fold")
    t.add_column("evidence", ratio=2, overflow="fold", style="green")
    for f in list(findings)[:limit]:
        title = Text(f.title)
        if f.finding_id:
            title.append(f"\n{f.finding_id}", style="dim")
        evidence = ", ".join(f.evidence[:3])
        if f.detail:
            evidence = f"{f.detail} {evidence}".strip()
        t.add_row(severity_badge(f.severity), title, f.location, evidence)
    return t


def print_summary(
    console: Console,
    target: str,
    results: dict[str, Any],
    stats: Any = None,
    outputs: Iterable[str] = (),
    duration: float | None = None,
    scan_id: str | None = None,
) -> list[Finding]:
    findings = collect_findings(results)
    counts = Counter(f.severity for f in findings)

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="dim", no_wrap=True)
    grid.add_column()
    grid.add_row("findings", _severity_bar(counts))

    modules = Text()
    for idx, (name, payload) in enumerate(results.items()):
        if idx:
            modules.append(" · ", style="dim")
        if isinstance(payload, dict) and payload.get("error"):
            modules.append(f"{name} failed", style="red")
        else:
            n = len(payload.get("data") or []) if isinstance(payload, dict) else 0
            modules.append(name, style="cyan" if n else "dim")
            modules.append(f" {n}", style="bold" if n else "dim")
    if modules:
        grid.add_row("modules", modules)
    if stats is not None:
        elapsed = duration if duration is not None else stats.elapsed
        traffic = (f"{stats.requests:,} requests · {stats.requests / max(elapsed, 1e-6):,.0f} req/s · "
                   f"{human_bytes(stats.bytes)} · {human_duration(elapsed)}")
        if stats.errors:
            traffic += f" · {stats.errors:,} errors"
        grid.add_row("traffic", traffic)
    outs = [o for o in outputs if o]
    if outs:
        grid.add_row("saved", Text(" · ".join(outs), style="bold"))
    if scan_id:
        grid.add_row("scan id", Text(f"{scan_id}  (falsealarm list-scans · --diff on the next run)", style="dim"))

    worst = findings[0].severity if findings else None
    border = {"critical": "red", "high": "red", "medium": "yellow", "low": "green"}.get(worst or "", "cyan")
    console.print(Panel(grid, title=f"[bold]summary[/bold] [dim]{target}[/dim]", title_align="left",
                        border_style=border, box=box.ROUNDED))
    if findings:
        console.print(findings_table(findings))
        if len(findings) > 50:
            console.print(Text(f"  … {len(findings) - 50} more findings — use --report or --html", style="dim"))
    if not outs:
        console.print(Text("  tip: add --html report.html for a shareable report, -o results.json for raw data",
                           style="dim"))
    console.print()
    return findings
