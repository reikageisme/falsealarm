import asyncio
import os
import sys
from typing import Optional

import typer
from dotenv import load_dotenv
from rich.markdown import Markdown
from rich.panel import Panel

from falsealarm import __version__
from falsealarm.core.paths import nuclei_templates_dir

# Load environment variables from .env file
load_dotenv()

from falsealarm.core import (
    AsyncEngine,
    Database,
    FalseAlarmLogger,
    OutputManager,
    ScanConfig,
    ScanScheduler,
)

# Modules are now auto-discovered by the ScanScheduler

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="rich",
    help="FalseAlarm — Async Web Reconnaissance Engine"
)

SUPPORTED_COMMANDS = {
    "scan", "list-scans", "modules", "build-engine", "install-skill", "templates",
    "config", "--help", "-h", "--version",
}

def version_callback(value: bool):
    if value:
        typer.echo(f"FalseAlarm v{__version__}")
        raise typer.Exit()


@app.callback()
def root_options(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        callback=version_callback,
        is_eager=True,
        help="Show version",
    ),
):
    """FalseAlarm command-line interface."""


@app.command(name="list-scans")
def list_scans(
    db_path: Optional[str] = typer.Option(None, "--db", help="Database file (default: ~/.falsealarm/falsealarm.db)")
):
    """List saved scans."""
    async def _list_scans():
        db = Database(db_path=db_path)
        await db.init()
        scans = await db.list_scans()
        if not scans:
            print("No scans found.")
        else:
            for s in scans:
                print(f"[{s.get('id', 'N/A')}] Target: {s.get('target', 'N/A')} - Date: {s.get('created_at', 'N/A')}")
        await db.close()

    asyncio.run(_list_scans())

@app.command(name="modules")
def list_modules():
    """List installed scan modules and their descriptions."""
    import importlib
    import inspect
    import pkgutil

    from rich.console import Console
    from rich.table import Table

    import falsealarm.modules as modules_pkg
    from falsealarm.modules.base import BaseModule

    discovered: dict[str, str] = {}
    prefix = modules_pkg.__name__ + "."
    for _, module_name, _ in pkgutil.iter_modules(modules_pkg.__path__, prefix):
        module_obj = importlib.import_module(module_name)
        for _, cls in inspect.getmembers(module_obj, inspect.isclass):
            if issubclass(cls, BaseModule) and cls is not BaseModule and cls.name:
                discovered[cls.name] = cls.description

    table = Table(title="Available scan modules")
    table.add_column("Module", style="cyan")
    table.add_column("Description")
    for name in sorted(discovered):
        table.add_row(name, discovered[name])
    Console().print(table)


@app.command(name="install-skill")
def install_skill(
    target: str = typer.Option(
        "codex",
        "--target",
        help="Agent target: codex, claude, or project [default: codex]",
    ),
    destination: Optional[str] = typer.Option(
        None,
        "--destination",
        help="Custom final skill directory (overrides --target)",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Update an existing FalseAlarm skill in place",
    ),
):
    """Install the bundled FalseAlarm skill for an AI coding agent."""
    from falsealarm.core.skill_installer import install_agent_skill

    try:
        installed = install_agent_skill(
            target=target,
            destination=destination,
            force=force,
        )
    except (FileExistsError, FileNotFoundError, ValueError) as exc:
        typer.secho(f"[!] {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc

    typer.secho(f"[+] FalseAlarm skill installed at {installed}", fg=typer.colors.GREEN)

@app.command(name="scan")
def run_scan(
    url: Optional[str] = typer.Option(None, "-u", "--url", help="Target URL or domain"),
    target_list: Optional[str] = typer.Option(None, "-iL", "--list", help="File containing list of targets"),
    config_file: Optional[str] = typer.Option(None, "-c", "--config", help="YAML configuration profile file"),
    profile: str = typer.Option("default", "-p", "--profile", help="Profile name within the config file [default: default]"),
    module: Optional[str] = typer.Option(None, "-m", "--module", help="Specific module(s) comma-separated"),
    all_modules: bool = typer.Option(False, "-A", "--all", help="Run all available modules"),
    quick: bool = typer.Option(False, "-q", "--quick", help="Quick scan (fast modules only)"),
    threads: int = typer.Option(50, "-t", "--threads", help="Concurrent tasks [default: 50]"),
    rate: int = typer.Option(30, "-r", "--rate", help="Max requests/second [default: 30]"),
    timeout: int = typer.Option(10, "--timeout", help="Request timeout seconds [default: 10]"),
    delay: float = typer.Option(0.0, "--delay", help="Delay between requests ms [default: 0]"),
    proxy: Optional[str] = typer.Option(None, "--proxy", help="Proxy URL (http:// or socks5://)"),
    proxy_file: Optional[str] = typer.Option(None, "--proxy-file", help="File with proxy list"),
    random_agent: bool = typer.Option(False, "--random-agent", help="Use random User-Agent"),
    header: list[str] = typer.Option(None, "-H", "--header", help="Extra request header 'Name: value' (repeatable) — for authenticated scans"),
    cookie: Optional[str] = typer.Option(None, "-b", "--cookie", help="Cookie header for authenticated scans, e.g. 'session=abc; role=admin'"),
    scope: Optional[str] = typer.Option(None, "--scope", help="Only scan hosts matching these (comma-separated host/*.wildcard/CIDR/URL-prefix)"),
    exclude_scope: Optional[str] = typer.Option(None, "--exclude-scope", help="Never scan hosts matching these (comma-separated)"),
    parallel: int = typer.Option(1, "--parallel", help="Scan this many targets concurrently [default: 1]"),
    sqli_technique: Optional[str] = typer.Option(None, "--sqli-technique", help="sqli: techniques to run (error,boolean,time). Default: error,boolean (+time on --depth deep)"),
    sqli_delay: int = typer.Option(5, "--sqli-delay", help="sqli: seconds for time-based injection probes [default: 5]"),
    include_third_party_js: bool = typer.Option(False, "--include-third-party-js", help="Analyze third-party JavaScript assets (noisier)"),
    wordlist: Optional[str] = typer.Option(None, "-w", "--wordlist", help="Custom wordlist file"),
    output: Optional[str] = typer.Option(None, "-o", "--output", help="Output file path"),
    report: Optional[str] = typer.Option(None, "--report", help="Write a pentest-ready Markdown attack-surface report"),
    format_type: str = typer.Option("txt", "-f", "--format", help="Output format: table/json/jsonl/csv/txt/sarif [default: txt]"),
    silent: bool = typer.Option(False, "--silent", help="Only show results"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Show debug info"),
    resume: Optional[str] = typer.Option(None, "--resume", help="Resume scan by ID"),
    ai_triage: bool = typer.Option(False, "--ai-triage", help="Enable AI-driven Triage and Vulnerability Analysis"),
    diff: bool = typer.Option(False, "--diff", help="Compare results against the last completed scan of the same target"),
    depth: str = typer.Option("normal", "--depth", help="Scan depth profile: quick/normal/deep/insane"),
    adaptive_rate: bool = typer.Option(False, "--adaptive-rate", help="Auto-adjust rate on 429/503/timeout"),
    pipe: bool = typer.Option(False, "--pipe", help="Pipe mode: read targets from stdin if none given, stream NDJSON results to stdout, logs to stderr"),
    recursion_depth: int = typer.Option(0, "--recursion-depth", help="Recurse into discovered directories during dirfuzz (0 = off)"),
    notify_type: Optional[str] = typer.Option(None, "--notify-type", help="Notification platform: discord/slack/telegram"),
    notify_webhook: Optional[str] = typer.Option(None, "--notify-webhook", help="Discord/Slack incoming webhook URL"),
    telegram_token: Optional[str] = typer.Option(None, "--telegram-token", help="Telegram bot token (with --notify-type telegram)"),
    telegram_chat_id: Optional[str] = typer.Option(None, "--telegram-chat-id", help="Telegram chat/channel ID (with --notify-type telegram)"),
    templates: Optional[str] = typer.Option(None, "-T", "--templates", help="vulnscan: template files/dirs, comma-separated (nuclei templates supported; 'bundled' = built-in)"),
    tags: Optional[str] = typer.Option(None, "--tags", help="vulnscan: only run templates with these tags (comma-separated)"),
    exclude_tags: Optional[str] = typer.Option(None, "--exclude-tags", help="vulnscan: skip templates with these tags (dos,fuzz are skipped by default)"),
    severity: Optional[str] = typer.Option(None, "-s", "--severity", help="vulnscan: only run these severities (info,low,medium,high,critical)"),
    template_id: Optional[str] = typer.Option(None, "--template-id", help="vulnscan: only run these template IDs (comma-separated)"),
    exclude_id: Optional[str] = typer.Option(None, "--exclude-id", help="vulnscan: skip these template IDs (comma-separated)"),
    html: Optional[str] = typer.Option(None, "--html", help="Write a self-contained, shareable HTML report"),
    fail_on: Optional[str] = typer.Option(None, "--fail-on", help="Exit with code 2 if a finding at/above this severity is found (CI gate)"),
    no_banner: bool = typer.Option(False, "--no-banner", help="Skip the ASCII banner"),
    no_progress: bool = typer.Option(False, "--no-progress", help="Disable the live dashboard (plain scrolling log)"),
    no_config: bool = typer.Option(False, "--no-config", help="Ignore ~/.falsealarm/config.yaml user defaults"),
    version: Optional[bool] = typer.Option(None, "--version", callback=version_callback, is_eager=True, help="Show version"),
):
    """
    Run a security scan against a target.
    """
    if fail_on and fail_on.lower() not in {"info", "low", "medium", "high", "critical"}:
        raise typer.BadParameter("must be one of info, low, medium, high, critical", param_hint="--fail-on")
    ui_opts = {"html": html, "fail_on": fail_on.lower() if fail_on else None, "no_banner": no_banner,
               "no_progress": no_progress}
    cli_opts = {
        "headers": list(header or []),
        "cookie": cookie,
        "scope": _csv(scope),
        "exclude_scope": _csv(exclude_scope),
        "parallel": parallel if parallel != 1 else None,
        "sqli_techniques": _csv(sqli_technique),
        "sqli_delay": sqli_delay if sqli_delay != 5 else None,
    }
    template_opts = {
        "templates": _csv(templates),
        "template_tags": _csv(tags),
        "exclude_tags": _csv(exclude_tags),
        "severity": _csv(severity),
        "template_ids": _csv(template_id),
        "exclude_template_ids": _csv(exclude_id),
    }
    try:
        asyncio.run(
            _run_scan(
                url=url, target_list=target_list, config_file=config_file, profile=profile,
                module=module, all_modules=all_modules, quick=quick, threads=threads, rate=rate,
                timeout=timeout, delay=delay, proxy=proxy, proxy_file=proxy_file, random_agent=random_agent,
                include_third_party_js=include_third_party_js,
                wordlist=wordlist, output=output, report=report, format_type=format_type, silent=silent, verbose=verbose,
                resume=resume, ai_triage=ai_triage, diff=diff, depth=depth, adaptive_rate=adaptive_rate,
                notify_type=notify_type, notify_webhook=notify_webhook, telegram_token=telegram_token,
                telegram_chat_id=telegram_chat_id, pipe=pipe, recursion_depth=recursion_depth,
                template_opts=template_opts, ui_opts=ui_opts, cli_opts=cli_opts, no_config=no_config,
            )
        )
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(130)

async def _run_scan(
    url: Optional[str], target_list: Optional[str], config_file: Optional[str], profile: str,
    module: Optional[str], all_modules: bool, quick: bool, threads: int, rate: int,
    timeout: int, delay: float, proxy: Optional[str], proxy_file: Optional[str], random_agent: bool,
    include_third_party_js: bool,
    wordlist: Optional[str], output: Optional[str], report: Optional[str], format_type: str, silent: bool, verbose: bool,
    resume: Optional[str], ai_triage: bool, diff: bool = False, depth: str = "normal",
    adaptive_rate: bool = False, notify_type: Optional[str] = None, notify_webhook: Optional[str] = None,
    telegram_token: Optional[str] = None, telegram_chat_id: Optional[str] = None,
    pipe: bool = False, recursion_depth: int = 0, template_opts: Optional[dict] = None,
    ui_opts: Optional[dict] = None, cli_opts: Optional[dict] = None, no_config: bool = False,
):
    from falsealarm.core.utils import sanitize_target

    # Pipe mode keeps stdout machine-readable: logs/banner go to stderr and
    # results are streamed as NDJSON to stdout for chaining with other tools.
    pipe_mode = pipe or output == "-"
    logger = FalseAlarmLogger(silent=silent, verbose=verbose, stderr=pipe_mode,
                              live=not (ui_opts or {}).get("no_progress"))

    ui_opts = ui_opts or {}
    if not silent and not pipe_mode:
        if not ui_opts.get("no_banner"):
            logger.banner()
        logger.console.print("[yellow]⚠ Only scan systems you are authorised to test.[/yellow]\n")

    modules_list = []
    if module:
        modules_list = [sanitize_target(m.strip()) for m in module.split(',') if sanitize_target(m.strip())]
    elif all_modules:
        modules_list = ["all"]
    elif quick:
        modules_list = ["quick"]

    targets = []
    if url:
        targets.append(sanitize_target(url))
    if target_list:
        try:
            with open(target_list, 'r') as f:
                targets.extend([sanitize_target(line.strip()) for line in f if sanitize_target(line.strip())])
        except Exception as e:
            typer.secho(f"[!] Could not read target list: {e}", fg=typer.colors.RED)
            sys.exit(1)

    # Settings are layered, later wins: built-in defaults -> user config
    # (~/.falsealarm/config.yaml) -> named profile from -c file -> CLI flags.
    try:
        from falsealarm.core.paths import user_config_path

        user_layer = {}
        if not no_config:
            user_layer = ScanConfig.read_profile(str(user_config_path()), "default", required=False)
        profile_layer = ScanConfig.read_profile(config_file, profile, required=True) if config_file else {}
    except (ValueError, FileNotFoundError) as e:
        typer.secho(f"[!] Config Error: {e}", fg=typer.colors.RED)
        sys.exit(1)

    # Only non-default CLI flags override profile/user settings, so a value set
    # in config.yaml is not silently clobbered by a flag's default.
    cli_layer = {
        "target": sanitize_target(url) if url else None,
        "targets_file": target_list,
        "modules": modules_list or None,
        "threads": threads if threads != 50 else None,
        "rate": rate if rate != 30 else None,
        "timeout": timeout if timeout != 10 else None,
        "delay": delay if delay else None,
        "proxy": proxy, "proxy_file": proxy_file,
        "random_agent": random_agent or None,
        "include_third_party_js": include_third_party_js or None,
        "output": output, "report": report,
        "format": format_type if format_type != "txt" else None,
        "silent": silent or None, "verbose": verbose or None,
        "wordlist": wordlist, "resume": resume,
        "ai_triage": ai_triage or None, "diff": diff or None,
        "depth": depth if depth != "normal" else None,
        "adaptive_rate": adaptive_rate or None, "pipe": pipe or None,
        "recursion_depth": recursion_depth or None,
        "notify_type": notify_type, "notify_webhook": notify_webhook,
        "telegram_token": telegram_token, "telegram_chat_id": telegram_chat_id,
        **{k: v for k, v in (template_opts or {}).items() if v},
        **{k: v for k, v in (cli_opts or {}).items() if v},
    }
    try:
        config = ScanConfig.layered(user_layer, profile_layer, cli_layer)
    except (TypeError, ValueError) as e:
        typer.secho(f"[!] Config Error: {e}", fg=typer.colors.RED)
        sys.exit(1)

    # Ingest targets from stdin when piped and none were supplied explicitly.
    # This must happen before validate(), which requires at least one target.
    if not config.target and not config.targets and not config.targets_file and not config.resume:
        if pipe or not sys.stdin.isatty():
            stdin_targets = [
                sanitize_target(line.strip())
                for line in sys.stdin
                if line.strip() and not line.lstrip().startswith("#")
            ]
            config.targets = [t for t in stdin_targets if t]

    try:
        config.validate()
    except ValueError as e:
        typer.secho(f"[!] Validation Error: {e}", fg=typer.colors.RED)
        sys.exit(1)

    # Read target list if provided
    if config.targets_file:
        try:
            with open(config.targets_file, 'r') as f:
                config.targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            if not config.targets:
                typer.secho("[!] Target list file is empty.", fg=typer.colors.RED)
                sys.exit(1)
        except Exception as e:
            typer.secho(f"[!] Could not read target list: {e}", fg=typer.colors.RED)
            sys.exit(1)

    # Normalize target lists & expand CIDR notation if present
    import ipaddress
    raw_targets = config.targets if config.targets else ([config.target] if config.target else [])
    targets = []
    for t in raw_targets:
        if "/" in t and not t.startswith("http"):
            try:
                net = ipaddress.ip_network(t, strict=False)
                targets.extend([str(ip) for ip in net.hosts()])
            except ValueError:
                targets.append(t)
        else:
            targets.append(t)

    # We will currently run scans sequentially over targets
    db = Database()
    await db.init()

    if config.resume:
        scan = await db.get_scan(config.resume)
        if not scan:
            await db.close()
            raise typer.BadParameter(f"Scan ID '{config.resume}' was not found.", param_hint="--resume")

        restored = ScanConfig.from_dict(scan.get("config", {}))
        restored.target = scan["target"]
        restored.resume = config.resume
        restored.silent = silent
        restored.verbose = verbose
        engine = AsyncEngine(restored)
        scheduler = ScanScheduler(config=restored, engine=engine, db=db, logger=logger)
        try:
            scan_results = await scheduler.resume(config.resume)
            if output:
                await OutputManager.export(scan_results, output, format_type)
            if report:
                from falsealarm.core.report import PentestReport
                await PentestReport.export(scan["target"], scan_results, report)
        finally:
            await engine.close()
            await db.close()
        return

    # Apply the scope guard to the explicit targets too (not just discovered ones).
    from falsealarm.core.scope import ScopeGuard

    guard = ScopeGuard(config.scope, config.exclude_scope)
    if guard.active:
        in_scope = guard.filter(targets)
        if len(in_scope) != len(targets) and not silent:
            logger.warning(f"Scope guard: {len(targets) - len(in_scope)} target(s) skipped as out of scope.")
        targets = in_scope
        if not targets:
            typer.secho("[!] No targets remain in scope.", fg=typer.colors.RED)
            await db.close()
            sys.exit(1)

    parallel = max(1, min(int(config.parallel), len(targets)))
    gate_failed = False
    _print_lock = asyncio.Lock()

    async def _scan_one(current_target: str, tlogger: "FalseAlarmLogger") -> bool:
        if len(targets) > 1 and not silent and tlogger is logger:
            logger.console.print(f"\n[bold yellow]>>> Scanning Target: {current_target} <<<[/bold yellow]")

        target_config = ScanConfig.from_dict(config.to_dict())
        target_config.target = current_target

        engine = AsyncEngine(target_config)
        scheduler = ScanScheduler(config=target_config, engine=engine, db=db, logger=tlogger)
        local_gate = False
        try:
            scan_results = await scheduler.run()

            # Diff against the previous completed scan of this target, and
            # optionally push a notification with what changed.
            if target_config.diff or target_config.notify_type:
                from falsealarm.core.diff import diff_scan_results, format_diff_summary

                previous = await db.get_last_completed_scan(
                    current_target, exclude_scan_id=scheduler.scan_id
                )
                if previous is not None:
                    changes = diff_scan_results(previous, scan_results)
                    summary = format_diff_summary(current_target, changes)

                    if not silent and target_config.diff:
                        tlogger.console.print(Panel(
                            Markdown(summary),
                            title="[bold cyan]🔎 Diff vs. previous scan[/bold cyan]",
                            border_style="cyan",
                        ))

                    if changes and target_config.notify_type:
                        from falsealarm.core.notify import NotifyError, NotifyManager
                        try:
                            notifier = NotifyManager(
                                notify_type=target_config.notify_type,
                                webhook_url=target_config.notify_webhook,
                                telegram_token=target_config.telegram_token,
                                telegram_chat_id=target_config.telegram_chat_id,
                            )
                            await notifier.send(summary, title=f"FalseAlarm — {current_target}")
                            if not silent:
                                tlogger.success("Notification sent.")
                        except NotifyError as e:
                            tlogger.error(f"Notification failed: {e}")
                elif not silent and target_config.diff:
                    tlogger.info("No previous completed scan found for this target — nothing to diff against yet.")

            saved: list[str] = []

            def _per_target(path: str, default_ext: str) -> str:
                # Multiple targets: suffix the file name so targets don't overwrite each other.
                if len(targets) <= 1:
                    return path
                base, ext = os.path.splitext(path)
                safe_target = current_target.replace("://", "_").replace("/", "_").replace(":", "_")
                return f"{base}_{safe_target}{ext or default_ext}"

            # Pipe mode: stream NDJSON to stdout for chaining with other tools.
            if pipe_mode:
                stdout_fmt = "jsonl" if format_type in {"txt", "table", "csv"} else format_type
                await OutputManager.export(scan_results, "-", stdout_fmt)

            if output and output != "-":
                final_output = _per_target(output, "")
                await OutputManager.export(scan_results, final_output, format_type)
                saved.append(final_output)

            if report:
                from falsealarm.core.report import PentestReport
                final_report = _per_target(report, ".md")
                await PentestReport.export(current_target, scan_results, final_report)
                saved.append(final_report)

            if ui_opts.get("html"):
                from falsealarm.core.html_report import HTMLReport
                final_html = _per_target(ui_opts["html"], ".html")
                HTMLReport.export(current_target, scan_results, final_html, stats=engine.stats,
                                  duration=scheduler.duration, scan_id=scheduler.scan_id)
                saved.append(final_html)

            from falsealarm.core.findings import collect_findings, severity_at_least

            if not silent and not pipe_mode:
                from falsealarm.core.ui import print_module_views, print_summary

                tlogger.console.print()
                print_module_views(tlogger.console, scan_results)
                findings = print_summary(tlogger.console, current_target, scan_results, engine.stats, saved,
                                         scheduler.duration, scheduler.scan_id)
            else:
                findings = collect_findings(scan_results)
                for path in saved:
                    tlogger.success(f"Saved {path}")

            threshold = ui_opts.get("fail_on")
            if threshold and any(severity_at_least(f.severity, threshold) for f in findings):
                local_gate = True

        finally:
            await engine.close()
            # In parallel mode, flush this target's buffered output atomically.
            if tlogger is not logger:
                buffered = tlogger.export_text()
                if buffered.strip():
                    async with _print_lock:
                        logger.console.print(f"\n[bold yellow]>>> {current_target} <<<[/bold yellow]")
                        logger.console.file.write(buffered)
                        logger.console.file.flush()
        return local_gate

    if parallel > 1:
        # Concurrent targets: no shared live dashboard; each gets a buffered
        # logger flushed atomically on completion.
        sem = asyncio.Semaphore(parallel)

        async def _guarded(t: str) -> bool:
            async with sem:
                return await _scan_one(t, FalseAlarmLogger.buffered(verbose=verbose))

        if not silent:
            logger.info(f"Scanning {len(targets)} targets, {parallel} at a time…")
        gate_results = await asyncio.gather(*(_guarded(t) for t in targets if t), return_exceptions=True)
        for res in gate_results:
            if isinstance(res, Exception):
                logger.error(f"Target scan failed: {res}")
            elif res:
                gate_failed = True
    else:
        for current_target in targets:
            if current_target and await _scan_one(current_target, logger):
                gate_failed = True

    await db.close()

    if gate_failed:
        threshold = (ui_opts or {}).get("fail_on")
        if not silent:
            logger.console.print(f"[bold red]✗ --fail-on {threshold}: findings at or above '{threshold}' severity.[/bold red]")
        raise typer.Exit(2)

def _csv(value: Optional[str]) -> list[str]:
    return [v.strip() for v in (value or "").split(",") if v.strip()]


templates_app = typer.Typer(help="Manage and validate vulnscan templates (nuclei-compatible).", no_args_is_help=True)
app.add_typer(templates_app, name="templates")

NUCLEI_TEMPLATES_REPO = "https://github.com/projectdiscovery/nuclei-templates.git"
DEFAULT_NUCLEI_DIR = str(nuclei_templates_dir())


@templates_app.command(name="update")
def templates_update(
    destination: str = typer.Option(DEFAULT_NUCLEI_DIR, "--dir", help="Where to keep the nuclei-templates checkout"),
):
    """Download or update the community nuclei-templates repository (git required)."""
    import subprocess

    from rich.console import Console
    console = Console()
    try:
        if os.path.isdir(os.path.join(destination, ".git")):
            console.print(f"[*] Updating {destination} ...")
            subprocess.run(["git", "-C", destination, "pull", "--ff-only", "--depth", "1"], check=True)
        else:
            os.makedirs(os.path.dirname(destination), exist_ok=True)
            console.print(f"[*] Cloning nuclei-templates into {destination} ...")
            subprocess.run(["git", "clone", "--depth", "1", NUCLEI_TEMPLATES_REPO, destination], check=True)
    except FileNotFoundError:
        console.print("[red][!] git is not installed.[/red]")
        raise typer.Exit(1)
    except subprocess.CalledProcessError as e:
        console.print(f"[red][!] git failed: {e}[/red]")
        raise typer.Exit(1)
    console.print(f"[green][+] Templates ready.[/green] Use: falsealarm scan -u <url> -m vulnscan -T {os.path.join(destination, 'http')}")


@templates_app.command(name="validate")
def templates_validate(
    paths: list[str] = typer.Argument(..., help="Template files or directories"),
    tags: Optional[str] = typer.Option(None, "--tags", help="Only count templates with these tags"),
    severity: Optional[str] = typer.Option(None, "-s", "--severity", help="Only count these severities"),
    show_invalid: bool = typer.Option(False, "--show-invalid", help="List invalid template files"),
):
    """Check which templates FalseAlarm can run and why the others are skipped."""
    from collections import Counter

    from rich.console import Console
    from rich.table import Table

    from falsealarm.core.templates import TemplateFilter, load_templates

    console = Console()
    report = load_templates(paths, TemplateFilter.build(tags=_csv(tags), severities=_csv(severity)))
    console.print(f"[bold]Templates:[/bold] {report.summary()}")

    by_sev = Counter(t.severity for t in report.templates)
    table = Table(title="Runnable templates by severity")
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    for sev in ("critical", "high", "medium", "low", "info", "unknown"):
        if by_sev.get(sev):
            table.add_row(sev, str(by_sev[sev]))
    console.print(table)

    if report.unsupported:
        skipped = Table(title="Skipped (unsupported features)")
        skipped.add_column("Reason")
        skipped.add_column("Count", justify="right")
        for reason, count in report.unsupported.most_common():
            skipped.add_row(reason, str(count))
        console.print(skipped)
    if show_invalid:
        for path, err in report.invalid:
            console.print(f"[red]invalid[/red] {path}: {err}")
    if report.loaded == 0:
        raise typer.Exit(1)


config_app = typer.Typer(help="Manage ~/.falsealarm/config.yaml user defaults.", no_args_is_help=True)
app.add_typer(config_app, name="config")

CONFIG_TEMPLATE = """\
# FalseAlarm user defaults (~/.falsealarm/config.yaml).
# Applied to every scan; a profile from `-c file -p name` and explicit CLI
# flags override these. Run `falsealarm config path` to see the location.
default:
  rate: 30
  threads: 50
  timeout: 10
  random_agent: true
  # headers: ["Authorization: Bearer <token>"]   # authenticated scans
  # scope: ["example.com", "*.example.com"]        # stay in scope
  # templates: ["~/.falsealarm/nuclei-templates/http"]
  # exclude_tags: ["intrusive"]

# A second profile you can select with `-p stealth`.
stealth:
  rate: 5
  threads: 10
  random_agent: true
  adaptive_rate: true
  # proxy: socks5://127.0.0.1:9050
"""


@config_app.command(name="init")
def config_init(force: bool = typer.Option(False, "--force", help="Overwrite an existing config")):
    """Write a starter ~/.falsealarm/config.yaml."""
    from falsealarm.core.paths import ensure_home, user_config_path

    ensure_home()
    path = user_config_path()
    if path.exists() and not force:
        typer.secho(f"[!] {path} already exists. Use --force to overwrite.", fg=typer.colors.YELLOW)
        raise typer.Exit(1)
    path.write_text(CONFIG_TEMPLATE, encoding="utf-8")
    typer.secho(f"[+] Wrote {path}", fg=typer.colors.GREEN)


@config_app.command(name="path")
def config_path():
    """Print the config and home-directory locations."""
    from falsealarm.core.paths import default_db_path, home_dir, user_config_path

    print(f"home:    {home_dir()}")
    print(f"config:  {user_config_path()}")
    print(f"db:      {default_db_path()}")


@app.command(name="build-engine")
def build_engine():
    """
    Compile the high-performance Go engines natively.
    """
    import subprocess
    import sys

    from rich.console import Console
    console = Console()

    engine_dir = os.path.join(os.path.dirname(__file__), "..", "engine-go")
    binary_name = "dirfuzz-engine.exe" if sys.platform == "win32" else "dirfuzz-engine"

    console.print("[*] Locating Go environment...")
    have_go = True
    try:
        subprocess.run(["go", "version"], check=True, capture_output=True)
    except Exception:
        have_go = False

    if not have_go:
        # No Go toolchain: fetch the prebuilt binary from GitHub Releases so
        # users don't need to install Go just to get the fast fuzzer.
        console.print("[yellow][!] Go compiler not found — trying to download a prebuilt engine...[/yellow]")
        if _download_prebuilt_engine(console, engine_dir, binary_name):
            console.print("[green][+] Prebuilt engine installed.[/green]")
            return
        console.print(
            "[red][!] Could not obtain a prebuilt engine. Install Go "
            "(https://go.dev/doc/install) and re-run, or the Python fuzzer will be used.[/red]"
        )
        sys.exit(1)

    if not os.path.exists(engine_dir):
        console.print("[red][!] engine-go directory not found.[/red]")
        sys.exit(1)

    console.print("[*] Compiling DirFuzz Go Engine...")
    try:
        subprocess.run(
            ["go", "build", "-o", binary_name, "dirfuzz.go"],
            cwd=engine_dir,
            check=True
        )
        console.print(f"[green][+] Successfully compiled {binary_name}![/green]")
        console.print("[*] FalseAlarm is now running with Polyglot Engine (Python + Go) capabilities.")
    except subprocess.CalledProcessError as e:
        console.print(f"[red][!] Compilation failed: {e}[/red]")
        sys.exit(1)

def _download_prebuilt_engine(console, engine_dir: str, binary_name: str) -> bool:
    """Download the matching prebuilt dirfuzz engine from GitHub Releases.

    Returns True on success. Used as a fallback when the Go toolchain is
    unavailable so `pip install`-only users still get the fast engine.
    """
    import platform
    import stat
    import urllib.request

    system = platform.system().lower()  # linux / darwin / windows
    machine = platform.machine().lower()
    arch = "arm64" if machine in ("arm64", "aarch64") else "amd64"
    goos = {"linux": "linux", "darwin": "darwin", "windows": "windows"}.get(system)
    if not goos:
        console.print(f"[red][!] Unsupported platform: {system}[/red]")
        return False

    ext = ".exe" if goos == "windows" else ""
    asset = f"dirfuzz-engine-{goos}-{arch}{ext}"
    url = f"https://github.com/reikageisme/falsealarm/releases/latest/download/{asset}"
    os.makedirs(engine_dir, exist_ok=True)
    dest = os.path.join(engine_dir, binary_name)

    console.print(f"[*] Downloading {asset} ...")
    try:
        urllib.request.urlretrieve(url, dest)  # noqa: S310 (fixed GitHub host)
        if goos != "windows":
            os.chmod(dest, os.stat(dest).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
        return True
    except Exception as e:
        console.print(f"[red][!] Download failed: {e}[/red]")
        return False


def main():
    # Print the extended cheat-sheet banner if help is requested or no args provided
    is_help = len(sys.argv) == 1 or "--help" in sys.argv or "-h" in sys.argv
    if is_help:
        from falsealarm import print_banner
        print_banner(show_help=True)

    # Auto-inject 'scan' command for backward compatibility if the user just types `falsealarm -u ...`
    if len(sys.argv) > 1 and sys.argv[1] not in SUPPORTED_COMMANDS:
        sys.argv.insert(1, "scan")

    app()

if __name__ == "__main__":
    main()
