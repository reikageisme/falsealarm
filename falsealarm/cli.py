import asyncio
import sys
import typer
import os
from pathlib import Path
from dotenv import load_dotenv
from typing import Optional, List
from rich.panel import Panel
from rich.markdown import Markdown
from falsealarm import __version__

# Load environment variables from .env file
load_dotenv()

from falsealarm.core import (
    ScanConfig,
    AsyncEngine,
    Database,
    FalseAlarmLogger,
    ScanScheduler,
    OutputManager,
)
# Modules are now auto-discovered by the ScanScheduler

app = typer.Typer(
    add_completion=False, 
    no_args_is_help=True, 
    rich_markup_mode="rich",
    help="FalseAlarm — Async Web Reconnaissance Engine"
)

SUPPORTED_COMMANDS = {"scan", "list-scans", "modules", "build-engine", "--help", "-h", "--version"}

def version_callback(value: bool):
    if value:
        typer.echo(f"FalseAlarm v{__version__}")
        raise typer.Exit()

@app.command(name="list-scans")
def list_scans(
    db_path: str = typer.Option("falsealarm.db", "--db", help="Database file path")
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
    from falsealarm.modules.base import BaseModule
    import falsealarm.modules as modules_pkg
    import importlib
    import inspect
    import pkgutil
    from rich.table import Table
    from rich.console import Console

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
    wordlist: Optional[str] = typer.Option(None, "-w", "--wordlist", help="Custom wordlist file"),
    output: Optional[str] = typer.Option(None, "-o", "--output", help="Output file path"),
    report: Optional[str] = typer.Option(None, "--report", help="Write a pentest-ready Markdown attack-surface report"),
    format_type: str = typer.Option("txt", "-f", "--format", help="Output format: table/json/csv/txt/sarif [default: txt]"),
    silent: bool = typer.Option(False, "--silent", help="Only show results"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Show debug info"),
    resume: Optional[str] = typer.Option(None, "--resume", help="Resume scan by ID"),
    ai_triage: bool = typer.Option(False, "--ai-triage", help="Enable AI-driven Triage and Vulnerability Analysis"),
    diff: bool = typer.Option(False, "--diff", help="Compare results against the last completed scan of the same target"),
    depth: str = typer.Option("normal", "--depth", help="Scan depth profile: quick/normal/deep/insane"),
    adaptive_rate: bool = typer.Option(False, "--adaptive-rate", help="Auto-adjust rate on 429/503/timeout"),
    notify_type: Optional[str] = typer.Option(None, "--notify-type", help="Notification platform: discord/slack/telegram"),
    notify_webhook: Optional[str] = typer.Option(None, "--notify-webhook", help="Discord/Slack incoming webhook URL"),
    telegram_token: Optional[str] = typer.Option(None, "--telegram-token", help="Telegram bot token (with --notify-type telegram)"),
    telegram_chat_id: Optional[str] = typer.Option(None, "--telegram-chat-id", help="Telegram chat/channel ID (with --notify-type telegram)"),
    version: Optional[bool] = typer.Option(None, "--version", callback=version_callback, is_eager=True, help="Show version"),
):
    """
    Run a security scan against a target.
    """
    try:
        asyncio.run(
            _run_scan(
                url=url, target_list=target_list, config_file=config_file, profile=profile,
                module=module, all_modules=all_modules, quick=quick, threads=threads, rate=rate,
                timeout=timeout, delay=delay, proxy=proxy, proxy_file=proxy_file, random_agent=random_agent,
                wordlist=wordlist, output=output, report=report, format_type=format_type, silent=silent, verbose=verbose,
                resume=resume, ai_triage=ai_triage, diff=diff, depth=depth, adaptive_rate=adaptive_rate, 
                notify_type=notify_type, notify_webhook=notify_webhook, telegram_token=telegram_token, 
                telegram_chat_id=telegram_chat_id,
            )
        )
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(130)

async def _run_scan(
    url: Optional[str], target_list: Optional[str], config_file: Optional[str], profile: str,
    module: Optional[str], all_modules: bool, quick: bool, threads: int, rate: int,
    timeout: int, delay: float, proxy: Optional[str], proxy_file: Optional[str], random_agent: bool,
    wordlist: Optional[str], output: Optional[str], report: Optional[str], format_type: str, silent: bool, verbose: bool,
    resume: Optional[str], ai_triage: bool, diff: bool = False, depth: str = "normal", 
    adaptive_rate: bool = False, notify_type: Optional[str] = None, notify_webhook: Optional[str] = None, 
    telegram_token: Optional[str] = None, telegram_chat_id: Optional[str] = None,
):
    from falsealarm.core.utils import sanitize_target
    logger = FalseAlarmLogger(silent=silent, verbose=verbose)
    
    if not silent:
        logger.banner()
        typer.secho("⚠ Legal: Only use on systems you have permission to test.\n", fg=typer.colors.YELLOW)
        
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

    if config_file:
        try:
            config = ScanConfig.from_file(config_file, profile)
            # Override YAML config with explicit CLI flags if provided
            if url: config.target = sanitize_target(url)
            if target_list: config.targets_file = target_list
            if modules_list: config.modules = modules_list
            if output: config.output = output
            if report: config.report = report
            if silent: config.silent = silent
            if verbose: config.verbose = verbose
            config.depth = depth
            config.adaptive_rate = adaptive_rate
        except Exception as e:
            typer.secho(f"[!] Config Error: {e}", fg=typer.colors.RED)
            sys.exit(1)
    else:
        config = ScanConfig(
            target=url or "",
            targets_file=target_list,
            modules=modules_list,
            threads=threads,
            rate=rate,
            timeout=timeout,
            delay=delay,
            proxy=proxy,
            proxy_file=proxy_file,
            random_agent=random_agent,
            output=output,
            report=report,
            format=format_type,
            silent=silent,
            verbose=verbose,
            wordlist=wordlist,
            resume=resume,
            ai_triage=ai_triage,
            diff=diff,
            depth=depth,
            adaptive_rate=adaptive_rate,
            notify_type=notify_type,
            notify_webhook=notify_webhook,
            telegram_token=telegram_token,
            telegram_chat_id=telegram_chat_id,
        )
        
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
    
    for current_target in targets:
        if not current_target:
            continue
            
        if len(targets) > 1 and not silent:
            logger.console.print(f"\n[bold yellow]>>> Scanning Target: {current_target} <<<[/bold yellow]")
            
        # Create a deep copy of config for this specific target
        target_config = ScanConfig.from_dict(config.to_dict())
        target_config.target = current_target
        
        if not silent and len(targets) == 1:
            logger.scan_config(target_config)
            
        engine = AsyncEngine(target_config)
        
        scheduler = ScanScheduler(config=target_config, engine=engine, db=db, logger=logger)
        
        # Modules are automatically registered during ScanScheduler initialization
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
                    logger.console.print(Panel(
                        Markdown(summary),
                        title="[bold cyan]🔎 Diff vs. previous scan[/bold cyan]",
                        border_style="cyan",
                    ))

                if changes and target_config.notify_type:
                    from falsealarm.core.notify import NotifyManager, NotifyError
                    try:
                        notifier = NotifyManager(
                            notify_type=target_config.notify_type,
                            webhook_url=target_config.notify_webhook,
                            telegram_token=target_config.telegram_token,
                            telegram_chat_id=target_config.telegram_chat_id,
                        )
                        await notifier.send(summary, title=f"FalseAlarm — {current_target}")
                        if not silent:
                            logger.success("Notification sent.")
                    except NotifyError as e:
                        logger.error(f"Notification failed: {e}")
            elif not silent and target_config.diff:
                logger.info("No previous completed scan found for this target — nothing to diff against yet.")

        if not silent:
            for mod_name, mod_data in scan_results.items():
                data = mod_data.get("data", [])
                if data:
                    columns = list(data[0].keys())
                    rows = [[str(item.get(col, "")) for col in columns] for item in data]
                    logger.table(f"{mod_name.upper()} Results ({current_target})", columns, rows)
        
        if output:
            # If multiple targets, append target name to output file to avoid overwrite
            final_output = output
            if len(targets) > 1:
                base, ext = os.path.splitext(output)
                safe_target = current_target.replace("://", "_").replace("/", "_").replace(":", "_")
                final_output = f"{base}_{safe_target}{ext}"
                
            await OutputManager.export(scan_results, final_output, format_type)
            if not silent:
                logger.success(f"Results for {current_target} saved to {final_output}")

        if report:
            from falsealarm.core.report import PentestReport
            final_report = report
            if len(targets) > 1:
                base, ext = os.path.splitext(report)
                safe_target = current_target.replace("://", "_").replace("/", "_").replace(":", "_")
                final_report = f"{base}_{safe_target}{ext or '.md'}"
            await PentestReport.export(current_target, scan_results, final_report)
            if not silent:
                logger.success(f"Pentest report for {current_target} saved to {final_report}")
                
        await engine.close()
        
    await db.close()

@app.command(name="build-engine")
def build_engine():
    """
    Compile the high-performance Go engines natively.
    """
    import subprocess
    import sys
    from rich.console import Console
    console = Console()
    
    console.print("[*] Locating Go environment...")
    try:
        subprocess.run(["go", "version"], check=True, capture_output=True)
    except Exception:
        console.print("[red][!] Go compiler not found. Please install Go (https://go.dev/doc/install) first.[/red]")
        sys.exit(1)
        
    engine_dir = os.path.join(os.path.dirname(__file__), "..", "engine-go")
    if not os.path.exists(engine_dir):
        console.print("[red][!] engine-go directory not found.[/red]")
        sys.exit(1)
        
    binary_name = "dirfuzz-engine.exe" if sys.platform == "win32" else "dirfuzz-engine"
    
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
