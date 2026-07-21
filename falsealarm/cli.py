import asyncio
import sys
import typer
import os
from pathlib import Path
from dotenv import load_dotenv
from typing import Optional, List
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
    format_type: str = typer.Option("txt", "-f", "--format", help="Output format: table/json/csv/txt [default: txt]"),
    silent: bool = typer.Option(False, "--silent", help="Only show results"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Show debug info"),
    resume: Optional[str] = typer.Option(None, "--resume", help="Resume scan by ID"),
    ai_triage: bool = typer.Option(False, "--ai-triage", help="Enable AI-driven Triage and Vulnerability Analysis"),
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
                wordlist=wordlist, output=output, format_type=format_type, silent=silent, verbose=verbose,
                resume=resume, ai_triage=ai_triage
            )
        )
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(130)

async def _run_scan(
    url: Optional[str], target_list: Optional[str], config_file: Optional[str], profile: str,
    module: Optional[str], all_modules: bool, quick: bool, threads: int, rate: int,
    timeout: int, delay: float, proxy: Optional[str], proxy_file: Optional[str], random_agent: bool,
    wordlist: Optional[str], output: Optional[str], format_type: str, silent: bool, verbose: bool,
    resume: Optional[str], ai_triage: bool
):
    logger = FalseAlarmLogger(silent=silent, verbose=verbose)
    
    if not silent:
        logger.banner()
        typer.secho("⚠ Legal: Only use on systems you have permission to test.\n", fg=typer.colors.YELLOW)
        
    modules_list = []
    if module:
        modules_list = [m.strip() for m in module.split(',')]
    elif all_modules:
        modules_list = ["all"]
    elif quick:
        modules_list = ["quick"]
        
    if config_file:
        try:
            config = ScanConfig.from_file(config_file, profile)
            # Override YAML config with explicit CLI flags if provided
            if url: config.target = url
            if target_list: config.targets_file = target_list
            if modules_list: config.modules = modules_list
            if output: config.output = output
            if silent: config.silent = silent
            if verbose: config.verbose = verbose
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
            format=format_type,
            silent=silent,
            verbose=verbose,
            wordlist=wordlist,
            resume=resume,
            ai_triage=ai_triage,
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
            
    # Normalize target lists
    targets = config.targets if config.targets else [config.target]
    
    # We will currently run scans sequentially over targets
    db = Database()
    await db.init()
    
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
    # Auto-inject 'scan' command for backward compatibility if the user just types `falsealarm -u ...`
    if len(sys.argv) > 1 and sys.argv[1] not in ["scan", "list-scans", "build-engine", "--help", "--version"]:
        sys.argv.insert(1, "scan")
    app()

if __name__ == "__main__":
    main()
