import asyncio
import sys
import typer
from typing import Optional, List
from falsealarm import __version__
from falsealarm.core import (
    ScanConfig,
    AsyncEngine,
    Database,
    FalseAlarmLogger,
    ScanScheduler,
    OutputManager,
)
from falsealarm.modules import (
    DNSEnumModule,
    SubdomainModule,
    HTTPProbeModule,
    TechDetectModule,
    HeadersSSLModule,
    DirFuzzModule,
    JSAnalysisModule,
    WaybackModule,
    CORSModule,
    PortScanModule,
    WebSocketModule,
    VulnScanModule,
)

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
    url: str = typer.Option(..., "-u", "--url", help="Target URL or domain [required for scan]"),
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
    version: Optional[bool] = typer.Option(None, "--version", callback=version_callback, is_eager=True, help="Show version"),
):
    """
    Run a security scan against a target.
    """
    try:
        asyncio.run(
            _run_scan(
                url=url, module=module, all_modules=all_modules, quick=quick, threads=threads, rate=rate,
                timeout=timeout, delay=delay, proxy=proxy, proxy_file=proxy_file, random_agent=random_agent,
                wordlist=wordlist, output=output, format_type=format_type, silent=silent, verbose=verbose,
                resume=resume
            )
        )
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(130)

async def _run_scan(
    url: str, module: Optional[str], all_modules: bool, quick: bool, threads: int, rate: int,
    timeout: int, delay: float, proxy: Optional[str], proxy_file: Optional[str], random_agent: bool,
    wordlist: Optional[str], output: Optional[str], format_type: str, silent: bool, verbose: bool,
    resume: Optional[str]
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
        
    config = ScanConfig(
        target=url,
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
    )
    
    if not silent:
        logger.scan_config(config)
        
    engine = AsyncEngine(config)
    db = Database()
    
    await db.init()
    
    scheduler = ScanScheduler(config=config, engine=engine, db=db, logger=logger)
    
    # Register modules
    scheduler.register_module(DNSEnumModule)
    scheduler.register_module(SubdomainModule)
    scheduler.register_module(HTTPProbeModule)
    scheduler.register_module(TechDetectModule)
    scheduler.register_module(HeadersSSLModule)
    scheduler.register_module(DirFuzzModule)
    scheduler.register_module(JSAnalysisModule)
    scheduler.register_module(WaybackModule)
    scheduler.register_module(CORSModule)
    scheduler.register_module(PortScanModule)
    scheduler.register_module(WebSocketModule)
    scheduler.register_module(VulnScanModule)
    
    scan_results = await scheduler.run()
    
    if not silent:
        for mod_name, mod_data in scan_results.items():
            data = mod_data.get("data", [])
            if data:
                columns = list(data[0].keys())
                rows = [[str(item.get(col, "")) for col in columns] for item in data]
                logger.table(f"{mod_name.upper()} Results", columns, rows)
    
    if output:
        await OutputManager.export(scan_results, output, format_type)
        if not silent:
            logger.success(f"Results saved to {output}")
            
    await engine.close()
    await db.close()

def main():
    # Auto-inject 'scan' command for backward compatibility if the user just types `falsealarm -u ...`
    if len(sys.argv) > 1 and sys.argv[1] not in ["scan", "list-scans", "--help", "--version"]:
        sys.argv.insert(1, "scan")
    app()

if __name__ == "__main__":
    main()
