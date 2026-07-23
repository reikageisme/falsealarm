"""
FalseAlarm - Advanced Asynchronous Web Reconnaissance Engine
Layer 7 Intelligence & Attack Surface Mapping Framework.
"""

__version__ = "1.0.0-dev"
__author__ = "reikageisme"
__license__ = "MIT"
__codename__ = "Phantom Strike"

def print_banner(console=None, show_help=False) -> None:
    """
    Kết xuất (Render) ASCII Banner và thông tin hệ thống.
    Được gọi ngay khi khởi chạy công cụ qua CLI.
    """
    import platform
    import textwrap
    from rich.console import Console, Group
    from rich.panel import Panel
    from rich.text import Text
    from rich.align import Align
    from rich.table import Table
    
    if console is None:
        console = Console()
        
    banner_ascii = textwrap.dedent(r"""
        ___________        .__             _____  .__                        
        \_   _____/____    |  |   ______ _/ ____\ |  | _____ _______  _____  
         |    __) \__  \   |  |  /  ___/ \   __\  |  | \__  \\_  __ \/     \ 
         |     \   / __ \_ |  |__\___ \   |  |    |  |__/ __ \|  | \/  Y Y  \
         \___  /  (____  / |____/____  >  |__|    |____(____  /__|  |__|_|  /
             \/        \/            \/                     \/            \/ 
    """).strip('\n')
    
    # overflow="ignore" and no_wrap=True ensures ASCII art isn't truncated with '...' or broken
    styled_banner = Text(banner_ascii, style="bold bright_red", overflow="ignore", no_wrap=True)
    
    metadata = f"""
[bold cyan]v{__version__}[/bold cyan] | Codename: [bold yellow]{__codename__}[/bold yellow]
[dim]Asynchronous I/O Engine Active | Python {platform.python_version()}[/dim]
[dim]Developed by {__author__}[/dim]
    """
    
    left_content = Text()
    left_content.append(styled_banner)
    left_content.append("\n\n")
    left_content.append(Text.from_markup(metadata, justify="center"))

    if show_help:
        cheat_sheet = textwrap.dedent("""
            [bold yellow]# 1. Comprehensive mapping (All modules)[/bold yellow]
            falsealarm scan -u example.com -A
            
            [bold yellow]# 2. Targeted modular scan (DNS and Tech only)[/bold yellow]
            falsealarm scan -u example.com -m dns,techdetect
            
            [bold yellow]# 3. Multi-target file or CIDR range scan[/bold yellow]
            falsealarm scan -iL targets.txt -q
            falsealarm scan -u 192.168.1.0/24 -m portscan,httpprobe
            
            [bold yellow]# 4. Stealth & High-Speed Fuzzing[/bold yellow]
            falsealarm scan -u example.com -A -r 15 --proxy socks5://127.0.0.1:9050
            
            [bold yellow]# 5. Load scan parameters from a YAML profile[/bold yellow]
            falsealarm scan -c profile.yaml -p stealth
            
            [bold yellow]# 6. AI Triage Integration[/bold yellow]
            falsealarm scan -u example.com -A --ai-triage
        """).strip('\n')
        
        right_content = Text.from_markup(cheat_sheet)
        
        grid = Table.grid(expand=True, padding=(0, 4))
        grid.add_column(justify="center", no_wrap=True)
        grid.add_column(justify="left", ratio=1)
        grid.add_row(left_content, right_content)
        
        final_content = grid
        expand_panel = False
    else:
        final_content = Align.center(left_content)
        expand_panel = False
    
    panel = Panel(
        final_content,
        border_style="red",
        title="[bold white] Layer 7 Reconnaissance Engine [/bold white]",
        subtitle="[bold white] Deep InfoSec Lab [/bold white]",
        expand=expand_panel
    )
    
    console.print(panel)

from falsealarm.core import (
    ScanConfig,
    AsyncEngine,
    Database,
    FalseAlarmLogger,
    ScanScheduler,
    OutputManager,
)

from falsealarm.modules import (
    BaseModule,
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
)

__all__ = [
    "__version__",
    "print_banner",
    "ScanConfig",
    "AsyncEngine",
    "Database",
    "FalseAlarmLogger",
    "ScanScheduler",
    "OutputManager",
    "BaseModule",
    "DNSEnumModule",
    "SubdomainModule",
    "HTTPProbeModule",
    "TechDetectModule",
    "HeadersSSLModule",
    "DirFuzzModule",
    "JSAnalysisModule",
    "WaybackModule",
    "CORSModule",
    "PortScanModule",
    "WebSocketModule",
]
