"""
FalseAlarm - Advanced Asynchronous Web Reconnaissance Engine
Layer 7 Intelligence & Attack Surface Mapping Framework.
"""

__version__ = "1.0.0-dev"
__author__ = "ReiKage & Contributors"
__license__ = "MIT"
__codename__ = "Phantom Strike"

def print_banner(console=None) -> None:
    """
    Kết xuất (Render) ASCII Banner và thông tin hệ thống.
    Được gọi ngay khi khởi chạy công cụ qua CLI.
    """
    import platform
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    
    if console is None:
        console = Console()
        
    # Sử dụng font Slant sắc nét, mang hơi hướng Cyberpunk / Hacker
    banner_ascii = r"""
    ___________        .__             _____  .__                        
    \_   _____/____    |  |   ______ _/ ____\ |  | _____ _______  _____  
     |    __) \__  \   |  |  /  ___/ \   __\  |  | \__  \\_  __ \/     \ 
     |     \   / __ \_ |  |__\___ \   |  |    |  |__/ __ \|  | \/  Y Y  \
     \___  /  (____  / |____/____  >  |__|    |____(____  /__|  |__|_|  /
         \/        \/            \/                     \/            \/ 
    """
    
    # Định dạng màu đỏ rực (bright_red) cảnh báo
    styled_banner = Text(banner_ascii, style="bold bright_red", justify="center")
    
    # Bổ sung siêu dữ liệu (Metadata) hiển thị chuyên nghiệp
    metadata = f"\n[bold cyan]v{__version__}[/bold cyan] | Codename: [bold yellow]{__codename__}[/bold yellow]\n[dim]Asynchronous I/O Engine Active | Python {platform.python_version()}[/dim]\n[dim]Developed by {__author__}[/dim]\n"
    
    styled_metadata = Text.from_markup(metadata, justify="center")
    styled_banner.append("\n")
    styled_banner.append(styled_metadata)
    
    # Đóng gói toàn bộ vào một Panel để tạo khung viền cứng cáp
    panel = Panel(
        styled_banner,
        border_style="red",
        title="[bold white] Layer 7 Reconnaissance Engine [/bold white]",
        subtitle="[bold white] Deep InfoSec Lab [/bold white]",
        expand=False
    )
    
    # In ra terminal
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
