"""
FalseAlarm - Advanced Asynchronous Web Reconnaissance Engine
Layer 7 Intelligence & Attack Surface Mapping Framework.
"""

__version__ = "1.0.0-dev"
__author__ = "ReiKage"
__license__ = "MIT"
__codename__ = "Phantom Strike"

def print_banner(console=None) -> None:
    """
    Kết xuất (Render) ASCII Banner và thông tin hệ thống.
    Được gọi ngay khi khởi chạy công cụ qua CLI.
    """
    import platform
    import textwrap
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    from rich.align import Align
    
    if console is None:
        console = Console()
        
    # 1. Dùng textwrap.dedent để dọn dẹp các khoảng trắng thụt lề dư thừa của Python
    # strip('\n') để bỏ các dòng trống thừa ở đầu và cuối chuỗi
    banner_ascii = textwrap.dedent(r"""
        ___________        .__             _____  .__                        
        \_   _____/____    |  |   ______ _/ ____\ |  | _____ _______  _____  
         |    __) \__  \   |  |  /  ___/ \   __\  |  | \__  \\_  __ \/     \ 
         |     \   / __ \_ |  |__\___ \   |  |    |  |__/ __ \|  | \/  Y Y  \
         \___  /  (____  / |____/____  >  |__|    |____(____  /__|  |__|_|  /
             \/        \/            \/                     \/            \/ 
    """).strip('\n')
    
    # 2. KHÔNG DÙNG justify="center" ở đây để giữ nguyên cấu trúc khối block
    styled_banner = Text(banner_ascii, style="bold bright_red")
    
    # Bổ sung siêu dữ liệu (Metadata) hiển thị chuyên nghiệp
    metadata = f"""
[bold cyan]v{__version__}[/bold cyan] | Codename: [bold yellow]{__codename__}[/bold yellow]
[dim]Asynchronous I/O Engine Active | Python {platform.python_version()}[/dim]
[dim]Developed by {__author__}[/dim]
    """
    
    styled_metadata = Text.from_markup(metadata, justify="center")
    
    # Gom khối banner và metadata lại với nhau
    full_content = Text()
    full_content.append(styled_banner)
    full_content.append("\n\n")
    full_content.append(styled_metadata)
    
    # 3. Sử dụng Align.center để căn giữa TOÀN BỘ khối này vào giữa màn hình terminal
    centered_content = Align.center(full_content)
    
    # Đóng gói toàn bộ vào một Panel để tạo khung viền cứng cáp
    panel = Panel(
        centered_content,
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
