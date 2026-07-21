"""FalseAlarm - Async Web Reconnaissance Engine"""

__version__ = "1.0.0"
__author__ = "FalseAlarm Team"
__license__ = "MIT"

BANNER = r"""
  _____     _          _    _                  
 |  ___|_ _| |___  ___/ \  | | __ _ _ __ _ __ ___  
 | |_ / _` | / __|/ _ \ | | |/ _` | '__| '_ ` _ \ 
 |  _| (_| | \__ \  __/ | | | (_| | |  | | | | | |
 |_|  \__,_|_|___/\___\_| |_|\__,_|_|  |_| |_| |_|
                                                    
  Web Reconnaissance Engine v{version}
  https://github.com/falsealarm
""".format(version=__version__)

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
    "BANNER",
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
