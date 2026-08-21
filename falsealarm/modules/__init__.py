"""FalseAlarm Scan Modules"""

from .base import BaseModule
from .cors import CORSModule
from .dirfuzz import DirFuzzModule
from .dns_enum import DNSEnumModule
from .favicon import FaviconModule
from .graphql import GraphQLModule
from .headers_ssl import HeadersSSLModule
from .httpprobe import HTTPProbeModule
from .js_analysis import JSAnalysisModule
from .openredirect import OpenRedirectModule
from .portscan import PortScanModule
from .subdomain import SubdomainModule
from .techdetect import TechDetectModule
from .vulnscan import VulnScanModule
from .wayback import WaybackModule
from .websocket import WebSocketModule

__all__ = [
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
    "VulnScanModule",
    "FaviconModule",
    "GraphQLModule",
    "OpenRedirectModule",
]
