"""
FalseAlarm — Pipeline Orchestration (DAG)

Defines the execution graph for modules. Instead of running all modules independently,
the output of upstream modules (like subdomain discovery) becomes the input for downstream
modules (like probing and vulnscanning).
"""
from falsealarm.core.config import ScanConfig

class PipelineManager:
    """
    Manages the dependency graph of scan modules.
    """
    def __init__(self, config: ScanConfig):
        self.config = config
        
        # The DAG mapping: upstream -> list of downstreams
        # Based on the blueprint:
        # subdomain -> httpprobe
        # dns -> httpprobe
        # httpprobe -> techdetect, dirfuzz, headers_ssl, cors, websocket, js_analysis
        # techdetect -> vulnscan
        # portscan runs parallel/independent initially, but open HTTP ports feed back into httpprobe.
        
        self.graph = {
            "subdomain": ["httpprobe"],
            "dns": ["httpprobe"],
            "httpprobe": ["techdetect", "dirfuzz", "headers_ssl", "cors", "websocket", "js_analysis"],
            "techdetect": ["vulnscan"],
            "portscan": [] # Portscan feeds httpprobe dynamically in the scheduler
        }
        
        self.depth_profiles = {
            "quick": ["httpprobe", "headers_ssl"],
            "normal": ["httpprobe", "headers_ssl", "techdetect", "vulnscan", "cors"],
            "deep": ["httpprobe", "headers_ssl", "techdetect", "vulnscan", "cors", "dirfuzz", "websocket", "js_analysis"],
            "insane": ["httpprobe", "headers_ssl", "techdetect", "vulnscan", "cors", "dirfuzz", "websocket", "js_analysis", "portscan", "dns", "subdomain"]
        }

    def get_allowed_modules(self) -> list[str]:
        """Return allowed modules in a stable, user-visible execution order."""
        if self.config.modules and "all" not in self.config.modules and "quick" not in self.config.modules:
            return list(dict.fromkeys(self.config.modules))

        depth = "quick" if "quick" in self.config.modules else self.config.depth
        return list(self.depth_profiles.get(depth, self.depth_profiles["normal"]))

    def get_downstream(self, module_name: str) -> list[str]:
        """Get the allowed downstream modules for a given module."""
        allowed = self.get_allowed_modules()
        all_downstream = self.graph.get(module_name, [])
        return [m for m in all_downstream if m in allowed]
        
    def get_entry_points(self) -> list[str]:
        """Get modules that have no upstream dependencies in the current allowed set."""
        allowed = self.get_allowed_modules()
        
        # Find all modules that are downstreams of something
        has_upstream: set[str] = set()
        for up, down_list in self.graph.items():
            if up in allowed:
                for down in down_list:
                    has_upstream.add(down)
                    
        # Entry points are allowed modules that have no upstream
        entry_points = [m for m in allowed if m not in has_upstream]
        
        # If the user only selected downstream modules explicitly (e.g. -m vulnscan)
        # then those become the entry points.
        if not entry_points and allowed:
            entry_points = list(allowed)
            
        return entry_points
