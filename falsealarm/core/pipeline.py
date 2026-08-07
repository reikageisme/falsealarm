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

        self.aliases = {
            "headers_ssl": "ssl",
            "techdetect": "tech",
        }
        
        # The DAG mapping: upstream -> list of downstreams
        # Based on the blueprint:
        # subdomain -> httpprobe
        # dns -> httpprobe
        # httpprobe -> tech, dirfuzz, ssl, cors, websocket, js_analysis
        # tech -> vulnscan
        # portscan runs parallel/independent initially, but open HTTP ports feed back into httpprobe.
        
        self.graph = {
            "subdomain": ["httpprobe"],
            "dns": ["httpprobe"],
            "httpprobe": ["tech", "ssl", "cors", "dirfuzz", "websocket", "js_analysis"],
            "tech": ["vulnscan"],
            "portscan": ["httpprobe"],
        }

        self.depth_profiles = {
            "quick": ["httpprobe", "ssl"],
            "normal": ["httpprobe", "ssl", "tech", "vulnscan", "cors"],
            "deep": ["httpprobe", "ssl", "tech", "vulnscan", "cors", "dirfuzz", "websocket", "js_analysis", "wayback"],
            "insane": ["dns", "subdomain", "portscan", "httpprobe", "ssl", "tech", "vulnscan", "cors", "dirfuzz", "websocket", "js_analysis", "wayback"],
        }

    def _canonicalize(self, modules: list[str]) -> list[str]:
        return list(dict.fromkeys(self.aliases.get(name, name) for name in modules))

    def get_allowed_modules(self) -> list[str]:
        """Return allowed modules in a stable, user-visible execution order."""
        if self.config.modules and "all" not in self.config.modules and "quick" not in self.config.modules:
            return self._canonicalize(self.config.modules)

        if "all" in self.config.modules:
            return list(self.depth_profiles["insane"])

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
                    if down in allowed:
                        has_upstream.add(down)
                    
        # Entry points are allowed modules that have no upstream
        entry_points = [m for m in allowed if m not in has_upstream]
        
        # If the user only selected downstream modules explicitly (e.g. -m vulnscan)
        # then those become the entry points.
        if not entry_points and allowed:
            entry_points = list(allowed)
            
        return entry_points
