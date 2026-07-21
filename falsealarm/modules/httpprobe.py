import asyncio
import hashlib
from typing import Any
from urllib.parse import urlparse
from falsealarm.modules.base import BaseModule, ModuleResult

class HTTPProbeModule(BaseModule):
    name = "httpprobe"
    description = "HTTP Probing and Similarity Hashing (Alive checks)"

    async def run(self, target: str) -> ModuleResult:
        self._start_timer()
        results: list[dict[str, Any]] = []
        stats = {"alive": 0, "dead": 0}

        urls_to_probe = []
        # If target is a raw domain, probe both HTTP and HTTPS
        if not target.startswith("http"):
            urls_to_probe = [f"http://{target}", f"https://{target}"]
        else:
            urls_to_probe = [target]

        async def probe_url(url: str):
            try:
                response = await self.engine.get(url, allow_redirects=False)
                if not response.get("error"):
                    status = response.get("status", 0)
                    body = response.get("body", "")
                    
                    # Compute a simple similarity hash (SimHash logic simplified for Phase 2)
                    # We hash the length and status code to group identical responses
                    sim_hash = hashlib.md5(f"{status}_{len(body)}_{response.get('title', '')}".encode()).hexdigest()

                    return {
                        "url": url,
                        "status": status,
                        "content_length": response.get("content_length", 0),
                        "title": response.get("title", ""),
                        "redirect": response.get("redirect_url", ""),
                        "server": response.get("headers", {}).get("Server", ""),
                        "sim_hash": sim_hash,
                        "alive": True
                    }
                else:
                    return {"url": url, "alive": False, "error": response.get("error")}
            except Exception as e:
                return {"url": url, "alive": False, "error": str(e)}

        tasks = [probe_url(url) for url in urls_to_probe]
        probe_results = await asyncio.gather(*tasks)

        for r in probe_results:
            if r.get("alive"):
                stats["alive"] += 1
                results.append(r)
            else:
                stats["dead"] += 1

        return self._make_result(target, results, stats)
