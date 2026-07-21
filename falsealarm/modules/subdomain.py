import aiohttp
import asyncio
from typing import Any
from urllib.parse import urlparse
from falsealarm.modules.base import BaseModule, ModuleResult

class SubdomainModule(BaseModule):
    name = "subdomain"
    description = "Subdomain Enumeration via OSINT (crt.sh) and Brute-force"

    async def run(self, target: str) -> ModuleResult:
        self._start_timer()
        results: list[dict[str, Any]] = []
        stats = {"subdomains_found": 0}
        
        # Clean target to get root domain
        if target.startswith("http"):
            target = urlparse(target).hostname or target
            
        target = target.replace("www.", "")
        
        self.logger.info(f"Enumerating subdomains for {target} via crt.sh...")
        
        # Query crt.sh
        crt_url = f"https://crt.sh/?q=%.{target}&output=json"
        
        try:
            # We bypass the engine here briefly to avoid our own proxy/rate limits 
            # interfering with a direct API call, or we can use the engine.
            # Using engine is safer for consistency:
            response = await self.engine.get(crt_url, headers={"Accept": "application/json"})
            
            if not response.get("error") and response.get("status") == 200:
                import json
                try:
                    data = json.loads(response.get("body", "[]"))
                    subdomains = set()
                    
                    for entry in data:
                        name = entry.get("name_value", "").lower()
                        # Clean up wildcard domains and newlines
                        for sub in name.split('\n'):
                            sub = sub.strip().replace("*.", "")
                            if sub and sub.endswith(target):
                                subdomains.add(sub)
                                
                    for sub in subdomains:
                        results.append({
                            "type": "subdomain",
                            "domain": sub,
                            "source": "crt.sh"
                        })
                        stats["subdomains_found"] += 1
                        
                except json.JSONDecodeError:
                    self.logger.error("Failed to parse crt.sh response")
            else:
                self.logger.warning(f"crt.sh returned status {response.get('status')} or error {response.get('error')}")
                
        except Exception as e:
            self.logger.debug(f"Subdomain enumeration failed: {e}")

        return self._make_result(target, results, stats)
