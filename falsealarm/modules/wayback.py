import json
import urllib.parse
from typing import Any
from falsealarm.modules.base import BaseModule, ModuleResult

class WaybackModule(BaseModule):
    name = "wayback"
    description = "Wayback Machine URL Discovery"

    async def run(self, target: str) -> ModuleResult:
        self._start_timer()
        results: list[dict[str, Any]] = []
        stats = {"urls_found": 0, "sensitive_extensions": 0}

        # Clean target to get domain
        if target.startswith("http"):
            target = urllib.parse.urlparse(target).hostname or target
            
        target = target.replace("www.", "")
        
        self.logger.info(f"Fetching historical URLs from Wayback Machine for {target}...")
        
        # Wayback Machine CDX API
        # collapse=urlkey to remove duplicates
        cdx_url = f"https://web.archive.org/cdx/search/cdx?url=*.{target}/*&output=json&collapse=urlkey&fl=original,mimetype,timestamp"
        
        sensitive_exts = ('.php', '.asp', '.aspx', '.jsp', '.env', '.bak', '.old', '.zip', '.sql', '.json', '.xml', '.config')

        try:
            response = await self.engine.get(cdx_url, headers={"Accept": "application/json"})
            
            if not response.get("error") and response.get("status") == 200:
                try:
                    data = json.loads(response.get("body", "[]"))
                    # The first row is the header: ["original", "mimetype", "timestamp"]
                    if len(data) > 1:
                        for row in data[1:]:
                            if len(row) >= 3:
                                original_url = row[0]
                                mimetype = row[1]
                                timestamp = row[2]
                                
                                item = {
                                    "type": "wayback_url",
                                    "url": original_url,
                                    "mimetype": mimetype,
                                    "timestamp": timestamp,
                                    "is_sensitive": False
                                }
                                
                                # Check for sensitive extensions or query parameters
                                parsed_url = urllib.parse.urlparse(original_url)
                                if parsed_url.path.endswith(sensitive_exts) or parsed_url.query:
                                    item["is_sensitive"] = True
                                    stats["sensitive_extensions"] += 1
                                    
                                results.append(item)
                                stats["urls_found"] += 1
                                
                except json.JSONDecodeError:
                    self.logger.error("Failed to parse Wayback Machine response")
            else:
                self.logger.warning(f"Wayback API returned status {response.get('status')} or error {response.get('error')}")
                
        except Exception as e:
            self.logger.debug(f"Wayback enumeration failed: {e}")

        return self._make_result(target, results, stats)
