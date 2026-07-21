import json
import re
from typing import Any
from urllib.parse import urlparse
from falsealarm.modules.base import BaseModule, ModuleResult
from falsealarm.core.utils import get_data_path

class TechDetectModule(BaseModule):
    name = "tech"
    description = "Technology Detection (CMS, WAF, Frameworks) via signatures"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.signatures = self._load_signatures()

    def _load_signatures(self) -> dict:
        try:
            path = get_data_path("tech_signatures.json")
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data.get("technologies", {})
        except Exception as e:
            self.logger.error(f"Failed to load tech signatures: {e}")
            return {}

    async def run(self, target: str) -> ModuleResult:
        self._start_timer()
        results: list[dict[str, Any]] = []
        stats = {"technologies_found": 0}

        if not target.startswith("http"):
            target = f"http://{target}"

        try:
            response = await self.engine.get(target)
            if response.get("error"):
                return self._make_result(target, results, stats)

            headers = {k.lower(): v for k, v in response.get("headers", {}).items()}
            body = response.get("body", "")
            
            # Simple cookie extraction from headers
            cookies = headers.get("set-cookie", "")

            detected = []

            for tech_name, tech_data in self.signatures.items():
                is_detected = False
                
                # Check Headers
                if "headers" in tech_data:
                    for h_name, h_val in tech_data["headers"].items():
                        if h_name.lower() in headers:
                            if h_val.lower() in headers[h_name.lower()].lower():
                                is_detected = True
                                break
                
                # Check Cookies
                if not is_detected and "cookies" in tech_data:
                    for cookie in tech_data["cookies"]:
                        if cookie.lower() in cookies.lower():
                            is_detected = True
                            break

                # Check HTML (body)
                if not is_detected and "html" in tech_data:
                    for html_sig in tech_data["html"]:
                        if html_sig.lower() in body.lower():
                            is_detected = True
                            break
                            
                # Check Meta tags
                if not is_detected and "meta" in tech_data:
                    for m_name, m_val in tech_data["meta"].items():
                        # Basic regex to find meta tags
                        pattern = re.compile(f'<meta[^>]*name=["\']{m_name}["\'][^>]*content=["\']([^"\']*{m_val}[^"\']*)["\']', re.IGNORECASE)
                        if pattern.search(body):
                            is_detected = True
                            break

                if is_detected:
                    detected.append({
                        "name": tech_name,
                        "category": tech_data.get("category", "Unknown")
                    })
                    stats["technologies_found"] += 1

            if detected:
                results.append({
                    "type": "technology_stack",
                    "target": target,
                    "technologies": detected
                })

        except Exception as e:
            self.logger.debug(f"Tech detection failed: {e}")

        return self._make_result(target, results, stats)
