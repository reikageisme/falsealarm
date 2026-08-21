import asyncio
import re
from typing import Any
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from falsealarm.core.utils import canonical_url
from falsealarm.modules.base import BaseModule, ModuleResult


class JSAnalysisModule(BaseModule):
    name = "js_analysis"
    description = "JavaScript AST Analysis & Secrets Extraction"

    # Regex patterns for common secrets/tokens
    SECRET_PATTERNS = {
        "Google API Key": r'AIza[0-9A-Za-z-_]{35}',
        "AWS Access Key": r'AKIA[0-9A-Z]{16}',
        "Stripe Standard API": r'sk_live_[0-9a-zA-Z]{24}',
        "RSA Private Key": r'-----BEGIN RSA PRIVATE KEY-----',
        "Generic Bearer Token": r'Bearer [a-zA-Z0-9\-\._\~\+\/]+',
        "Github Access Token": r'ghp_[0-9a-zA-Z]{36}',
        "JWT Token": r'eyJ[a-zA-Z0-9]{10,}\.eyJ[a-zA-Z0-9]{10,}\.[a-zA-Z0-9_\-]+'
    }

    # Regex for endpoints
    ENDPOINT_PATTERN = re.compile(
        r'["\'](https?://[^"\'\\\s]+|/[A-Za-z0-9._~-][A-Za-z0-9._~/?#=&%+:-]*)["\']'
    )

    async def run(self, target: str) -> ModuleResult:
        self._start_timer()
        results: list[dict[str, Any]] = []
        stats = {"js_files_analyzed": 0, "secrets_found": 0, "endpoints_extracted": 0}

        if not target.startswith("http"):
            target = f"http://{target}"

        try:
            # 1. Fetch main page to extract JS links
            response = await self.engine.get(target)
            if response.get("error"):
                return self._make_result(target, results, stats)

            html_body = response.get("body", "")
            js_urls = self._extract_js_urls(html_body, target)

            if not js_urls:
                self.logger.debug("No external JS files found on the target.")
                return self._make_result(target, results, stats)

            self.logger.info(f"Found {len(js_urls)} JS files. Analyzing...")

            # 2. Download and analyze JS files concurrently
            async def analyze_js(js_url: str):
                try:
                    res = await self.engine.get(js_url)
                    if res.get("error") or res.get("status") != 200:
                        return None

                    js_code = res.get("body", "")
                    stats["js_files_analyzed"] += 1

                    found_secrets = []
                    found_endpoints = set()

                    # Extract Secrets via Regex
                    for secret_name, pattern in self.SECRET_PATTERNS.items():
                        matches = re.findall(pattern, js_code)
                        if matches:
                            # Remove duplicates
                            unique_matches = list(set(matches))
                            for match in unique_matches:
                                found_secrets.append({"type": secret_name, "value": match})
                                stats["secrets_found"] += 1

                    # Extract Endpoints via Regex
                    endpoints = self.ENDPOINT_PATTERN.findall(js_code)
                    if endpoints:
                        for ep in endpoints:
                            normalized = self._normalize_endpoint(ep, target)
                            if normalized:
                                found_endpoints.add(normalized)

                    if found_secrets or found_endpoints:
                        return {
                            "type": "js_analysis",
                            "source": js_url,
                            "secrets": found_secrets,
                            "endpoints": list(found_endpoints)
                        }

                except Exception as e:
                    self.logger.debug(f"Failed to analyze {js_url}: {e}")
                return None

            tasks = [analyze_js(url) for url in js_urls]
            analysis_results = await asyncio.gather(*tasks)

            for r in analysis_results:
                if r:
                    results.append(r)

            stats["endpoints_extracted"] = len({
                endpoint
                for item in results
                for endpoint in item.get("endpoints", [])
            })

        except Exception as e:
            self.logger.error(f"JS Analysis failed: {e}")

        return self._make_result(target, results, stats)

    def _extract_js_urls(self, html: str, base_url: str) -> list[str]:
        """Extract all external JavaScript URLs from HTML."""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            script_tags = soup.find_all('script', src=True)
            urls = []
            for tag in script_tags:
                src = tag['src']
                full_url = urljoin(base_url, src)
                if self.config.include_third_party_js or self._same_origin(full_url, base_url):
                    urls.append(canonical_url(full_url))
            # Remove duplicates
            return list(dict.fromkeys(urls))
        except Exception:
            return []

    @staticmethod
    def _same_origin(candidate: str, target: str) -> bool:
        candidate_host = (urlparse(candidate).hostname or "").lower()
        target_host = (urlparse(target).hostname or "").lower()
        return bool(candidate_host and candidate_host == target_host)

    @classmethod
    def _normalize_endpoint(cls, endpoint: str, target: str) -> str | None:
        if endpoint.startswith(("http://", "https://")):
            return canonical_url(endpoint) if cls._same_origin(endpoint, target) else None
        if endpoint.startswith("/") and not endpoint.startswith("//"):
            return canonical_url(urljoin(target, endpoint))
        return None
