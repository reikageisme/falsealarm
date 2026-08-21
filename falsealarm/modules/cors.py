from typing import Any
from urllib.parse import urlparse

from falsealarm.modules.base import BaseModule, ModuleResult


class CORSModule(BaseModule):
    name = "cors"
    description = "CORS Misconfiguration Detection"

    @staticmethod
    def _bypass_origins(host: str) -> list[str]:
        """Build well-formed test origins from the target hostname.

        Uses the hostname (not the full URL) so every Origin header is valid
        and actually exercises the common trust-check bypasses.
        """
        origins = ["https://evil.com", "null"]
        if host:
            origins += [
                f"https://{host}.evil.com",      # Suffix bypass (trusts *.evil.com)
                f"https://evil-{host}",          # Prefix bypass (naive startswith check)
                f"https://{host}.attacker.tld",  # Domain-appended bypass
            ]
        return origins

    async def run(self, target: str) -> ModuleResult:
        self._start_timer()
        results: list[dict[str, Any]] = []
        stats = {"vulnerabilities_found": 0}

        if not target.startswith("http"):
            target = f"http://{target}"

        host = urlparse(target).hostname or ""
        origins_to_test = self._bypass_origins(host)

        async def test_origin(origin: str):
            try:
                headers = {"Origin": origin}
                # Using a GET request, but OPTIONS is also valid for preflight
                response = await self.engine.get(target, headers=headers)

                if not response.get("error"):
                    res_headers = {k.lower(): v for k, v in response.get("headers", {}).items()}

                    acao = res_headers.get("access-control-allow-origin")
                    acac = res_headers.get("access-control-allow-credentials")

                    # Vulnerable condition: Reflection of malicious origin AND credentials allowed
                    # Or reflection of 'null'
                    is_vulnerable = False
                    vuln_type = ""

                    if acao == origin:
                        if acac == "true":
                            is_vulnerable = True
                            vuln_type = f"Arbitrary Origin Reflection with Credentials (Origin: {origin})"
                        elif origin == "null":
                            is_vulnerable = True
                            vuln_type = "Null Origin Allowed"
                        else:
                            # Reflected but no credentials, still notable but lower impact
                            results.append({
                                "type": "cors_info",
                                "target": target,
                                "origin_tested": origin,
                                "acao": acao,
                                "acac": acac,
                                "note": "Origin reflected, but credentials not allowed."
                            })

                    if is_vulnerable:
                        stats["vulnerabilities_found"] += 1
                        results.append({
                            "type": "cors_vulnerability",
                            "target": target,
                            "origin_tested": origin,
                            "acao": acao,
                            "acac": acac,
                            "vulnerability": vuln_type
                        })
            except Exception as e:
                self.logger.debug(f"CORS test failed for {origin}: {e}")

        # Execute tests sequentially to avoid rate limiting or WAF blocks on same endpoint
        for origin in origins_to_test:
            await test_origin(origin)

        return self._make_result(target, results, stats)
