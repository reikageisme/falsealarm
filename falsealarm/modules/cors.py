from typing import Any
from urllib.parse import urlparse
from falsealarm.modules.base import BaseModule, ModuleResult

class CORSModule(BaseModule):
    name = "cors"
    description = "CORS Misconfiguration Detection"

    async def run(self, target: str) -> ModuleResult:
        self._start_timer()
        results: list[dict[str, Any]] = []
        stats = {"vulnerabilities_found": 0}

        if not target.startswith("http"):
            target = f"http://{target}"

        # Origins to test for misconfiguration
        origins_to_test = [
            "https://evil.com",          # Arbitrary origin
            "null",                      # Null origin
            f"{target}.evil.com",        # Prefix match bypass
            f"https://evil{urlparse(target).hostname}" # Suffix match bypass
        ]

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
