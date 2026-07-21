import asyncio
import json
import socket
import ssl
from typing import Any
from urllib.parse import urlparse
from falsealarm.modules.base import BaseModule, ModuleResult

class HeadersSSLModule(BaseModule):
    name = "ssl"
    description = "Analyze Security Headers and SSL/TLS Certificates"

    async def run(self, target: str) -> ModuleResult:
        self._start_timer()
        results: list[dict[str, Any]] = []
        stats = {"ssl_valid": False, "security_headers_count": 0}

        # Handle formatting
        if not target.startswith("http"):
            target = f"https://{target}"
        parsed = urlparse(target)
        hostname = parsed.hostname or target
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        # 1. Analyze HTTP Headers via aiohttp engine
        try:
            response = await self.engine.get(target, allow_redirects=False)
            if not response.get("error"):
                headers = response.get("headers", {})
                
                # Check standard security headers
                security_headers = {
                    "Strict-Transport-Security": "HSTS",
                    "Content-Security-Policy": "CSP",
                    "X-Frame-Options": "X-Frame-Options",
                    "X-Content-Type-Options": "X-Content-Type-Options",
                    "Referrer-Policy": "Referrer-Policy",
                    "Permissions-Policy": "Permissions-Policy"
                }

                found_headers = {}
                for header_name, common_name in security_headers.items():
                    # Case insensitive header lookup
                    value = next((v for k, v in headers.items() if k.lower() == header_name.lower()), None)
                    if value:
                        found_headers[common_name] = value
                        stats["security_headers_count"] += 1

                results.append({
                    "type": "security_headers",
                    "target": target,
                    "headers_found": found_headers,
                    "missing_headers": [h for h, c in security_headers.items() if c not in found_headers]
                })
        except Exception as e:
            self.logger.debug(f"Headers analysis failed: {e}")

        # 2. Analyze SSL Certificate (if HTTPS)
        if port == 443 or parsed.scheme == "https":
            ssl_info = await self._get_ssl_cert(hostname, port)
            if ssl_info:
                stats["ssl_valid"] = True
                results.append({
                    "type": "ssl_certificate",
                    "target": hostname,
                    **ssl_info
                })

        return self._make_result(target, results, stats)

    async def _get_ssl_cert(self, hostname: str, port: int) -> dict[str, Any]:
        """Fetch SSL certificate information asynchronously using thread execution."""
        def fetch_cert():
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            try:
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert(binary_form=False)
                        if not cert:
                            return None
                        
                        # Parse Issuer
                        issuer = {}
                        for rdn in cert.get("issuer", []):
                            for key, val in rdn:
                                issuer[key] = val
                        
                        # Parse Subject
                        subject = {}
                        for rdn in cert.get("subject", []):
                            for key, val in rdn:
                                subject[key] = val

                        # Parse SANs
                        sans = []
                        for method, val in cert.get("subjectAltName", []):
                            sans.append(val)

                        return {
                            "issuer": issuer.get("organizationName", issuer.get("commonName", "Unknown")),
                            "subject": subject.get("commonName", hostname),
                            "valid_from": cert.get("notBefore", ""),
                            "valid_to": cert.get("notAfter", ""),
                            "sans": sans,
                            "version": cert.get("version", ""),
                            "serialNumber": cert.get("serialNumber", "")
                        }
            except Exception as e:
                self.logger.debug(f"SSL fetch failed for {hostname}: {e}")
                return None
                
        return await asyncio.to_thread(fetch_cert)
