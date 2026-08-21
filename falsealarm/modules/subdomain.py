import asyncio
import json
import random
import string
from typing import Any
from urllib.parse import urlparse

import dns.exception
import dns.resolver

from falsealarm.core.utils import get_data_path
from falsealarm.modules.base import BaseModule, ModuleResult


class SubdomainModule(BaseModule):
    name = "subdomain"
    description = "Subdomain Enumeration via crt.sh (OSINT) and DNS brute-force"

    async def run(self, target: str) -> ModuleResult:
        self._start_timer()
        results: list[dict[str, Any]] = []
        stats = {"subdomains_found": 0, "from_crtsh": 0, "from_bruteforce": 0, "wildcard": False}

        # Clean target to get root domain
        if target.startswith("http"):
            target = urlparse(target).hostname or target
        target = target.replace("www.", "")

        found: dict[str, str] = {}  # subdomain -> source

        # 1. Passive OSINT via crt.sh
        await self._enumerate_crtsh(target, found, stats)

        # 2. Active DNS brute-force over the bundled wordlist
        await self._bruteforce_dns(target, found, stats)

        for sub, source in sorted(found.items()):
            results.append({"type": "subdomain", "domain": sub, "source": source})
            stats["subdomains_found"] += 1

        return self._make_result(target, results, stats)

    async def _enumerate_crtsh(self, target: str, found: dict[str, str], stats: dict) -> None:
        self.logger.info(f"Enumerating subdomains for {target} via crt.sh...")
        crt_url = f"https://crt.sh/?q=%.{target}&output=json"
        try:
            response = await self.engine.get(crt_url, headers={"Accept": "application/json"})
            if not response.get("error") and response.get("status") == 200:
                try:
                    data = json.loads(response.get("body", "[]"))
                except json.JSONDecodeError:
                    self.logger.error("Failed to parse crt.sh response")
                    return
                for entry in data:
                    name = entry.get("name_value", "").lower()
                    for sub in name.split("\n"):
                        sub = sub.strip().replace("*.", "")
                        if sub and sub.endswith(target) and sub not in found:
                            found[sub] = "crt.sh"
                            stats["from_crtsh"] += 1
            else:
                self.logger.warning(
                    f"crt.sh returned status {response.get('status')} or error {response.get('error')}"
                )
        except Exception as e:
            self.logger.debug(f"crt.sh enumeration failed: {e}")

    async def _bruteforce_dns(self, target: str, found: dict[str, str], stats: dict) -> None:
        wordlist_path = get_data_path("wordlists/subdomains_top1k.txt")
        try:
            with open(wordlist_path, "r", encoding="utf-8") as f:
                words = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
        except Exception as e:
            self.logger.debug(f"Subdomain wordlist unavailable ({e}); skipping brute-force.")
            return

        resolver = dns.resolver.Resolver()
        resolver.timeout = self.config.timeout
        resolver.lifetime = self.config.timeout

        # Wildcard detection: if a random label resolves, brute-force would be
        # all false positives, so we skip it rather than flood the report.
        rand_label = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
        if await self._resolves(resolver, f"{rand_label}.{target}"):
            stats["wildcard"] = True
            self.logger.warning(
                f"{target} uses wildcard DNS; skipping brute-force to avoid false positives."
            )
            return

        self.logger.info(f"Brute-forcing {len(words)} DNS labels on {target}...")
        sem = asyncio.Semaphore(max(1, self.config.threads))

        async def probe(label: str) -> None:
            candidate = f"{label}.{target}"
            if candidate in found:
                return
            async with sem:
                if await self._resolves(resolver, candidate):
                    found[candidate] = "dns-brute"
                    stats["from_bruteforce"] += 1
                    self.logger.success(f"Resolved: {candidate}")

        await asyncio.gather(*(probe(w) for w in words))

    @staticmethod
    async def _resolves(resolver: "dns.resolver.Resolver", name: str) -> bool:
        def _query() -> bool:
            try:
                resolver.resolve(name, "A")
                return True
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                    dns.resolver.NoNameservers, dns.exception.Timeout):
                return False
            except Exception:
                return False
        return await asyncio.to_thread(_query)
