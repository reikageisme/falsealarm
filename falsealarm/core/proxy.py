"""
FalseAlarm — Proxy Manager

Manages proxy rotation for HTTP and SOCKS5 proxies. Supports loading
proxies from a file, round-robin rotation, health checking, and
automatic dead proxy removal.
"""

import asyncio
import aiohttp
from pathlib import Path
from typing import Any


class ProxyManager:
    """Manage and rotate HTTP/SOCKS5 proxies.

    Supports loading proxies from a single URL or a file containing
    one proxy URL per line. Proxies are rotated round-robin style.
    Dead proxies are automatically excluded.

    Args:
        proxy: Single proxy URL (e.g., 'http://host:port' or 'socks5://host:port').
        proxy_file: Path to a file with one proxy URL per line.
    """

    def __init__(
        self,
        proxy: str | None = None,
        proxy_file: str | None = None,
    ):
        self._proxies: list[str] = []
        self._dead_proxies: set[str] = set()
        self._index: int = 0
        self._initial_proxy = proxy
        self._proxy_file = proxy_file

        # Load initial single proxy
        if proxy:
            self._proxies.append(proxy)

    async def load_proxies(self) -> None:
        """Load proxies from the proxy file.

        Reads proxies from the file specified in the constructor,
        one per line. Lines starting with '#' are ignored.
        """
        if self._proxy_file:
            path = Path(self._proxy_file)
            if path.exists():
                with open(path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            if line not in self._proxies:
                                self._proxies.append(line)

    def get_proxy(self) -> str | None:
        """Get the next proxy URL via round-robin rotation.

        Skips dead proxies. Returns None if no proxies are available
        or all proxies are marked dead.
        """
        if not self._proxies:
            return None

        alive = [p for p in self._proxies if p not in self._dead_proxies]
        if not alive:
            return None

        proxy = alive[self._index % len(alive)]
        self._index += 1
        return proxy

    def get_proxy_for_aiohttp(self) -> str | None:
        """Get proxy formatted for aiohttp's proxy parameter.

        aiohttp accepts HTTP proxies directly. For SOCKS5 proxies,
        aiohttp-socks connector must be used instead.
        """
        proxy = self.get_proxy()
        if proxy and proxy.startswith(("http://", "https://")):
            return proxy
        # SOCKS proxies need to be handled via connector, not proxy param
        return None

    def get_connector(self, limit: int = 100, limit_per_host: int = 10) -> Any:
        """Create an aiohttp connector, optionally with SOCKS5 support.

        Args:
            limit: Total connection pool limit.
            limit_per_host: Per-host connection limit.

        Returns:
            A TCPConnector or ProxyConnector depending on proxy type.
        """
        proxy = self.get_proxy()
        if proxy and proxy.startswith("socks"):
            try:
                from aiohttp_socks import ProxyConnector
                return ProxyConnector.from_url(
                    proxy,
                    limit=limit,
                    limit_per_host=limit_per_host,
                    ssl=False,
                )
            except ImportError:
                # Fall back to regular connector if aiohttp-socks not installed
                pass

        return aiohttp.TCPConnector(
            limit=limit,
            limit_per_host=limit_per_host,
            ssl=False,
            enable_cleanup_closed=True,
        )

    async def health_check(self, proxy: str, timeout: int = 5) -> bool:
        """Check if a proxy is alive by making a test request.

        Args:
            proxy: Proxy URL to check.
            timeout: Request timeout in seconds.

        Returns:
            True if the proxy responded successfully.
        """
        test_url = "http://httpbin.org/ip"
        try:
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(
                    test_url,
                    proxy=proxy if proxy.startswith("http") else None,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                ) as resp:
                    return resp.status == 200
        except Exception:
            return False

    def mark_dead(self, proxy: str) -> None:
        """Mark a proxy as dead so it will be skipped in rotation.

        Args:
            proxy: The proxy URL to mark as dead.
        """
        self._dead_proxies.add(proxy)

    def mark_alive(self, proxy: str) -> None:
        """Remove the dead mark from a proxy.

        Args:
            proxy: The proxy URL to mark as alive again.
        """
        self._dead_proxies.discard(proxy)

    @property
    def has_proxies(self) -> bool:
        """Check if any alive proxies are available."""
        return bool(
            [p for p in self._proxies if p not in self._dead_proxies]
        )

    @property
    def total(self) -> int:
        """Total number of loaded proxies."""
        return len(self._proxies)

    @property
    def alive_count(self) -> int:
        """Number of alive proxies."""
        return len(
            [p for p in self._proxies if p not in self._dead_proxies]
        )

    async def health_check_all(self, timeout: int = 5) -> dict[str, bool]:
        """Run health checks on all proxies concurrently.

        Returns:
            Dict mapping proxy URL to health status.
        """
        results = {}
        tasks = []
        for proxy in self._proxies:
            tasks.append(self.health_check(proxy, timeout))

        statuses = await asyncio.gather(*tasks, return_exceptions=True)
        for proxy, status in zip(self._proxies, statuses):
            is_alive = status is True
            results[proxy] = is_alive
            if not is_alive:
                self.mark_dead(proxy)
            else:
                self.mark_alive(proxy)

        return results
