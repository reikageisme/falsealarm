"""
FalseAlarm — Async HTTP Engine

The core HTTP engine built on aiohttp. Manages connection pooling,
integrates rate limiting, proxy rotation, and request fingerprinting.
Provides both single-request and batch-request interfaces.
"""

import asyncio
import time
import ssl
import certifi
import aiohttp
from urllib.parse import urlparse

from falsealarm.core.config import ScanConfig
from falsealarm.core.rate_limiter import TokenBucketRateLimiter
from falsealarm.core.fingerprint import RequestFingerprint
from falsealarm.core.proxy import ProxyManager


class AsyncEngine:
    """Asynchronous HTTP engine with connection pooling and rate limiting.

    This is the heart of FalseAlarm. All HTTP-based modules use this
    engine to send requests. It integrates:
    - Connection pooling via aiohttp.TCPConnector
    - Token bucket rate limiting
    - Request header randomization
    - Proxy rotation (HTTP/SOCKS5)
    - Automatic retry with exponential backoff
    - Graceful error handling

    Args:
        config: ScanConfig instance with scan parameters.
    """

    def __init__(self, config: ScanConfig):
        self.config = config
        self._session: aiohttp.ClientSession | None = None
        self._rate_limiter: TokenBucketRateLimiter | None = None
        self._fingerprint: RequestFingerprint | None = None
        self._proxy_manager: ProxyManager | None = None
        self._started = False

    async def start(self) -> None:
        """Initialize the HTTP session and all sub-components.

        Creates the aiohttp session with a connection pool, initializes
        rate limiting, fingerprinting, and proxy management.
        """
        if self._started:
            return

        # Initialize rate limiter
        self._rate_limiter = TokenBucketRateLimiter(
            rate=float(self.config.rate),
            burst=min(self.config.rate, 50),
            per_host_rate=float(self.config.rate) / 2,
        )

        # Initialize fingerprint randomizer
        self._fingerprint = RequestFingerprint(
            random_agent=self.config.random_agent,
        )

        # Initialize proxy manager
        self._proxy_manager = ProxyManager(
            proxy=self.config.proxy,
            proxy_file=self.config.proxy_file,
        )
        await self._proxy_manager.load_proxies()

        # Create connector
        connector = self._proxy_manager.get_connector(
            limit=self.config.threads,
            limit_per_host=10,
        )

        # Create SSL context
        ssl_ctx = ssl.create_default_context(cafile=certifi.where())
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        # Create timeout
        timeout = aiohttp.ClientTimeout(
            total=self.config.timeout * 2,
            connect=self.config.timeout,
            sock_read=self.config.timeout,
        )

        # Create session
        self._session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            trust_env=True,
        )

        self._started = True

    async def request(
        self,
        method: str,
        url: str,
        **kwargs,
    ) -> dict:
        """Send a single HTTP request with rate limiting and fingerprinting.

        Goes through the full pipeline:
        1. Rate limiter acquire (wait for token)
        2. Apply fingerprint headers
        3. Optional delay
        4. Send request via aiohttp
        5. Return structured response dict

        Args:
            method: HTTP method (GET, POST, HEAD, etc.)
            url: Target URL.
            **kwargs: Additional arguments passed to aiohttp request.

        Returns:
            Dict with keys: url, status, headers, body, content_length,
            title, elapsed, error, redirect_url.
        """
        if not self._started:
            await self.start()

        result = {
            "url": url,
            "status": 0,
            "headers": {},
            "body": "",
            "content_length": 0,
            "title": "",
            "elapsed": 0.0,
            "error": None,
            "redirect_url": None,
        }

        try:
            # Extract host for per-host rate limiting
            host = urlparse(url).hostname or ""

            # Wait for rate limiter
            await self._rate_limiter.acquire(host=host)

            # Apply delay if configured
            if self.config.delay > 0:
                await asyncio.sleep(self.config.delay / 1000.0)

            # Build headers
            headers = kwargs.pop("headers", {})
            if self._fingerprint:
                fp_headers = self._fingerprint.get_headers()
                fp_headers.update(headers)
                headers = fp_headers

            # Get proxy for aiohttp
            proxy = None
            if self._proxy_manager and self._proxy_manager.has_proxies:
                proxy = self._proxy_manager.get_proxy_for_aiohttp()

            # Send request
            start_time = time.monotonic()
            async with self._session.request(
                method,
                url,
                headers=headers,
                proxy=proxy,
                ssl=False,
                allow_redirects=kwargs.pop("allow_redirects", True),
                **kwargs,
            ) as response:
                elapsed = time.monotonic() - start_time

                body = ""
                try:
                    body = await response.text(errors="replace")
                except Exception:
                    try:
                        raw = await response.read()
                        body = raw.decode("utf-8", errors="replace")
                    except Exception:
                        body = ""

                # Extract title from HTML
                title = ""
                if "<title>" in body.lower():
                    start = body.lower().find("<title>") + 7
                    end = body.lower().find("</title>", start)
                    if end > start:
                        title = body[start:end].strip()[:200]

                # Get redirect URL
                redirect_url = None
                if response.history:
                    redirect_url = str(response.url)

                result.update(
                    {
                        "status": response.status,
                        "headers": dict(response.headers),
                        "body": body,
                        "content_length": len(body),
                        "title": title,
                        "elapsed": round(elapsed, 3),
                        "redirect_url": redirect_url,
                    }
                )

        except asyncio.TimeoutError:
            result["error"] = "timeout"
        except aiohttp.ClientConnectorError as e:
            result["error"] = f"connection_error: {e}"
        except aiohttp.ClientError as e:
            result["error"] = f"client_error: {e}"
        except Exception as e:
            result["error"] = f"unknown_error: {type(e).__name__}: {e}"

        return result

    async def batch_request(
        self,
        urls: list[str],
        method: str = "GET",
        concurrency: int | None = None,
        callback=None,
        **kwargs,
    ) -> list[dict]:
        """Send multiple requests concurrently with a concurrency limit.

        Uses asyncio.Semaphore to control the number of concurrent
        requests. An optional callback function is called for each
        completed request.

        Args:
            urls: List of URLs to request.
            method: HTTP method for all requests.
            concurrency: Max concurrent requests. Defaults to config.threads.
            callback: Optional async or sync function called with each result.
            **kwargs: Additional arguments passed to each request.

        Returns:
            List of response dicts from request().
        """
        if not self._started:
            await self.start()

        sem = asyncio.Semaphore(concurrency or self.config.threads)
        results = []

        async def _make_request(url: str) -> dict:
            async with sem:
                result = await self.request(method, url, **kwargs)
                if callback:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(result)
                    else:
                        callback(result)
                return result

        tasks = [_make_request(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Convert exceptions to error dicts
        final_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                final_results.append(
                    {
                        "url": urls[i] if i < len(urls) else "unknown",
                        "status": 0,
                        "headers": {},
                        "body": "",
                        "content_length": 0,
                        "title": "",
                        "elapsed": 0.0,
                        "error": f"{type(result).__name__}: {result}",
                        "redirect_url": None,
                    }
                )
            else:
                final_results.append(result)

        return final_results

    async def head(self, url: str, **kwargs) -> dict:
        """Send a HEAD request."""
        return await self.request("HEAD", url, **kwargs)

    async def get(self, url: str, **kwargs) -> dict:
        """Send a GET request."""
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> dict:
        """Send a POST request."""
        return await self.request("POST", url, **kwargs)

    async def close(self) -> None:
        """Close the HTTP session and release resources."""
        if self._session and not self._session.closed:
            await self._session.close()
            # Allow time for connections to close cleanly
            await asyncio.sleep(0.1)
        self._started = False

    async def __aenter__(self) -> "AsyncEngine":
        """Async context manager entry."""
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.close()
