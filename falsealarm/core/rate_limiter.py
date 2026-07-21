"""
FalseAlarm — Token Bucket Rate Limiter

Implements a token bucket algorithm with millisecond precision for
controlling request rates. Supports per-host rate limiting to avoid
overwhelming individual targets.
"""

import asyncio
import time
from collections import defaultdict


class TokenBucketRateLimiter:
    """Token Bucket rate limiter with per-host support.

    The token bucket algorithm allows bursts of requests up to the bucket
    capacity, while maintaining an average rate over time. Tokens are
    replenished continuously based on elapsed time.

    Args:
        rate: Maximum requests per second (e.g., 30.0).
        burst: Maximum burst size (bucket capacity).
        per_host_rate: Optional per-host rate limit. If set, each unique
            host gets its own bucket with this rate.
    """

    def __init__(
        self,
        rate: float = 30.0,
        burst: int = 10,
        per_host_rate: float | None = None,
    ):
        self.rate = rate
        self.burst = burst
        self.per_host_rate = per_host_rate

        # Global bucket
        self._tokens: float = float(burst)
        self._last_refill: float = time.monotonic()
        self._lock = asyncio.Lock()

        # Per-host buckets: host -> (tokens, last_refill)
        self._host_buckets: dict[str, list[float]] = defaultdict(
            lambda: [float(burst), time.monotonic()]
        )
        self._host_lock = asyncio.Lock()

    def _refill(self) -> None:
        """Refill the global bucket based on elapsed time."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(
            float(self.burst),
            self._tokens + elapsed * self.rate,
        )
        self._last_refill = now

    def _refill_host(self, host: str) -> None:
        """Refill a per-host bucket based on elapsed time."""
        rate = self.per_host_rate or self.rate
        now = time.monotonic()
        bucket = self._host_buckets[host]
        elapsed = now - bucket[1]
        bucket[0] = min(float(self.burst), bucket[0] + elapsed * rate)
        bucket[1] = now

    async def acquire(self, host: str | None = None) -> None:
        """Acquire a token, waiting if necessary.

        This method blocks (asynchronously) until a token is available
        in both the global bucket and the per-host bucket (if applicable).

        Args:
            host: Optional hostname for per-host rate limiting.
        """
        # Acquire from global bucket
        while True:
            async with self._lock:
                self._refill()
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    break
            # Calculate wait time for next token
            wait_time = (1.0 - self._tokens) / self.rate if self.rate > 0 else 0.1
            await asyncio.sleep(max(0.001, wait_time))

        # Acquire from per-host bucket if configured
        if host and self.per_host_rate:
            while True:
                async with self._host_lock:
                    self._refill_host(host)
                    bucket = self._host_buckets[host]
                    if bucket[0] >= 1.0:
                        bucket[0] -= 1.0
                        break
                rate = self.per_host_rate
                wait_time = 1.0 / rate if rate > 0 else 0.1
                await asyncio.sleep(max(0.001, wait_time))

    @property
    def current_tokens(self) -> float:
        """Return the current number of available tokens (approximate)."""
        self._refill()
        return self._tokens

    def reset(self) -> None:
        """Reset the rate limiter to full capacity."""
        self._tokens = float(self.burst)
        self._last_refill = time.monotonic()
        self._host_buckets.clear()
