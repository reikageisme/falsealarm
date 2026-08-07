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
        adaptive: bool = False,
    ):
        self.max_rate = rate
        self.rate = rate
        self.burst = burst
        self.per_host_rate = per_host_rate
        self.adaptive = adaptive
        
        self.consecutive_errors = 0
        self.consecutive_successes = 0
        self._adaptive_lock = asyncio.Lock()

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
        if self.rate <= 0:
            return

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

    async def report_status(self, success: bool, status_code: int = 200) -> None:
        """
        Report the status of a request to adjust the rate adaptively.
        If the server returns 429/503 or a connection/timeout error, we reduce the rate.
        If we get stable successful responses, we slowly recover to max_rate.
        """
        if not self.adaptive:
            return

        async with self._adaptive_lock:
            if not success or status_code in (429, 503):
                self.consecutive_errors += 1
                self.consecutive_successes = 0
                
                # If we get 3 consecutive rate limit / timeout errors, drop rate by 50%
                if self.consecutive_errors >= 3:
                    new_rate = max(1.0, self.rate * 0.5)
                    if new_rate != self.rate:
                        self.rate = new_rate
                    self.consecutive_errors = 0
            else:
                self.consecutive_successes += 1
                self.consecutive_errors = 0
                
                # Recover rate by 20% after 20 consecutive successful requests
                if self.consecutive_successes >= 20 and self.rate < self.max_rate:
                    new_rate = min(self.max_rate, self.rate * 1.2)
                    if new_rate != self.rate:
                        self.rate = new_rate
                    self.consecutive_successes = 0
