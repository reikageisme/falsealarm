import asyncio
import time
import pytest
from falsealarm.core.rate_limiter import TokenBucketRateLimiter

@pytest.mark.asyncio
async def test_rate_limiter_respects_rate():
    # rate=50, burst=10 -> initial 10 tokens free, remaining 40 tokens require 40/50 = 0.8s
    limiter = TokenBucketRateLimiter(rate=50, burst=10, per_host_rate=50)
    start_time = time.time()
    
    # Simulate 50 requests
    for _ in range(50):
        await limiter.acquire()
        
    duration = time.time() - start_time
    assert duration >= 0.7

@pytest.mark.asyncio
async def test_rate_limiter_zero_rate():
    # If rate is 0, it means unlimited, should not block
    limiter = TokenBucketRateLimiter(rate=0, burst=0, per_host_rate=0)
    start_time = time.time()
    
    for _ in range(100):
        await limiter.acquire()
        
    duration = time.time() - start_time
    assert duration < 0.1 # Should be almost instant
