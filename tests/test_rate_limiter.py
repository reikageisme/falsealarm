import asyncio
import time
import pytest
from falsealarm.core.rate_limiter import TokenBucketRateLimiter

@pytest.mark.asyncio
async def test_rate_limiter_respects_rate():
    limiter = TokenBucketRateLimiter(rate=50, burst=50, per_host_rate=50) # 50 req/sec
    start_time = time.time()
    
    # Simulate 50 requests
    for _ in range(50):
        await limiter.acquire()
        
    duration = time.time() - start_time
    
    # 50 requests at 50 req/sec should take at least 1 second (minus small overhead)
    assert duration >= 0.9

@pytest.mark.asyncio
async def test_rate_limiter_zero_rate():
    # If rate is 0, it means unlimited, should not block
    limiter = TokenBucketRateLimiter(rate=0, burst=0, per_host_rate=0)
    start_time = time.time()
    
    for _ in range(100):
        await limiter.acquire()
        
    duration = time.time() - start_time
    assert duration < 0.1 # Should be almost instant
