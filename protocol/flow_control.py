"""Flow control — token bucket rate limiter.

Optional module to prevent overwhelming the peer or the network.
Can be inserted between the multiplexer and the transport.
"""

import asyncio
import time


class TokenBucket:
    """Token bucket rate limiter.

    Args:
        rate: tokens per second (bytes/s)
        capacity: maximum burst size in tokens (bytes)
    """

    def __init__(self, rate: float, capacity: float) -> None:
        self._rate = rate
        self._capacity = capacity
        self._tokens = capacity
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def consume(self, tokens: int) -> None:
        """Wait until `tokens` are available, then consume them."""
        while True:
            async with self._lock:  # noqa
                self._refill()
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return

            # Wait for tokens to accumulate
            wait_time = (tokens - self._tokens) / self._rate
            await asyncio.sleep(max(wait_time, 0.01))

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
        self._last_refill = now


class FlowController:
    """Wraps a raw send function with rate limiting."""

    def __init__(
        self,
        send_raw,
        rate_bytes_per_sec: float = 10_000_000,  # 10 MB/s default
        burst_bytes: float = 1_000_000,           # 1 MB burst
    ) -> None:
        self._send_raw = send_raw
        self._bucket = TokenBucket(rate_bytes_per_sec, burst_bytes)

    async def send(self, data: bytes) -> None:
        await self._bucket.consume(len(data))
        await self._send_raw(data)
