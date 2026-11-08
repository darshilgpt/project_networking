"""Token Bucket Rate Limiting for IP addresses, clients, and protocols."""

from __future__ import annotations

from dataclasses import dataclass, field
import logging
import time
from typing import Dict, Optional, Tuple

logger = logging.getLogger("dpi_ids_ips.ips.rate_limiter")


@dataclass
class TokenBucket:
    """Token bucket state for a single tracked identity."""
    rate: float            # Tokens added per second
    capacity: float        # Maximum tokens in bucket (burst allowance)
    tokens: float          # Current token count
    last_updated: float    # Last timestamp tokens were refreshed

    def consume(self, count: float, now: float) -> bool:
        """Adds elapsed tokens and attempts to consume 'count' tokens."""
        elapsed = now - self.last_updated
        if elapsed > 0:
            self.tokens = min(self.capacity, self.tokens + (elapsed * self.rate))
            self.last_updated = now

        if self.tokens >= count:
            self.tokens -= count
            return True
        return False


class RateLimiter:
    """Enforces bandwidth and packet rate limiting using token bucket algorithms."""

    def __init__(
        self,
        default_pps_limit: float = 100.0,
        default_pps_burst: float = 150.0,
        default_bps_limit: float = 5_000_000.0,  # 5 MB/s
        default_bps_burst: float = 10_000_000.0, # 10 MB/s
    ) -> None:
        self.default_pps_limit = default_pps_limit
        self.default_pps_burst = default_pps_burst
        self.default_bps_limit = default_bps_limit
        self.default_bps_burst = default_bps_burst

        # key -> TokenBucket
        self._packet_buckets: Dict[str, TokenBucket] = {}
        self._byte_buckets: Dict[str, TokenBucket] = {}

        # Custom limits per IP or client: key -> (rate, burst)
        self.custom_limits: Dict[str, Tuple[float, float]] = {}

        self.total_rate_checks = 0
        self.total_rate_violations = 0

    def set_custom_limit(self, identifier: str, pps_rate: float, pps_burst: float) -> None:
        """Sets custom packet-per-second rate and burst for an IP or client."""
        self.custom_limits[identifier] = (pps_rate, pps_burst)

    def check_rate_limit(
        self,
        identifier: str,
        packet_bytes: int = 1,
        now: Optional[float] = None,
    ) -> Tuple[bool, str]:
        """
        Evaluates whether an packet conforms to rate limits.

        Returns:
            Tuple of (is_allowed, reason)
        """
        self.total_rate_checks += 1
        ts = now or time.time()

        # 1. Packet rate check
        if identifier not in self._packet_buckets:
            rate, burst = self.custom_limits.get(identifier, (self.default_pps_limit, self.default_pps_burst))
            self._packet_buckets[identifier] = TokenBucket(
                rate=rate,
                capacity=burst,
                tokens=burst,
                last_updated=ts,
            )

        pkt_bucket = self._packet_buckets[identifier]
        if not pkt_bucket.consume(1.0, ts):
            self.total_rate_violations += 1
            return False, f"Packet rate limit exceeded ({pkt_bucket.rate:.0f} pps)"

        # 2. Byte rate check
        if identifier not in self._byte_buckets:
            self._byte_buckets[identifier] = TokenBucket(
                rate=self.default_bps_limit,
                capacity=self.default_bps_burst,
                tokens=self.default_bps_burst,
                last_updated=ts,
            )

        byte_bucket = self._byte_buckets[identifier]
        if not byte_bucket.consume(float(packet_bytes), ts):
            self.total_rate_violations += 1
            return False, f"Bandwidth rate limit exceeded ({byte_bucket.rate / 1_000_000:.1f} MB/s)"

        return True, "Rate limit satisfied"

    def clean_idle(self, max_idle_seconds: float = 300.0, now: Optional[float] = None) -> int:
        """Removes idle rate limit buckets to free memory."""
        ts = now or time.time()
        idle_keys = [k for k, b in self._packet_buckets.items() if ts - b.last_updated > max_idle_seconds]
        for k in idle_keys:
            del self._packet_buckets[k]
            if k in self._byte_buckets:
                del self._byte_buckets[k]
        return len(idle_keys)

