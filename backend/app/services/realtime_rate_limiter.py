from __future__ import annotations

import asyncio
import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from enum import Enum
from typing import Deque
from uuid import UUID


class RateLimitError(Exception):
    """Base exception for rate-limiting failures."""


class InvalidRateLimitConfigurationError(RateLimitError):
    """Raised when a rate limit is configured incorrectly."""


class RealtimeRateLimitExceeded(RateLimitError):
    """Raised when a caller exceeds an event rate limit."""

    def __init__(
        self,
        *,
        retry_after_seconds: float,
        scope: str,
    ) -> None:
        self.retry_after_seconds = max(0.0, retry_after_seconds)
        self.scope = scope
        super().__init__(
            f"Rate limit exceeded for {scope}; "
            f"retry after {self.retry_after_seconds:.2f} seconds"
        )


class RateLimitCategory(str, Enum):
    AUTHENTICATION = "authentication"
    HEARTBEAT = "heartbeat"
    MESSAGING = "messaging"
    MESSAGE_ACKNOWLEDGEMENT = "message_acknowledgement"
    CALL_SIGNALING = "call_signaling"
    GENERAL = "general"


@dataclass(frozen=True, slots=True)
class RateLimitPolicy:
    """Maximum number of events allowed within a rolling time window."""

    maximum_events: int
    window_seconds: float

    def __post_init__(self) -> None:
        if self.maximum_events < 1:
            raise InvalidRateLimitConfigurationError(
                "maximum_events must be at least 1"
            )

        if (
            not math.isfinite(self.window_seconds)
            or self.window_seconds <= 0
        ):
            raise InvalidRateLimitConfigurationError(
                "window_seconds must be finite and greater than zero"
            )


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    allowed: bool
    remaining: int
    retry_after_seconds: float
    limit: int
    window_seconds: float


@dataclass(slots=True)
class _Bucket:
    timestamps: Deque[float]
    last_seen_at: float


DEFAULT_POLICIES: dict[RateLimitCategory, RateLimitPolicy] = {
    RateLimitCategory.AUTHENTICATION: RateLimitPolicy(5, 60),
    RateLimitCategory.HEARTBEAT: RateLimitPolicy(30, 60),
    RateLimitCategory.MESSAGING: RateLimitPolicy(60, 60),
    RateLimitCategory.MESSAGE_ACKNOWLEDGEMENT: RateLimitPolicy(180, 60),
    RateLimitCategory.CALL_SIGNALING: RateLimitPolicy(120, 60),
    RateLimitCategory.GENERAL: RateLimitPolicy(120, 60),
}


class RealtimeRateLimiter:
    """
    In-process rolling-window rate limiter for authenticated devices.

    This implementation is suitable for a single backend process. In a
    multi-worker or multi-region deployment, use a shared atomic limiter,
    such as a Redis-backed implementation, so clients cannot bypass limits
    by reconnecting to another process.

    Callers must authenticate devices before using their device IDs as keys.
    """

    def __init__(
        self,
        policies: dict[RateLimitCategory, RateLimitPolicy] | None = None,
        *,
        idle_bucket_ttl_seconds: float = 600,
        maximum_buckets: int = 100_000,
    ) -> None:
        if (
            not math.isfinite(idle_bucket_ttl_seconds)
            or idle_bucket_ttl_seconds <= 0
        ):
            raise InvalidRateLimitConfigurationError(
                "idle_bucket_ttl_seconds must be greater than zero"
            )

        if maximum_buckets < 1:
            raise InvalidRateLimitConfigurationError(
                "maximum_buckets must be at least 1"
            )

        self._policies = dict(policies or DEFAULT_POLICIES)
        self._idle_bucket_ttl_seconds = idle_bucket_ttl_seconds
        self._maximum_buckets = maximum_buckets

        self._buckets: dict[
            tuple[UUID, RateLimitCategory],
            _Bucket,
        ] = {}

        self._lock = asyncio.Lock()

    async def check(
        self,
        device_id: UUID,
        category: RateLimitCategory,
        *,
        cost: int = 1,
    ) -> RateLimitDecision:
        """
        Check and consume rate-limit capacity atomically.

        `cost` allows callers to charge expensive operations more heavily
        than simple events. A rejected operation does not consume capacity.
        """
        if cost < 1:
            raise ValueError("cost must be at least 1")

        policy = self._policies.get(category)
        if policy is None:
            raise InvalidRateLimitConfigurationError(
                f"No rate-limit policy configured for {category.value}"
            )

        now = time.monotonic()
        key = (device_id, category)
        cutoff = now - policy.window_seconds

        async with self._lock:
            self._prune_bucket_timestamps(
                key=key,
                cutoff=cutoff,
            )

            bucket = self._buckets.get(key)

            if bucket is None:
                self._ensure_bucket_capacity(now)
                bucket = _Bucket(
                    timestamps=deque(),
                    last_seen_at=now,
                )
                self._buckets[key] = bucket

            bucket.last_seen_at = now

            used = len(bucket.timestamps)
            available = max(0, policy.maximum_events - used)

            if cost > available:
                if bucket.timestamps:
                    retry_after = max(
                        0.0,
                        bucket.timestamps[0]
                        + policy.window_seconds
                        - now,
                    )
                else:
                    retry_after = policy.window_seconds

                return RateLimitDecision(
                    allowed=False,
                    remaining=available,
                    retry_after_seconds=retry_after,
                    limit=policy.maximum_events,
                    window_seconds=policy.window_seconds,
                )

            for _ in range(cost):
                bucket.timestamps.append(now)

            return RateLimitDecision(
                allowed=True,
                remaining=max(
                    0,
                    policy.maximum_events - len(bucket.timestamps),
                ),
                retry_after_seconds=0.0,
                limit=policy.maximum_events,
                window_seconds=policy.window_seconds,
            )

    async def enforce(
        self,
        device_id: UUID,
        category: RateLimitCategory,
        *,
        cost: int = 1,
    ) -> RateLimitDecision:
        """Consume capacity or raise when the configured limit is exceeded."""
        decision = await self.check(
            device_id,
            category,
            cost=cost,
        )

        if not decision.allowed:
            raise RealtimeRateLimitExceeded(
                retry_after_seconds=decision.retry_after_seconds,
                scope=category.value,
            )

        return decision

    async def reset_device(self, device_id: UUID) -> int:
        """Clear in-process rate-limit state for a device."""
        async with self._lock:
            keys = [
                key
                for key in self._buckets
                if key[0] == device_id
            ]

            for key in keys:
                self._buckets.pop(key, None)

            return len(keys)

    async def cleanup(self) -> int:
        """Remove idle buckets and return the number removed."""
        now = time.monotonic()
        removed = 0

        async with self._lock:
            expired_keys = [
                key
                for key, bucket in self._buckets.items()
                if now - bucket.last_seen_at
                >= self._idle_bucket_ttl_seconds
            ]

            for key in expired_keys:
                self._buckets.pop(key, None)
                removed += 1

        return removed

    def _prune_bucket_timestamps(
        self,
        *,
        key: tuple[UUID, RateLimitCategory],
        cutoff: float,
    ) -> None:
        bucket = self._buckets.get(key)
        if bucket is None:
            return

        while bucket.timestamps and bucket.timestamps[0] <= cutoff:
            bucket.timestamps.popleft()

    def _ensure_bucket_capacity(self, now: float) -> None:
        """
        Bound memory usage by expiring idle buckets before rejecting new ones.

        This method is called while the limiter lock is held.
        """
        if len(self._buckets) < self._maximum_buckets:
            return

        expired_keys = [
            key
            for key, bucket in self._buckets.items()
            if now - bucket.last_seen_at
            >= self._idle_bucket_ttl_seconds
        ]

        for key in expired_keys:
            self._buckets.pop(key, None)

        if len(self._buckets) >= self._maximum_buckets:
            raise RateLimitError(
                "Rate limiter capacity reached; operation cannot be admitted"
            )


realtime_rate_limiter = RealtimeRateLimiter()
