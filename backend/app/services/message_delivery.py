"""GhostSim message delivery queue and worker lease management."""

from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.db import engine

logger = logging.getLogger(__name__)

MAX_BATCH_SIZE = 100
MAX_ATTEMPTS = 12
DEFAULT_LEASE_SECONDS = 60
MAX_LEASE_SECONDS = 300
MAX_ERROR_CODE_LENGTH = 100

_WORKER_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.:@-]{1,128}$")
_ERROR_CODE_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,100}$")


class MessageDeliveryError(Exception):
    """Base exception for delivery queue operations."""


class MessageDeliveryInputError(MessageDeliveryError):
    """Raised when delivery worker input is invalid."""


class MessageDeliveryNotFoundError(MessageDeliveryError):
    """Raised when a delivery does not exist or is not owned by the worker."""


class MessageDeliveryStorageError(MessageDeliveryError):
    """Raised when the delivery database operation fails."""


@dataclass(frozen=True)
class ClaimedDelivery:
    delivery_id: uuid.UUID
    message_id: uuid.UUID
    recipient_user_id: uuid.UUID
    recipient_device_id: uuid.UUID
    attempt_count: int
    lease_expires_at: datetime


@dataclass(frozen=True)
class DeliveryResult:
    delivery_id: uuid.UUID
    status: str
    attempt_count: int
    next_attempt_at: datetime | None = None


def _validate_worker_id(worker_id: str) -> str:
    if not isinstance(worker_id, str):
        raise MessageDeliveryInputError("worker_id must be a string.")

    worker_id = worker_id.strip()

    if not _WORKER_ID_PATTERN.fullmatch(worker_id):
        raise MessageDeliveryInputError(
            "worker_id must contain 1-128 permitted characters."
        )

    return worker_id


def _validate_uuid(value: uuid.UUID | str, field_name: str) -> uuid.UUID:
    try:
        return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))
    except (ValueError, TypeError, AttributeError) as exc:
        raise MessageDeliveryInputError(
            f"{field_name} must be a valid UUID."
        ) from exc


def _validate_lease_seconds(lease_seconds: int) -> int:
    if isinstance(lease_seconds, bool) or not isinstance(lease_seconds, int):
        raise MessageDeliveryInputError("lease_seconds must be an integer.")

    if not 5 <= lease_seconds <= MAX_LEASE_SECONDS:
        raise MessageDeliveryInputError(
            f"lease_seconds must be between 5 and {MAX_LEASE_SECONDS}."
        )

    return lease_seconds


def _validate_batch_size(batch_size: int) -> int:
    if isinstance(batch_size, bool) or not isinstance(batch_size, int):
        raise MessageDeliveryInputError("batch_size must be an integer.")

    if not 1 <= batch_size <= MAX_BATCH_SIZE:
        raise MessageDeliveryInputError(
            f"batch_size must be between 1 and {MAX_BATCH_SIZE}."
        )

    return batch_size


def _validate_error_code(error_code: str) -> str:
    if not isinstance(error_code, str):
        raise MessageDeliveryInputError("error_code must be a string.")

    error_code = error_code.strip()

    if not _ERROR_CODE_PATTERN.fullmatch(error_code):
        raise MessageDeliveryInputError(
            "error_code contains invalid characters or exceeds 100 characters."
        )

    return error_code


def _delivery_from_row(row: Any) -> ClaimedDelivery:
    return ClaimedDelivery(
        delivery_id=uuid.UUID(str(row["delivery_id"])),
        message_id=uuid.UUID(str(row["message_id"])),
        recipient_user_id=uuid.UUID(str(row["recipient_user_id"])),
        recipient_device_id=uuid.UUID(str(row["recipient_device_id"])),
        attempt_count=int(row["attempt_count"]),
        lease_expires_at=row["lease_expires_at"],
    )


async def claim_queued_deliveries(
    worker_id: str,
    *,
    batch_size: int = 25,
    lease_seconds: int = DEFAULT_LEASE_SECONDS,
) -> list[ClaimedDelivery]:
    """Claim due deliveries using PostgreSQL row locks and expiring leases.

    Claims remain in their existing queued/failed state. The worker must
    send the ciphertext through an authenticated transport and report the
    actual result using the functions below.

    A delivery is not returned when its recipient account or device is
    inactive, or when the recipient device is not authorized.
    """

    worker_id = _validate_worker_id(worker_id)
    batch_size = _validate_batch_size(batch_size)
    lease_seconds = _validate_lease_seconds(lease_seconds)

    try:
        async with engine.begin() as connection:
            result = await connection.execute(
                text(
                    """
                    WITH candidates AS (
                        SELECT d.id
                        FROM message_deliveries AS d
                        JOIN users AS u
                          ON u.id = d.recipient_user_id
                         AND u.status = 'active'
                        JOIN devices AS device
                          ON device.id = d.recipient_device_id
                         AND device.user_id = d.recipient_user_id
                         AND device.status = 'active'
                        JOIN messages AS m
                          ON m.id = d.message_id
                         AND m.sender_user_id IS NOT NULL
                        JOIN conversation_participants AS cp
                          ON cp.conversation_id = m.conversation_id
                         AND cp.user_id = d.recipient_user_id
                        WHERE d.status IN ('queued', 'failed')
                          AND (
                              d.next_attempt_at IS NULL
                              OR d.next_attempt_at <= NOW()
                          )
                          AND (
                              d.lease_expires_at IS NULL
                              OR d.lease_expires_at <= NOW()
                          )
                          AND d.attempt_count < :max_attempts
                        ORDER BY
                            COALESCE(d.next_attempt_at, d.queued_at),
                            d.queued_at,
                            d.id
                        FOR UPDATE OF d SKIP LOCKED
                        LIMIT :batch_size
                    )
                    UPDATE message_deliveries AS d
                    SET claimed_at = NOW(),
                        lease_expires_at =
                            NOW() + (:lease_seconds * INTERVAL '1 second'),
                        worker_id = :worker_id
                    FROM candidates AS c
                    WHERE d.id = c.id
                    RETURNING
                        d.id AS delivery_id,
                        d.message_id,
                        d.recipient_user_id,
                        d.recipient_device_id,
                        d.attempt_count,
                        d.lease_expires_at
                    """
                ),
                {
                    "max_attempts": MAX_ATTEMPTS,
                    "batch_size": batch_size,
                    "lease_seconds": lease_seconds,
                    "worker_id": worker_id,
                },
            )

            rows = result.mappings().all()
            return [_delivery_from_row(row) for row in rows]

    except SQLAlchemyError as exc:
        logger.exception("Unable to claim GhostSim message deliveries.")
        raise MessageDeliveryStorageError(
            "Unable to claim message deliveries."
        ) from exc


async def renew_delivery_lease(
    delivery_id: uuid.UUID | str,
    worker_id: str,
    *,
    lease_seconds: int = DEFAULT_LEASE_SECONDS,
) -> datetime:
    """Extend a lease that is still valid and owned by this worker."""

    delivery_id = _validate_uuid(delivery_id, "delivery_id")
    worker_id = _validate_worker_id(worker_id)
    lease_seconds = _validate_lease_seconds(lease_seconds)

    try:
        async with engine.begin() as connection:
            result = await connection.execute(
                text(
                    """
                    UPDATE message_deliveries
                    SET lease_expires_at =
                        NOW() + (:lease_seconds * INTERVAL '1 second')
                    WHERE id = :delivery_id
                      AND worker_id = :worker_id
                      AND lease_expires_at > NOW()
                      AND status IN ('queued', 'failed')
                    RETURNING lease_expires_at
                    """
                ),
                {
                    "delivery_id": delivery_id,
                    "worker_id": worker_id,
                    "lease_seconds": lease_seconds,
                },
            )

            row = result.mappings().first()

            if row is None:
                raise MessageDeliveryNotFoundError(
                    "Delivery lease is missing, expired, or owned by another worker."
                )

            return row["lease_expires_at"]

    except MessageDeliveryNotFoundError:
        raise
    except SQLAlchemyError as exc:
        logger.exception("Unable to renew GhostSim delivery lease.")
        raise MessageDeliveryStorageError(
            "Unable to renew the delivery lease."
        ) from exc


async def mark_delivery_sent(
    delivery_id: uuid.UUID | str,
    worker_id: str,
) -> DeliveryResult:
    """Record that the transport acknowledged sending the message.

    The transport must call this only after it has actually accepted the
    delivery. This does not mean the recipient has received or read it.
    """

    delivery_id = _validate_uuid(delivery_id, "delivery_id")
    worker_id = _validate_worker_id(worker_id)

    try:
        async with engine.begin() as connection:
            result = await connection.execute(
                text(
                    """
                    UPDATE message_deliveries
                    SET status = 'sent',
                        worker_id = NULL,
                        claimed_at = NULL,
                        lease_expires_at = NULL,
                        next_attempt_at = NULL,
                        last_error_code = NULL
                    WHERE id = :delivery_id
                      AND worker_id = :worker_id
                      AND lease_expires_at > NOW()
                      AND status IN ('queued', 'failed')
                    RETURNING id, status, attempt_count
                    """
                ),
                {
                    "delivery_id": delivery_id,
                    "worker_id": worker_id,
                },
            )

            row = result.mappings().first()

            if row is None:
                raise MessageDeliveryNotFoundError(
                    "Delivery lease is missing, expired, or owned by another worker."
                )

            return DeliveryResult(
                delivery_id=uuid.UUID(str(row["id"])),
                status=row["status"],
                attempt_count=int(row["attempt_count"]),
            )

    except MessageDeliveryNotFoundError:
        raise
    except SQLAlchemyError as exc:
        logger.exception("Unable to mark GhostSim delivery as sent.")
        raise MessageDeliveryStorageError(
            "Unable to record the sent status."
        ) from exc


async def mark_delivery_delivered(
    delivery_id: uuid.UUID | str,
    worker_id: str,
) -> DeliveryResult:
    """Record a recipient-device delivery acknowledgement.

    Call this only when the authenticated transport has verified an
    acknowledgement from the intended recipient device.
    """

    delivery_id = _validate_uuid(delivery_id, "delivery_id")
    worker_id = _validate_worker_id(worker_id)

    try:
        async with engine.begin() as connection:
            result = await connection.execute(
                text(
                    """
                    UPDATE message_deliveries
                    SET status = 'delivered',
                        delivered_at = COALESCE(delivered_at, NOW()),
                        worker_id = NULL,
                        claimed_at = NULL,
                        lease_expires_at = NULL,
                        next_attempt_at = NULL,
                        last_error_code = NULL
                    WHERE id = :delivery_id
                      AND worker_id = :worker_id
                      AND lease_expires_at > NOW()
                      AND status IN ('queued', 'failed', 'sent')
                    RETURNING id, status, attempt_count
                    """
                ),
                {
                    "delivery_id": delivery_id,
                    "worker_id": worker_id,
                },
            )

            row = result.mappings().first()

            if row is None:
                raise MessageDeliveryNotFoundError(
                    "Delivery lease is missing, expired, or owned by another worker."
                )

            return DeliveryResult(
                delivery_id=uuid.UUID(str(row["id"])),
                status=row["status"],
                attempt_count=int(row["attempt_count"]),
            )

    except MessageDeliveryNotFoundError:
        raise
    except SQLAlchemyError as exc:
        logger.exception("Unable to mark GhostSim delivery as delivered.")
        raise MessageDeliveryStorageError(
            "Unable to record the delivered status."
        ) from exc


async def record_delivery_failure(
    delivery_id: uuid.UUID | str,
    worker_id: str,
    error_code: str,
) -> DeliveryResult:
    """Release a claimed delivery and schedule bounded exponential backoff.

    Once the retry limit is reached, the delivery becomes failed and is
    no longer eligible for automatic claiming by this service.
    """

    delivery_id = _validate_uuid(delivery_id, "delivery_id")
    worker_id = _validate_worker_id(worker_id)
    error_code = _validate_error_code(error_code)

    try:
        async with engine.begin() as connection:
            result = await connection.execute(
                text(
                    """
                    UPDATE message_deliveries
                    SET attempt_count = attempt_count + 1,
                        status = CASE
                            WHEN attempt_count + 1 >= :max_attempts
                                THEN 'failed'
                            ELSE 'queued'
                        END,
                        next_attempt_at = CASE
                            WHEN attempt_count + 1 >= :max_attempts
                                THEN NULL
                            ELSE NOW() + (
                                LEAST(
                                    :max_backoff_seconds,
                                    :base_backoff_seconds
                                    * POWER(
                                        2,
                                        LEAST(attempt_count, 10)
                                    )
                                ) * INTERVAL '1 second'
                            )
                        END,
                        last_error_code = :error_code,
                        worker_id = NULL,
                        claimed_at = NULL,
                        lease_expires_at = NULL
                    WHERE id = :delivery_id
                      AND worker_id = :worker_id
                      AND lease_expires_at > NOW()
                      AND status IN ('queued', 'failed')
                    RETURNING
                        id,
                        status,
                        attempt_count,
                        next_attempt_at
                    """
                ),
                {
                    "delivery_id": delivery_id,
                    "worker_id": worker_id,
                    "error_code": error_code,
                    "max_attempts": MAX_ATTEMPTS,
                    "base_backoff_seconds": 2,
                    "max_backoff_seconds": 3600,
                },
            )

            row = result.mappings().first()

            if row is None:
                raise MessageDeliveryNotFoundError(
                    "Delivery lease is missing, expired, or owned by another worker."
                )

            return DeliveryResult(
                delivery_id=uuid.UUID(str(row["id"])),
                status=row["status"],
                attempt_count=int(row["attempt_count"]),
                next_attempt_at=row["next_attempt_at"],
            )

    except MessageDeliveryNotFoundError:
        raise
    except SQLAlchemyError as exc:
        logger.exception("Unable to record GhostSim delivery failure.")
        raise MessageDeliveryStorageError(
            "Unable to record the delivery failure."
        ) from exc


async def release_delivery_lease(
    delivery_id: uuid.UUID | str,
    worker_id: str,
) -> bool:
    """Release a lease without changing delivery status or retry count.

    Use when a worker must stop processing before attempting transport.
    """

    delivery_id = _validate_uuid(delivery_id, "delivery_id")
    worker_id = _validate_worker_id(worker_id)

    try:
        async with engine.begin() as connection:
            result = await connection.execute(
                text(
                    """
                    UPDATE message_deliveries
                    SET worker_id = NULL,
                        claimed_at = NULL,
                        lease_expires_at = NULL
                    WHERE id = :delivery_id
                      AND worker_id = :worker_id
                      AND status IN ('queued', 'failed')
                    RETURNING id
                    """
                ),
                {
                    "delivery_id": delivery_id,
                    "worker_id": worker_id,
                },
            )

            return result.scalar_one_or_none() is not None

    except SQLAlchemyError as exc:
        logger.exception("Unable to release GhostSim delivery lease.")
        raise MessageDeliveryStorageError(
            "Unable to release the delivery lease."
        ) from exc
