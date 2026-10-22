from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.db import get_session


logger = logging.getLogger("ghostsim.message_acknowledgements")


class MessageAcknowledgementError(Exception):
    """Base exception for message acknowledgement operations."""


class MessageAcknowledgementInputError(
    MessageAcknowledgementError
):
    """Raised when acknowledgement input is invalid."""


class MessageAcknowledgementNotFoundError(
    MessageAcknowledgementError
):
    """Raised when the delivery does not belong to the authenticated device."""


class MessageAcknowledgementStorageError(
    MessageAcknowledgementError
):
    """Raised when an acknowledgement cannot be persisted."""


class MessageAcknowledgementState(str, Enum):
    RECEIVED = "received"
    DELIVERED = "delivered"
    READ = "read"


@dataclass(frozen=True, slots=True)
class MessageAcknowledgementResult:
    delivery_id: UUID
    message_id: UUID
    recipient_user_id: UUID
    recipient_device_id: UUID
    state: MessageAcknowledgementState
    acknowledged_at: datetime
    changed: bool


async def acknowledge_message_delivery(
    *,
    authenticated_user_id: UUID,
    authenticated_device_id: UUID,
    delivery_id: UUID,
    message_id: UUID,
    state: MessageAcknowledgementState,
) -> MessageAcknowledgementResult:
    """
    Persist an acknowledgement for a message delivery owned by the caller.

    The authenticated identity and device must come from the server-side
    authentication context, never from untrusted client claims.

    Acknowledgements are monotonic: an earlier state cannot overwrite a later
    state. The client cannot acknowledge a delivery belonging to another
    account or device.
    """
    if not isinstance(state, MessageAcknowledgementState):
        raise MessageAcknowledgementInputError(
            "Invalid acknowledgement state"
        )

    if authenticated_user_id.int == 0 or authenticated_device_id.int == 0:
        raise MessageAcknowledgementInputError(
            "Authenticated user and device IDs are required"
        )

    if delivery_id.int == 0 or message_id.int == 0:
        raise MessageAcknowledgementInputError(
            "Delivery and message IDs are required"
        )

    # The delivery status vocabulary in the existing database starts with
    # queued/sent/delivered/read/failed/cancelled. "received" is represented
    # by the transport event and is not stored as a database status.
    target_status = {
        MessageAcknowledgementState.RECEIVED: "sent",
        MessageAcknowledgementState.DELIVERED: "delivered",
        MessageAcknowledgementState.READ: "read",
    }[state]

    try:
        async with get_session() as session:
            row_result = await session.execute(
                text(
                    """
                    SELECT
                        d.id AS delivery_id,
                        d.message_id,
                        d.recipient_user_id,
                        d.recipient_device_id,
                        d.status,
                        d.delivered_at,
                        d.read_at,
                        m.sender_user_id
                    FROM message_deliveries AS d
                    JOIN messages AS m
                      ON m.id = d.message_id
                    JOIN devices AS device
                      ON device.id = d.recipient_device_id
                     AND device.user_id = d.recipient_user_id
                    WHERE d.id = :delivery_id
                      AND d.message_id = :message_id
                      AND d.recipient_user_id = :user_id
                      AND d.recipient_device_id = :device_id
                      AND device.status = 'active'
                    FOR UPDATE OF d
                    """
                ),
                {
                    "delivery_id": delivery_id,
                    "message_id": message_id,
                    "user_id": authenticated_user_id,
                    "device_id": authenticated_device_id,
                },
            )

            row = row_result.mappings().first()

            if row is None:
                raise MessageAcknowledgementNotFoundError(
                    "Message delivery was not found for this device"
                )

            current_status = str(row["status"])

            if current_status in {"failed", "cancelled", "queued"}:
                raise MessageAcknowledgementInputError(
                    "This delivery cannot be acknowledged in its current state"
                )

            if current_status == "read":
                final_status = "read"
            elif target_status == "read":
                final_status = "read"
            elif current_status == "delivered":
                final_status = "delivered"
            else:
                final_status = target_status

            changed = final_status != current_status

            update_result = await session.execute(
                text(
                    """
                    UPDATE message_deliveries
                    SET
                        status = :status,
                        delivered_at = CASE
                            WHEN :status IN ('delivered', 'read')
                            THEN COALESCE(delivered_at, NOW())
                            ELSE delivered_at
                        END,
                        read_at = CASE
                            WHEN :status = 'read'
                            THEN COALESCE(read_at, NOW())
                            ELSE read_at
                        END
                    WHERE id = :delivery_id
                      AND message_id = :message_id
                      AND recipient_user_id = :user_id
                      AND recipient_device_id = :device_id
                    RETURNING
                        id,
                        message_id,
                        recipient_user_id,
                        recipient_device_id,
                        status,
                        COALESCE(read_at, delivered_at, NOW())
                            AS acknowledged_at
                    """
                ),
                {
                    "status": final_status,
                    "delivery_id": delivery_id,
                    "message_id": message_id,
                    "user_id": authenticated_user_id,
                    "device_id": authenticated_device_id,
                },
            )

            updated = update_result.mappings().first()

            if updated is None:
                raise MessageAcknowledgementStorageError(
                    "Acknowledgement update returned no delivery"
                )

            return MessageAcknowledgementResult(
                delivery_id=UUID(str(updated["id"])),
                message_id=UUID(str(updated["message_id"])),
                recipient_user_id=UUID(
                    str(updated["recipient_user_id"])
                ),
                recipient_device_id=UUID(
                    str(updated["recipient_device_id"])
                ),
                state=MessageAcknowledgementState(
                    "read"
                    if updated["status"] == "read"
                    else (
                        "delivered"
                        if updated["status"] == "delivered"
                        else "received"
                    )
                ),
                acknowledged_at=updated["acknowledged_at"],
                changed=changed,
            )

    except (
        MessageAcknowledgementInputError,
        MessageAcknowledgementNotFoundError,
        MessageAcknowledgementStorageError,
    ):
        raise

    except SQLAlchemyError as exc:
        logger.exception(
            "Failed to persist message acknowledgement",
            extra={
                "delivery_id": str(delivery_id),
                "device_id": str(authenticated_device_id),
            },
        )
        raise MessageAcknowledgementStorageError(
            "Unable to persist acknowledgement"
        ) from exc
