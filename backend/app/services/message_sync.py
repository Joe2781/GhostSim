from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.db import get_session


logger = logging.getLogger("ghostsim.message_sync")


class MessageSyncError(Exception):
    """Base exception for message synchronization failures."""


class MessageSyncInputError(MessageSyncError):
    """Raised when synchronization parameters are invalid."""


class MessageSyncStorageError(MessageSyncError):
    """Raised when messages cannot be retrieved."""


@dataclass(frozen=True, slots=True)
class SyncedMessage:
    delivery_id: UUID
    message_id: UUID
    conversation_id: UUID
    sender_user_id: UUID
    recipient_device_id: UUID
    ciphertext: str
    content_type: str
    message_created_at: datetime
    delivery_status: str


@dataclass(frozen=True, slots=True)
class MessageSyncResult:
    messages: list[SyncedMessage]
    has_more: bool
    next_cursor: UUID | None


async def sync_pending_messages(
    *,
    authenticated_user_id: UUID,
    authenticated_device_id: UUID,
    limit: int = 50,
    before_delivery_id: UUID | None = None,
) -> MessageSyncResult:
    """
    Retrieve persisted messages addressed to an authenticated device.

    This operation does not mark messages as delivered or read. The client
    must acknowledge receipt separately after it has successfully accepted
    the message.

    The cursor uses delivery IDs for stable pagination. Delivery records remain
    the source of truth for retrying messages after reconnects.
    """
    if authenticated_user_id.int == 0:
        raise MessageSyncInputError("Authenticated user ID is required")

    if authenticated_device_id.int == 0:
        raise MessageSyncInputError("Authenticated device ID is required")

    if not 1 <= limit <= 100:
        raise MessageSyncInputError("limit must be between 1 and 100")

    query = text(
        """
        SELECT
            d.id AS delivery_id,
            d.message_id,
            m.conversation_id,
            m.sender_user_id,
            d.recipient_device_id,
            m.ciphertext,
            COALESCE(m.content_type, 'encrypted') AS content_type,
            m.created_at AS message_created_at,
            d.status AS delivery_status
        FROM message_deliveries AS d
        JOIN messages AS m
          ON m.id = d.message_id
        JOIN devices AS device
          ON device.id = d.recipient_device_id
         AND device.user_id = d.recipient_user_id
        JOIN conversation_participants AS cp
          ON cp.conversation_id = m.conversation_id
         AND cp.user_id = :user_id
        WHERE d.recipient_user_id = :user_id
          AND d.recipient_device_id = :device_id
          AND device.status = 'active'
          AND d.status IN ('queued', 'sent', 'failed')
          AND (
              :before_delivery_id IS NULL
              OR d.id < :before_delivery_id
          )
        ORDER BY d.queued_at DESC, d.id DESC
        LIMIT :fetch_limit
        """
    )

    try:
        async with get_session() as session:
            result = await session.execute(
                query,
                {
                    "user_id": authenticated_user_id,
                    "device_id": authenticated_device_id,
                    "before_delivery_id": before_delivery_id,
                    "fetch_limit": limit + 1,
                },
            )

            rows = result.mappings().all()

    except SQLAlchemyError as exc:
        logger.exception(
            "Unable to synchronize pending messages",
            extra={
                "user_id": str(authenticated_user_id),
                "device_id": str(authenticated_device_id),
            },
        )
        raise MessageSyncStorageError(
            "Unable to retrieve pending messages"
        ) from exc

    has_more = len(rows) > limit
    page_rows = rows[:limit]

    messages = [
        SyncedMessage(
            delivery_id=UUID(str(row["delivery_id"])),
            message_id=UUID(str(row["message_id"])),
            conversation_id=UUID(str(row["conversation_id"])),
            sender_user_id=UUID(str(row["sender_user_id"])),
            recipient_device_id=UUID(str(row["recipient_device_id"])),
            ciphertext=row["ciphertext"],
            content_type=str(row["content_type"]),
            message_created_at=row["message_created_at"],
            delivery_status=str(row["delivery_status"]),
        )
        for row in page_rows
    ]

    next_cursor = (
        messages[-1].delivery_id
        if has_more and messages
        else None
    )

    return MessageSyncResult(
        messages=messages,
        has_more=has_more,
        next_cursor=next_cursor,
    )
