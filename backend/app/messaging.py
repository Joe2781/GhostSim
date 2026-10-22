"""GhostSim messaging service.

Provides:
- Direct GhostSim-to-GhostSim conversations.
- Encrypted-payload message storage.
- Idempotent message submission.
- Per-device delivery queues.
- Authorized conversation history retrieval.

Security:
- The caller must supply an authenticated account UUID.
- Sender devices must be active and owned by the sender.
- Message content is expected to be encrypted by the client.
- This service does not implement encryption or manage private keys.
- Messages are never treated as successfully delivered merely
  because they were accepted by the server.
"""

from __future__ import annotations

import logging
import re
import uuid

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.db import get_session_factory


logger = logging.getLogger("ghostsim.messaging")


MessageType = Literal[
    "text",
    "image",
    "voice",
    "video",
    "file",
]

MAX_CIPHERTEXT_LENGTH = 1_000_000
MAX_NONCE_LENGTH = 4096
MAX_ENCRYPTED_METADATA_LENGTH = 16_384
MAX_IDEMPOTENCY_KEY_LENGTH = 200
MIN_IDEMPOTENCY_KEY_LENGTH = 16
MAX_PAGE_SIZE = 100

_ALLOWED_MESSAGE_TYPES = frozenset(
    {"text", "image", "voice", "video", "file"}
)

_GHOSTSIM_ID_PATTERN = re.compile(
    r"^[A-Z]{2}[-·][A-Z0-9]{6}$"
)


class MessagingError(Exception):
    """Base exception for messaging operations."""


class MessagingValidationError(MessagingError):
    """A message or conversation input is invalid."""


class MessagingAccountError(MessagingError):
    """An account does not exist or cannot use messaging."""


class MessagingDeviceError(MessagingError):
    """The sender device is not authorized for messaging."""


class ConversationNotFoundError(MessagingError):
    """The conversation does not exist or is not accessible."""


class RecipientNotFoundError(MessagingError):
    """The destination GhostSim identity was not found."""


class MessageNotFoundError(MessagingError):
    """A requested message does not exist."""


class MessagingStorageError(MessagingError):
    """A messaging database operation failed."""


@dataclass(frozen=True, slots=True)
class DirectConversation:
    conversation_id: uuid.UUID
    created_at: datetime
    updated_at: datetime
    recipient_user_id: uuid.UUID


@dataclass(frozen=True, slots=True)
class StoredMessage:
    message_id: uuid.UUID
    conversation_id: uuid.UUID
    sender_user_id: uuid.UUID
    sender_device_id: uuid.UUID
    message_type: str
    ciphertext: str
    encryption_version: int
    encryption_nonce: str | None
    encrypted_metadata: str | None
    created_at: datetime
    duplicate_request: bool = False


@dataclass(frozen=True, slots=True)
class MessageHistoryItem:
    message_id: uuid.UUID
    conversation_id: uuid.UUID
    sender_user_id: uuid.UUID
    sender_device_id: uuid.UUID | None
    message_type: str
    ciphertext: str
    encryption_version: int
    encryption_nonce: str | None
    encrypted_metadata: str | None
    created_at: datetime
    edited_at: datetime | None


def _validate_uuid(value: uuid.UUID, field: str) -> None:
    if not isinstance(value, uuid.UUID):
        raise MessagingValidationError(
            f"{field} must be a valid UUID."
        )


def _normalize_ghostsim_id(value: str) -> str:
    if not isinstance(value, str):
        raise MessagingValidationError(
            "GhostSim ID must be text."
        )

    normalized = value.strip().upper()

    if not _GHOSTSIM_ID_PATTERN.fullmatch(normalized):
        raise MessagingValidationError(
            "Enter a valid GhostSim ID, such as NG-7K2P9A."
        )

    # The public ID is represented internally using a hyphen.
    return normalized.replace("·", "-")


def _validate_ciphertext(value: str) -> str:
    if not isinstance(value, str):
        raise MessagingValidationError(
            "Message ciphertext must be text."
        )

    value = value.strip()

    if not value:
        raise MessagingValidationError(
            "Message ciphertext cannot be empty."
        )

    if len(value) > MAX_CIPHERTEXT_LENGTH:
        raise MessagingValidationError(
            "The encrypted message exceeds the maximum supported size."
        )

    return value


def _validate_message_type(value: str) -> MessageType:
    if (
        not isinstance(value, str)
        or value not in _ALLOWED_MESSAGE_TYPES
    ):
        raise MessagingValidationError(
            "The requested message type is not supported."
        )

    return value  # type: ignore[return-value]


def _validate_idempotency_key(value: str) -> str:
    if not isinstance(value, str):
        raise MessagingValidationError(
            "An idempotency key is required."
        )

    value = value.strip()

    if not (
        MIN_IDEMPOTENCY_KEY_LENGTH
        <= len(value)
        <= MAX_IDEMPOTENCY_KEY_LENGTH
    ):
        raise MessagingValidationError(
            "The idempotency key must contain between 16 and 200 characters."
        )

    if any(ord(character) < 33 or ord(character) > 126 for character in value):
        raise MessagingValidationError(
            "The idempotency key contains unsupported characters."
        )

    return value


def _validate_encryption_fields(
    *,
    encryption_version: int,
    encryption_nonce: str | None,
    encrypted_metadata: str | None,
) -> None:
    if (
        not isinstance(encryption_version, int)
        or isinstance(encryption_version, bool)
        or encryption_version < 1
        or encryption_version > 32767
    ):
        raise MessagingValidationError(
            "The encryption protocol version is invalid."
        )

    if encryption_nonce is not None:
        if (
            not isinstance(encryption_nonce, str)
            or not encryption_nonce
            or len(encryption_nonce) > MAX_NONCE_LENGTH
        ):
            raise MessagingValidationError(
                "The encryption nonce is invalid."
            )

    if encrypted_metadata is not None:
        if (
            not isinstance(encrypted_metadata, str)
            or len(encrypted_metadata) > MAX_ENCRYPTED_METADATA_LENGTH
        ):
            raise MessagingValidationError(
                "The encrypted metadata exceeds the maximum supported size."
            )


async def create_or_get_direct_conversation(
    *,
    sender_user_id: uuid.UUID,
    recipient_ghostsim_id: str,
) -> DirectConversation:
    """Create or retrieve a direct conversation using a public GhostSim ID.

    The public ID resolves to an internal account UUID. Public IDs
    are not used as conversation ownership keys.

    Repeated requests between the same two accounts return the
    same direct conversation.
    """
    _validate_uuid(sender_user_id, "sender_user_id")
    public_id = _normalize_ghostsim_id(recipient_ghostsim_id)

    country_code, suffix = public_id.split("-", 1)

    session_factory = get_session_factory()

    try:
        async with session_factory() as session:
            async with session.begin():
                sender_result = await session.execute(
                    text(
                        """
                        SELECT id
                        FROM users
                        WHERE id = :sender_id
                          AND status = 'active'
                        FOR SHARE
                        """
                    ),
                    {"sender_id": str(sender_user_id)},
                )

                if sender_result.scalar_one_or_none() is None:
                    raise MessagingAccountError(
                        "The sender account is not active."
                    )

                recipient_result = await session.execute(
                    text(
                        """
                        SELECT u.id
                        FROM ghostsim_ids AS gi
                        JOIN users AS u
                          ON u.id = gi.user_id
                        WHERE gi.country_code = :country_code
                          AND gi.suffix = :suffix
                          AND gi.status = 'assigned'
                          AND u.status = 'active'
                        """
                    ),
                    {
                        "country_code": country_code,
                        "suffix": suffix,
                    },
                )

                recipient_user_id = (
                    recipient_result.scalar_one_or_none()
                )

                if recipient_user_id is None:
                    raise RecipientNotFoundError(
                        "This GhostSim ID could not be found."
                    )

                if recipient_user_id == sender_user_id:
                    raise MessagingValidationError(
                        "You cannot start a direct conversation with yourself."
                    )

                first_id, second_id = sorted(
                    (
                        str(sender_user_id),
                        str(recipient_user_id),
                    )
                )

                direct_pair_key = f"{first_id}:{second_id}"

                conversation_result = await session.execute(
                    text(
                        """
                        INSERT INTO conversations (
                            conversation_type,
                            created_by,
                            direct_pair_key
                        )
                        VALUES (
                            'direct',
                            :created_by,
                            :direct_pair_key
                        )
                        ON CONFLICT (direct_pair_key)
                        DO UPDATE SET
                            updated_at = conversations.updated_at
                        RETURNING
                            id,
                            created_at,
                            updated_at
                        """
                    ),
                    {
                        "created_by": str(sender_user_id),
                        "direct_pair_key": direct_pair_key,
                    },
                )

                conversation = (
                    conversation_result.mappings().one()
                )

                await session.execute(
                    text(
                        """
                        INSERT INTO conversation_participants (
                            conversation_id,
                            user_id,
                            role
                        )
                        VALUES
                            (
                                :conversation_id,
                                :sender_id,
                                'member'
                            ),
                            (
                                :conversation_id,
                                :recipient_id,
                                'member'
                            )
                        ON CONFLICT (conversation_id, user_id)
                        DO NOTHING
                        """
                    ),
                    {
                        "conversation_id": str(conversation["id"]),
                        "sender_id": str(sender_user_id),
                        "recipient_id": str(recipient_user_id),
                    },
                )

                return DirectConversation(
                    conversation_id=conversation["id"],
                    created_at=conversation["created_at"],
                    updated_at=conversation["updated_at"],
                    recipient_user_id=recipient_user_id,
                )

    except MessagingError:
        raise

    except SQLAlchemyError as exc:
        logger.error(
            "Direct conversation operation failed (%s).",
            type(exc).__name__,
        )

        raise MessagingStorageError(
            "The conversation could not be opened right now."
        ) from exc


async def send_encrypted_message(
    *,
    sender_user_id: uuid.UUID,
    sender_device_id: uuid.UUID,
    conversation_id: uuid.UUID,
    idempotency_key: str,
    message_type: str,
    ciphertext: str,
    encryption_version: int = 1,
    encryption_nonce: str | None = None,
    encrypted_metadata: str | None = None,
) -> StoredMessage:
    """Persist an encrypted message and queue it for recipient devices.

    A retry with the same sender, device, and idempotency key returns
    the original message instead of creating a duplicate.

    Delivery records are created for currently active recipient
    devices. If the recipient has no active devices, the message
    remains stored, and a future delivery worker must handle offline
    recipients when their devices become available.
    """
    _validate_uuid(sender_user_id, "sender_user_id")
    _validate_uuid(sender_device_id, "sender_device_id")
    _validate_uuid(conversation_id, "conversation_id")

    normalized_key = _validate_idempotency_key(idempotency_key)
    normalized_type = _validate_message_type(message_type)
    normalized_ciphertext = _validate_ciphertext(ciphertext)

    _validate_encryption_fields(
        encryption_version=encryption_version,
        encryption_nonce=encryption_nonce,
        encrypted_metadata=encrypted_metadata,
    )

    session_factory = get_session_factory()

    try:
        async with session_factory() as session:
            async with session.begin():
                account_result = await session.execute(
                    text(
                        """
                        SELECT id
                        FROM users
                        WHERE id = :user_id
                          AND status = 'active'
                        FOR SHARE
                        """
                    ),
                    {"user_id": str(sender_user_id)},
                )

                if account_result.scalar_one_or_none() is None:
                    raise MessagingAccountError(
                        "The sender account is not active."
                    )

                device_result = await session.execute(
                    text(
                        """
                        SELECT id
                        FROM devices
                        WHERE id = :device_id
                          AND user_id = :user_id
                          AND status = 'active'
                        FOR SHARE
                        """
                    ),
                    {
                        "device_id": str(sender_device_id),
                        "user_id": str(sender_user_id),
                    },
                )

                if device_result.scalar_one_or_none() is None:
                    raise MessagingDeviceError(
                        "The sender device is not active or is not owned by this account."
                    )

                participant_result = await session.execute(
                    text(
                        """
                        SELECT 1
                        FROM conversation_participants
                        WHERE conversation_id = :conversation_id
                          AND user_id = :user_id
                          AND left_at IS NULL
                        FOR SHARE
                        """
                    ),
                    {
                        "conversation_id": str(conversation_id),
                        "user_id": str(sender_user_id),
                    },
                )

                if participant_result.scalar_one_or_none() is None:
                    raise ConversationNotFoundError(
                        "The conversation was not found or is not accessible."
                    )

                # Reserve the idempotency key before creating the message.
                # Concurrent retries with the same key serialize on the
                # database primary key.
                await session.execute(
                    text(
                        """
                        INSERT INTO message_idempotency (
                            sender_user_id,
                            sender_device_id,
                            idempotency_key
                        )
                        VALUES (
                            :sender_user_id,
                            :sender_device_id,
                            :idempotency_key
                        )
                        ON CONFLICT (
                            sender_user_id,
                            sender_device_id,
                            idempotency_key
                        )
                        DO NOTHING
                        """
                    ),
                    {
                        "sender_user_id": str(sender_user_id),
                        "sender_device_id": str(sender_device_id),
                        "idempotency_key": normalized_key,
                    },
                )

                idempotency_result = await session.execute(
                    text(
                        """
                        SELECT message_id
                        FROM message_idempotency
                        WHERE sender_user_id = :sender_user_id
                          AND sender_device_id = :sender_device_id
                          AND idempotency_key = :idempotency_key
                        FOR UPDATE
                        """
                    ),
                    {
                        "sender_user_id": str(sender_user_id),
                        "sender_device_id": str(sender_device_id),
                        "idempotency_key": normalized_key,
                    },
                )

                idempotency_row = (
                    idempotency_result.mappings().one()
                )

                existing_message_id = idempotency_row["message_id"]

                if existing_message_id is not None:
                    existing_result = await session.execute(
                        text(
                            """
                            SELECT
                                id,
                                conversation_id,
                                sender_user_id,
                                sender_device_id,
                                message_type,
                                ciphertext,
                                encryption_version,
                                encryption_nonce,
                                encrypted_metadata,
                                created_at
                            FROM messages
                            WHERE id = :message_id
                              AND sender_user_id = :sender_user_id
                            """
                        ),
                        {
                            "message_id": str(existing_message_id),
                            "sender_user_id": str(sender_user_id),
                        },
                    )

                    existing = (
                        existing_result.mappings().one_or_none()
                    )

                    if existing is None:
                        raise MessagingStorageError(
                            "The original message for this retry could not be retrieved."
                        )

                    # Reusing a key for different content must not
                    # silently report a successful new send.
                    if (
                        existing["conversation_id"] != conversation_id
                        or existing["message_type"] != normalized_type
                        or existing["ciphertext"] != normalized_ciphertext
                        or existing["encryption_version"] != encryption_version
                        or existing["encryption_nonce"] != encryption_nonce
                        or existing["encrypted_metadata"] != encrypted_metadata
                    ):
                        raise MessagingValidationError(
                            "This idempotency key was already used for a different message."
                        )

                    return StoredMessage(
                        message_id=existing["id"],
                        conversation_id=existing["conversation_id"],
                        sender_user_id=existing["sender_user_id"],
                        sender_device_id=existing["sender_device_id"],
                        message_type=existing["message_type"],
                        ciphertext=existing["ciphertext"],
                        encryption_version=existing["encryption_version"],
                        encryption_nonce=existing["encryption_nonce"],
                        encrypted_metadata=existing["encrypted_metadata"],
                        created_at=existing["created_at"],
                        duplicate_request=True,
                    )

                # Create the message only after authorization and
                # idempotency reservation have succeeded.
                message_result = await session.execute(
                    text(
                        """
                        INSERT INTO messages (
                            conversation_id,
                            sender_user_id,
                            sender_device_id,
                            message_type,
                            ciphertext,
                            encryption_version,
                            encryption_nonce,
                            encrypted_metadata
                        )
                        VALUES (
                            :conversation_id,
                            :sender_user_id,
                            :sender_device_id,
                            :message_type,
                            :ciphertext,
                            :encryption_version,
                            :encryption_nonce,
                            :encrypted_metadata
                        )
                        RETURNING
                            id,
                            conversation_id,
                            sender_user_id,
                            sender_device_id,
                            message_type,
                            ciphertext,
                            encryption_version,
                            encryption_nonce,
                            encrypted_metadata,
                            created_at
                        """
                    ),
                    {
                        "conversation_id": str(conversation_id),
                        "sender_user_id": str(sender_user_id),
                        "sender_device_id": str(sender_device_id),
                        "message_type": normalized_type,
                        "ciphertext": normalized_ciphertext,
                        "encryption_version": encryption_version,
                        "encryption_nonce": encryption_nonce,
                        "encrypted_metadata": encrypted_metadata,
                    },
                )

                message = message_result.mappings().one()

                # Queue delivery for every active device owned by
                # every other active participant.
                await session.execute(
                    text(
                        """
                        INSERT INTO message_deliveries (
                            message_id,
                            recipient_user_id,
                            recipient_device_id,
                            status,
                            queued_at,
                            next_attempt_at
                        )
                        SELECT
                            :message_id,
                            cp.user_id,
                            d.id,
                            'queued',
                            NOW(),
                            NOW()
                        FROM conversation_participants AS cp
                        JOIN users AS u
                          ON u.id = cp.user_id
                        JOIN devices AS d
                          ON d.user_id = cp.user_id
                        WHERE cp.conversation_id = :conversation_id
                          AND cp.left_at IS NULL
                          AND cp.user_id <> :sender_user_id
                          AND u.status = 'active'
                          AND d.status = 'active'
                        ON CONFLICT (
                            message_id,
                            recipient_device_id
                        )
                        DO NOTHING
                        """
                    ),
                    {
                        "message_id": str(message["id"]),
                        "conversation_id": str(conversation_id),
                        "sender_user_id": str(sender_user_id),
                    },
                )

                await session.execute(
                    text(
                        """
                        UPDATE message_idempotency
                        SET message_id = :message_id
                        WHERE sender_user_id = :sender_user_id
                          AND sender_device_id = :sender_device_id
                          AND idempotency_key = :idempotency_key
                        """
                    ),
                    {
                        "message_id": str(message["id"]),
                        "sender_user_id": str(sender_user_id),
                        "sender_device_id": str(sender_device_id),
                        "idempotency_key": normalized_key,
                    },
                )

                await session.execute(
                    text(
                        """
                        UPDATE conversations
                        SET updated_at = NOW()
                        WHERE id = :conversation_id
                        """
                    ),
                    {"conversation_id": str(conversation_id)},
                )

                return StoredMessage(
                    message_id=message["id"],
                    conversation_id=message["conversation_id"],
                    sender_user_id=message["sender_user_id"],
                    sender_device_id=message["sender_device_id"],
                    message_type=message["message_type"],
                    ciphertext=message["ciphertext"],
                    encryption_version=message["encryption_version"],
                    encryption_nonce=message["encryption_nonce"],
                    encrypted_metadata=message["encrypted_metadata"],
                    created_at=message["created_at"],
                )

    except MessagingError:
        raise

    except SQLAlchemyError as exc:
        logger.error(
            "Encrypted message submission failed (%s).",
            type(exc).__name__,
        )

        raise MessagingStorageError(
            "The message could not be saved right now. Please retry safely."
        ) from exc


async def get_conversation_messages(
    *,
    user_id: uuid.UUID,
    conversation_id: uuid.UUID,
    limit: int = 50,
    before_message_id: uuid.UUID | None = None,
) -> list[MessageHistoryItem]:
    """Retrieve a page of encrypted messages for a conversation.

    Only active participants can read history. Deleted messages
    are excluded. Pagination uses an existing message ID as a
    stable cursor and returns newest messages first.
    """
    _validate_uuid(user_id, "user_id")
    _validate_uuid(conversation_id, "conversation_id")

    if (
        not isinstance(limit, int)
        or isinstance(limit, bool)
        or limit < 1
        or limit > MAX_PAGE_SIZE
    ):
        raise MessagingValidationError(
            f"limit must be between 1 and {MAX_PAGE_SIZE}."
        )

    if before_message_id is not None:
        _validate_uuid(before_message_id, "before_message_id")

    session_factory = get_session_factory()

    try:
        async with session_factory() as session:
            access_result = await session.execute(
                text(
                    """
                    SELECT 1
                    FROM conversation_participants AS cp
                    JOIN users AS u
                      ON u.id = cp.user_id
                    WHERE cp.conversation_id = :conversation_id
                      AND cp.user_id = :user_id
                      AND cp.left_at IS NULL
                      AND u.status = 'active'
                    """
                ),
                {
                    "conversation_id": str(conversation_id),
                    "user_id": str(user_id),
                },
            )

            if access_result.scalar_one_or_none() is None:
                raise ConversationNotFoundError(
                    "The conversation was not found or is not accessible."
                )

            if before_message_id is not None:
                cursor_result = await session.execute(
                    text(
                        """
                        SELECT created_at
                        FROM messages
                        WHERE id = :message_id
                          AND conversation_id = :conversation_id
                          AND deleted_at IS NULL
                        """
                    ),
                    {
                        "message_id": str(before_message_id),
                        "conversation_id": str(conversation_id),
                    },
                )

                cursor_created_at = cursor_result.scalar_one_or_none()

                if cursor_created_at is None:
                    raise MessageNotFoundError(
                        "The pagination cursor was not found in this conversation."
                    )

                result = await session.execute(
                    text(
                        """
                        SELECT
                            id,
                            conversation_id,
                            sender_user_id,
                            sender_device_id,
                            message_type,
                            ciphertext,
                            encryption_version,
                            encryption_nonce,
                            encrypted_metadata,
                            created_at,
                            edited_at
                        FROM messages
                        WHERE conversation_id = :conversation_id
                          AND deleted_at IS NULL
                          AND (
                              created_at < :cursor_created_at
                              OR (
                                  created_at = :cursor_created_at
                                  AND id < :cursor_message_id
                              )
                          )
                        ORDER BY created_at DESC, id DESC
                        LIMIT :limit
                        """
                    ),
                    {
                        "conversation_id": str(conversation_id),
                        "cursor_created_at": cursor_created_at,
                        "cursor_message_id": str(before_message_id),
                        "limit": limit,
                    },
                )
            else:
                result = await session.execute(
                    text(
                        """
                        SELECT
                            id,
                            conversation_id,
                            sender_user_id,
                            sender_device_id,
                            message_type,
                            ciphertext,
                            encryption_version,
                            encryption_nonce,
                            encrypted_metadata,
                            created_at,
                            edited_at
                        FROM messages
                        WHERE conversation_id = :conversation_id
                          AND deleted_at IS NULL
                        ORDER BY created_at DESC, id DESC
                        LIMIT :limit
                        """
                    ),
                    {
                        "conversation_id": str(conversation_id),
                        "limit": limit,
                    },
                )

            rows = result.mappings().all()

            return [
                MessageHistoryItem(
                    message_id=row["id"],
                    conversation_id=row["conversation_id"],
                    sender_user_id=row["sender_user_id"],
                    sender_device_id=row["sender_device_id"],
                    message_type=row["message_type"],
                    ciphertext=row["ciphertext"],
                    encryption_version=row["encryption_version"],
                    encryption_nonce=row["encryption_nonce"],
                    encrypted_metadata=row["encrypted_metadata"],
                    created_at=row["created_at"],
                    edited_at=row["edited_at"],
                )
                for row in rows
            ]

    except MessagingError:
        raise

    except SQLAlchemyError as exc:
        logger.error(
            "Conversation history retrieval failed (%s).",
            type(exc).__name__,
        )

        raise MessagingStorageError(
            "Conversation history is temporarily unavailable."
        ) from exc
