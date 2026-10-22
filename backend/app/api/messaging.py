"""GhostSim messaging API.

All endpoints require a valid GhostSim bearer session.
Message bodies must already be encrypted by the client.
"""

from __future__ import annotations

import logging
import uuid

from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from app.api.devices import get_authenticated_account
from app.services.messaging import (
    ConversationNotFoundError,
    MessagingAccountError,
    MessagingDeviceError,
    MessagingError,
    MessagingStorageError,
    MessagingValidationError,
    MessageNotFoundError,
    RecipientNotFoundError,
    create_or_get_direct_conversation,
    get_conversation_messages,
    send_encrypted_message,
)


logger = logging.getLogger("ghostsim.api.messaging")

router = APIRouter(
    prefix="/api/v1/messaging",
    tags=["messaging"],
)

security = HTTPBearer(auto_error=False)


class OpenConversationRequest(BaseModel):
    recipient_ghostsim_id: str = Field(
        min_length=9,
        max_length=9,
        description="Recipient public ID, such as NG-7K2P9A.",
    )


class OpenConversationResponse(BaseModel):
    conversation_id: uuid.UUID
    recipient_user_id: uuid.UUID
    created_at: datetime
    updated_at: datetime


class SendMessageRequest(BaseModel):
    conversation_id: uuid.UUID
    sender_device_id: uuid.UUID
    idempotency_key: str = Field(
        min_length=16,
        max_length=200,
    )
    message_type: Literal["text", "image", "voice", "video", "file"]
    ciphertext: str = Field(
        min_length=1,
        max_length=1_000_000,
        description="Client-encrypted message payload.",
    )
    encryption_version: int = Field(default=1, ge=1, le=32767)
    encryption_nonce: str | None = Field(
        default=None,
        max_length=4096,
    )
    encrypted_metadata: str | None = Field(
        default=None,
        max_length=16_384,
    )


class SendMessageResponse(BaseModel):
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
    duplicate_request: bool


class MessageHistoryItemResponse(BaseModel):
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


def _raise_messaging_http_error(exc: Exception) -> None:
    """Map service exceptions to safe public HTTP responses."""

    if isinstance(exc, MessagingValidationError):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    if isinstance(exc, (MessagingAccountError, MessagingDeviceError)):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        ) from exc

    if isinstance(exc, RecipientNotFoundError):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="The recipient GhostSim ID could not be found.",
        ) from exc

    if isinstance(
        exc,
        (ConversationNotFoundError, MessageNotFoundError),
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc

    if isinstance(exc, MessagingStorageError):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The messaging service is temporarily unavailable.",
        ) from exc

    if isinstance(exc, MessagingError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The messaging request could not be completed.",
        ) from exc

    logger.exception("Unexpected messaging API error.")

    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="An unexpected messaging error occurred.",
    ) from exc


@router.post(
    "/conversations/direct",
    response_model=OpenConversationResponse,
    status_code=status.HTTP_200_OK,
)
async def open_direct_conversation(
    request: OpenConversationRequest,
    account=Depends(get_authenticated_account),
) -> OpenConversationResponse:
    """Open an existing direct conversation or create one."""

    try:
        conversation = await create_or_get_direct_conversation(
            sender_user_id=uuid.UUID(str(account.user_id)),
            recipient_ghostsim_id=request.recipient_ghostsim_id,
        )

        return OpenConversationResponse(
            conversation_id=conversation.conversation_id,
            recipient_user_id=conversation.recipient_user_id,
            created_at=conversation.created_at,
            updated_at=conversation.updated_at,
        )

    except Exception as exc:
        _raise_messaging_http_error(exc)


@router.post(
    "/messages",
    response_model=SendMessageResponse,
    status_code=status.HTTP_201_CREATED,
)
async def send_message(
    request: SendMessageRequest,
    account=Depends(get_authenticated_account),
) -> SendMessageResponse:
    """Store an encrypted message and queue recipient-device delivery."""

    try:
        message = await send_encrypted_message(
            sender_user_id=uuid.UUID(str(account.user_id)),
            sender_device_id=request.sender_device_id,
            conversation_id=request.conversation_id,
            idempotency_key=request.idempotency_key,
            message_type=request.message_type,
            ciphertext=request.ciphertext,
            encryption_version=request.encryption_version,
            encryption_nonce=request.encryption_nonce,
            encrypted_metadata=request.encrypted_metadata,
        )

        return SendMessageResponse(
            message_id=message.message_id,
            conversation_id=message.conversation_id,
            sender_user_id=message.sender_user_id,
            sender_device_id=message.sender_device_id,
            message_type=message.message_type,
            ciphertext=message.ciphertext,
            encryption_version=message.encryption_version,
            encryption_nonce=message.encryption_nonce,
            encrypted_metadata=message.encrypted_metadata,
            created_at=message.created_at,
            duplicate_request=message.duplicate_request,
        )

    except Exception as exc:
        _raise_messaging_http_error(exc)


@router.get(
    "/conversations/{conversation_id}/messages",
    response_model=list[MessageHistoryItemResponse],
)
async def list_conversation_messages(
    conversation_id: uuid.UUID,
    limit: int = Query(default=50, ge=1, le=100),
    before_message_id: uuid.UUID | None = Query(default=None),
    account=Depends(get_authenticated_account),
) -> list[MessageHistoryItemResponse]:
    """Retrieve a page of encrypted conversation history."""

    try:
        messages = await get_conversation_messages(
            user_id=uuid.UUID(str(account.user_id)),
            conversation_id=conversation_id,
            limit=limit,
            before_message_id=before_message_id,
        )

        return [
            MessageHistoryItemResponse(
                message_id=message.message_id,
                conversation_id=message.conversation_id,
                sender_user_id=message.sender_user_id,
                sender_device_id=message.sender_device_id,
                message_type=message.message_type,
                ciphertext=message.ciphertext,
                encryption_version=message.encryption_version,
                encryption_nonce=message.encryption_nonce,
                encrypted_metadata=message.encrypted_metadata,
                created_at=message.created_at,
                edited_at=message.edited_at,
            )
            for message in messages
        ]

    except Exception as exc:
        _raise_messaging_http_error(exc)
