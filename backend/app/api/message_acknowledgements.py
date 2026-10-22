from __future__ import annotations

import logging
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.exc import SQLAlchemyError

from app.api.devices import AuthenticatedAccount, get_authenticated_account
from app.services.message_acknowledgements import (
    MessageAcknowledgementInputError,
    MessageAcknowledgementNotFoundError,
    MessageAcknowledgementState,
    MessageAcknowledgementStorageError,
    acknowledge_message_delivery,
)


logger = logging.getLogger("ghostsim.api.message_acknowledgements")

router = APIRouter(
    prefix="/api/v1/messaging",
    tags=["message acknowledgements"],
)


class AcknowledgeMessageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    delivery_id: UUID
    message_id: UUID
    state: Literal["received", "delivered", "read"]


class AcknowledgeMessageResponse(BaseModel):
    delivery_id: UUID
    message_id: UUID
    state: Literal["received", "delivered", "read"]
    acknowledged_at: str
    changed: bool


@router.post(
    "/acknowledgements",
    response_model=AcknowledgeMessageResponse,
    status_code=status.HTTP_200_OK,
)
async def acknowledge_message(
    request: AcknowledgeMessageRequest,
    account: AuthenticatedAccount = Depends(get_authenticated_account),
) -> AcknowledgeMessageResponse:
    """
    Record a message acknowledgement for the authenticated account's device.

    The server derives the account and device identity from the authenticated
    session. Clients cannot provide another user's identity in the request.
    """
    # The current account dependency provides the authenticated user and
    # session. Resolve the device from that session rather than trusting a
    # device ID supplied in the request body.
    from sqlalchemy import text

    from app.db import get_session

    try:
        async with get_session() as session:
            result = await session.execute(
                text(
                    """
                    SELECT device_id
                    FROM auth_sessions
                    WHERE id = :session_id
                      AND user_id = :user_id
                      AND session_status = 'active'
                      AND expires_at > NOW()
                    LIMIT 1
                    """
                ),
                {
                    "session_id": account.session_id,
                    "user_id": account.user_id,
                },
            )
            row = result.mappings().first()

    except SQLAlchemyError:
        logger.exception(
            "Could not resolve the authenticated session device"
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Message acknowledgement is temporarily unavailable.",
        )

    if row is None or row["device_id"] is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This session is not bound to an active device.",
        )

    try:
        result = await acknowledge_message_delivery(
            authenticated_user_id=account.user_id,
            authenticated_device_id=UUID(str(row["device_id"])),
            delivery_id=request.delivery_id,
            message_id=request.message_id,
            state=MessageAcknowledgementState(request.state),
        )

    except MessageAcknowledgementNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Message delivery was not found.",
        )

    except MessageAcknowledgementInputError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        )

    except MessageAcknowledgementStorageError:
        logger.exception(
            "Failed to store message acknowledgement",
            extra={
                "user_id": str(account.user_id),
                "delivery_id": str(request.delivery_id),
            },
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to save message acknowledgement.",
        )

    return AcknowledgeMessageResponse(
        delivery_id=result.delivery_id,
        message_id=result.message_id,
        state=result.state.value,
        acknowledged_at=result.acknowledged_at.isoformat(),
        changed=result.changed,
    )
