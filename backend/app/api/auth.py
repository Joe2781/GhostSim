"""GhostSim authentication and account-session API."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.api.devices import (
    AuthenticatedAccount,
    get_authenticated_account,
)
from app.db import get_session_factory
from app.services.auth_sessions import (
    AuthenticationSessionError,
    AuthenticationSessionNotFoundError,
    AuthenticationSessionStorageError,
    SessionAccountNotFoundError,
    revoke_all_user_sessions,
    revoke_authentication_session,
)


logger = logging.getLogger("ghostsim.api.auth")

router = APIRouter(
    prefix="/api/v1/auth",
    tags=["authentication"],
)


class AccountProfileResponse(BaseModel):
    """Safe account information for the authenticated account."""

    model_config = ConfigDict(from_attributes=True)

    account_id: uuid.UUID
    identity_country: str
    account_status: str
    display_name: str | None
    preferred_language: str
    ghostsim_id: str | None
    created_at: datetime | None


class LogoutResponse(BaseModel):
    """Result of logging out the current session."""

    success: bool
    session_id: uuid.UUID
    status: str
    revoked_at: datetime


class RevokeOtherSessionsResponse(BaseModel):
    """Result of revoking other sessions."""

    success: bool
    revoked_sessions: int
    current_session_preserved: bool


def _raise_session_error(exc: Exception) -> None:
    """Convert authentication service errors into safe HTTP responses."""

    if isinstance(exc, AuthenticationSessionNotFoundError):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="The requested active session was not found.",
        ) from exc

    if isinstance(exc, SessionAccountNotFoundError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="The account is unavailable.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    if isinstance(exc, AuthenticationSessionStorageError):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The session operation is temporarily unavailable.",
        ) from exc

    if isinstance(exc, AuthenticationSessionError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The session operation could not be completed.",
        ) from exc

    logger.error(
        "Unexpected authentication service error (%s).",
        type(exc).__name__,
    )

    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
