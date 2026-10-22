"""GhostSim device API routes.

Provides authenticated endpoints for device registration,
listing, verification, activation, and revocation.

Account identity is derived from a valid server-side session.
Never trust a user_id supplied in the request body.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.db import get_session_factory
from app.services.device_registry import (
    DeviceAccountNotFoundError,
    DeviceAlreadyRevokedError,
    DeviceNotFoundError,
    DeviceRegistryError,
    DeviceValidationError,
    list_registered_devices,
    register_device,
    revoke_device,
)
from app.services.device_verification import (
    DeviceVerificationError,
    VerificationDeviceNotFoundError,
    VerificationInputError,
    VerificationStateError,
    VerificationStorageError,
    create_device_challenge,
    verify_and_activate_device,
)


logger = logging.getLogger("ghostsim.api.devices")

router = APIRouter(prefix="/api/v1/devices", tags=["devices"])

bearer_scheme = HTTPBearer(auto_error=False)

DevicePlatform = Literal[
    "android",
    "ios",
    "windows",
    "macos",
    "linux",
    "web",
]

RevocationReason = Literal[
    "owner_request",
    "suspected_compromise",
    "device_lost",
    "account_security",
    "administrative_action",
    "other",
]


class AuthenticatedAccount(BaseModel):
    """Identity resolved from a verified server-side session."""

    model_config = ConfigDict(frozen=True)

    user_id: uuid.UUID
    session_id: uuid.UUID


class DeviceRegistrationRequest(BaseModel):
    """Fields required to register a new device."""

    model_config = ConfigDict(extra="forbid")

    device_name: str = Field(min_length=1, max_length=100)
    platform: DevicePlatform
    public_key: str = Field(min_length=32, max_length=4096)


class DeviceResponse(BaseModel):
    """Public device information without key material."""

    device_id: uuid.UUID
    device_name: str
    platform: str
    status: str
    registered_at: datetime
    last_seen_at: datetime | None


class DeviceListResponse(BaseModel):
    devices: list[DeviceResponse]


class ChallengeResponse(BaseModel):
    """Short-lived proof-of-possession challenge."""

    challenge_id: uuid.UUID
    device_id: uuid.UUID
    challenge: str
    expires_at: datetime
    verification_method: str


class VerifyDeviceRequest(BaseModel):
    """Proof submitted by the device."""

    model_config = ConfigDict(extra="forbid")

    challenge: str = Field(min_length=1, max_length=256)
    signature: str = Field(min_length=1, max_length=256)


class VerifyDeviceResponse(BaseModel):
    challenge_id: uuid.UUID
    device_id: uuid.UUID
    outcome: str
    device_status: str
    attempts_remaining: int


class RevokeDeviceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason_code: RevocationReason = "owner_request"
    reason_details: str | None = Field(default=None, max_length=2000)


class RevokeDeviceResponse(BaseModel):
    device_id: uuid.UUID
    status: str
    revoked_at: datetime


async def get_authenticated_account(
    credentials: HTTPAuthorizationCredentials | None = Depends(
        bearer_scheme
    ),
) -> AuthenticatedAccount:
    """Resolve an active bearer token through its stored SHA-256 hash.

    This dependency expects high-entropy opaque bearer tokens created
    by the authentication service. It never stores or logs the raw
    token. The authentication service must generate such tokens using
    a cryptographically secure random generator.
    """
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication is required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials

    if not token or len(token) > 4096:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="The authentication token is invalid.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    session_factory = get_session_factory()

    try:
        async with session_factory() as session:
            result = await session.execute(
                text(
                    """
                    SELECT
                        auth_sessions.id AS session_id,
                        auth_sessions.user_id AS user_id
                    FROM auth_sessions
                    JOIN users
                      ON users.id = auth_sessions.user_id
                    WHERE auth_sessions.token_hash = :token_hash
                      AND auth_sessions.session_status = 'active'
                      AND auth_sessions.expires_at > NOW()
                      AND users.status = 'active'
                    LIMIT 1
                    """
                ),
                {"token_hash": token_hash},
            )

            row = result.mappings().one_or_none()

            if row is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="The session is invalid or has expired.",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            # Update activity without exposing the token or its hash.
            await session.execute(
                text(
                    """
                    UPDATE auth_sessions
                    SET last_used_at = NOW()
                    WHERE id = :session_id
                    """
                ),
                {"session_id": str(row["session_id"])},
            )
            await session.commit()

            return AuthenticatedAccount(
                user_id=row["user_id"],
                session_id=row["session_id"],
            )

    except HTTPException:
        raise

    except SQLAlchemyError as exc:
        logger.warning(
            "Session authentication failed (%s).",
            type(exc).__name__,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication is temporarily unavailable.",
        ) from exc


def _map_device(device) -> DeviceResponse:
    return DeviceResponse(
        device_id=device.device_id,
        device_name=device.device_name,
        platform=device.platform,
        status=device.status,
        registered_at=device.registered_at,
        last_seen_at=device.last_seen_at,
    )


def _raise_device_error(exc: Exception) -> None:
    """Translate service exceptions into safe HTTP responses."""
    if isinstance(
        exc,
        (DeviceNotFoundError, DeviceAccountNotFoundError,
         VerificationDeviceNotFoundError),
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="The requested device was not found.",
        ) from exc

    if isinstance(
        exc,
        (
            DeviceValidationError,
            VerificationInputError,
            VerificationStateError,
            DeviceAlreadyRevokedError,
        ),
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    if isinstance(
        exc,
        (VerificationStorageError, DeviceRegistryError),
    ):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The device operation is temporarily unavailable.",
        ) from exc

    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="The device operation could not be completed.",
    ) from exc


@router.post(
    "",
    response_model=DeviceResponse,
    status_code=status.HTTP_201_CREATED,
)
async def register_new_device(
    payload: DeviceRegistrationRequest,
    account: AuthenticatedAccount = Depends(get_authenticated_account),
) -> DeviceResponse:
    """Register a device in pending state.

    Registration does not activate the device or grant relay permission.
    """
    try:
        device = await register_device(
            user_id=account.user_id,
            device_name=payload.device_name,
            platform=payload.platform,
            public_key=payload.public_key,
        )
        return _map_device(device)

    except Exception as exc:
        _raise_device_error(exc)


@router.get("", response_model=DeviceListResponse)
async def get_devices(
    account: AuthenticatedAccount = Depends(get_authenticated_account),
) -> DeviceListResponse:
    """List non-revoked devices belonging to the authenticated account."""
    try:
        devices = await list_registered_devices(
            user_id=account.user_id,
            include_revoked=False,
        )
        return DeviceListResponse(
            devices=[_map_device(device) for device in devices]
        )

    except Exception as exc:
        _raise_device_error(exc)


@router.post(
    "/{device_id}/verification-challenge",
    response_model=ChallengeResponse,
)
async def request_verification_challenge(
    device_id: uuid.UUID,
    account: AuthenticatedAccount = Depends(get_authenticated_account),
) -> ChallengeResponse:
    """Create a short-lived challenge for a pending device."""
    try:
        challenge = await create_device_challenge(
            user_id=account.user_id,
            device_id=device_id,
        )

        return ChallengeResponse(
            challenge_id=challenge.challenge_id,
            device_id=challenge.device_id,
            challenge=challenge.challenge,
            expires_at=challenge.expires_at,
            verification_method=challenge.verification_method,
        )

    except Exception as exc:
        _raise_device_error(exc)


@router.post(
    "/{device_id}/verify/{challenge_id}",
    response_model=VerifyDeviceResponse,
)
async def verify_device(
    device_id: uuid.UUID,
    challenge_id: uuid.UUID,
    payload: VerifyDeviceRequest,
    account: AuthenticatedAccount = Depends(get_authenticated_account),
) -> VerifyDeviceResponse:
    """Verify a signature and activate the device on success."""
    try:
        result = await verify_and_activate_device(
            user_id=account.user_id,
            device_id=device_id,
            challenge_id=challenge_id,
            challenge=payload.challenge,
            signature=payload.signature,
        )

        return VerifyDeviceResponse(
            challenge_id=result.challenge_id,
            device_id=result.device_id,
            outcome=result.outcome,
            device_status=result.device_status,
            attempts_remaining=result.attempts_remaining,
        )

    except Exception as exc:
        _raise_device_error(exc)


@router.post(
    "/{device_id}/revoke",
    response_model=RevokeDeviceResponse,
)
async def revoke_registered_device(
    device_id: uuid.UUID,
    payload: RevokeDeviceRequest,
    account: AuthenticatedAccount = Depends(get_authenticated_account),
) -> RevokeDeviceResponse:
    """Revoke a device owned by the authenticated account."""
    try:
        result = await revoke_device(
            user_id=account.user_id,
            device_id=device_id,
            reason_code=payload.reason_code,
            reason_details=payload.reason_details,
        )

        return RevokeDeviceResponse(
            device_id=result.device_id,
            status=result.status,
            revoked_at=result.revoked_at,
        )

    except Exception as exc:
        _raise_device_error(exc)
