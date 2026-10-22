"""GhostSim authentication session management.

Creates and revokes opaque bearer-token sessions after the caller
has independently verified the user's identity.

Security rules:

- Never store raw bearer tokens in PostgreSQL.
- Return a newly created token only once to the caller.
- Store only the SHA-256 hash of a high-entropy random token.
- Never log tokens, token hashes, passwords, or private keys.
- Session creation does not replace external identity verification.
  """

from future import annotations

import hashlib
import logging
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.db import get_session_factory

logger = logging.getLogger("ghostsim.auth.sessions")

DEFAULT_SESSION_LIFETIME = timedelta(days=30)
MAX_SESSION_LIFETIME = timedelta(days=90)
MIN_SESSION_LIFETIME = timedelta(minutes=5)

TOKEN_BYTES = 32
MAX_CLIENT_LABEL_LENGTH = 120

class AuthenticationSessionError(Exception):
"""Base exception for authentication session operations."""

class SessionAccountNotFoundError(AuthenticationSessionError):
"""Raised when the requested account does not exist or is inactive."""

class SessionDeviceError(AuthenticationSessionError):
"""Raised when a supplied device is not eligible for a session."""

class AuthenticationSessionNotFoundError(AuthenticationSessionError):
"""Raised when an active session cannot be found for the account."""

class AuthenticationSessionStorageError(AuthenticationSessionError):
"""Raised when session persistence fails."""

class AuthenticationSessionInputError(AuthenticationSessionError):
"""Raised when session creation input is invalid."""

@dataclass(frozen=True)
class CreatedAuthenticationSession:
"""A newly created session and its one-time bearer token."""

session_id: uuid.UUID
user_id: uuid.UUID
access_token: str
token_type: str
expires_at: datetime

@dataclass(frozen=True)
class RevokedAuthenticationSession:
"""Result of revoking an authentication session."""

session_id: uuid.UUID
revoked_at: datetime
status: str

def _validate_uuid(value: uuid.UUID, field_name: str) -> None:
if not isinstance(value, uuid.UUID):
raise AuthenticationSessionInputError(
f"{field_name} must be a valid UUID."
)

def _hash_token(token: str) -> str:
"""Hash an opaque, high-entropy bearer token for database storage."""

return hashlib.sha256(token.encode("utf-8")).hexdigest()

def _validate_lifetime(lifetime: timedelta) -> None:
if not isinstance(lifetime, timedelta):
raise AuthenticationSessionInputError(
"Session lifetime must be a timedelta."
)

if not (
    MIN_SESSION_LIFETIME
    <= lifetime
    <= MAX_SESSION_LIFETIME
):
    raise AuthenticationSessionInputError(
        "Session lifetime must be between 5 minutes and 90 days."
    )

async def create_authentication_session(
*,
user_id: uuid.UUID,
device_id: uuid.UUID | None = None,
client_label: str | None = None,
lifetime: timedelta = DEFAULT_SESSION_LIFETIME,
) -> CreatedAuthenticationSession:
"""Create a session for an already authenticated active account.

IMPORTANT:
The calling authentication flow must first verify credentials
through a trusted authentication provider or a completed
first-party authentication process.

This function does not verify passwords, email ownership, OAuth
tokens, or third-party identity-provider tokens.

If device_id is supplied, that device must already be active and
belong to the specified account. For a newly authenticated device
that has not yet been registered and activated, omit device_id.

The raw access token is returned only in this result. The database
receives its SHA-256 hash, never the original token.
"""

_validate_uuid(user_id, "user_id")
_validate_lifetime(lifetime)

if device_id is not None:
    _validate_uuid(device_id, "device_id")

if client_label is not None:
    if not isinstance(client_label, str):
        raise AuthenticationSessionInputError(
            "Client label must be text."
        )

    client_label = client_label.strip()

    if len(client_label) > MAX_CLIENT_LABEL_LENGTH:
        raise AuthenticationSessionInputError(
            "Client label cannot exceed 120 characters."
        )

    if not client_label:
        client_label = None

# Generate a high-entropy opaque token.
# It is never derived from the account ID or device ID.
access_token = secrets.token_urlsafe(TOKEN_BYTES)
token_hash = _hash_token(access_token)

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
                    FOR UPDATE
                    """
                ),
                {"user_id": str(user_id)},
            )

            if account_result.mappings().one_or_none() is None:
                raise SessionAccountNotFoundError(
                    "The account does not exist or is inactive."
                )

            if device_id is not None:
                device_result = await session.execute(
                    text(
                        """
                        SELECT id
                        FROM devices
                        WHERE id = :device_id
                          AND user_id = :user_id
                          AND status = 'active'
                        """
                    ),
                    {
                        "device_id": str(device_id),
                        "user_id": str(user_id),
                    },
                )

                if device_result.mappings().one_or_none() is None:
                    raise SessionDeviceError(
                        "The device is not active for this account."
                    )

            session_result = await session.execute(
                text(
                    """
                    INSERT INTO auth_sessions (
                        user_id,
                        device_id,
                        token_hash,
                        session_status,
                        expires_at,
                        client_label
                    )
                    VALUES (
                        :user_id,
                        :device_id,
                        :token_hash,
                        'active',
                        NOW() + (
                            :lifetime_seconds
                            * INTERVAL '1 second'
                        ),
                        :client_label
                    )
                    RETURNING id, created_at, expires_at
                    """
                ),
                {
                    "user_id": str(user_id),
                    "device_id": (
                        str(device_id)
                        if device_id is not None
                        else None
                    ),
                    "token_hash": token_hash,
                    "lifetime_seconds": int(
                        lifetime.total_seconds()
                    ),
                    "client_label": client_label,
                },
            )

            session_row = session_result.mappings().one()

            await session.execute(
                text(
                    """
                    INSERT INTO security_audit_events (
                        user_id,
                        device_id,
                        event_type,
                        outcome,
                        metadata
                    )
                    VALUES (
                        :user_id,
                        :device_id,
                        'login_succeeded',
                        'success',
                        CAST(:metadata AS JSONB)
                    )
                    """
                ),
                {
                    "user_id": str(user_id),
                    "device_id": (
                        str(device_id)
                        if device_id is not None
                        else None
                    ),
                    "metadata": (
                        '{"authentication":"verified",'
                        '"session_created":true}'
                    ),
                },
            )

            return CreatedAuthenticationSession(
                session_id=session_row["id"],
                user_id=user_id,
                access_token=access_token,
                token_type="Bearer",
                expires_at=session_row["expires_at"],
            )

except AuthenticationSessionError:
    raise

except SQLAlchemyError as exc:
    logger.warning(
        "Authentication session creation failed (%s).",
        type(exc).__name__,
    )
    raise AuthenticationSessionStorageError(
        "The authentication session could not be created."
    ) from exc

async def revoke_authentication_session(
*,
user_id: uuid.UUID,
session_id: uuid.UUID,
) -> RevokedAuthenticationSession:
"""Revoke one active session belonging to the specified account.

The raw bearer token is not needed to revoke a session when the
caller has already authenticated the account and authorized this
session-specific operation.
"""

_validate_uuid(user_id, "user_id")
_validate_uuid(session_id, "session_id")

session_factory = get_session_factory()

try:
    async with session_factory() as session:
        async with session.begin():
            result = await session.execute(
                text(
                    """
                    UPDATE auth_sessions
                    SET
                        session_status = 'revoked',
                        revoked_at = NOW()
                    WHERE id = :session_id
                      AND user_id = :user_id
                      AND session_status = 'active'
                      AND expires_at > NOW()
                    RETURNING id, device_id, revoked_at
                    """
                ),
                {
                    "session_id": str(session_id),
                    "user_id": str(user_id),
                },
            )

            row = result.mappings().one_or_none()

            if row is None:
                raise AuthenticationSessionNotFoundError(
                    "No active session was found for this account."
                )

            await session.execute(
                text(
                    """
                    INSERT INTO security_audit_events (
                        user_id,
                        device_id,
                        event_type,
                        outcome,
                        metadata
                    )
                    VALUES (
                        :user_id,
                        :device_id,
                        'session_revoked',
                        'success',
                        CAST(:metadata AS JSONB)
                    )
                    """
                ),
                {
                    "user_id": str(user_id),
                    "device_id": (
                        str(row["device_id"])
                        if row["device_id"] is not None
                        else None
                    ),
                    "metadata": (
                        '{"reason":"authorized_session_revocation"}'
                    ),
                },
            )

            return RevokedAuthenticationSession(
                session_id=row["id"],
                revoked_at=row["revoked_at"],
                status="revoked",
            )

except AuthenticationSessionError:
    raise

except SQLAlchemyError as exc:
    logger.warning(
        "Authentication session revocation failed (%s).",
        type(exc).__name__,
    )
    raise AuthenticationSessionStorageError(
        "The authentication session could not be revoked."
    ) from exc

async def revoke_all_user_sessions(
*,
user_id: uuid.UUID,
except_session_id: uuid.UUID | None = None,
) -> int:
"""Revoke all active sessions for an account, optionally preserving
the current session.

Intended for security-sensitive workflows such as password
changes, account recovery, or suspected account compromise.
"""

_validate_uuid(user_id, "user_id")

if except_session_id is not None:
    _validate_uuid(except_session_id, "except_session_id")

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
                    FOR UPDATE
                    """
                ),
                {"user_id": str(user_id)},
            )

            if account_result.mappings().one_or_none() is None:
                raise SessionAccountNotFoundError(
                    "The account does not exist."
                )

            result = await session.execute(
                text(
                    """
                    UPDATE auth_sessions
                    SET
                        session_status = 'revoked',
                        revoked_at = NOW()
                    WHERE user_id = :user_id
                      AND session_status = 'active'
                      AND expires_at > NOW()
                      AND (
                          :except_session_id IS NULL
                          OR id <> :except_session_id
                      )
                    RETURNING id
                    """
                ),
                {
                    "user_id": str(user_id),
                    "except_session_id": (
                        str(except_session_id)
                        if except_session_id is not None
                        else None
                    ),
                },
            )

            revoked_rows = result.mappings().all()
            revoked_count = len(revoked_rows)

            if revoked_count:
                await session.execute(
                    text(
                        """
                        INSERT INTO security_audit_events (
                            user_id,
                            event_type,
                            outcome,
                            metadata
                        )
                        VALUES (
                            :user_id,
                            'session_revoked',
                            'success',
                            CAST(:metadata AS JSONB)
                        )
                        """
                    ),
                    {
                        "user_id": str(user_id),
                        "metadata": (
                            '{"reason":"account_session_revocation",'
                            '"revoked_count":'
                            + str(revoked_count)
                            + "}"
                        ),
                    },
                )

            return revoked_count

except AuthenticationSessionError:
    raise

except SQLAlchemyError as exc:
    logger.warning(
        "Account session revocation failed (%s).",
        type(exc).__name__,
    )
    raise AuthenticationSessionStorageError(
        "The account sessions could not be revoked."
    ) from exc
