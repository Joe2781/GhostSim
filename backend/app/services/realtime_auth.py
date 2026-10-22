from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.db import get_session


logger = logging.getLogger("ghostsim.realtime_auth")


class RealtimeAuthenticationError(Exception):
    """Base exception for real-time authentication failures."""


class InvalidRealtimeCredentialsError(RealtimeAuthenticationError):
    """Raised when a session or device cannot be authenticated."""


class RealtimeAuthenticationStorageError(RealtimeAuthenticationError):
    """Raised when authentication storage cannot be queried."""


@dataclass(frozen=True, slots=True)
class AuthenticatedRealtimeDevice:
    user_id: UUID
    device_id: UUID
    session_id: UUID
    session_expires_at: datetime


async def authenticate_realtime_device(
    *,
    access_token: str,
    device_id: UUID,
) -> AuthenticatedRealtimeDevice:
    """
    Authenticate an active session and confirm device ownership.

    The raw access token is never stored or logged by this service. Only its
    SHA-256 hash is used to find the corresponding database session.

    This function does not grant relay privileges or network participation.
    Those require separate authorization and explicit owner consent.
    """
    if not access_token or len(access_token) < 32 or len(access_token) > 4096:
        raise InvalidRealtimeCredentialsError(
            "Invalid session credentials"
        )

    token_hash = hashlib.sha256(
        access_token.encode("utf-8")
    ).hexdigest()

    query = text(
        """
        SELECT
            s.id AS session_id,
            s.user_id,
            s.expires_at,
            d.id AS device_id
        FROM auth_sessions AS s
        JOIN users AS u
          ON u.id = s.user_id
        JOIN devices AS d
          ON d.user_id = s.user_id
        WHERE s.token_hash = :token_hash
          AND s.session_status = 'active'
          AND s.expires_at > NOW()
          AND u.status = 'active'
          AND d.id = :device_id
          AND d.status = 'active'
        LIMIT 1
        """
    )

    try:
        async with get_session() as session:
            result = await session.execute(
                query,
                {
                    "token_hash": token_hash,
                    "device_id": device_id,
                },
            )
            row = result.mappings().first()

            if row is None:
                raise InvalidRealtimeCredentialsError(
                    "Session or device is not authorized"
                )

            await session.execute(
                text(
                    """
                    UPDATE auth_sessions
                    SET last_used_at = NOW()
                    WHERE id = :session_id
                      AND session_status = 'active'
                    """
                ),
                {"session_id": row["session_id"]},
            )

            await session.execute(
                text(
                    """
                    UPDATE devices
                    SET last_seen_at = NOW()
                    WHERE id = :device_id
                      AND status = 'active'
                    """
                ),
                {"device_id": row["device_id"]},
            )

            expires_at = row["expires_at"]

            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)

            return AuthenticatedRealtimeDevice(
                user_id=UUID(str(row["user_id"])),
                device_id=UUID(str(row["device_id"])),
                session_id=UUID(str(row["session_id"])),
                session_expires_at=expires_at,
            )

    except InvalidRealtimeCredentialsError:
        raise

    except SQLAlchemyError as exc:
        logger.exception(
            "Database error while authenticating a real-time device",
            extra={"device_id": str(device_id)},
        )
        raise RealtimeAuthenticationStorageError(
            "Unable to authenticate device at this time"
        ) from exc
