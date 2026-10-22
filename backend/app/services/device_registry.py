"""GhostSim device registry.

Manages device registration, device listings, and device revocation.

Security principles:
- The authenticated account UUID is supplied by a trusted caller.
- Private keys never enter this service.
- New devices remain pending until a separate verification flow
  establishes that the device controls its registered public key.
- Revocation and its audit records are committed atomically.
- Database operations use real PostgreSQL through SQLAlchemy.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.db import get_session_factory


logger = logging.getLogger("ghostsim.devices")


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

_ALLOWED_PLATFORMS = frozenset(
    {
        "android",
        "ios",
        "windows",
        "macos",
        "linux",
        "web",
    }
)

_ALLOWED_REVOCATION_REASONS = frozenset(
    {
        "owner_request",
        "suspected_compromise",
        "device_lost",
        "account_security",
        "administrative_action",
        "other",
    }
)

_MAX_DEVICE_NAME_LENGTH = 100
_MIN_PUBLIC_KEY_LENGTH = 32
_MAX_PUBLIC_KEY_LENGTH = 4096
_MAX_REASON_DETAILS_LENGTH = 2000


class DeviceRegistryError(Exception):
    """Base exception for device registry operations."""


class DeviceValidationError(DeviceRegistryError):
    """A supplied device field is invalid."""


class DeviceAccountNotFoundError(DeviceRegistryError):
    """The account does not exist or is not eligible."""


class DeviceNotFoundError(DeviceRegistryError):
    """The requested device does not exist for this account."""


class DeviceAlreadyRevokedError(DeviceRegistryError):
    """The requested device has already been revoked."""


class DeviceRegistrationError(DeviceRegistryError):
    """Device registration could not be completed."""


@dataclass(frozen=True, slots=True)
class RegisteredDevice:
    """Public, non-secret information about a registered device."""

    device_id: uuid.UUID
    user_id: uuid.UUID
    device_name: str
    platform: str
    status: str
    registered_at: datetime
    last_seen_at: datetime | None


@dataclass(frozen=True, slots=True)
class DeviceRevocation:
    """Result of a successful device revocation."""

    device_id: uuid.UUID
    user_id: uuid.UUID
    status: str
    revoked_at: datetime


def _validate_device_name(value: str) -> str:
    """Normalize and validate a human-readable device name."""
    if not isinstance(value, str):
        raise DeviceValidationError(
            "Device name must be a string."
        )

    value = value.strip()

    if not 1 <= len(value) <= _MAX_DEVICE_NAME_LENGTH:
        raise DeviceValidationError(
            "Device name must contain between 1 and 100 characters."
        )

    if any(ord(character) < 32 for character in value):
        raise DeviceValidationError(
            "Device name contains unsupported control characters."
        )

    return value


def _validate_platform(value: str) -> DevicePlatform:
    """Validate the platform against supported database values."""
    if not isinstance(value, str):
        raise DeviceValidationError(
            "Device platform must be a string."
        )

    normalized = value.strip().lower()

    if normalized not in _ALLOWED_PLATFORMS:
        raise DeviceValidationError(
            "The requested device platform is not supported."
        )

    return normalized  # type: ignore[return-value]


def _validate_public_key(value: str) -> str:
    """Validate the size of an encoded public key.

    Cryptographic format and proof-of-possession verification belong
    to the dedicated device verification flow.
    """
    if not isinstance(value, str):
        raise DeviceValidationError(
            "Device public key must be a string."
        )

    value = value.strip()

    if not (
        _MIN_PUBLIC_KEY_LENGTH
        <= len(value)
        <= _MAX_PUBLIC_KEY_LENGTH
    ):
        raise DeviceValidationError(
            "Device public key has an invalid length."
        )

    if any(ord(character) < 33 or ord(character) > 126 for character in value):
        raise DeviceValidationError(
            "Device public key must use printable ASCII characters."
        )

    return value


def _row_to_device(row) -> RegisteredDevice:
    """Convert a database result into a public device record."""
    return RegisteredDevice(
        device_id=row["id"],
        user_id=row["user_id"],
        device_name=row["device_name"],
        platform=row["platform"],
        status=row["status"],
        registered_at=row["registered_at"],
        last_seen_at=row["last_seen_at"],
    )


async def register_device(
    *,
    user_id: uuid.UUID,
    device_name: str,
    platform: str,
    public_key: str,
) -> RegisteredDevice:
    """Register a device for an existing, eligible account.

    The caller must authenticate the user and obtain user_id from
    trusted authentication context, not from an untrusted request
    body alone.

    Registration creates a pending device. It does not prove
    possession of the private key and does not authorize network
    relay participation.
    """
    if not isinstance(user_id, uuid.UUID):
        raise DeviceValidationError(
            "A valid authenticated account UUID is required."
        )

    normalized_name = _validate_device_name(device_name)
    normalized_platform = _validate_platform(platform)
    normalized_public_key = _validate_public_key(public_key)

    session_factory = get_session_factory()

    try:
        async with session_factory() as session:
            async with session.begin():
                account_result = await session.execute(
                    text(
                        """
                        SELECT id, status
                        FROM users
                        WHERE id = :user_id
                        FOR UPDATE
                        """
                    ),
                    {"user_id": str(user_id)},
                )

                account = (
                    account_result.mappings().one_or_none()
                )

                if (
                    account is None
                    or account["status"] != "active"
                ):
                    raise DeviceAccountNotFoundError(
                        "The account does not exist or is not eligible "
                        "for device registration."
                    )

                device_result = await session.execute(
                    text(
                        """
                        INSERT INTO devices (
                            user_id,
                            device_name,
                            platform,
                            public_key,
                            status
                        )
                        VALUES (
                            :user_id,
                            :device_name,
                            :platform,
                            :public_key,
                            'pending'
                        )
                        RETURNING
                            id,
                            user_id,
                            device_name,
                            platform,
                            status,
                            registered_at,
                            last_seen_at
                        """
                    ),
                    {
                        "user_id": str(user_id),
                        "device_name": normalized_name,
                        "platform": normalized_platform,
                        "public_key": normalized_public_key,
                    },
                )

                device_row = (
                    device_result.mappings().one()
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
                            'device_registered',
                            'success',
                            CAST(:metadata AS JSONB)
                        )
                        """
                    ),
                    {
                        "user_id": str(user_id),
                        "device_id": str(device_row["id"]),
                        "metadata": (
                            '{"platform": "'
                            + normalized_platform
                            + '", "initial_status": "pending"}'
                        ),
                    },
                )

                return _row_to_device(device_row)

    except DeviceRegistryError:
        raise

    except SQLAlchemyError as exc:
        logger.error(
            "Device registration failed (%s).",
            type(exc).__name__,
        )

        raise DeviceRegistrationError(
            "Device registration is temporarily unavailable. "
            "The public key may already be registered."
        ) from exc


async def list_registered_devices(
    *,
    user_id: uuid.UUID,
    include_revoked: bool = False,
) -> list[RegisteredDevice]:
    """List devices belonging to the authenticated account.

    Revoked devices are excluded by default. The returned records
    deliberately omit public keys and all private key material.
    """
    if not isinstance(user_id, uuid.UUID):
        raise DeviceValidationError(
            "A valid authenticated account UUID is required."
        )

    session_factory = get_session_factory()

    query = """
        SELECT
            id,
            user_id,
            device_name,
            platform,
            status,
            registered_at,
            last_seen_at
        FROM devices
        WHERE user_id = :user_id
    """

    if not include_revoked:
        query += " AND status <> 'revoked'"

    query += " ORDER BY registered_at DESC, id DESC"

    try:
        async with session_factory() as session:
            result = await session.execute(
                text(query),
                {"user_id": str(user_id)},
            )

            return [
                _row_to_device(row)
                for row in result.mappings().all()
            ]

    except SQLAlchemyError as exc:
        logger.error(
            "Device listing failed (%s).",
            type(exc).__name__,
        )

        raise DeviceRegistryError(
            "Registered devices are temporarily unavailable."
        ) from exc


async def revoke_device(
    *,
    user_id: uuid.UUID,
    device_id: uuid.UUID,
    reason_code: str = "owner_request",
    reason_details: str | None = None,
) -> DeviceRevocation:
    """Revoke a device owned by the authenticated account.

    Revocation, its history entry, and its security audit event
    are committed in one transaction.

    This operation does not itself disconnect an already-running
    network socket or invalidate every existing session. Those
    enforcement actions must also be implemented by the
    authentication and networking services.
    """
    if (
        not isinstance(user_id, uuid.UUID)
        or not isinstance(device_id, uuid.UUID)
    ):
        raise DeviceValidationError(
            "Valid account and device UUIDs are required."
        )

    if (
        not isinstance(reason_code, str)
        or reason_code not in _ALLOWED_REVOCATION_REASONS
    ):
        raise DeviceValidationError(
            "The device revocation reason is not supported."
        )

    if reason_details is not None:
        if not isinstance(reason_details, str):
            raise DeviceValidationError(
                "Revocation details must be text."
            )

        reason_details = reason_details.strip()

        if len(reason_details) > _MAX_REASON_DETAILS_LENGTH:
            raise DeviceValidationError(
                "Revocation details are too long."
            )

        if not reason_details:
            reason_details = None

    session_factory = get_session_factory()

    try:
        async with session_factory() as session:
            async with session.begin():
                device_result = await session.execute(
                    text(
                        """
                        SELECT
                            id,
                            user_id,
                            status,
                            revoked_at
                        FROM devices
                        WHERE id = :device_id
                          AND user_id = :user_id
                        FOR UPDATE
                        """
                    ),
                    {
                        "device_id": str(device_id),
                        "user_id": str(user_id),
                    },
                )

                device = (
                    device_result.mappings().one_or_none()
                )

                if device is None:
                    raise DeviceNotFoundError(
                        "The device was not found for this account."
                    )

                if device["status"] == "revoked":
                    raise DeviceAlreadyRevokedError(
                        "This device has already been revoked."
                    )

                if device["status"] != "active":
                    raise DeviceRegistryError(
                        "Only an activated device can be revoked "
                        "through this operation."
                    )

                update_result = await session.execute(
                    text(
                        """
                        UPDATE devices
                        SET
                            status = 'revoked',
                            revoked_at = NOW()
                        WHERE id = :device_id
                          AND user_id = :user_id
                          AND status = 'active'
                        RETURNING revoked_at
                        """
                    ),
                    {
                        "device_id": str(device_id),
                        "user_id": str(user_id),
                    },
                )

                updated = (
                    update_result.mappings().one_or_none()
                )

                if updated is None:
                    raise DeviceRegistryError(
                        "The device state changed before revocation "
                        "could be completed."
                    )

                revoked_at = updated["revoked_at"]

                await session.execute(
                    text(
                        """
                        INSERT INTO device_revocations (
                            device_id,
                            revoked_by_user_id,
                            reason_code,
                            reason_details,
                            revoked_at
                        )
                        VALUES (
                            :device_id,
                            :user_id,
                            :reason_code,
                            :reason_details,
                            :revoked_at
                        )
                        """
                    ),
                    {
                        "device_id": str(device_id),
                        "user_id": str(user_id),
                        "reason_code": reason_code,
                        "reason_details": reason_details,
                        "revoked_at": revoked_at,
                    },
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
                            'device_revoked',
                            'success',
                            CAST(:metadata AS JSONB)
                        )
                        """
                    ),
                    {
                        "user_id": str(user_id),
                        "device_id": str(device_id),
                        "metadata": (
                            '{"reason_code": "'
                            + reason_code
                            + '"}'
                        ),
                    },
                )

                return DeviceRevocation(
                    device_id=device_id,
                    user_id=user_id,
                    status="revoked",
                    revoked_at=revoked_at,
                )

    except DeviceRegistryError:
        raise

    except SQLAlchemyError as exc:
        logger.error(
            "Device revocation failed (%s).",
            type(exc).__name__,
        )

        raise DeviceRegistryError(
            "Device revocation could not be completed."
        ) from exc
