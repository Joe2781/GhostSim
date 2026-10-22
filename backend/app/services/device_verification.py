"""GhostSim device verification and activation.

A device proves possession of its Ed25519 private key by signing
a short-lived random challenge. Private keys never reach the server.

Public keys and signatures must be URL-safe Base64 encodings of
raw Ed25519 bytes. The client signs the decoded challenge bytes.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.db import get_session_factory


logger = logging.getLogger("ghostsim.device_verification")

CHALLENGE_TTL_SECONDS = 300
MAX_CHALLENGE_ATTEMPTS = 5
RAW_CHALLENGE_BYTES = 32
RAW_ED25519_PUBLIC_KEY_BYTES = 32
RAW_ED25519_SIGNATURE_BYTES = 64


class DeviceVerificationError(Exception):
    """Base exception for device verification operations."""


class VerificationInputError(DeviceVerificationError):
    """A verification input is malformed or invalid."""


class VerificationDeviceNotFoundError(DeviceVerificationError):
    """The device does not exist for the supplied account."""


class VerificationStateError(DeviceVerificationError):
    """The device or challenge is not in a verifiable state."""


class VerificationStorageError(DeviceVerificationError):
    """Verification could not be completed in the database."""


VerificationOutcome = Literal[
    "verified",
    "invalid_signature",
    "expired",
    "already_used",
]


@dataclass(frozen=True, slots=True)
class DeviceChallenge:
    """Challenge returned to a registered device."""

    challenge_id: uuid.UUID
    device_id: uuid.UUID
    challenge: str
    expires_at: datetime
    verification_method: str = "ed25519"


@dataclass(frozen=True, slots=True)
class DeviceVerificationResult:
    """Non-secret result of a verification attempt."""

    challenge_id: uuid.UUID
    device_id: uuid.UUID
    outcome: VerificationOutcome
    device_status: str
    attempts_remaining: int


def _decode_urlsafe_base64(
    value: str,
    *,
    field_name: str,
) -> bytes:
    """Decode padded or unpadded URL-safe Base64."""
    if not isinstance(value, str) or not value or len(value) > 8192:
        raise VerificationInputError(f"{field_name} is invalid.")

    try:
        encoded = value.encode("ascii")
        padding = b"=" * ((4 - len(encoded) % 4) % 4)

        decoded = base64.b64decode(
            encoded + padding,
            altchars=b"-_",
            validate=True,
        )
    except (UnicodeEncodeError, ValueError) as exc:
        raise VerificationInputError(
            f"{field_name} must be URL-safe Base64."
        ) from exc

    if not decoded:
        raise VerificationInputError(f"{field_name} is empty.")

    return decoded


def _encode_urlsafe_base64(value: bytes) -> str:
    """Encode bytes as URL-safe Base64 without padding."""
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode_public_key(encoded_key: str) -> Ed25519PublicKey:
    """Load a raw Ed25519 public key stored as URL-safe Base64."""
    raw_key = _decode_urlsafe_base64(
        encoded_key,
        field_name="Registered public key",
    )

    if len(raw_key) != RAW_ED25519_PUBLIC_KEY_BYTES:
        raise VerificationInputError(
            "The registered public key is not a raw Ed25519 key."
        )

    try:
        return Ed25519PublicKey.from_public_bytes(raw_key)
    except ValueError as exc:
        raise VerificationInputError(
            "The registered public key is invalid."
        ) from exc


async def create_device_challenge(
    *,
    user_id: uuid.UUID,
    device_id: uuid.UUID,
) -> DeviceChallenge:
    """Create a short-lived challenge for a pending device.

    The raw challenge is returned once. Only its SHA-256 hash is
    stored in PostgreSQL.

    The caller must derive user_id from trusted authentication
    context rather than trusting an arbitrary request-body value.
    """
    if not isinstance(user_id, uuid.UUID) or not isinstance(
        device_id, uuid.UUID
    ):
        raise VerificationInputError(
            "Valid account and device UUIDs are required."
        )

    challenge_bytes = secrets.token_bytes(RAW_CHALLENGE_BYTES)
    challenge_text = _encode_urlsafe_base64(challenge_bytes)
    challenge_hash = hashlib.sha256(challenge_bytes).hexdigest()

    session_factory = get_session_factory()

    try:
        async with session_factory() as session:
            async with session.begin():
                device_result = await session.execute(
                    text(
                        """
                        SELECT id, user_id, status
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

                device = device_result.mappings().one_or_none()

                if device is None:
                    raise VerificationDeviceNotFoundError(
                        "The device was not found for this account."
                    )

                if device["status"] == "active":
                    raise VerificationStateError(
                        "This device is already active."
                    )

                if device["status"] != "pending":
                    raise VerificationStateError(
                        "Only a pending device can be verified."
                    )

                # Expire any previous pending challenge so the
                # database's one-pending-challenge index is respected.
                await session.execute(
                    text(
                        """
                        UPDATE device_verification_challenges
                        SET challenge_status = 'expired'
                        WHERE device_id = :device_id
                          AND challenge_status = 'pending'
                        """
                    ),
                    {"device_id": str(device_id)},
                )

                result = await session.execute(
                    text(
                        """
                        INSERT INTO device_verification_challenges (
                            device_id,
                            challenge_hash,
                            verification_method,
                            challenge_status,
                            attempts,
                            max_attempts,
                            expires_at
                        )
                        VALUES (
                            :device_id,
                            :challenge_hash,
                            'ed25519',
                            'pending',
                            0,
                            :max_attempts,
                            NOW() + (:ttl_seconds * INTERVAL '1 second')
                        )
                        RETURNING id, expires_at
                        """
                    ),
                    {
                        "device_id": str(device_id),
                        "challenge_hash": challenge_hash,
                        "max_attempts": MAX_CHALLENGE_ATTEMPTS,
                        "ttl_seconds": CHALLENGE_TTL_SECONDS,
                    },
                )

                challenge_row = result.mappings().one()

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
                            'device_verification_challenge_created',
                            'success',
                            CAST(:metadata AS JSONB)
                        )
                        """
                    ),
                    {
                        "user_id": str(user_id),
                        "device_id": str(device_id),
                        "metadata": (
                            '{"verification_method":"ed25519",'
                            '"ttl_seconds":300}'
                        ),
                    },
                )

                return DeviceChallenge(
                    challenge_id=challenge_row["id"],
                    device_id=device_id,
                    challenge=challenge_text,
                    expires_at=challenge_row["expires_at"],
                )

    except DeviceVerificationError:
        raise

    except SQLAlchemyError as exc:
        logger.warning(
            "Challenge creation failed (%s).",
            type(exc).__name__,
        )
        raise VerificationStorageError(
            "A verification challenge could not be created."
        ) from exc


async def verify_and_activate_device(
    *,
    user_id: uuid.UUID,
    device_id: uuid.UUID,
    challenge_id: uuid.UUID,
    challenge: str,
    signature: str,
) -> DeviceVerificationResult:
    """Verify a signed challenge and activate a pending device.

    The device signs the decoded challenge bytes using its Ed25519
    private key. On success, challenge consumption, device
    activation, activation history, and the audit event are
    committed in one database transaction.

    Invalid signatures consume an attempt. Challenges are single-use.
    """
    if not all(
        isinstance(value, uuid.UUID)
        for value in (user_id, device_id, challenge_id)
    ):
        raise VerificationInputError(
            "Valid account, device, and challenge UUIDs are required."
        )

    challenge_bytes = _decode_urlsafe_base64(
        challenge,
        field_name="Challenge",
    )
    signature_bytes = _decode_urlsafe_base64(
        signature,
        field_name="Signature",
    )

    if len(challenge_bytes) != RAW_CHALLENGE_BYTES:
        raise VerificationInputError(
            "The challenge has an invalid length."
        )

    if len(signature_bytes) != RAW_ED25519_SIGNATURE_BYTES:
        raise VerificationInputError(
            "The Ed25519 signature has an invalid length."
        )

    supplied_hash = hashlib.sha256(challenge_bytes).hexdigest()
    session_factory = get_session_factory()

    try:
        async with session_factory() as session:
            async with session.begin():
                device_result = await session.execute(
                    text(
                        """
                        SELECT id, user_id, public_key, status
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

                device = device_result.mappings().one_or_none()

                if device is None:
                    raise VerificationDeviceNotFoundError(
                        "The device was not found for this account."
                    )

                if device["status"] == "active":
                    raise VerificationStateError(
                        "This device is already active."
                    )

                if device["status"] != "pending":
                    raise VerificationStateError(
                        "Only a pending device can be verified."
                    )

                challenge_result = await session.execute(
                    text(
                        """
                        SELECT
                            id,
                            device_id,
                            challenge_hash,
                            challenge_status,
                            attempts,
                            max_attempts,
                            expires_at
                        FROM device_verification_challenges
                        WHERE id = :challenge_id
                          AND device_id = :device_id
                        FOR UPDATE
                        """
                    ),
                    {
                        "challenge_id": str(challenge_id),
                        "device_id": str(device_id),
                    },
                )

                challenge_row = (
                    challenge_result.mappings().one_or_none()
                )

                if challenge_row is None:
                    raise VerificationStateError(
                        "The verification challenge was not found."
                    )

                if challenge_row["challenge_status"] != "pending":
                    return DeviceVerificationResult(
                        challenge_id=challenge_id,
                        device_id=device_id,
                        outcome="already_used",
                        device_status="pending",
                        attempts_remaining=0,
                    )

                now = datetime.now(challenge_row["expires_at"].tzinfo)

                if challenge_row["expires_at"] <= now:
                    await session.execute(
                        text(
                            """
                            UPDATE device_verification_challenges
                            SET challenge_status = 'expired'
                            WHERE id = :challenge_id
                            """
                        ),
                        {"challenge_id": str(challenge_id)},
                    )

                    return DeviceVerificationResult(
                        challenge_id=challenge_id,
                        device_id=device_id,
                        outcome="expired",
                        device_status="pending",
                        attempts_remaining=0,
                    )

                if not secrets.compare_digest(
                    challenge_row["challenge_hash"],
                    supplied_hash,
                ):
                    raise VerificationInputError(
                        "The supplied challenge does not match this record."
                    )

                if challenge_row["attempts"] >= challenge_row["max_attempts"]:
                    await session.execute(
                        text(
                            """
                            UPDATE device_verification_challenges
                            SET challenge_status = 'failed'
                            WHERE id = :challenge_id
                            """
                        ),
                        {"challenge_id": str(challenge_id)},
                    )

                    return DeviceVerificationResult(
                        challenge_id=challenge_id,
                        device_id=device_id,
                        outcome="invalid_signature",
                        device_status="pending",
                        attempts_remaining=0,
                    )

                public_key = _decode_public_key(device["public_key"])

                try:
                    public_key.verify(signature_bytes, challenge_bytes)
                    signature_valid = True
                except InvalidSignature:
                    signature_valid = False

                next_attempts = challenge_row["attempts"] + 1

                if not signature_valid:
                    next_status = (
                        "failed"
                        if next_attempts >= challenge_row["max_attempts"]
                        else "pending"
                    )

                    await session.execute(
                        text(
                            """
                            UPDATE device_verification_challenges
                            SET
                                attempts = :attempts,
                                challenge_status = :challenge_status
                            WHERE id = :challenge_id
                            """
                        ),
                        {
                            "attempts": next_attempts,
                            "challenge_status": next_status,
                            "challenge_id": str(challenge_id),
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
                                'device_verification_failed',
                                'failure',
                                CAST(:metadata AS JSONB)
                            )
                            """
                        ),
                        {
                            "user_id": str(user_id),
                            "device_id": str(device_id),
                            "metadata": (
                                '{"attempts":'
                                + str(next_attempts)
                                + ',"max_attempts":'
                                + str(challenge_row["max_attempts"])
                                + '}'
                            ),
                        },
                    )

                    return DeviceVerificationResult(
                        challenge_id=challenge_id,
                        device_id=device_id,
                        outcome="invalid_signature",
                        device_status="pending",
                        attempts_remaining=max(
                            0,
                            challenge_row["max_attempts"] - next_attempts,
                        ),
                    )

                # Consume the challenge and activate the device in
                # the same transaction. Any failure rolls back both.
                verified_result = await session.execute(
                    text(
                        """
                        UPDATE device_verification_challenges
                        SET
                            attempts = :attempts,
                            challenge_status = 'consumed',
                            verified_at = NOW(),
                            consumed_at = NOW()
                        WHERE id = :challenge_id
                          AND challenge_status = 'pending'
                        RETURNING verified_at
                        """
                    ),
                    {
                        "attempts": next_attempts,
                        "challenge_id": str(challenge_id),
                    },
                )

                if verified_result.mappings().one_or_none() is None:
                    raise VerificationStateError(
                        "The challenge could not be consumed."
                    )

                activation_result = await session.execute(
                    text(
                        """
                        UPDATE devices
                        SET
                            status = 'active',
                            last_seen_at = NOW()
                        WHERE id = :device_id
                          AND user_id = :user_id
                          AND status = 'pending'
                        RETURNING id
                        """
                    ),
                    {
                        "device_id": str(device_id),
                        "user_id": str(user_id),
                    },
                )

                if activation_result.mappings().one_or_none() is None:
                    raise VerificationStateError(
                        "The device could not be activated."
                    )

                await session.execute(
                    text(
                        """
                        INSERT INTO device_activation_records (
                            device_id,
                            verification_challenge_id,
                            activation_status,
                            activated_at
                        )
                        VALUES (
                            :device_id,
                            :challenge_id,
                            'activated',
                            NOW()
                        )
                        """
                    ),
                    {
                        "device_id": str(device_id),
                        "challenge_id": str(challenge_id),
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
                            'device_activated',
                            'success',
                            CAST(:metadata AS JSONB)
                        )
                        """
                    ),
                    {
                        "user_id": str(user_id),
                        "device_id": str(device_id),
                        "metadata": (
                            '{"verification_method":"ed25519"}'
                        ),
                    },
                )

                return DeviceVerificationResult(
                    challenge_id=challenge_id,
                    device_id=device_id,
                    outcome="verified",
                    device_status="active",
                    attempts_remaining=(
                        challenge_row["max_attempts"] - next_attempts
                    ),
                )

    except DeviceVerificationError:
        raise

    except SQLAlchemyError as exc:
        logger.warning(
            "Device verification failed at storage layer (%s).",
            type(exc).__name__,
        )
        raise VerificationStorageError(
            "Device verification is temporarily unavailable."
        ) from exc
