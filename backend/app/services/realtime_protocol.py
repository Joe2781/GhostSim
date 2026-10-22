from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator


PROTOCOL_VERSION = 1
MAX_EVENT_BYTES = 64 * 1024
MAX_EVENT_ID_LENGTH = 128
MAX_ERROR_MESSAGE_LENGTH = 256


class RealtimeProtocolError(Exception):
    """Base exception for real-time protocol validation errors."""


class InvalidRealtimeEventError(RealtimeProtocolError):
    """Raised when an incoming real-time event is invalid."""


class RealtimeEventType(str, Enum):
    AUTHENTICATE = "authenticate"
    AUTHENTICATED = "authenticated"
    AUTHENTICATION_FAILED = "authentication_failed"

    PING = "ping"
    PONG = "pong"

    MESSAGE_AVAILABLE = "message_available"
    MESSAGE_ACKNOWLEDGEMENT = "message_acknowledgement"
    MESSAGE_RECEIVED = "message_received"
    MESSAGE_DELIVERED = "message_delivered"
    MESSAGE_READ = "message_read"

    CALL_OFFER = "call_offer"
    CALL_ANSWER = "call_answer"
    CALL_ICE_CANDIDATE = "call_ice_candidate"
    CALL_REJECTED = "call_rejected"
    CALL_ENDED = "call_ended"
    CALL_RINGING = "call_ringing"

    DEVICE_STATUS_CHANGED = "device_status_changed"

    ERROR = "error"


class RealtimeEnvelope(BaseModel):
    """Standard envelope shared by GhostSim real-time events."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
    )

    version: int = PROTOCOL_VERSION
    event_id: str = Field(
        default_factory=lambda: str(uuid4()),
        min_length=1,
        max_length=MAX_EVENT_ID_LENGTH,
    )
    type: RealtimeEventType
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    payload: dict[str, Any] = Field(default_factory=dict)

    @field_validator("version")
    @classmethod
    def validate_version(cls, value: int) -> int:
        if value != PROTOCOL_VERSION:
            raise ValueError("Unsupported protocol version")
        return value

    @field_validator("event_id")
    @classmethod
    def validate_event_id(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", value):
            raise ValueError("Invalid event ID format")
        return value

    @field_validator("timestamp")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("Timestamp must include a timezone")
        return value.astimezone(timezone.utc)


class AuthenticationPayload(BaseModel):
    """Credentials for the initial WebSocket authentication event."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    access_token: str = Field(min_length=32, max_length=4096)
    device_id: UUID
    connection_id: str = Field(min_length=1, max_length=128)

    @field_validator("connection_id")
    @classmethod
    def validate_connection_id(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", value):
            raise ValueError("Invalid connection ID format")
        return value


class MessageAcknowledgementPayload(BaseModel):
    """Client acknowledgement for a message delivery event."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    delivery_id: UUID
    message_id: UUID
    acknowledgement: str = Field(
        default="received",
        pattern=r"^(received|delivered|read)$",
    )


class CallSignalPayload(BaseModel):
    """Validated outer structure for call signaling events."""

    model_config = ConfigDict(extra="forbid")

    call_id: UUID
    peer_device_id: UUID | None = None
    data: dict[str, Any] = Field(default_factory=dict)


class ProtocolErrorPayload(BaseModel):
    """Safe, concise error representation sent to a client."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    code: str = Field(min_length=1, max_length=64)
    message: str = Field(
        min_length=1,
        max_length=MAX_ERROR_MESSAGE_LENGTH,
    )
    retryable: bool = False


def encode_event(
    event_type: RealtimeEventType,
    payload: dict[str, Any] | None = None,
    event_id: str | None = None,
) -> dict[str, Any]:
    """Create a validated JSON-compatible event envelope."""
    values: dict[str, Any] = {
        "type": event_type,
        "payload": payload or {},
    }

    if event_id is not None:
        values["event_id"] = event_id

    envelope = RealtimeEnvelope.model_validate(values)
    return envelope.model_dump(mode="json")


def decode_event(raw_data: str | bytes) -> RealtimeEnvelope:
    """
    Decode and validate an incoming JSON event.

    This function validates structure and size, but does not authenticate the
    sender or authorize any requested operation.
    """
    if isinstance(raw_data, bytes):
        raw_bytes = raw_data
        try:
            text = raw_data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InvalidRealtimeEventError(
                "Event must be valid UTF-8"
            ) from exc
    elif isinstance(raw_data, str):
        text = raw_data
        raw_bytes = raw_data.encode("utf-8")
    else:
        raise InvalidRealtimeEventError(
            "Event must be a string or byte sequence"
        )

    if len(raw_bytes) > MAX_EVENT_BYTES:
        raise InvalidRealtimeEventError("Event exceeds the maximum size")

    try:
        decoded = json.loads(text)
        if not isinstance(decoded, dict):
            raise InvalidRealtimeEventError(
                "Event must be a JSON object"
            )

        return RealtimeEnvelope.model_validate(decoded)

    except InvalidRealtimeEventError:
        raise
    except (json.JSONDecodeError, ValidationError, ValueError) as exc:
        raise InvalidRealtimeEventError(
            "Event has an invalid structure"
        ) from exc


def validate_payload(
    payload_model: type[BaseModel],
    payload: dict[str, Any],
) -> BaseModel:
    """Validate an event payload against its dedicated Pydantic model."""
    try:
        return payload_model.model_validate(payload)
    except ValidationError as exc:
        raise InvalidRealtimeEventError(
            "Event payload is invalid"
        ) from exc
