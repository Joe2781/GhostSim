from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any
from uuid import UUID

from app.services.device_connection_manager import (
    DeviceNotConnectedError,
    device_connection_manager,
)
from app.services.realtime_protocol import (
    RealtimeEventType,
    encode_event,
)


logger = logging.getLogger("ghostsim.realtime_dispatcher")


class EventDispatchError(Exception):
    """Base exception for real-time event dispatch failures."""


class EventDispatchInputError(EventDispatchError):
    """Raised when an event contains invalid dispatch parameters."""


class EventDispatchUnavailableError(EventDispatchError):
    """Raised when the recipient has no usable real-time connection."""


class DispatchOutcome(str, Enum):
    SENT_TO_CONNECTION = "sent_to_connection"
    RECIPIENT_OFFLINE = "recipient_offline"
    DELIVERY_FAILED = "delivery_failed"


@dataclass(frozen=True, slots=True)
class DispatchResult:
    recipient_device_id: UUID
    event_id: str
    outcome: DispatchOutcome
    connections_reached: int


class RealtimeEventDispatcher:
    """
    Dispatches validated protocol events to connected GhostSim devices.

    A successful dispatch means the WebSocket server accepted the send
    operation. It does not mean the recipient application processed the event
    or that a message was delivered or read.

    Persistent messages must remain in the database and be retried through
    the delivery worker when a recipient is offline or a send fails.
    """

    def __init__(self) -> None:
        self._connection_manager = device_connection_manager

    async def notify_message_available(
        self,
        *,
        recipient_device_id: UUID,
        delivery_id: UUID,
        message_id: UUID,
    ) -> DispatchResult:
        """
        Notify a device that a persisted message is available.

        The encrypted message body is deliberately not included in this event.
        The authenticated recipient can retrieve the message through the
        authorized messaging API.
        """
        return await self._dispatch(
            recipient_device_id=recipient_device_id,
            event_type=RealtimeEventType.MESSAGE_AVAILABLE,
            payload={
                "delivery_id": str(delivery_id),
                "message_id": str(message_id),
            },
        )

    async def notify_call_event(
        self,
        *,
        recipient_device_id: UUID,
        call_id: UUID,
        event_type: RealtimeEventType,
        payload: dict[str, Any] | None = None,
    ) -> DispatchResult:
        """Dispatch a supported call notification to a connected device."""
        allowed_types = {
            RealtimeEventType.CALL_OFFER,
            RealtimeEventType.CALL_ANSWER,
            RealtimeEventType.CALL_REJECTED,
            RealtimeEventType.CALL_ENDED,
            RealtimeEventType.CALL_RINGING,
        }

        if event_type not in allowed_types:
            raise EventDispatchInputError(
                "Unsupported call notification event type"
            )

        event_payload = dict(payload or {})
        event_payload["call_id"] = str(call_id)

        return await self._dispatch(
            recipient_device_id=recipient_device_id,
            event_type=event_type,
            payload=event_payload,
        )

    async def notify_device_status(
        self,
        *,
        recipient_device_id: UUID,
        subject_device_id: UUID,
        status: str,
    ) -> DispatchResult:
        """Notify a recipient about an authorized device-status change."""
        allowed_statuses = {
            "online",
            "offline",
            "busy",
            "unavailable",
        }

        if status not in allowed_statuses:
            raise EventDispatchInputError(
                "Invalid device status"
            )

        return await self._dispatch(
            recipient_device_id=recipient_device_id,
            event_type=RealtimeEventType.DEVICE_STATUS_CHANGED,
            payload={
                "device_id": str(subject_device_id),
                "status": status,
            },
        )

    async def _dispatch(
        self,
        *,
        recipient_device_id: UUID,
        event_type: RealtimeEventType,
        payload: dict[str, Any],
    ) -> DispatchResult:
        """
        Send one event and return a truthful transport-level outcome.

        This method intentionally does not mark persistent messages as
        delivered. That requires a separate, authorized acknowledgement
        workflow backed by the database.
        """
        event = encode_event(
            event_type=event_type,
            payload=payload,
        )
        event_id = str(event["event_id"])

        try:
            connections_reached = (
                await self._connection_manager.send_to_device(
                    device_id=recipient_device_id,
                    payload=event,
                )
            )

            logger.debug(
                "Real-time event dispatched",
                extra={
                    "recipient_device_id": str(recipient_device_id),
                    "event_type": event_type.value,
                    "event_id": event_id,
                    "connections_reached": connections_reached,
                },
            )

            return DispatchResult(
                recipient_device_id=recipient_device_id,
                event_id=event_id,
                outcome=DispatchOutcome.SENT_TO_CONNECTION,
                connections_reached=connections_reached,
            )

        except DeviceNotConnectedError:
            logger.debug(
                "Real-time recipient is offline",
                extra={
                    "recipient_device_id": str(recipient_device_id),
                    "event_type": event_type.value,
                    "event_id": event_id,
                },
            )

            return DispatchResult(
                recipient_device_id=recipient_device_id,
                event_id=event_id,
                outcome=DispatchOutcome.RECIPIENT_OFFLINE,
                connections_reached=0,
            )

        except Exception as exc:
            logger.exception(
                "Real-time event dispatch failed",
                extra={
                    "recipient_device_id": str(recipient_device_id),
                    "event_type": event_type.value,
                    "event_id": event_id,
                },
            )

            raise EventDispatchUnavailableError(
                "Real-time event could not be dispatched"
            ) from exc


realtime_event_dispatcher = RealtimeEventDispatcher()
