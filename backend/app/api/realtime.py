from __future__ import annotations

import asyncio
import logging
import secrets
from uuid import UUID, uuid4

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from pydantic import ValidationError
from starlette.websockets import WebSocketState

from app.services.device_connection_manager import (
    DeviceConnectionError,
    DeviceConnectionLimitError,
    device_connection_manager,
)
from app.services.realtime_auth import (
    InvalidRealtimeCredentialsError,
    RealtimeAuthenticationStorageError,
    authenticate_realtime_device,
)
from app.services.realtime_protocol import (
    AuthenticationPayload,
    InvalidRealtimeEventError,
    MessageAcknowledgementPayload,
    ProtocolErrorPayload,
    RealtimeEnvelope,
    RealtimeEventType,
    decode_event,
    encode_event,
    validate_payload,
)
from app.services.realtime_rate_limiter import (
    RateLimitCategory,
    RealtimeRateLimitExceeded,
    realtime_rate_limiter,
)


logger = logging.getLogger("ghostsim.api.realtime")

router = APIRouter(prefix="/api/v1/realtime", tags=["real-time"])

AUTHENTICATION_TIMEOUT_SECONDS = 10
MAX_CONSECUTIVE_INVALID_EVENTS = 5
HEARTBEAT_INTERVAL_SECONDS = 30


async def _send_event(
    websocket: WebSocket,
    event_type: RealtimeEventType,
    payload: dict | None = None,
) -> None:
    await websocket.send_json(
        encode_event(event_type, payload or {})
    )


async def _send_error(
    websocket: WebSocket,
    code: str,
    message: str,
    *,
    retryable: bool = False,
) -> None:
    await _send_event(
        websocket,
        RealtimeEventType.ERROR,
        ProtocolErrorPayload(
            code=code,
            message=message,
            retryable=retryable,
        ).model_dump(),
    )


async def _receive_authentication(
    websocket: WebSocket,
) -> AuthenticationPayload:
    try:
        raw = await asyncio.wait_for(
            websocket.receive_text(),
            timeout=AUTHENTICATION_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError as exc:
        raise InvalidRealtimeCredentialsError(
            "Authentication timed out"
        ) from exc

    envelope = decode_event(raw)

    if envelope.type != RealtimeEventType.AUTHENTICATE:
        raise InvalidRealtimeCredentialsError(
            "Authentication must be the first event"
        )

    payload = validate_payload(
        AuthenticationPayload,
        envelope.payload,
    )

    assert isinstance(payload, AuthenticationPayload)
    return payload


async def _handle_authenticated_event(
    websocket: WebSocket,
    *,
    user_id: UUID,
    device_id: UUID,
    envelope: RealtimeEnvelope,
) -> bool:
    """
    Handle protocol events that are safe at this stage.

    Returns False when the connection should close. Message acknowledgements
    are validated here, but persistent delivery-state updates will be connected
    to the delivery service in a later integration step.
    """
    if envelope.type == RealtimeEventType.PING:
        await _send_event(
            websocket,
            RealtimeEventType.PONG,
            {"reply_to": envelope.event_id},
        )
        return True

    if envelope.type == RealtimeEventType.MESSAGE_ACKNOWLEDGEMENT:
        payload = validate_payload(
            MessageAcknowledgementPayload,
            envelope.payload,
        )
        assert isinstance(payload, MessageAcknowledgementPayload)

        # A client acknowledgement is not proof of delivery ownership.
        # Persisting it requires a database check against this user/device.
        logger.debug(
            "Received message acknowledgement",
            extra={
                "user_id": str(user_id),
                "device_id": str(device_id),
                "delivery_id": str(payload.delivery_id),
                "message_id": str(payload.message_id),
                "acknowledgement": payload.acknowledgement,
            },
        )

        await _send_event(
            websocket,
            RealtimeEventType.MESSAGE_RECEIVED,
            {
                "delivery_id": str(payload.delivery_id),
                "message_id": str(payload.message_id),
                "accepted": False,
                "reason": "persistent_acknowledgement_not_integrated",
            },
        )
        return True

    if envelope.type in {
        RealtimeEventType.CALL_OFFER,
        RealtimeEventType.CALL_ANSWER,
        RealtimeEventType.CALL_ICE_CANDIDATE,
        RealtimeEventType.CALL_REJECTED,
        RealtimeEventType.CALL_ENDED,
    }:
        await _send_error(
            websocket,
            "CALL_SIGNALING_NOT_READY",
            "Call signaling is not enabled on this endpoint yet.",
            retryable=True,
        )
        return True

    if envelope.type in {
        RealtimeEventType.AUTHENTICATE,
        RealtimeEventType.AUTHENTICATED,
        RealtimeEventType.AUTHENTICATION_FAILED,
        RealtimeEventType.MESSAGE_AVAILABLE,
        RealtimeEventType.MESSAGE_RECEIVED,
        RealtimeEventType.MESSAGE_DELIVERED,
        RealtimeEventType.MESSAGE_READ,
        RealtimeEventType.PONG,
        RealtimeEventType.ERROR,
    }:
        await _send_error(
            websocket,
            "EVENT_NOT_ACCEPTED",
            "This event type is not accepted from clients.",
        )
        return True

    await _send_error(
        websocket,
        "UNKNOWN_EVENT",
        "The requested event is not supported.",
    )
    return True


@router.websocket("/connect")
async def realtime_websocket(websocket: WebSocket) -> None:
    """
    Authenticated real-time connection for registered GhostSim devices.

    Clients must connect over WSS in production and send an authenticate
    envelope as their first message. The server validates the session and
    device before registering the connection.
    """
    await websocket.accept()

    connection_id: str | None = None
    authenticated_device_id: UUID | None = None
    authenticated_user_id: UUID | None = None
    authenticated_session_id: UUID | None = None

    try:
        try:
            auth_payload = await _receive_authentication(websocket)

            await realtime_rate_limiter.enforce(
                auth_payload.device_id,
                RateLimitCategory.AUTHENTICATION,
            )

            authenticated = await authenticate_realtime_device(
                access_token=auth_payload.access_token,
                device_id=auth_payload.device_id,
            )

            authenticated_device_id = authenticated.device_id
            authenticated_user_id = authenticated.user_id
            authenticated_session_id = authenticated.session_id
            connection_id = auth_payload.connection_id

            await device_connection_manager.register(
                device_id=authenticated.device_id,
                connection_id=connection_id,
                websocket=websocket,
            )

        except (
            InvalidRealtimeCredentialsError,
            InvalidRealtimeEventError,
            RealtimeRateLimitExceeded,
            ValidationError,
        ):
            await _send_event(
                websocket,
                RealtimeEventType.AUTHENTICATION_FAILED,
                {"message": "Authentication failed"},
            )
            await websocket.close(code=1008)
            return

        except RealtimeAuthenticationStorageError:
            await _send_error(
                websocket,
                "AUTHENTICATION_UNAVAILABLE",
                "Authentication is temporarily unavailable.",
                retryable=True,
            )
            await websocket.close(code=1011)
            return

        except DeviceConnectionLimitError:
            await _send_error(
                websocket,
                "CONNECTION_LIMIT_REACHED",
                "This device has reached its connection limit.",
            )
            await websocket.close(code=1008)
            return

        except DeviceConnectionError:
            await _send_error(
                websocket,
                "CONNECTION_REJECTED",
                "The connection could not be registered.",
            )
            await websocket.close(code=1011)
            return

        await _send_event(
            websocket,
            RealtimeEventType.AUTHENTICATED,
            {
                "device_id": str(authenticated_device_id),
                "connection_id": connection_id,
                "session_id": str(authenticated_session_id),
            },
        )

        invalid_events = 0

        while True:
            try:
                raw = await websocket.receive_text()
                envelope = decode_event(raw)

                category = (
                    RateLimitCategory.HEARTBEAT
                    if envelope.type == RealtimeEventType.PING
                    else (
                        RateLimitCategory.MESSAGE_ACKNOWLEDGEMENT
                        if envelope.type
                        == RealtimeEventType.MESSAGE_ACKNOWLEDGEMENT
                        else RateLimitCategory.GENERAL
                    )
                )

                await realtime_rate_limiter.enforce(
                    authenticated_device_id,
                    category,
                )

                await _handle_authenticated_event(
                    websocket,
                    user_id=authenticated_user_id,
                    device_id=authenticated_device_id,
                    envelope=envelope,
                )

                invalid_events = 0

            except RealtimeRateLimitExceeded as exc:
                await _send_error(
                    websocket,
                    "RATE_LIMITED",
                    "Too many events. Please slow down.",
                    retryable=True,
                )

                if exc.retry_after_seconds > 30:
                    await websocket.close(code=1008)
                    return

            except InvalidRealtimeEventError:
                invalid_events += 1

                await _send_error(
                    websocket,
                    "INVALID_EVENT",
                    "The event format is invalid.",
                )

                if invalid_events >= MAX_CONSECUTIVE_INVALID_EVENTS:
                    await websocket.close(code=1008)
                    return

            except ValidationError:
                invalid_events += 1

                await _send_error(
                    websocket,
                    "INVALID_PAYLOAD",
                    "The event payload is invalid.",
                )

                if invalid_events >= MAX_CONSECUTIVE_INVALID_EVENTS:
                    await websocket.close(code=1008)
                    return

    except WebSocketDisconnect:
        pass

    except Exception:
        logger.exception(
            "Unexpected real-time WebSocket failure",
            extra={
                "device_id": (
                    str(authenticated_device_id)
                    if authenticated_device_id
                    else None
                ),
                "user_id": (
                    str(authenticated_user_id)
                    if authenticated_user_id
                    else None
                ),
            },
        )

        if websocket.client_state == WebSocketState.CONNECTED:
            try:
                await websocket.close(code=1011)
            except Exception:
                pass

    finally:
        if authenticated_device_id is not None and connection_id is not None:
            await device_connection_manager.unregister(
                device_id=authenticated_device_id,
                connection_id=connection_id,
                websocket=websocket,
            )


@router.get("/status")
async def realtime_status() -> dict[str, str | int]:
    """Return basic service status without exposing device identities."""
    return {
        "service": "GhostSim Real-Time",
        "protocol_version": 1,
        "status": "available",
    }
