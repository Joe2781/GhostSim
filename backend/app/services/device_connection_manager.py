from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from fastapi import WebSocket
from starlette.websockets import WebSocketDisconnect, WebSocketState


logger = logging.getLogger("ghostsim.connections")


class DeviceConnectionError(Exception):
    """Base exception for device connection operations."""


class DeviceNotConnectedError(DeviceConnectionError):
    """Raised when a device has no active connection."""


class DeviceConnectionLimitError(DeviceConnectionError):
    """Raised when a device exceeds its permitted connection count."""


@dataclass(frozen=True, slots=True)
class ConnectionSnapshot:
    device_id: UUID
    connection_id: str
    connected_at: float
    last_activity_at: float


@dataclass(slots=True)
class _ActiveConnection:
    device_id: UUID
    connection_id: str
    websocket: WebSocket
    connected_at: float
    last_activity_at: float
    send_lock: asyncio.Lock


class DeviceConnectionManager:
    """
    Manages authenticated, live WebSocket connections for GhostSim devices.

    Authentication must happen before register() is called.

    This manager does not authenticate devices, create sessions, or authorize
    relay participation. Those responsibilities belong to the authentication
    and device authorization layers.

    Connections are held in process memory. A multi-instance deployment will
    require shared connection routing or a dedicated signaling layer.
    """

    def __init__(self, max_connections_per_device: int = 3) -> None:
        if max_connections_per_device < 1:
            raise ValueError("max_connections_per_device must be at least 1")

        self._max_connections_per_device = max_connections_per_device
        self._connections: dict[UUID, dict[str, _ActiveConnection]] = {}
        self._lock = asyncio.Lock()

    async def register(
        self,
        device_id: UUID,
        connection_id: str,
        websocket: WebSocket,
    ) -> ConnectionSnapshot:
        """
        Register an already-authenticated WebSocket connection.

        The caller is responsible for accepting the WebSocket and verifying
        that the authenticated account owns the device.
        """
        if not connection_id or not connection_id.strip():
            raise ValueError("connection_id must not be empty")

        if websocket.client_state != WebSocketState.CONNECTED:
            raise DeviceConnectionError(
                "WebSocket must be connected before registration"
            )

        now = time.time()

        async with self._lock:
            device_connections = self._connections.setdefault(device_id, {})

            existing = device_connections.get(connection_id)
            if existing is not None:
                if existing.websocket is websocket:
                    existing.last_activity_at = now
                    return self._snapshot(existing)

                raise DeviceConnectionError(
                    "Connection ID is already registered"
                )

            if len(device_connections) >= self._max_connections_per_device:
                if not device_connections:
                    self._connections.pop(device_id, None)

                raise DeviceConnectionLimitError(
                    "Device has reached its active connection limit"
                )

            connection = _ActiveConnection(
                device_id=device_id,
                connection_id=connection_id,
                websocket=websocket,
                connected_at=now,
                last_activity_at=now,
                send_lock=asyncio.Lock(),
            )

            device_connections[connection_id] = connection

            return self._snapshot(connection)

    async def unregister(
        self,
        device_id: UUID,
        connection_id: str,
        websocket: WebSocket | None = None,
    ) -> bool:
        """
        Remove a connection without accidentally removing its replacement.

        When websocket is supplied, removal occurs only if the stored WebSocket
        is the same object. Returns True when a connection was removed.
        """
        async with self._lock:
            device_connections = self._connections.get(device_id)
            if not device_connections:
                return False

            connection = device_connections.get(connection_id)
            if connection is None:
                return False

            if websocket is not None and connection.websocket is not websocket:
                return False

            device_connections.pop(connection_id, None)

            if not device_connections:
                self._connections.pop(device_id, None)

            return True

    async def send_to_device(
        self,
        device_id: UUID,
        payload: dict[str, Any],
        connection_id: str | None = None,
    ) -> int:
        """
        Send a JSON event to one or more active connections for a device.

        Returns the number of connections that accepted the send operation.
        A successful WebSocket send is not proof that the recipient application
        processed or acknowledged the event.
        """
        async with self._lock:
            device_connections = self._connections.get(device_id, {})

            if connection_id is not None:
                selected = device_connections.get(connection_id)
                connections = [selected] if selected is not None else []
            else:
                connections = list(device_connections.values())

        if not connections:
            raise DeviceNotConnectedError(
                f"No active connection for device {device_id}"
            )

        results = await asyncio.gather(
            *(self._send_json(connection, payload) for connection in connections),
            return_exceptions=True,
        )

        successful = 0
        failed_connections: list[tuple[str, WebSocket]] = []

        for connection, result in zip(connections, results):
            if result is True:
                successful += 1
            else:
                failed_connections.append(
                    (connection.connection_id, connection.websocket)
                )

        for failed_id, failed_websocket in failed_connections:
            await self.unregister(
                device_id=device_id,
                connection_id=failed_id,
                websocket=failed_websocket,
            )

        if successful == 0:
            raise DeviceNotConnectedError(
                f"Unable to deliver event to device {device_id}"
            )

        return successful

    async def _send_json(
        self,
        connection: _ActiveConnection,
        payload: dict[str, Any],
    ) -> bool:
        """Serialize sends for a connection and update its activity timestamp."""
        try:
            async with connection.send_lock:
                if (
                    connection.websocket.client_state
                    != WebSocketState.CONNECTED
                ):
                    return False

                await connection.websocket.send_json(payload)
                connection.last_activity_at = time.time()
                return True

        except (
            WebSocketDisconnect,
            RuntimeError,
            OSError,
        ):
            logger.info(
                "Device connection is no longer writable",
                extra={
                    "device_id": str(connection.device_id),
                    "connection_id": connection.connection_id,
                },
            )
            return False

        except Exception:
            logger.exception(
                "Unexpected error while sending a device event",
                extra={
                    "device_id": str(connection.device_id),
                    "connection_id": connection.connection_id,
                },
            )
            return False

    async def is_connected(self, device_id: UUID) -> bool:
        """Return whether the device currently has any registered connections."""
        async with self._lock:
            return bool(self._connections.get(device_id))

    async def connection_count(self, device_id: UUID) -> int:
        """Return the number of active connections registered for a device."""
        async with self._lock:
            return len(self._connections.get(device_id, {}))

    async def list_connections(
        self,
        device_id: UUID,
    ) -> list[ConnectionSnapshot]:
        """Return connection metadata without exposing WebSocket objects."""
        async with self._lock:
            connections = self._connections.get(device_id, {})
            return [
                self._snapshot(connection)
                for connection in connections.values()
            ]

    async def list_connected_device_ids(self) -> list[UUID]:
        """Return device IDs that currently have registered connections."""
        async with self._lock:
            return [
                device_id
                for device_id, connections in self._connections.items()
                if connections
            ]

    async def close_device_connections(
        self,
        device_id: UUID,
        code: int = 1000,
        reason: str = "Connection closed",
    ) -> int:
        """
        Remove and close all connections for a device.

        Call this after a device is revoked or its authenticated session is
        invalidated. The caller must perform the relevant authorization checks.
        """
        async with self._lock:
            connections = list(
                self._connections.pop(device_id, {}).values()
            )

        if not connections:
            return 0

        async def close_connection(
            connection: _ActiveConnection,
        ) -> bool:
            try:
                async with connection.send_lock:
                    if (
                        connection.websocket.client_state
                        == WebSocketState.CONNECTED
                    ):
                        await connection.websocket.close(
                            code=code,
                            reason=reason,
                        )
                return True
            except Exception:
                logger.info(
                    "Could not cleanly close device connection",
                    extra={
                        "device_id": str(device_id),
                        "connection_id": connection.connection_id,
                    },
                )
                return False

        await asyncio.gather(
            *(close_connection(connection) for connection in connections),
            return_exceptions=True,
        )

        return len(connections)

    @staticmethod
    def _snapshot(connection: _ActiveConnection) -> ConnectionSnapshot:
        return ConnectionSnapshot(
            device_id=connection.device_id,
            connection_id=connection.connection_id,
            connected_at=connection.connected_at,
            last_activity_at=connection.last_activity_at,
        )


# One manager per backend process.
device_connection_manager = DeviceConnectionManager(
    max_connections_per_device=3
)
