"""GhostSim background message delivery worker.

This worker manages queue leases and delegates actual network delivery
to an injected transport implementation. It never treats a queue claim
as proof of delivery.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import socket
import uuid
from dataclasses import dataclass
from typing import Protocol

from app.services.message_delivery import (
    ClaimedDelivery,
    MessageDeliveryError,
    claim_queued_deliveries,
    mark_delivery_sent,
    record_delivery_failure,
    release_delivery_lease,
)

logger = logging.getLogger(__name__)

DEFAULT_POLL_INTERVAL_SECONDS = 1.0
MAX_POLL_INTERVAL_SECONDS = 30.0
DEFAULT_BATCH_SIZE = 25
MAX_CONCURRENT_DELIVERIES = 10


@dataclass(frozen=True)
class TransportResult:
    """Result returned by a real authenticated transport."""

    accepted: bool
    error_code: str | None = None


class MessageTransport(Protocol):
    """Interface implemented by GhostSim's authenticated transport."""

    async def send(self, delivery: ClaimedDelivery) -> TransportResult:
        """Send a delivery and return its actual transport result."""
        ...


class TransportUnavailableError(Exception):
    """Raised when no usable message transport is configured."""


class MessageDeliveryWorker:
    """Lease-aware worker for queued GhostSim messages."""

    def __init__(
        self,
        *,
        worker_id: str | None = None,
        transport: MessageTransport | None = None,
        poll_interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS,
        batch_size: int = DEFAULT_BATCH_SIZE,
        max_concurrent_deliveries: int = MAX_CONCURRENT_DELIVERIES,
    ) -> None:
        if not 0.1 <= poll_interval_seconds <= MAX_POLL_INTERVAL_SECONDS:
            raise ValueError(
                f"poll_interval_seconds must be between 0.1 and "
                f"{MAX_POLL_INTERVAL_SECONDS}."
            )

        if not 1 <= batch_size <= 100:
            raise ValueError("batch_size must be between 1 and 100.")

        if not 1 <= max_concurrent_deliveries <= 100:
            raise ValueError(
                "max_concurrent_deliveries must be between 1 and 100."
            )

        hostname = socket.gethostname() or "ghostsim-worker"
        self.worker_id = worker_id or (
            f"{hostname}:{os.getpid()}:{uuid.uuid4().hex[:12]}"
        )
        self.transport = transport
        self.poll_interval_seconds = poll_interval_seconds
        self.batch_size = batch_size
        self.max_concurrent_deliveries = max_concurrent_deliveries
        self._stopping = asyncio.Event()
        self._semaphore = asyncio.Semaphore(max_concurrent_deliveries)

    def stop(self) -> None:
        """Request a graceful shutdown."""
        self._stopping.set()

    async def _process_delivery(self, delivery: ClaimedDelivery) -> None:
        async with self._semaphore:
            if self._stopping.is_set():
                try:
                    await release_delivery_lease(
                        delivery.delivery_id,
                        self.worker_id,
                    )
                except MessageDeliveryError:
                    logger.exception(
                        "Could not release delivery during shutdown: %s",
                        delivery.delivery_id,
                    )
                return

            if self.transport is None:
                # Do not increment attempts or claim a delivery was sent
                # when no real transport has been configured.
                try:
                    await release_delivery_lease(
                        delivery.delivery_id,
                        self.worker_id,
                    )
                except MessageDeliveryError:
                    logger.exception(
                        "Could not release delivery without transport: %s",
                        delivery.delivery_id,
                    )

                logger.warning(
                    "No message transport configured; released delivery %s.",
                    delivery.delivery_id,
                )
                return

            try:
                result = await self.transport.send(delivery)

                if result.accepted:
                    await mark_delivery_sent(
                        delivery.delivery_id,
                        self.worker_id,
                    )
                    logger.info(
                        "Transport accepted delivery %s.",
                        delivery.delivery_id,
                    )
                else:
                    error_code = result.error_code or "transport_rejected"
                    await record_delivery_failure(
                        delivery.delivery_id,
                        self.worker_id,
                        error_code,
                    )
                    logger.warning(
                        "Transport rejected delivery %s: %s",
                        delivery.delivery_id,
                        error_code,
                    )

            except asyncio.CancelledError:
                # The lease will expire and become reclaimable if it cannot
                # be released during cancellation.
                try:
                    await release_delivery_lease(
                        delivery.delivery_id,
                        self.worker_id,
                    )
                except MessageDeliveryError:
                    logger.exception(
                        "Could not release cancelled delivery %s.",
                        delivery.delivery_id,
                    )
                raise

            except MessageDeliveryError:
                logger.exception(
                    "Queue operation failed for delivery %s.",
                    delivery.delivery_id,
                )

            except Exception:
                logger.exception(
                    "Unexpected transport failure for delivery %s.",
                    delivery.delivery_id,
                )
                try:
                    await record_delivery_failure(
                        delivery.delivery_id,
                        self.worker_id,
                        "transport_exception",
                    )
                except MessageDeliveryError:
                    logger.exception(
                        "Could not record transport failure for delivery %s.",
                        delivery.delivery_id,
                    )

    async def run(self) -> None:
        """Poll the queue until a graceful shutdown is requested."""
        logger.info("GhostSim message worker started: %s", self.worker_id)

        while not self._stopping.is_set():
            try:
                deliveries = await claim_queued_deliveries(
                    self.worker_id,
                    batch_size=self.batch_size,
                )

                if deliveries:
                    await asyncio.gather(
                        *(
                            self._process_delivery(delivery)
                            for delivery in deliveries
                        )
                    )
                    continue

            except asyncio.CancelledError:
                raise

            except MessageDeliveryError:
                logger.exception("Message queue operation failed.")

            except Exception:
                logger.exception("Unexpected message worker error.")

            try:
                await asyncio.wait_for(
                    self._stopping.wait(),
                    timeout=self.poll_interval_seconds,
                )
            except asyncio.TimeoutError:
                pass

        logger.info("GhostSim message worker stopped: %s", self.worker_id)


async def run_worker() -> None:
    """Run the worker process.

    A real transport must be supplied by the deployment entry point.
    Without one, the worker safely releases claims instead of pretending
    that messages were sent.
    """
    worker = MessageDeliveryWorker()

    loop = asyncio.get_running_loop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, worker.stop)
        except (NotImplementedError, RuntimeError):
            # Some environments do not support asyncio signal handlers.
            pass

    await worker.run()


if __name__ == "__main__":
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    asyncio.run(run_worker())
