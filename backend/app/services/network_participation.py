"""GhostSim network participation and consent management.

Controls whether an activated device may participate in the
distributed GhostSim network.

Device registration and network participation are separate:
a registered device must not relay traffic or cache content
unless the owner has explicitly enabled those capabilities.

This module persists real consent and capability settings in
PostgreSQL. It does not pretend to establish network connections.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass
from typing import Literal

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.db import get_session_factory


logger = logging.getLogger("ghostsim.network_participation")


ParticipationStatus = Literal[
    "disabled",
    "active",
]

_MAX_RELAY_BANDWIDTH_KBPS = 1_000_000
_MAX_CONCURRENT_RELAYS = 100
_MAX_CACHE_BYTES = 10**13


class NetworkParticipationError(Exception):
    """Base exception for network participation operations."""


class ParticipationValidationError(NetworkParticipationError):
    """A participation setting is invalid."""


class ParticipationDeviceNotFoundError(NetworkParticipationError):
    """The device does not belong to the requesting account."""


class ParticipationDeviceNotEligibleError(NetworkParticipationError):
    """The device is not eligible to participate."""


@dataclass(frozen=True, slots=True)
class NetworkParticipation:
    """Persisted network participation settings for a device."""

    device_id: uuid.UUID
    user_id: uuid.UUID
    participation_status: str
    owner_consent: bool
    can_discover_peers: bool
    can_relay_traffic: bool
    can_cache_content: bool
    max_relay_bandwidth_kbps: int
    max_concurrent_relays: int
    max_cache_bytes: int
    allow_metered_networks: bool
    allow_battery_powered_relay: bool


def _row_to_participation(row) -> NetworkParticipation:
    """Convert a database row into a participation record."""
    return NetworkParticipation(
        device_id=row["device_id"],
        user_id=row["user_id"],
        participation_status=row["participation_status"],
        owner_consent=(
            row["owner_consent_at"] is not None
            and row["consent_revoked_at"] is None
        ),
        can_discover_peers=row["can_discover_peers"],
        can_relay_traffic=row["can_relay_traffic"],
        can_cache_content=row["can_cache_content"],
        max_relay_bandwidth_kbps=row["max_relay_bandwidth_kbps"],
        max_concurrent_relays=row["max_concurrent_relays"],
        max_cache_bytes=row["max_cache_bytes"],
        allow_metered_networks=row["allow_metered_networks"],
        allow_battery_powered_relay=(
            row["allow_battery_powered_relay"]
        ),
    )


def _validate_nonnegative_integer(
    name: str,
    value: int,
    maximum: int,
) -> int:
    """Validate a resource limit without accepting booleans."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ParticipationValidationError(
            f"{name} must be an integer."
        )

    if not 0 <= value <= maximum:
        raise ParticipationValidationError(
            f"{name} must be between 0 and {maximum}."
        )

    return value


async def get_network_participation(
    *,
    user_id: uuid.UUID,
    device_id: uuid.UUID,
) -> NetworkParticipation:
    """Return the persisted participation settings for one device.

    The device must belong to the authenticated account.
    A device without a participation profile is reported as
    disabled; reading settings does not create or enable a profile.
    """
    if (
        not isinstance(user_id, uuid.UUID)
        or not isinstance(device_id, uuid.UUID)
    ):
        raise ParticipationValidationError(
            "Valid account and device UUIDs are required."
        )

    session_factory = get_session_factory()

    try:
        async with session_factory() as session:
            result = await session.execute(
                text(
                    """
                    SELECT
                        d.id AS device_id,
                        d.user_id,
                        COALESCE(
                            np.participation_status,
                            'disabled'
                        ) AS participation_status,
                        np.owner_consent_at,
                        np.consent_revoked_at,
                        COALESCE(
                            np.can_discover_peers,
                            FALSE
                        ) AS can_discover_peers,
                        COALESCE(
                            np.can_relay_traffic,
                            FALSE
                        ) AS can_relay_traffic,
                        COALESCE(
                            np.can_cache_content,
                            FALSE
                        ) AS can_cache_content,
                        COALESCE(
                            np.max_relay_bandwidth_kbps,
                            0
                        ) AS max_relay_bandwidth_kbps,
                        COALESCE(
                            np.max_concurrent_relays,
                            0
                        ) AS max_concurrent_relays,
                        COALESCE(
                            np.max_cache_bytes,
                            0
                        ) AS max_cache_bytes,
                        COALESCE(
                            np.allow_metered_networks,
                            FALSE
                        ) AS allow_metered_networks,
                        COALESCE(
                            np.allow_battery_powered_relay,
                            FALSE
                        ) AS allow_battery_powered_relay
                    FROM devices AS d
                    LEFT JOIN device_network_profiles AS np
                      ON np.device_id = d.id
                    WHERE d.id = :device_id
                      AND d.user_id = :user_id
                    """
                ),
                {
                    "device_id": str(device_id),
                    "user_id": str(user_id),
                },
            )

            row = result.mappings().one_or_none()

            if row is None:
                raise ParticipationDeviceNotFoundError(
                    "The device was not found for this account."
                )

            return _row_to_participation(row)

    except NetworkParticipationError:
        raise

    except SQLAlchemyError as exc:
        logger.error(
            "Participation settings lookup failed (%s).",
            type(exc).__name__,
        )

        raise NetworkParticipationError(
            "Network participation settings are temporarily unavailable."
        ) from exc


async def set_network_participation(
    *,
    user_id: uuid.UUID,
    device_id: uuid.UUID,
    enabled: bool,
    can_discover_peers: bool = True,
    can_relay_traffic: bool = False,
    can_cache_content: bool = False,
    max_relay_bandwidth_kbps: int = 0,
    max_concurrent_relays: int = 0,
    max_cache_bytes: int = 0,
    allow_metered_networks: bool = False,
    allow_battery_powered_relay: bool = False,
) -> NetworkParticipation:
    """Enable or disable explicitly authorized device participation.

    The account and device IDs must come from trusted
    authentication context.

    Defaults are deliberately conservative:
    - Relay traffic is disabled.
    - Content caching is disabled.
    - Resource limits are zero.
    - Metered-network use is disabled.
    - Battery-powered relaying is disabled.

    Enabling participation records consent and preferences.
    It does not verify device capabilities, create peer links,
    establish internet reachability, or start packet forwarding.
    """
    if (
        not isinstance(user_id, uuid.UUID)
        or not isinstance(device_id, uuid.UUID)
    ):
        raise ParticipationValidationError(
            "Valid account and device UUIDs are required."
        )

    for name, value in (
        ("enabled", enabled),
        ("can_discover_peers", can_discover_peers),
        ("can_relay_traffic", can_relay_traffic),
        ("can_cache_content", can_cache_content),
        ("allow_metered_networks", allow_metered_networks),
        (
            "allow_battery_powered_relay",
            allow_battery_powered_relay,
        ),
    ):
        if not isinstance(value, bool):
            raise ParticipationValidationError(
                f"{name} must be a boolean."
            )

    bandwidth = _validate_nonnegative_integer(
        "max_relay_bandwidth_kbps",
        max_relay_bandwidth_kbps,
        _MAX_RELAY_BANDWIDTH_KBPS,
    )

    concurrent_relays = _validate_nonnegative_integer(
        "max_concurrent_relays",
        max_concurrent_relays,
        _MAX_CONCURRENT_RELAYS,
    )

    cache_bytes = _validate_nonnegative_integer(
        "max_cache_bytes",
        max_cache_bytes,
        _MAX_CACHE_BYTES,
    )

    if not enabled and (
        can_relay_traffic
        or can_cache_content
        or can_discover_peers
        or bandwidth
        or concurrent_relays
        or cache_bytes
    ):
        raise ParticipationValidationError(
            "Disabled participation cannot retain enabled "
            "capabilities or nonzero resource limits."
        )

    if enabled and not (
        can_discover_peers
        or can_relay_traffic
        or can_cache_content
    ):
        raise ParticipationValidationError(
            "Enable at least one network participation capability."
        )

    if can_relay_traffic and (
        bandwidth == 0 or concurrent_relays == 0
    ):
        raise ParticipationValidationError(
            "Traffic relaying requires nonzero bandwidth and "
            "concurrent-relay limits."
        )

    if not can_relay_traffic and (
        bandwidth != 0 or concurrent_relays != 0
    ):
        raise ParticipationValidationError(
            "Relay resource limits must be zero when relaying "
            "is disabled."
        )

    if can_cache_content and cache_bytes == 0:
        raise ParticipationValidationError(
            "Content caching requires a nonzero cache limit."
        )

    if not can_cache_content and cache_bytes != 0:
        raise ParticipationValidationError(
            "The cache limit must be zero when caching is disabled."
        )

    if not enabled and (
        allow_metered_networks
        or allow_battery_powered_relay
    ):
        raise ParticipationValidationError(
            "Network-use preferences cannot be enabled when "
            "participation is disabled."
        )

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

                device = (
                    device_result.mappings().one_or_none()
                )

                if device is None:
                    raise ParticipationDeviceNotFoundError(
                        "The device was not found for this account."
                    )

                if device["status"] != "active":
                    raise ParticipationDeviceNotEligibleError(
                        "Only an activated device can participate "
                        "in the GhostSim network."
                    )

                if enabled:
                    status = "active"
                    consent_time_sql = "NOW()"
                    revoked_time_sql = "NULL"
                    discover_value = can_discover_peers
                    relay_value = can_relay_traffic
                    cache_value = can_cache_content
                    bandwidth_value = bandwidth
                    concurrent_value = concurrent_relays
                    cache_bytes_value = cache_bytes
                    metered_value = allow_metered_networks
                    battery_value = allow_battery_powered_relay
                    event_type = "network_consent_granted"
                else:
                    status = "disabled"
                    consent_time_sql = "owner_consent_at"
                    revoked_time_sql = "NOW()"
                    discover_value = False
                    relay_value = False
                    cache_value = False
                    bandwidth_value = 0
                    concurrent_value = 0
                    cache_bytes_value = 0
                    metered_value = False
                    battery_value = False
                    event_type = "network_consent_revoked"

                # The status and capability values are controlled
                # internally, not interpolated from user input.
                upsert_sql = f"""
                    INSERT INTO device_network_profiles (
                        device_id,
                        participation_status,
                        owner_consent_at,
                        consent_revoked_at,
                        can_discover_peers,
                        can_relay_traffic,
                        can_cache_content,
                        max_relay_bandwidth_kbps,
                        max_concurrent_relays,
                        max_cache_bytes,
                        allow_metered_networks,
                        allow_battery_powered_relay,
                        last_capability_check_at
                    )
                    VALUES (
                        :device_id,
                        :status,
                        {consent_time_sql},
                        {revoked_time_sql},
                        :discover,
                        :relay,
                        :cache,
                        :bandwidth,
                        :concurrent,
                        :cache_bytes,
                        :metered,
                        :battery,
                        NULL
                    )
                    ON CONFLICT (device_id)
                    DO UPDATE SET
                        participation_status = EXCLUDED.participation_status,
                        owner_consent_at = CASE
                            WHEN EXCLUDED.participation_status = 'active'
                            THEN NOW()
                            ELSE device_network_profiles.owner_consent_at
                        END,
                        consent_revoked_at = CASE
                            WHEN EXCLUDED.participation_status = 'active'
                            THEN NULL
                            ELSE NOW()
                        END,
                        can_discover_peers = EXCLUDED.can_discover_peers,
                        can_relay_traffic = EXCLUDED.can_relay_traffic,
                        can_cache_content = EXCLUDED.can_cache_content,
                        max_relay_bandwidth_kbps =
                            EXCLUDED.max_relay_bandwidth_kbps,
                        max_concurrent_relays =
                            EXCLUDED.max_concurrent_relays,
                        max_cache_bytes = EXCLUDED.max_cache_bytes,
                        allow_metered_networks =
                            EXCLUDED.allow_metered_networks,
                        allow_battery_powered_relay =
                            EXCLUDED.allow_battery_powered_relay,
                        last_capability_check_at = NULL,
                        updated_at = NOW()
                    RETURNING
                        device_id,
                        participation_status,
                        owner_consent_at,
                        consent_revoked_at,
                        can_discover_peers,
                        can_relay_traffic,
                        can_cache_content,
                        max_relay_bandwidth_kbps,
                        max_concurrent_relays,
                        max_cache_bytes,
                        allow_metered_networks,
                        allow_battery_powered_relay
                """

                profile_result = await session.execute(
                    text(upsert_sql),
                    {
                        "device_id": str(device_id),
                        "status": status,
                        "discover": discover_value,
                        "relay": relay_value,
                        "cache": cache_value,
                        "bandwidth": bandwidth_value,
                        "concurrent": concurrent_value,
                        "cache_bytes": cache_bytes_value,
                        "metered": metered_value,
                        "battery": battery_value,
                    },
                )

                profile = (
                    profile_result.mappings().one()
                )

                audit_metadata = json.dumps(
                    {
                        "participation_status": status,
                        "can_discover_peers": discover_value,
                        "can_relay_traffic": relay_value,
                        "can_cache_content": cache_value,
                    },
                    separators=(",", ":"),
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
                            :event_type,
                            'success',
                            CAST(:metadata AS JSONB)
                        )
                        """
                    ),
                    {
                        "user_id": str(user_id),
                        "device_id": str(device_id),
                        "event_type": event_type,
                        "metadata": audit_metadata,
                    },
                )

                return NetworkParticipation(
                    device_id=device_id,
                    user_id=user_id,
                    participation_status=profile[
                        "participation_status"
                    ],
                    owner_consent=(
                        profile["owner_consent_at"] is not None
                        and profile["consent_revoked_at"] is None
                    ),
                    can_discover_peers=profile[
                        "can_discover_peers"
                    ],
                    can_relay_traffic=profile[
                        "can_relay_traffic"
                    ],
                    can_cache_content=profile[
                        "can_cache_content"
                    ],
                    max_relay_bandwidth_kbps=profile[
                        "max_relay_bandwidth_kbps"
                    ],
                    max_concurrent_relays=profile[
                        "max_concurrent_relays"
                    ],
                    max_cache_bytes=profile["max_cache_bytes"],
                    allow_metered_networks=profile[
                        "allow_metered_networks"
                    ],
                    allow_battery_powered_relay=profile[
                        "allow_battery_powered_relay"
                    ],
                )

    except NetworkParticipationError:
        raise

    except SQLAlchemyError as exc:
        logger.error(
            "Network participation update failed (%s).",
            type(exc).__name__,
        )

        raise NetworkParticipationError(
            "Network participation could not be updated."
        ) from exc
