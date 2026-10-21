"""GhostSim public ID assignment service.

Public IDs have the format CC·XXXXXX, where CC is the
account's two-letter identity-country code and XXXXXX is a
six-character uppercase alphanumeric suffix.

The authenticated account UUID remains the permanent identity.

This module performs real PostgreSQL operations. It does not
create fake users or assign IDs without a database transaction.
"""

from future import annotations

import logging
import secrets
import string
import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.db import get_session_factory

logger = logging.getLogger("ghostsim.identity")

_SUFFIX_ALPHABET = string.ascii_uppercase + string.digits
_SUFFIX_LENGTH = 6
_MAX_ALLOCATION_ATTEMPTS = 10

class GhostSimIDError(Exception):
"""Base exception for GhostSim ID allocation."""

class AccountNotFoundError(GhostSimIDError):
"""The requested account does not exist."""

class AccountNotEligibleError(GhostSimIDError):
"""The account cannot receive an ID in its current state."""

class IDAllocationError(GhostSimIDError):
"""A public ID could not be allocated."""

@dataclass(frozen=True, slots=True)
class GhostSimIDAssignment:
"""A public GhostSim ID and its assignment-history record."""

account_id: uuid.UUID
assignment_id: uuid.UUID
country_code: str
suffix: str
assigned_at: datetime

@property
def public_id(self) -> str:
    """Return the human-readable public ID."""
    return f"{self.country_code}·{self.suffix}"

def _generate_suffix() -> str:
"""Generate a cryptographically random six-character suffix."""
return "".join(
secrets.choice(_SUFFIX_ALPHABET)
for _ in range(_SUFFIX_LENGTH)
)

async def assign_ghostsim_id(
account_id: uuid.UUID,
) -> GhostSimIDAssignment:
"""Assign or retrieve the public ID for an existing account.

The country prefix comes from users.identity_country, not
from an arbitrary request parameter or a claimed IP address.

The caller must authenticate the account before calling this
service. Never expose this function through an unauthenticated
endpoint.

The ID and its assignment history are committed atomically.
The user row is locked to serialize allocations for the same
account.
"""

session_factory = get_session_factory()

try:
    async with session_factory() as session:
        async with session.begin():

            user_result = await session.execute(
                text(
                    """
                    SELECT id, status, identity_country
                    FROM users
                    WHERE id = :account_id
                    FOR UPDATE
                    """
                ),
                {"account_id": str(account_id)},
            )

            user = user_result.mappings().one_or_none()

            if user is None:
                raise AccountNotFoundError(
                    "The GhostSim account does not exist."
                )

            if user["status"] != "active":
                raise AccountNotEligibleError(
                    "This account is not eligible for ID assignment."
                )

            country_code = user["identity_country"]

            if (
                not isinstance(country_code, str)
                or len(country_code) != 2
                or not country_code.isalpha()
                or country_code != country_code.upper()
            ):
                raise AccountNotEligibleError(
                    "The account has an invalid identity-country code."
                )

            # Return an existing assignment and its actual
            # assignment-history record ID.
            existing_result = await session.execute(
                text(
                    """
                    SELECT
                        ga.id AS assignment_id,
                        gi.country_code,
                        gi.suffix,
                        ga.assigned_at
                    FROM ghostsim_ids AS gi
                    JOIN ghostsim_id_assignments AS ga
                      ON ga.ghostsim_id_id = gi.id
                     AND ga.user_id = gi.user_id
                    WHERE gi.user_id = :account_id
                      AND gi.status = 'assigned'
                    ORDER BY ga.assigned_at DESC, ga.id DESC
                    LIMIT 1
                    """
                ),
                {"account_id": str(account_id)},
            )

            existing = existing_result.mappings().one_or_none()

            if existing is not None:
                return GhostSimIDAssignment(
                    account_id=account_id,
                    assignment_id=existing["assignment_id"],
                    country_code=existing["country_code"],
                    suffix=existing["suffix"],
                    assigned_at=existing["assigned_at"],
                )

            # The database unique constraint remains the final
            # authority on country-prefix and suffix uniqueness.
            for _ in range(_MAX_ALLOCATION_ATTEMPTS):
                suffix = _generate_suffix()

                insert_result = await session.execute(
                    text(
                        """
                        INSERT INTO ghostsim_ids (
                            country_code,
                            suffix,
                            user_id,
                            status,
                            assigned_at
                        )
                        VALUES (
                            :country_code,
                            :suffix,
                            :account_id,
                            'assigned',
                            NOW()
                        )
                        ON CONFLICT (country_code, suffix)
                        DO NOTHING
                        RETURNING id, country_code, suffix, assigned_at
                        """
                    ),
                    {
                        "country_code": country_code,
                        "suffix": suffix,
                        "account_id": str(account_id),
                    },
                )

                assigned = insert_result.mappings().one_or_none()

                if assigned is None:
                    continue

                assignment_id = uuid.uuid4()

                await session.execute(
                    text(
                        """
                        INSERT INTO ghostsim_id_assignments (
                            id,
                            ghostsim_id_id,
                            user_id,
                            assigned_at
                        )
                        VALUES (
                            :assignment_id,
                            :ghostsim_id_id,
                            :account_id,
                            :assigned_at
                        )
                        """
                    ),
                    {
                        "assignment_id": str(assignment_id),
                        "ghostsim_id_id": str(assigned["id"]),
                        "account_id": str(account_id),
                        "assigned_at": assigned["assigned_at"],
                    },
                )

                return GhostSimIDAssignment(
                    account_id=account_id,
                    assignment_id=assignment_id,
                    country_code=assigned["country_code"],
                    suffix=assigned["suffix"],
                    assigned_at=assigned["assigned_at"],
                )

            raise IDAllocationError(
                "Unable to allocate a unique GhostSim ID. "
                "Please retry later."
            )

except GhostSimIDError:
    raise

except SQLAlchemyError as exc:
    # Never log connection strings, SQL parameters, or secrets.
    logger.error(
        "GhostSim ID allocation failed because of a database error."
    )

    raise IDAllocationError(
        "GhostSim ID allocation is temporarily unavailable."
    ) from exc
