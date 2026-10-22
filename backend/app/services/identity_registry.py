"""GhostSim verified identity registry.

Responsibilities:
- Register an account from a previously verified identity.
- Resolve an existing account using its provider-issued subject.
- Never automatically link accounts merely because email addresses match.
- Record identity creation in the security audit log.
- Keep database changes transactional.
- Never store provider access tokens, passwords, or private keys.

IMPORTANT:
The caller must independently verify the authentication provider's
signature, issuer, audience, expiry, nonce/state where applicable,
and other required protocol checks before calling this module.

This module does not implement OAuth/OIDC verification or password
authentication. It must never receive an unverified provider subject.
"""

from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass
from typing import Literal

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.db import get_session_factory

logger = logging.getLogger("ghostsim.identity.registry")

IdentityProvider = Literal[
    "email",
    "google",
    "apple",
    "facebook",
    "github",
    "microsoft",
    "yahoo",
]

SUPPORTED_PROVIDERS = frozenset(
    {
        "email",
        "google",
        "apple",
        "facebook",
        "github",
        "microsoft",
        "yahoo",
    }
)

COUNTRY_CODE_PATTERN = re.compile(r"^[A-Z]{2}$")

MAX_PROVIDER_SUBJECT_LENGTH = 512
MAX_EMAIL_LENGTH = 320
MAX_DISPLAY_NAME_LENGTH = 80
MAX_LANGUAGE_LENGTH = 35


class IdentityRegistryError(Exception):
    """Base exception for identity registry operations."""


class IdentityInputError(IdentityRegistryError):
    """Raised when identity registration input is invalid."""


class IdentityRegistryStorageError(IdentityRegistryError):
    """Raised when identity data cannot be persisted or retrieved."""


@dataclass(frozen=True, slots=True)
class RegisteredIdentity:
    """The account and provider identity resolved by the registry.

    This object contains no access token, refresh token, password,
    or private cryptographic key.
    """

    account_id: uuid.UUID
    identity_id: uuid.UUID
    provider: str
    provider_subject: str
    identity_country: str
    account_status: str
    created: bool
    email: str | None
    email_verified: bool
    display_name: str | None


def _validate_provider(provider: str) -> str:
    if not isinstance(provider, str):
        raise IdentityInputError("Authentication provider is invalid.")

    normalized = provider.strip().lower()

    if normalized not in SUPPORTED_PROVIDERS:
        raise IdentityInputError(
            "The authentication provider is not supported."
        )

    return normalized


def _validate_provider_subject(provider_subject: str) -> str:
    if not isinstance(provider_subject, str):
        raise IdentityInputError(
            "The verified provider subject must be text."
        )

    subject = provider_subject.strip()

    if not subject or len(subject) > MAX_PROVIDER_SUBJECT_LENGTH:
        raise IdentityInputError(
            "The verified provider subject has an invalid length."
        )

    # Provider subjects are opaque identifiers. Do not lowercase,
    # rewrite, or otherwise normalize their contents.
    return subject


def _validate_country_code(identity_country: str) -> str:
    if not isinstance(identity_country, str):
        raise IdentityInputError(
            "The account identity country must be a two-letter code."
        )

    country = identity_country.strip().upper()

    if not COUNTRY_CODE_PATTERN.fullmatch(country):
        raise IdentityInputError(
            "The account identity country must be a valid-format "
            "two-letter uppercase code."
        )

    return country


def _validate_optional_email(
    email: str | None,
    email_verified: bool,
) -> str | None:
    if not isinstance(email_verified, bool):
        raise IdentityInputError(
            "The email verification status must be a boolean."
        )

    if email is None:
        return None

    if not isinstance(email, str):
        raise IdentityInputError("Email must be text.")

    normalized = email.strip()

    if not normalized:
        return None

    if len(normalized) > MAX_EMAIL_LENGTH:
        raise IdentityInputError("Email exceeds the maximum length.")

    # This is deliberately a basic structural check, not proof that
    # the address exists or belongs to the user. Ownership must be
    # established by the trusted authentication provider.
    if (
        normalized.count("@") != 1
        or normalized.startswith("@")
        or normalized.endswith("@")
        or any(character.isspace() for character in normalized)
    ):
        raise IdentityInputError("Email has an invalid format.")

    local_part, domain_part = normalized.rsplit("@", 1)

    if not local_part or "." not in domain_part:
        raise IdentityInputError("Email has an invalid format.")

    return normalized


def _validate_display_name(
    display_name: str | None,
) -> str | None:
    if display_name is None:
        return None

    if not isinstance(display_name, str):
        raise IdentityInputError("Display name must be text.")

    normalized = display_name.strip()

    if not normalized:
        return None

    if len(normalized) > MAX_DISPLAY_NAME_LENGTH:
        raise IdentityInputError(
            "Display name cannot exceed 80 characters."
        )

    return normalized


def _validate_language(preferred_language: str) -> str:
    if not isinstance(preferred_language, str):
        raise IdentityInputError(
            "Preferred language must be text."
        )

    language = preferred_language.strip()

    if not 2 <= len(language) <= MAX_LANGUAGE_LENGTH:
        raise IdentityInputError(
            "Preferred language must contain between 2 and 35 characters."
        )

    return language


async def register_verified_identity(
    *,
    provider: IdentityProvider | str,
    provider_subject: str,
    identity_country: str,
    email: str | None = None,
    email_verified: bool = False,
    display_name: str | None = None,
    preferred_language: str = "en",
) -> RegisteredIdentity:
    """Create or resolve a GhostSim account from a verified identity.

    The caller must verify the identity provider's authentication
    response before calling this function.

    Behavior:
    1. If the provider subject already exists, return its account.
    2. Otherwise, create a user and provider identity atomically.
    3. If another request registers the same identity concurrently,
       resolve and return the winning account.
    4. Never link an identity to an account based only on email.
    5. Record newly created identities in the security audit log.

    This function does not create an authentication session or
    assign a public GhostSim ID. Those are separate operations.
    """

    normalized_provider = _validate_provider(provider)
    normalized_subject = _validate_provider_subject(provider_subject)
    normalized_country = _validate_country_code(identity_country)
    normalized_email = _validate_optional_email(
        email,
        email_verified,
    )
    normalized_display_name = _validate_display_name(display_name)
    normalized_language = _validate_language(preferred_language)

    session_factory = get_session_factory()

    try:
        async with session_factory() as session:
            async with session.begin():
                # Fast path: resolve an identity that already exists.
                existing_result = await session.execute(
                    text(
                        """
                        SELECT
                            ai.id AS identity_id,
                            ai.user_id AS account_id,
                            ai.provider,
                            ai.provider_subject,
                            ai.email,
                            ai.email_verified,
                            u.identity_country,
                            u.status AS account_status,
                            u.display_name
                        FROM auth_identities AS ai
                        JOIN users AS u
                          ON u.id = ai.user_id
                        WHERE ai.provider = :provider
                          AND ai.provider_subject = :provider_subject
                        FOR UPDATE OF u
                        """
                    ),
                    {
                        "provider": normalized_provider,
                        "provider_subject": normalized_subject,
                    },
                )

                existing = existing_result.mappings().one_or_none()

                if existing is not None:
                    # Refresh authentication activity only after the
                    # caller has verified the provider identity.
                    await session.execute(
                        text(
                            """
                            UPDATE auth_identities
                            SET last_authenticated_at = NOW()
                            WHERE id = :identity_id
                            """
                        ),
                        {"identity_id": str(existing["identity_id"])},
                    )

                    return RegisteredIdentity(
                        account_id=existing["account_id"],
                        identity_id=existing["identity_id"],
                        provider=existing["provider"],
                        provider_subject=existing["provider_subject"],
                        identity_country=existing["identity_country"],
                        account_status=existing["account_status"],
                        created=False,
                        email=existing["email"],
                        email_verified=existing["email_verified"],
                        display_name=existing["display_name"],
                    )

                # Create a permanent internal account UUID. The public
                # GhostSim ID is assigned separately by its own service.
                user_result = await session.execute(
                    text(
                        """
                        INSERT INTO users (
                            identity_country,
                            preferred_language,
                            display_name
                        )
                        VALUES (
                            :identity_country,
                            :preferred_language,
                            :display_name
                        )
                        RETURNING id, identity_country, status, display_name
                        """
                    ),
                    {
                        "identity_country": normalized_country,
                        "preferred_language": normalized_language,
                        "display_name": normalized_display_name,
                    },
                )

                user = user_result.mappings().one()

                # ON CONFLICT handles two simultaneous registrations
                # attempting to create the same provider identity.
                # No email-based account linking is performed.
                identity_result = await session.execute(
                    text(
                        """
                        INSERT INTO auth_identities (
                            user_id,
                            provider,
                            provider_subject,
                            email,
                            email_verified,
                            last_authenticated_at
                        )
                        VALUES (
                            :user_id,
                            :provider,
                            :provider_subject,
                            :email,
                            :email_verified,
                            NOW()
                        )
                        ON CONFLICT (provider, provider_subject)
                        DO NOTHING
                        RETURNING id, user_id
                        """
                    ),
                    {
                        "user_id": str(user["id"]),
                        "provider": normalized_provider,
                        "provider_subject": normalized_subject,
                        "email": normalized_email,
                        "email_verified": email_verified,
                    },
                )

                inserted_identity = (
                    identity_result.mappings().one_or_none()
                )

                if inserted_identity is None:
                    # Another transaction won the unique provider-subject
                    # race. Remove the unlinked account created by this
                    # transaction, then resolve the winning identity.
                    await session.execute(
                        text(
                            """
                            DELETE FROM users
                            WHERE id = :user_id
                              AND NOT EXISTS (
                                  SELECT 1
                                  FROM auth_identities
                                  WHERE user_id = :user_id
                              )
                            """
                        ),
                        {"user_id": str(user["id"])},
                    )

                    winner_result = await session.execute(
                        text(
                            """
                            SELECT
                                ai.id AS identity_id,
                                ai.user_id AS account_id,
                                ai.provider,
                                ai.provider_subject,
                                ai.email,
                                ai.email_verified,
                                u.identity_country,
                                u.status AS account_status,
                                u.display_name
                            FROM auth_identities AS ai
                            JOIN users AS u
                              ON u.id = ai.user_id
                            WHERE ai.provider = :provider
                              AND ai.provider_subject = :provider_subject
                            FOR UPDATE OF u
                            """
                        ),
                        {
                            "provider": normalized_provider,
                            "provider_subject": normalized_subject,
                        },
                    )

                    winner = winner_result.mappings().one_or_none()

                    if winner is None:
                        # This should be rare and can occur if an
                        # administrator removes the identity concurrently.
                        raise IdentityRegistryStorageError(
                            "The verified identity could not be resolved."
                        )

                    await session.execute(
                        text(
                            """
                            UPDATE auth_identities
                            SET last_authenticated_at = NOW()
                            WHERE id = :identity_id
                            """
                        ),
                        {"identity_id": str(winner["identity_id"])},
                    )

                    return RegisteredIdentity(
                        account_id=winner["account_id"],
                        identity_id=winner["identity_id"],
                        provider=winner["provider"],
                        provider_subject=winner["provider_subject"],
                        identity_country=winner["identity_country"],
                        account_status=winner["account_status"],
                        created=False,
                        email=winner["email"],
                        email_verified=winner["email_verified"],
                        display_name=winner["display_name"],
                    )

                # Audit only controlled metadata. Never include email,
                # provider subject, tokens, or other identity claims.
                await session.execute(
                    text(
                        """
                        INSERT INTO security_audit_events (
                            user_id,
                            event_type,
                            outcome,
                            metadata
                        )
                        VALUES (
                            :user_id,
                            'identity_added',
                            'success',
                            CAST(:metadata AS JSONB)
                        )
                        """
                    ),
                    {
                        "user_id": str(user["id"]),
                        "metadata": (
                            '{"provider":"'
                            + normalized_provider
                            + '","registration_method":'
                            '"verified_provider_identity"}'
                        ),
                    },
                )

                return RegisteredIdentity(
                    account_id=user["id"],
                    identity_id=inserted_identity["id"],
                    provider=normalized_provider,
                    provider_subject=normalized_subject,
                    identity_country=user["identity_country"],
                    account_status=user["status"],
                    created=True,
                    email=normalized_email,
                    email_verified=email_verified,
                    display_name=user["display_name"],
                )

    except IdentityRegistryError:
        raise

    except SQLAlchemyError as exc:
        logger.warning(
            "Identity registration failed (%s).",
            type(exc).__name__,
        )
        raise IdentityRegistryStorageError(
            "Identity registration is temporarily unavailable."
        ) from exc
