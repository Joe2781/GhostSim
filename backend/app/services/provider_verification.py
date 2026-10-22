"""Trusted Firebase Authentication token verification for GhostSim.

This module verifies Firebase ID tokens on the backend. It never
accepts a client-supplied user ID as proof of identity.

Firebase Authentication must be configured for the providers used
by the application. Firebase Admin credentials must be supplied
through the server environment or application default credentials.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger("ghostsim.auth.provider_verification")

_firebase_initialization_lock = threading.Lock()

SUPPORTED_PROVIDERS = {
    "password": "email",
    "emailLink": "email",
    "google.com": "google",
    "apple.com": "apple",
    "facebook.com": "facebook",
    "github.com": "github",
    "microsoft.com": "microsoft",
    "yahoo.com": "yahoo",
}

MAX_ID_TOKEN_LENGTH = 16_384


class ProviderVerificationError(Exception):
    """Base exception for identity-provider verification failures."""


class InvalidProviderTokenError(ProviderVerificationError):
    """Raised when a provider token is invalid or expired."""


class UnsupportedIdentityProviderError(ProviderVerificationError):
    """Raised when the token uses an unsupported sign-in provider."""


class ProviderConfigurationError(ProviderVerificationError):
    """Raised when trusted Firebase server configuration is missing."""


@dataclass(frozen=True)
class VerifiedProviderIdentity:
    """Identity claims extracted from a successfully verified token."""

    provider: str
    provider_subject: str
    email: str | None
    email_verified: bool
    display_name: str | None
    preferred_language: str
    firebase_project_id: str


def _get_required_project_id() -> str:
    """Read the expected Firebase project ID from server configuration."""

    project_id = os.getenv("FIREBASE_PROJECT_ID", "").strip()

    if not project_id:
        raise ProviderConfigurationError(
            "FIREBASE_PROJECT_ID is not configured on the server."
        )

    if len(project_id) > 256:
        raise ProviderConfigurationError(
            "FIREBASE_PROJECT_ID has an invalid length."
        )

    return project_id


def _get_firebase_app(project_id: str) -> Any:
    """Return a Firebase Admin app initialized for the expected project."""

    try:
        import firebase_admin
        from firebase_admin import credentials

    except ImportError as exc:
        raise ProviderConfigurationError(
            "Firebase Admin SDK is not installed on the server."
        ) from exc

    try:
        return firebase_admin.get_app("ghostsim")

    except ValueError:
        pass

    with _firebase_initialization_lock:
        # Another request may have initialized the app while this
        # request waited for the initialization lock.
        try:
            return firebase_admin.get_app("ghostsim")
        except ValueError:
            pass

        service_account_json = os.getenv(
            "FIREBASE_SERVICE_ACCOUNT_JSON",
            "",
        ).strip()

        if service_account_json:
            try:
                service_account_data = json.loads(
                    service_account_json
                )
            except json.JSONDecodeError as exc:
                raise ProviderConfigurationError(
                    "FIREBASE_SERVICE_ACCOUNT_JSON is not valid JSON."
                ) from exc

            if not isinstance(service_account_data, dict):
                raise ProviderConfigurationError(
                    "Firebase service-account configuration must "
                    "be a JSON object."
                )

            credential_project = service_account_data.get(
                "project_id"
            )

            if credential_project != project_id:
                raise ProviderConfigurationError(
                    "The Firebase service-account project does not "
                    "match FIREBASE_PROJECT_ID."
                )

            try:
                credential = credentials.Certificate(
                    service_account_data
                )
            except Exception as exc:
                raise ProviderConfigurationError(
                    "The Firebase service-account credentials "
                    "could not be loaded."
                ) from exc

        else:
            # Supports workload identity and application-default
            # credentials. No credential file is committed to Git.
            try:
                credential = credentials.ApplicationDefault()
            except Exception as exc:
                raise ProviderConfigurationError(
                    "Firebase Admin credentials are not available."
                ) from exc

        try:
            return firebase_admin.initialize_app(
                credential,
                options={"projectId": project_id},
                name="ghostsim",
            )
        except Exception as exc:
            logger.error(
                "Firebase Admin initialization failed (%s).",
                type(exc).__name__,
            )
            raise ProviderConfigurationError(
                "Firebase Authentication verification is unavailable."
            ) from exc


def _optional_string(
    value: Any,
    *,
    field_name: str,
    maximum_length: int,
) -> str | None:
    """Normalize an optional string claim without trusting its shape."""

    if value is None:
        return None

    if not isinstance(value, str):
        return None

    normalized = value.strip()

    if not normalized:
        return None

    if len(normalized) > maximum_length:
        raise InvalidProviderTokenError(
            f"The verified {field_name} claim exceeds its allowed length."
        )

    return normalized


def verify_firebase_id_token(
    id_token: str,
) -> VerifiedProviderIdentity:
    """Verify a Firebase ID token and return its trusted identity.

    The Firebase Admin SDK verifies the token's signature, issuer,
    audience, expiry, and other required claims. Revocation and
    disabled-account checks are also requested.

    Never call this function with a provider access token, refresh
    token, arbitrary JWT, or an unverified decoded token.
    """

    if not isinstance(id_token, str):
        raise InvalidProviderTokenError(
            "A Firebase ID token is required."
        )

    token = id_token.strip()

    if not token or len(token) > MAX_ID_TOKEN_LENGTH:
        raise InvalidProviderTokenError(
            "The Firebase ID token is missing or has an invalid length."
        )

    project_id = _get_required_project_id()
    firebase_app = _get_firebase_app(project_id)

    try:
        from firebase_admin import auth

        claims = auth.verify_id_token(
            token,
            app=firebase_app,
            check_revoked=True,
        )

    except ProviderConfigurationError:
        raise

    except Exception as exc:
        # Do not return raw provider errors, token content, or claims
        # to the client or include them in logs.
        logger.info(
            "Firebase ID token verification rejected (%s).",
            type(exc).__name__,
        )
        raise InvalidProviderTokenError(
            "The identity token is invalid, expired, revoked, "
            "or belongs to a disabled account."
        ) from exc

    if not isinstance(claims, dict):
        raise InvalidProviderTokenError(
            "The verified token contains invalid claims."
        )

    token_project = claims.get("aud")

    if token_project != project_id:
        raise InvalidProviderTokenError(
            "The token belongs to a different Firebase project."
        )

    subject = claims.get("uid") or claims.get("sub")

    if not isinstance(subject, str):
        raise InvalidProviderTokenError(
            "The verified token does not contain a valid identity."
        )

    subject = subject.strip()

    if not subject or len(subject) > 128:
        raise InvalidProviderTokenError(
            "The verified identity has an invalid subject."
        )

    firebase_claims = claims.get("firebase")

    if not isinstance(firebase_claims, dict):
        raise InvalidProviderTokenError(
            "The token does not contain Firebase authentication claims."
        )

    sign_in_provider = firebase_claims.get("sign_in_provider")

    if not isinstance(sign_in_provider, str):
        raise InvalidProviderTokenError(
            "The token does not identify its authentication provider."
        )

    provider = SUPPORTED_PROVIDERS.get(sign_in_provider)

    if provider is None:
        raise UnsupportedIdentityProviderError(
            "This Firebase sign-in provider is not supported by GhostSim."
        )

    email = _optional_string(
        claims.get("email"),
        field_name="email",
        maximum_length=320,
    )

    email_verified = claims.get("email_verified", False)

    if not isinstance(email_verified, bool):
        raise InvalidProviderTokenError(
            "The verified email status is invalid."
        )

    # Do not allow an unverified email/password account to proceed
    # through the normal authenticated-account flow.
    if provider == "email" and not email_verified:
        raise InvalidProviderTokenError(
            "Verify your email address before signing in."
        )

    display_name = _optional_string(
        claims.get("name"),
        field_name="display name",
        maximum_length=80,
    )

    preferred_language = _optional_string(
        claims.get("preferred_language"),
        field_name="preferred language",
        maximum_length=35,
    ) or "en"

    return VerifiedProviderIdentity(
        provider=provider,
        provider_subject=subject,
        email=email,
        email_verified=email_verified,
        display_name=display_name,
        preferred_language=preferred_language,
        firebase_project_id=project_id,
    )
