from __future__ import annotations

import logging
from typing import Literal

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field, field_validator

from app.services.auth_sessions import (
    AuthenticationSessionError,
    create_authentication_session,
)
from app.services.ghostsim_ids import (
    AccountNotEligibleError,
    AccountNotFoundError,
    GhostSimIDError,
    assign_ghostsim_id,
)
from app.services.identity_registry import (
    IdentityRegistryError,
    register_verified_identity,
)
from app.services.provider_verification import (
    ProviderVerificationError,
    verify_firebase_id_token,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/provider-auth",
    tags=["provider authentication"],
)


class ProviderLoginRequest(BaseModel):
    id_token: str = Field(min_length=20, max_length=20000)
    identity_country: str = Field(
        min_length=2,
        max_length=2,
        description="Two-letter account identity country code, such as NG.",
    )
    client_label: str | None = Field(
        default=None,
        max_length=120,
        description="Optional device or client description.",
    )

    @field_validator("identity_country")
    @classmethod
    def normalize_country(cls, value: str) -> str:
        normalized = value.strip().upper()

        if len(normalized) != 2 or not normalized.isalpha():
            raise ValueError(
                "identity_country must contain exactly two letters."
            )

        return normalized

    @field_validator("client_label")
    @classmethod
    def normalize_client_label(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        value = value.strip()
        return value or None


class ProviderLoginResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int
    account_id: str
    ghostsim_id: str
    provider: str
    email: str | None
    email_verified: bool
    display_name: str | None
    is_new_account: bool


@router.post(
    "/login",
    response_model=ProviderLoginResponse,
    status_code=status.HTTP_200_OK,
)
async def provider_login(
    request: ProviderLoginRequest,
) -> ProviderLoginResponse:
    """
    Verify a Firebase ID token, resolve the GhostSim account,
    ensure a public GhostSim ID exists, and create a session.

    The client must obtain its Firebase ID token through the
    Firebase client SDK. The backend never trusts client-supplied
    account IDs or provider identity claims.
    """

    try:
        verified_identity = verify_firebase_id_token(
            request.id_token
        )
    except ProviderVerificationError as exc:
        logger.info("Provider authentication was rejected.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication could not be verified.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    except Exception as exc:
        logger.exception("Provider token verification failed.")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication verification is temporarily unavailable.",
        ) from exc

    try:
        identity = register_verified_identity(
            provider=verified_identity.provider,
            provider_subject=verified_identity.provider_subject,
            identity_country=request.identity_country,
            email=verified_identity.email,
            email_verified=verified_identity.email_verified,
            display_name=verified_identity.display_name,
            preferred_language="en",
        )
    except IdentityRegistryError as exc:
        logger.exception("GhostSim identity registration failed.")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Your account could not be loaded. Please try again.",
        ) from exc
    except Exception as exc:
        logger.exception("Unexpected identity registration error.")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Your account could not be loaded. Please try again.",
        ) from exc

    if identity.account_status != "active":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This GhostSim account is not currently active.",
        )

    try:
        assigned_id = assign_ghostsim_id(
            account_id=identity.account_id
        )
    except (
        AccountNotFoundError,
        AccountNotEligibleError,
    ) as exc:
        logger.warning(
            "GhostSim ID assignment was refused for account %s.",
            identity.account_id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="A GhostSim ID cannot currently be assigned to this account.",
        ) from exc
    except GhostSimIDError as exc:
        logger.exception("GhostSim ID assignment failed.")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Your GhostSim identity is temporarily unavailable.",
        ) from exc
    except Exception as exc:
        logger.exception("Unexpected GhostSim ID assignment error.")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Your GhostSim identity is temporarily unavailable.",
        ) from exc

    try:
        session = create_authentication_session(
            user_id=identity.account_id,
            device_id=None,
            client_label=request.client_label,
        )
    except AuthenticationSessionError as exc:
        logger.exception("GhostSim authentication session creation failed.")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="A secure session could not be created. Please try again.",
        ) from exc
    except Exception as exc:
        logger.exception("Unexpected authentication session error.")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="A secure session could not be created. Please try again.",
        ) from exc

    return ProviderLoginResponse(
        access_token=session.access_token,
        expires_in=session.expires_in,
        account_id=str(identity.account_id),
        ghostsim_id=assigned_id.public_id,
        provider=verified_identity.provider,
        email=verified_identity.email,
        email_verified=verified_identity.email_verified,
        display_name=verified_identity.display_name,
        is_new_account=identity.created,
    )
