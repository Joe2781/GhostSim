BEGIN;

-- ============================================================
-- GHOSTSIM: CORE IDENTITY DATABASE
-- PostgreSQL 15+
--
-- Stores permanent internal user identities, external
-- authentication identities, public GhostSim IDs, and devices.
--
-- Never store passwords, private cryptographic keys, or
-- authentication tokens in these tables.
-- ============================================================

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN (
            'active',
            'suspended',
            'deletion_pending',
            'deleted'
        )),

    -- Account's declared identity country.
    -- This is not necessarily the user's current location.
    identity_country CHAR(2) NOT NULL
        CHECK (identity_country ~ '^[A-Z]{2}$'),

    preferred_language TEXT NOT NULL DEFAULT 'en'
        CHECK (
            length(preferred_language) BETWEEN 2 AND 35
        ),

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ,

    CHECK (
        (status = 'deleted' AND deleted_at IS NOT NULL)
        OR
        (status <> 'deleted' AND deleted_at IS NULL)
    )
);

CREATE INDEX users_status_created_idx
    ON users (status, created_at DESC);


-- ============================================================
-- AUTHENTICATION IDENTITIES
--
-- Authentication is delegated to a verified authentication
-- service or a properly implemented authentication server.
-- Provider subjects must come from verified authentication.
-- ============================================================

CREATE TABLE auth_identities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id UUID NOT NULL
        REFERENCES users(id) ON DELETE RESTRICT,

    provider TEXT NOT NULL
        CHECK (
            provider IN (
                'email',
                'google',
                'apple',
                'facebook',
                'github',
                'microsoft',
                'yahoo'
            )
        ),

    -- Stable subject identifier issued by the provider.
    -- For email authentication, use the identifier assigned
    -- by the authentication system, not an unverified address.
    provider_subject TEXT NOT NULL
        CHECK (
            length(provider_subject) BETWEEN 1 AND 512
        ),

    email TEXT,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_authenticated_at TIMESTAMPTZ,

    UNIQUE (provider, provider_subject),
    UNIQUE (user_id, provider),

    CHECK (
        email IS NULL
        OR length(email) BETWEEN 3 AND 320
    )
);

CREATE INDEX auth_identities_user_idx
    ON auth_identities (user_id);


-- ============================================================
-- GHOSTSIM PUBLIC ID REGISTRY
--
-- Example displayed ID: NG·7K2P9A
--
-- Country prefix: NG
-- Six-character alphanumeric suffix: 7K2P9A
--
-- The internal user UUID never changes when a public ID
-- changes. Public IDs must never transfer ownership of an
-- old account, its messages, or its cryptographic keys.
-- ============================================================

CREATE TABLE ghostsim_ids (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    country_code CHAR(2) NOT NULL
        CHECK (country_code ~ '^[A-Z]{2}$'),

    suffix CHAR(6) NOT NULL
        CHECK (suffix ~ '^[A-Z0-9]{6}$'),

    user_id UUID
        REFERENCES users(id) ON DELETE RESTRICT,

    status TEXT NOT NULL DEFAULT 'available'
        CHECK (
            status IN (
                'available',
                'assigned',
                'quarantined',
                'retired'
            )
        ),

    assigned_at TIMESTAMPTZ,
    released_at TIMESTAMPTZ,
    quarantine_until TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- An ID cannot be allocated twice within a country.
    UNIQUE (country_code, suffix),

    CHECK (
        (
            status = 'assigned'
            AND user_id IS NOT NULL
            AND assigned_at IS NOT NULL
            AND released_at IS NULL
            AND quarantine_until IS NULL
        )
        OR
        (
            status = 'available'
            AND user_id IS NULL
            AND released_at IS NULL
            AND quarantine_until IS NULL
        )
        OR
        (
            status = 'quarantined'
            AND user_id IS NULL
            AND released_at IS NOT NULL
            AND quarantine_until IS NOT NULL
        )
        OR
        (
            status = 'retired'
            AND user_id IS NULL
            AND released_at IS NOT NULL
            AND quarantine_until IS NULL
        )
    )
);

-- A user can have only one currently assigned public ID.
CREATE UNIQUE INDEX ghostsim_ids_one_active_per_user_idx
    ON ghostsim_ids (user_id)
    WHERE status = 'assigned';

CREATE INDEX ghostsim_ids_available_idx
    ON ghostsim_ids (country_code, suffix)
    WHERE status = 'available';

CREATE INDEX ghostsim_ids_quarantine_idx
    ON ghostsim_ids (quarantine_until)
    WHERE status = 'quarantined';


-- ============================================================
-- GHOSTSIM DEVICES
--
-- A user may register multiple devices.
-- Public device IDs are not GhostSim user IDs.
-- ============================================================

CREATE TABLE devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id UUID NOT NULL
        REFERENCES users(id) ON DELETE RESTRICT,

    device_name TEXT NOT NULL
        CHECK (length(device_name) BETWEEN 1 AND 100),

    platform TEXT NOT NULL
        CHECK (
            platform IN (
                'android',
                'ios',
                'windows',
                'macos',
                'linux',
                'web'
            )
        ),

    -- Public key or key fingerprint used to identify the
    -- device cryptographically. Private keys stay on-device.
    public_key TEXT NOT NULL
        CHECK (length(public_key) BETWEEN 32 AND 4096),

    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (
            status IN (
                'pending',
                'active',
                'revoked'
            )
        ),

    registered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,

    -- Prevent accidental reuse of the same public key.
    UNIQUE (public_key),

    CHECK (
        (status = 'revoked' AND revoked_at IS NOT NULL)
        OR
        (status <> 'revoked' AND revoked_at IS NULL)
    )
);

CREATE INDEX devices_user_status_idx
    ON devices (user_id, status);

CREATE INDEX devices_active_last_seen_idx
    ON devices (last_seen_at DESC)
    WHERE status = 'active';


-- ============================================================
-- UPDATE TIMESTAMPS
-- ============================================================

CREATE FUNCTION set_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$;

CREATE TRIGGER users_set_updated_at
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();


COMMIT;
