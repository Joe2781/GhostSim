BEGIN;

-- ============================================================
-- GHOSTSIM: DEVICE VERIFICATION
--
-- Stores short-lived challenges used to verify that a device
-- possesses the private key corresponding to its registered
-- public key.
--
-- The private key must NEVER leave the device.
-- Challenges are single-use and expire automatically through
-- application-level checks and scheduled cleanup.
-- ============================================================

CREATE TABLE IF NOT EXISTS device_verification_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    device_id UUID NOT NULL
        REFERENCES devices(id) ON DELETE RESTRICT,

    -- SHA-256 hash of a cryptographically random challenge.
    -- The raw challenge is returned to the device and is not
    -- stored in this table.
    challenge_hash CHAR(64) NOT NULL
        CHECK (challenge_hash ~ '^[a-f0-9]{64}$'),

    -- Identifies the verification protocol and signature format.
    verification_method TEXT NOT NULL DEFAULT 'ed25519'
        CHECK (verification_method IN ('ed25519')),

    challenge_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (
            challenge_status IN (
                'pending',
                'verified',
                'failed',
                'expired',
                'consumed'
            )
        ),

    attempts INTEGER NOT NULL DEFAULT 0
        CHECK (attempts >= 0),

    max_attempts INTEGER NOT NULL DEFAULT 5
        CHECK (max_attempts BETWEEN 1 AND 10),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    expires_at TIMESTAMPTZ NOT NULL,

    verified_at TIMESTAMPTZ,

    consumed_at TIMESTAMPTZ,

    -- Optional request correlation value for safe retries.
    request_key UUID NOT NULL DEFAULT gen_random_uuid(),

    CONSTRAINT device_verification_expiry_check
        CHECK (expires_at > created_at),

    CONSTRAINT device_verification_attempts_check
        CHECK (attempts <= max_attempts),

    CONSTRAINT device_verification_verified_timestamp_check
        CHECK (
            challenge_status NOT IN ('verified', 'consumed')
            OR verified_at IS NOT NULL
        ),

    CONSTRAINT device_verification_consumed_timestamp_check
        CHECK (
            challenge_status <> 'consumed'
            OR consumed_at IS NOT NULL
        ),

    UNIQUE (challenge_hash),

    UNIQUE (request_key)
);

-- Efficiently find a device's newest verification challenges.
CREATE INDEX IF NOT EXISTS
    device_verification_device_recent_idx
ON device_verification_challenges (
    device_id,
    created_at DESC
);

-- Efficiently find expired challenges for cleanup.
CREATE INDEX IF NOT EXISTS
    device_verification_expiry_idx
ON device_verification_challenges (expires_at)
WHERE challenge_status = 'pending';

-- Efficiently find challenges awaiting verification.
CREATE INDEX IF NOT EXISTS
    device_verification_pending_idx
ON device_verification_challenges (
    device_id,
    challenge_status,
    expires_at
)
WHERE challenge_status = 'pending';

-- Prevent multiple pending challenges for one device.
CREATE UNIQUE INDEX IF NOT EXISTS
    device_verification_one_pending_per_device_idx
ON device_verification_challenges (device_id)
WHERE challenge_status = 'pending';

-- Record the successful activation event separately from
-- the challenge lifecycle for traceability.
CREATE TABLE IF NOT EXISTS device_activation_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    device_id UUID NOT NULL
        REFERENCES devices(id) ON DELETE RESTRICT,

    verification_challenge_id UUID NOT NULL
        REFERENCES device_verification_challenges(id)
        ON DELETE RESTRICT,

    activation_status TEXT NOT NULL DEFAULT 'activated'
        CHECK (
            activation_status IN (
                'activated',
                'deactivated',
                'revoked'
            )
        ),

    activated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    deactivated_at TIMESTAMPTZ,

    -- A device can have only one activation record per
    -- verification challenge.
    UNIQUE (verification_challenge_id),

    CONSTRAINT device_activation_deactivation_check
        CHECK (
            (
                activation_status = 'activated'
                AND deactivated_at IS NULL
            )
            OR
            (
                activation_status IN ('deactivated', 'revoked')
                AND deactivated_at IS NOT NULL
            )
        )
);

CREATE INDEX IF NOT EXISTS
    device_activation_device_recent_idx
ON device_activation_records (
    device_id,
    activated_at DESC
);

COMMIT;
