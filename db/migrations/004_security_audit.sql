BEGIN;

-- =========================================================
-- 1. Security audit events
--
-- Record security-sensitive events without storing passwords,
-- private keys, bearer tokens, message plaintext, or call media.
-- =========================================================

CREATE TABLE IF NOT EXISTS security_audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id UUID
        REFERENCES users(id) ON DELETE SET NULL,

    device_id UUID
        REFERENCES devices(id) ON DELETE SET NULL,

    event_type TEXT NOT NULL
        CHECK (
            event_type IN (
                'login_succeeded',
                'login_failed',
                'logout',
                'session_revoked',
                'device_registered',
                'device_revoked',
                'identity_added',
                'identity_removed',
                'ghostsim_id_assigned',
                'ghostsim_id_released',
                'network_consent_granted',
                'network_consent_revoked',
                'relay_authorized',
                'relay_rejected',
                'permission_denied',
                'suspicious_activity',
                'account_suspended',
                'account_restored'
            )
        ),

    outcome TEXT NOT NULL DEFAULT 'success'
        CHECK (outcome IN ('success', 'failure', 'blocked')),

    -- Use controlled, non-sensitive metadata only.
    metadata JSONB NOT NULL DEFAULT '{}'::JSONB
        CHECK (jsonb_typeof(metadata) = 'object'),

    correlation_id UUID,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS
    security_audit_user_timeline_idx
ON security_audit_events (user_id, occurred_at DESC);

CREATE INDEX IF NOT EXISTS
    security_audit_device_timeline_idx
ON security_audit_events (device_id, occurred_at DESC);

CREATE INDEX IF NOT EXISTS
    security_audit_event_timeline_idx
ON security_audit_events (event_type, occurred_at DESC);

-- =========================================================
-- 2. Device revocation history
--
-- Revoking a device must be enforced by backend services.
-- History is retained so security investigations can
-- distinguish revoked devices from devices never registered.
-- =========================================================

CREATE TABLE IF NOT EXISTS device_revocations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    device_id UUID NOT NULL
        REFERENCES devices(id) ON DELETE RESTRICT,

    revoked_by_user_id UUID
        REFERENCES users(id) ON DELETE SET NULL,

    reason_code TEXT NOT NULL
        CHECK (
            reason_code IN (
                'owner_request',
                'suspected_compromise',
                'device_lost',
                'account_security',
                'administrative_action',
                'other'
            )
        ),

    reason_details TEXT,

    revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Allows a later authorized re-registration to be recorded
    -- without deleting the historical revocation.
    superseded_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS
    device_revocations_device_timeline_idx
ON device_revocations (device_id, revoked_at DESC);

CREATE INDEX IF NOT EXISTS
    device_revocations_active_idx
ON device_revocations (device_id)
WHERE superseded_at IS NULL;

-- =========================================================
-- 3. Authenticated sessions
--
-- Store a cryptographic hash of a high-entropy random token,
-- never the original bearer token. Generate tokens securely
-- in the authentication service.
-- =========================================================

CREATE TABLE IF NOT EXISTS auth_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id UUID NOT NULL
        REFERENCES users(id) ON DELETE RESTRICT,

    device_id UUID
        REFERENCES devices(id) ON DELETE RESTRICT,

    token_hash TEXT NOT NULL UNIQUE,

    session_status TEXT NOT NULL DEFAULT 'active'
        CHECK (
            session_status IN (
                'active',
                'revoked',
                'expired'
            )
        ),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,

    -- Optional, minimized metadata. Avoid storing precise
    -- location or unnecessary device fingerprint data.
    client_label TEXT,

    CONSTRAINT auth_session_expiry_check
        CHECK (expires_at > created_at),

    CONSTRAINT auth_session_revocation_check
        CHECK (
            (session_status = 'revoked' AND revoked_at IS NOT NULL)
            OR
            (session_status <> 'revoked' AND revoked_at IS NULL)
        ),

    CONSTRAINT auth_session_label_length_check
        CHECK (
            client_label IS NULL
            OR char_length(client_label) <= 120
        )
);

CREATE INDEX IF NOT EXISTS
    auth_sessions_user_status_idx
ON auth_sessions (user_id, session_status, expires_at);

CREATE INDEX IF NOT EXISTS
    auth_sessions_expiry_idx
ON auth_sessions (expires_at)
WHERE session_status = 'active';

-- =========================================================
-- 4. API request idempotency
--
-- Helps prevent duplicate side effects when a client retries
-- a request after a timeout or unstable connection.
--
-- Store a digest of the request and a bounded response record.
-- Do not store authorization headers, credentials, or private
-- message content in this table.
-- =========================================================

CREATE TABLE IF NOT EXISTS api_idempotency_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id UUID NOT NULL
        REFERENCES users(id) ON DELETE RESTRICT,

    device_id UUID
        REFERENCES devices(id) ON DELETE RESTRICT,

    idempotency_key TEXT NOT NULL,

    request_digest TEXT NOT NULL,

    response_status INTEGER
        CHECK (
            response_status IS NULL
            OR response_status BETWEEN 100 AND 599
        ),

    response_reference TEXT,

    record_status TEXT NOT NULL DEFAULT 'processing'
        CHECK (
            record_status IN (
                'processing',
                'completed',
                'failed'
            )
        ),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,

    CONSTRAINT api_idempotency_key_length_check
        CHECK (char_length(idempotency_key) BETWEEN 16 AND 200),

    CONSTRAINT api_request_digest_length_check
        CHECK (char_length(request_digest) BETWEEN 32 AND 256),

    CONSTRAINT api_idempotency_expiry_check
        CHECK (expires_at > created_at),

    CONSTRAINT api_idempotency_completion_check
        CHECK (
            record_status <> 'completed'
            OR response_status IS NOT NULL
        ),

    UNIQUE (user_id, idempotency_key)
);

CREATE INDEX IF NOT EXISTS
    api_idempotency_expiry_idx
ON api_idempotency_records (expires_at);

-- =========================================================
-- 5. Rate-limit counters
--
-- This is a persistence foundation for distributed rate
-- limiting. A production implementation must use atomic
-- transactions or a dedicated rate-limiting system and must
-- define retention and cleanup policies.
--
-- subject_hash should be a keyed digest generated by the
-- backend, not a raw IP address, token, or email address.
-- =========================================================

CREATE TABLE IF NOT EXISTS rate_limit_buckets (
    bucket_key TEXT PRIMARY KEY,

    subject_hash TEXT NOT NULL,

    action_name TEXT NOT NULL,

    window_started_at TIMESTAMPTZ NOT NULL,

    request_count INTEGER NOT NULL DEFAULT 0
        CHECK (request_count >= 0),

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,

    CONSTRAINT rate_limit_expiry_check
        CHECK (expires_at > window_started_at),

    CONSTRAINT rate_limit_key_length_check
        CHECK (
            char_length(bucket_key) BETWEEN 16 AND 256
        ),

    CONSTRAINT rate_limit_subject_length_check
        CHECK (
            char_length(subject_hash) BETWEEN 32 AND 256
        ),

    CONSTRAINT rate_limit_action_length_check
        CHECK (
            char_length(action_name) BETWEEN 1 AND 100
        )
);

CREATE INDEX IF NOT EXISTS
    rate_limit_buckets_expiry_idx
ON rate_limit_buckets (expires_at);

CREATE INDEX IF NOT EXISTS
    rate_limit_buckets_subject_action_idx
ON rate_limit_buckets (subject_hash, action_name, window_started_at);

-- =========================================================
-- 6. Security policy changes
--
-- Tracks important changes to account and device security
-- policy. This table does not itself authorize a change.
-- =========================================================

CREATE TABLE IF NOT EXISTS security_policy_changes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    changed_by_user_id UUID
        REFERENCES users(id) ON DELETE SET NULL,

    changed_by_device_id UUID
        REFERENCES devices(id) ON DELETE SET NULL,

    target_user_id UUID
        REFERENCES users(id) ON DELETE SET NULL,

    target_device_id UUID
        REFERENCES devices(id) ON DELETE SET NULL,

    policy_name TEXT NOT NULL,

    old_value JSONB,
    new_value JSONB,

    change_reason TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT security_policy_name_length_check
        CHECK (char_length(policy_name) BETWEEN 1 AND 120),

    CONSTRAINT security_policy_old_value_object_check
        CHECK (
            old_value IS NULL
            OR jsonb_typeof(old_value) = 'object'
        ),

    CONSTRAINT security_policy_new_value_object_check
        CHECK (
            new_value IS NULL
            OR jsonb_typeof(new_value) = 'object'
        )
);

CREATE INDEX IF NOT EXISTS
    security_policy_changes_target_user_idx
ON security_policy_changes (target_user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS
    security_policy_changes_target_device_idx
ON security_policy_changes (target_device_id, created_at DESC);

COMMIT;
