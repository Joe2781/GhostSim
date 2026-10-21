BEGIN;

-- =========================================================
-- 1. Device network participation
--
-- A registered device may participate in the GhostSim
-- network only after its owner explicitly grants consent.
-- Device capabilities and resource limits must be verified
-- by trusted backend services, not blindly accepted from
-- client requests.
-- =========================================================

CREATE TABLE IF NOT EXISTS device_network_profiles (
    device_id UUID PRIMARY KEY
        REFERENCES devices(id) ON DELETE RESTRICT,

    participation_status TEXT NOT NULL DEFAULT 'disabled'
        CHECK (
            participation_status IN (
                'disabled',
                'pending',
                'active',
                'suspended',
                'revoked'
            )
        ),

    owner_consent_at TIMESTAMPTZ,
    consent_revoked_at TIMESTAMPTZ,

    -- Device capability declarations. The backend must
    -- validate supported capabilities independently.
    can_discover_peers BOOLEAN NOT NULL DEFAULT FALSE,
    can_relay_traffic BOOLEAN NOT NULL DEFAULT FALSE,
    can_cache_content BOOLEAN NOT NULL DEFAULT FALSE,

    -- Resource limits are policy inputs, not guarantees
    -- that the device can sustain those resources.
    max_relay_bandwidth_kbps INTEGER NOT NULL DEFAULT 0
        CHECK (max_relay_bandwidth_kbps >= 0),

    max_concurrent_relays INTEGER NOT NULL DEFAULT 0
        CHECK (max_concurrent_relays BETWEEN 0 AND 100),

    max_cache_bytes BIGINT NOT NULL DEFAULT 0
        CHECK (max_cache_bytes >= 0),

    allow_metered_networks BOOLEAN NOT NULL DEFAULT FALSE,
    allow_battery_powered_relay BOOLEAN NOT NULL DEFAULT FALSE,

    last_capability_check_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT network_consent_state_check
        CHECK (
            participation_status <> 'active'
            OR (
                owner_consent_at IS NOT NULL
                AND consent_revoked_at IS NULL
            )
        ),

    CONSTRAINT network_relay_permission_check
        CHECK (
            can_relay_traffic = FALSE
            OR (
                participation_status = 'active'
                AND owner_consent_at IS NOT NULL
                AND consent_revoked_at IS NULL
            )
        ),

    CONSTRAINT network_cache_permission_check
        CHECK (
            can_cache_content = FALSE
            OR (
                participation_status = 'active'
                AND owner_consent_at IS NOT NULL
                AND consent_revoked_at IS NULL
            )
        )
);

CREATE INDEX IF NOT EXISTS
    device_network_profiles_active_idx
ON device_network_profiles (participation_status)
WHERE participation_status = 'active';

-- =========================================================
-- 2. Network observations
--
-- Record short-lived, measured connection information.
-- Do not treat an observation as proof that a device can
-- reach the public internet or a particular destination.
--
-- Avoid storing precise location or raw network addresses
-- here unless a separately reviewed requirement justifies
-- it and appropriate protection is implemented.
-- =========================================================

CREATE TABLE IF NOT EXISTS network_observations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    device_id UUID NOT NULL
        REFERENCES devices(id) ON DELETE RESTRICT,

    observed_network_type TEXT NOT NULL
        CHECK (
            observed_network_type IN (
                'wifi',
                'cellular',
                'ethernet',
                'wifi_direct',
                'bluetooth',
                'other'
            )
        ),

    has_network_connection BOOLEAN NOT NULL DEFAULT FALSE,

    -- This is a measured reachability result, not a claim
    -- that every internet destination is reachable.
    internet_reachability TEXT NOT NULL DEFAULT 'unknown'
        CHECK (
            internet_reachability IN (
                'unknown',
                'reachable',
                'unreachable'
            )
        ),

    measured_rtt_ms INTEGER
        CHECK (measured_rtt_ms IS NULL OR measured_rtt_ms >= 0),

    measured_packet_loss_percent NUMERIC(5,2)
        CHECK (
            measured_packet_loss_percent IS NULL
            OR measured_packet_loss_percent BETWEEN 0 AND 100
        ),

    estimated_upload_kbps INTEGER
        CHECK (
            estimated_upload_kbps IS NULL
            OR estimated_upload_kbps >= 0
        ),

    estimated_download_kbps INTEGER
        CHECK (
            estimated_download_kbps IS NULL
            OR estimated_download_kbps >= 0
        ),

    is_metered BOOLEAN NOT NULL DEFAULT FALSE,

    observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,

    CONSTRAINT network_observation_expiry_check
        CHECK (expires_at > observed_at),

    CONSTRAINT network_observation_reachability_check
        CHECK (
            has_network_connection = TRUE
            OR internet_reachability <> 'reachable'
        )
);

CREATE INDEX IF NOT EXISTS
    network_observations_device_recent_idx
ON network_observations (device_id, observed_at DESC);

CREATE INDEX IF NOT EXISTS
    network_observations_expiry_idx
ON network_observations (expires_at);

-- =========================================================
-- 3. Temporary device-to-device links
--
-- These records describe links verified by the networking
-- service. They do not create Bluetooth, Wi-Fi Direct, or
-- internet connectivity on their own.
-- =========================================================

CREATE TABLE IF NOT EXISTS network_links (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    device_a_id UUID NOT NULL
        REFERENCES devices(id) ON DELETE RESTRICT,

    device_b_id UUID NOT NULL
        REFERENCES devices(id) ON DELETE RESTRICT,

    link_type TEXT NOT NULL
        CHECK (
            link_type IN (
                'direct_internet',
                'wifi_direct',
                'bluetooth',
                'local_network',
                'peer_relay'
            )
        ),

    link_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (
            link_status IN (
                'pending',
                'verified',
                'degraded',
                'closed',
                'expired'
            )
        ),

    measured_rtt_ms INTEGER
        CHECK (measured_rtt_ms IS NULL OR measured_rtt_ms >= 0),

    measured_packet_loss_percent NUMERIC(5,2)
        CHECK (
            measured_packet_loss_percent IS NULL
            OR measured_packet_loss_percent BETWEEN 0 AND 100
        ),

    verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    closed_at TIMESTAMPTZ,

    CONSTRAINT network_link_distinct_devices_check
        CHECK (device_a_id <> device_b_id),

    CONSTRAINT network_link_expiry_check
        CHECK (expires_at > created_at),

    CONSTRAINT network_link_closed_timestamp_check
        CHECK (
            (link_status = 'closed' AND closed_at IS NOT NULL)
            OR
            (link_status <> 'closed')
        ),

    CONSTRAINT network_link_verified_timestamp_check
        CHECK (
            link_status NOT IN ('verified', 'degraded')
            OR verified_at IS NOT NULL
        )
);

CREATE INDEX IF NOT EXISTS
    network_links_device_a_idx
ON network_links (device_a_id, link_status, expires_at);

CREATE INDEX IF NOT EXISTS
    network_links_device_b_idx
ON network_links (device_b_id, link_status, expires_at);

-- =========================================================
-- 4. Call sessions
--
-- The call service must verify that the initiating user
-- owns the initiating device and is authorized to contact
-- the recipient before creating a session.
-- =========================================================

CREATE TABLE IF NOT EXISTS call_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    caller_user_id UUID NOT NULL
        REFERENCES users(id) ON DELETE RESTRICT,

    caller_device_id UUID NOT NULL
        REFERENCES devices(id) ON DELETE RESTRICT,

    recipient_user_id UUID NOT NULL
        REFERENCES users(id) ON DELETE RESTRICT,

    call_type TEXT NOT NULL DEFAULT 'audio'
        CHECK (call_type IN ('audio', 'video')),

    call_status TEXT NOT NULL DEFAULT 'initiating'
        CHECK (
            call_status IN (
                'initiating',
                'ringing',
                'connecting',
                'active',
                'ended',
                'declined',
                'missed',
                'failed',
                'cancelled'
            )
        ),

    -- Random correlation value generated by the trusted
    -- service to make signaling retries idempotent.
    request_key TEXT NOT NULL UNIQUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ringing_at TIMESTAMPTZ,
    connected_at TIMESTAMPTZ,
    ended_at TIMESTAMPTZ,

    end_reason TEXT,

    -- Used for cleanup and stale-session detection.
    expires_at TIMESTAMPTZ NOT NULL,

    CONSTRAINT call_parties_distinct_check
        CHECK (caller_user_id <> recipient_user_id),

    CONSTRAINT call_expiry_check
        CHECK (expires_at > created_at),

    CONSTRAINT call_ringing_timestamp_check
        CHECK (
            call_status NOT IN (
                'ringing',
                'connecting',
                'active',
                'ended',
                'declined',
                'missed'
            )
            OR ringing_at IS NOT NULL
            OR call_status = 'missed'
        ),

    CONSTRAINT call_connected_timestamp_check
        CHECK (
            call_status <> 'active'
            OR connected_at IS NOT NULL
        ),

    CONSTRAINT call_ended_timestamp_check
        CHECK (
            call_status NOT IN (
                'ended',
                'declined',
                'missed',
                'failed',
                'cancelled'
            )
            OR ended_at IS NOT NULL
        )
);

CREATE INDEX IF NOT EXISTS
    call_sessions_caller_recent_idx
ON call_sessions (caller_user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS
    call_sessions_recipient_recent_idx
ON call_sessions (recipient_user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS
    call_sessions_active_expiry_idx
ON call_sessions (expires_at)
WHERE call_status IN (
    'initiating',
    'ringing',
    'connecting',
    'active'
);

-- =========================================================
-- 5. Call participants and registered receiving devices
--
-- A recipient may have several registered devices. The call
-- service decides which eligible devices should ring.
-- =========================================================

CREATE TABLE IF NOT EXISTS call_participants (
    call_id UUID NOT NULL
        REFERENCES call_sessions(id) ON DELETE RESTRICT,

    user_id UUID NOT NULL
        REFERENCES users(id) ON DELETE RESTRICT,

    device_id UUID NOT NULL
        REFERENCES devices(id) ON DELETE RESTRICT,

    participant_role TEXT NOT NULL
        CHECK (participant_role IN ('caller', 'recipient')),

    participant_status TEXT NOT NULL DEFAULT 'invited'
        CHECK (
            participant_status IN (
                'invited',
                'ringing',
                'connecting',
                'connected',
                'declined',
                'unreachable',
                'left'
            )
        ),

    invited_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ringing_at TIMESTAMPTZ,
    connected_at TIMESTAMPTZ,
    left_at TIMESTAMPTZ,

    PRIMARY KEY (call_id, device_id)
);

CREATE INDEX IF NOT EXISTS
    call_participants_user_status_idx
ON call_participants (user_id, participant_status);

-- =========================================================
-- 6. Call signaling event history
--
-- Store lifecycle metadata only. Do not store call audio,
-- video, session keys, or decrypted signaling payloads here.
-- The signaling service must authenticate and authorize
-- every event before recording or forwarding it.
-- =========================================================

CREATE TABLE IF NOT EXISTS call_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    call_id UUID NOT NULL
        REFERENCES call_sessions(id) ON DELETE RESTRICT,

    actor_user_id UUID
        REFERENCES users(id) ON DELETE SET NULL,

    actor_device_id UUID
        REFERENCES devices(id) ON DELETE SET NULL,

    event_type TEXT NOT NULL
        CHECK (
            event_type IN (
                'created',
                'ringing',
                'accepted',
                'declined',
                'connection_started',
                'connected',
                'connection_failed',
                'ended',
                'cancelled',
                'missed'
            )
        ),

    event_metadata JSONB NOT NULL DEFAULT '{}'::JSONB
        CHECK (jsonb_typeof(event_metadata) = 'object'),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS
    call_events_timeline_idx
ON call_events (call_id, created_at ASC);

-- =========================================================
-- 7. Temporary authorized relay sessions
--
-- This table records relay authorization, not packet
-- forwarding itself. A real relay service must authenticate
-- both endpoints, enforce policy and resource limits, use
-- encrypted transport, and terminate expired/revoked sessions.
-- =========================================================

CREATE TABLE IF NOT EXISTS relay_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    relay_device_id UUID NOT NULL
        REFERENCES devices(id) ON DELETE RESTRICT,

    requesting_device_id UUID NOT NULL
        REFERENCES devices(id) ON DELETE RESTRICT,

    purpose TEXT NOT NULL
        CHECK (purpose IN ('call_media', 'connectivity')),

    relay_status TEXT NOT NULL DEFAULT 'requested'
        CHECK (
            relay_status IN (
                'requested',
                'authorized',
                'active',
                'suspended',
                'terminated',
                'expired',
                'rejected'
            )
        ),

    authorized_at TIMESTAMPTZ,
    started_at TIMESTAMPTZ,
    terminated_at TIMESTAMPTZ,

    max_bandwidth_kbps INTEGER NOT NULL
        CHECK (max_bandwidth_kbps > 0),

    bytes_forwarded BIGINT NOT NULL DEFAULT 0
        CHECK (bytes_forwarded >= 0),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,

    CONSTRAINT relay_distinct_devices_check
        CHECK (relay_device_id <> requesting_device_id),

    CONSTRAINT relay_expiry_check
        CHECK (expires_at > created_at),

    CONSTRAINT relay_authorization_timestamp_check
        CHECK (
            relay_status NOT IN ('authorized', 'active', 'suspended')
            OR authorized_at IS NOT NULL
        ),

    CONSTRAINT relay_active_timestamp_check
        CHECK (
            relay_status <> 'active'
            OR started_at IS NOT NULL
        ),

    CONSTRAINT relay_terminated_timestamp_check
        CHECK (
            relay_status <> 'terminated'
            OR terminated_at IS NOT NULL
        )
);

CREATE INDEX IF NOT EXISTS
    relay_sessions_relay_device_idx
ON relay_sessions (relay_device_id, relay_status, expires_at);

CREATE INDEX IF NOT EXISTS
    relay_sessions_requesting_device_idx
ON relay_sessions (requesting_device_id, relay_status, expires_at);

-- =========================================================
-- 8. Automatic updated_at handling
-- =========================================================

DROP TRIGGER IF EXISTS device_network_profiles_set_updated_at
    ON device_network_profiles;

CREATE TRIGGER device_network_profiles_set_updated_at
BEFORE UPDATE ON device_network_profiles
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

COMMIT;
