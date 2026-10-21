
BEGIN;

-- =========================================================
-- 1. User profile extensions
-- The internal UUID remains permanent even if a public
-- GhostSim ID is later released and reassigned.
-- =========================================================

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS display_name TEXT,
    ADD COLUMN IF NOT EXISTS avatar_url TEXT,
    ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS account_created_at TIMESTAMPTZ
        NOT NULL DEFAULT NOW();

ALTER TABLE users
    ADD CONSTRAINT users_display_name_length_check
    CHECK (
        display_name IS NULL
        OR char_length(display_name) BETWEEN 1 AND 80
    );

-- =========================================================
-- 2. GhostSim ID assignment history
-- Preserve the history of assignments so a recycled public
-- ID never transfers the previous owner's account or keys.
-- =========================================================

CREATE TABLE IF NOT EXISTS ghostsim_id_assignments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    ghostsim_id_id UUID NOT NULL
        REFERENCES ghostsim_ids(id) ON DELETE RESTRICT,

    user_id UUID NOT NULL
        REFERENCES users(id) ON DELETE RESTRICT,

    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    released_at TIMESTAMPTZ,

    release_reason TEXT,

    CONSTRAINT ghostsim_assignment_release_check
        CHECK (
            (released_at IS NULL AND release_reason IS NULL)
            OR
            (released_at IS NOT NULL)
        )
);

CREATE UNIQUE INDEX IF NOT EXISTS
    ghostsim_id_assignments_one_active_per_id
ON ghostsim_id_assignments (ghostsim_id_id)
WHERE released_at IS NULL;

CREATE INDEX IF NOT EXISTS
    ghostsim_id_assignments_user_history_idx
ON ghostsim_id_assignments (user_id, assigned_at DESC);

-- =========================================================
-- 3. Conversations
-- Supports direct GhostSim-to-GhostSim conversations first.
-- Group conversations can be added without redesigning
-- message storage.
-- =========================================================

CREATE TABLE IF NOT EXISTS conversations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    conversation_type TEXT NOT NULL DEFAULT 'direct'
        CHECK (conversation_type IN ('direct', 'group')),

    created_by UUID NOT NULL
        REFERENCES users(id) ON DELETE RESTRICT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Optional direct-conversation deduplication key.
    -- For a direct conversation, the server can derive this
    -- from the two sorted internal user UUIDs.
    direct_pair_key TEXT UNIQUE,

    CONSTRAINT conversations_direct_pair_check
        CHECK (
            (conversation_type = 'direct'
                AND direct_pair_key IS NOT NULL)
            OR
            (conversation_type = 'group'
                AND direct_pair_key IS NULL)
        )
);

CREATE INDEX IF NOT EXISTS conversations_updated_at_idx
    ON conversations (updated_at DESC);

-- =========================================================
-- 4. Conversation participants
-- A user may leave a conversation without deleting its
-- history for other participants.
-- =========================================================

CREATE TABLE IF NOT EXISTS conversation_participants (
    conversation_id UUID NOT NULL
        REFERENCES conversations(id) ON DELETE RESTRICT,

    user_id UUID NOT NULL
        REFERENCES users(id) ON DELETE RESTRICT,

    role TEXT NOT NULL DEFAULT 'member'
        CHECK (role IN ('member', 'admin')),

    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    left_at TIMESTAMPTZ,

    last_read_message_id UUID,
    last_read_at TIMESTAMPTZ,

    PRIMARY KEY (conversation_id, user_id),

    CONSTRAINT participant_read_state_check
        CHECK (
            last_read_message_id IS NOT NULL
            OR last_read_at IS NULL
        )
);

CREATE INDEX IF NOT EXISTS
    conversation_participants_user_active_idx
ON conversation_participants (user_id, conversation_id)
WHERE left_at IS NULL;

-- =========================================================
-- 5. Messages
-- Store encrypted message payloads, not plaintext message
-- bodies. Encryption and key management must be implemented
-- in the clients before sending sensitive message content.
-- =========================================================

CREATE TABLE IF NOT EXISTS messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    conversation_id UUID NOT NULL
        REFERENCES conversations(id) ON DELETE RESTRICT,

    sender_user_id UUID NOT NULL
        REFERENCES users(id) ON DELETE RESTRICT,

    sender_device_id UUID
        REFERENCES devices(id) ON DELETE SET NULL,

    message_type TEXT NOT NULL DEFAULT 'text'
        CHECK (
            message_type IN (
                'text',
                'image',
                'voice',
                'video',
                'file',
                'system'
            )
        ),

    -- Base64 or another explicitly defined transport encoding
    -- for ciphertext. Never place plaintext here.
    ciphertext TEXT,

    -- Identifies the encryption envelope/protocol version.
    encryption_version SMALLINT NOT NULL DEFAULT 1
        CHECK (encryption_version > 0),

    -- Optional nonce/initialization data required by the
    -- selected, vetted encryption protocol.
    encryption_nonce TEXT,

    -- Optional authenticated metadata. Its interpretation
    -- must be defined by the application protocol.
    encrypted_metadata TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    edited_at TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ,

    -- A message can contain no ciphertext only when it is a
    -- system event. Actual message creation must validate
    -- type, encryption envelope, membership, and size.
    CONSTRAINT messages_payload_check
        CHECK (
            (message_type = 'system')
            OR
            (
                ciphertext IS NOT NULL
                AND char_length(ciphertext) > 0
            )
        )
);

CREATE INDEX IF NOT EXISTS
    messages_conversation_timeline_idx
ON messages (conversation_id, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS
    messages_sender_timeline_idx
ON messages (sender_user_id, created_at DESC);

-- =========================================================
-- 6. Per-device message delivery
-- A message can be queued for multiple registered devices
-- belonging to a recipient. The application must authorize
-- every recipient and device before creating these records.
-- =========================================================

CREATE TABLE IF NOT EXISTS message_deliveries (
    message_id UUID NOT NULL
        REFERENCES messages(id) ON DELETE RESTRICT,

    recipient_user_id UUID NOT NULL
        REFERENCES users(id) ON DELETE RESTRICT,

    recipient_device_id UUID NOT NULL
        REFERENCES devices(id) ON DELETE RESTRICT,

    status TEXT NOT NULL DEFAULT 'queued'
        CHECK (
            status IN (
                'queued',
                'sent',
                'delivered',
                'read',
                'failed',
                'cancelled'
            )
        ),

    queued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    delivered_at TIMESTAMPTZ,
    read_at TIMESTAMPTZ,

    attempt_count INTEGER NOT NULL DEFAULT 0
        CHECK (attempt_count >= 0),

    next_attempt_at TIMESTAMPTZ,
    last_error_code TEXT,

    PRIMARY KEY (message_id, recipient_device_id),

    CONSTRAINT delivery_timestamps_check
        CHECK (
            (delivered_at IS NULL OR status IN ('delivered', 'read'))
            AND
            (read_at IS NULL OR status = 'read')
        )
);

CREATE INDEX IF NOT EXISTS
    message_deliveries_queue_idx
ON message_deliveries (next_attempt_at, queued_at)
WHERE status IN ('queued', 'failed');

CREATE INDEX IF NOT EXISTS
    message_deliveries_recipient_status_idx
ON message_deliveries (recipient_user_id, status, queued_at DESC);

-- =========================================================
-- 7. Idempotency keys
-- Prevent retrying a network request from accidentally
-- creating the same message more than once.
-- =========================================================

CREATE TABLE IF NOT EXISTS message_idempotency (
    sender_user_id UUID NOT NULL
        REFERENCES users(id) ON DELETE RESTRICT,

    sender_device_id UUID NOT NULL
        REFERENCES devices(id) ON DELETE RESTRICT,

    idempotency_key TEXT NOT NULL,

    message_id UUID
        REFERENCES messages(id) ON DELETE RESTRICT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (
        sender_user_id,
        sender_device_id,
        idempotency_key
    ),

    CONSTRAINT message_idempotency_key_length_check
        CHECK (
            char_length(idempotency_key) BETWEEN 16 AND 200
        )
);

CREATE INDEX IF NOT EXISTS
    message_idempotency_created_at_idx
ON message_idempotency (created_at);

-- =========================================================
-- 8. Update timestamps automatically
-- =========================================================

DROP TRIGGER IF EXISTS conversations_set_updated_at
    ON conversations;

CREATE TRIGGER conversations_set_updated_at
BEFORE UPDATE ON conversations
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

COMMIT;
