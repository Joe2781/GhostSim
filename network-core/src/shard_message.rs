use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use uuid::Uuid;

pub const SHARD_MESSAGE_PROTOCOL_VERSION: u16 = 1;
pub const MAX_SHARD_MESSAGE_BYTES: usize = 1024 * 1024;
pub const MAX_SHARD_ID_BYTES: usize = 128;
pub const DEFAULT_MAX_MESSAGE_LIFETIME_MS: u64 = 60_000;
pub const DEFAULT_REPLAY_WINDOW_MS: u64 = 120_000;
pub const DEFAULT_MAX_REPLAY_ENTRIES: usize = 100_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ShardMessageId(Uuid);

impl ShardMessageId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for ShardMessageId {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ShardMessageNonce(Uuid);

impl ShardMessageNonce {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for ShardMessageNonce {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShardMessageKind {
    Heartbeat,
    WorkRequest,
    WorkResponse,
    WorkAccepted,
    WorkRejected,
    WorkCancelled,
    ResourceReport,
    RouteRequest,
    RouteResponse,
    PeerAnnouncement,
    PeerRevocation,
    GatewayRequest,
    GatewayResponse,
    ContentRequest,
    ContentResponse,
    Shutdown,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardMessage {
    pub protocol_version: u16,
    pub message_id: ShardMessageId,
    pub nonce: ShardMessageNonce,

    /// The logical sender identifier.
    ///
    /// This is an identifier, not proof of the sender's identity.
    pub sender_shard_id: String,

    /// The intended logical recipient.
    pub recipient_shard_id: String,

    pub kind: ShardMessageKind,

    /// Unix timestamp in milliseconds.
    pub created_at_ms: u64,

    /// Unix timestamp in milliseconds.
    pub expires_at_ms: u64,

    /// Application-specific message body.
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardMessageLimits {
    pub max_payload_bytes: usize,
    pub max_lifetime_ms: u64,
    pub max_clock_skew_ms: u64,
}

impl Default for ShardMessageLimits {
    fn default() -> Self {
        Self {
            max_payload_bytes: MAX_SHARD_MESSAGE_BYTES,
            max_lifetime_ms: DEFAULT_MAX_MESSAGE_LIFETIME_MS,
            max_clock_skew_ms: 5_000,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ShardMessageError {
    #[error("Unsupported shard message protocol version: {0}")]
    UnsupportedVersion(u16),

    #[error("Shard identifier is empty or too long")]
    InvalidShardIdentifier,

    #[error("Sender and recipient must be different")]
    SameSenderAndRecipient,

    #[error("Message creation timestamp is invalid")]
    InvalidCreationTimestamp,

    #[error("Message expiration timestamp is invalid")]
    InvalidExpirationTimestamp,

    #[error("Message lifetime exceeds the permitted limit")]
    LifetimeExceeded,

    #[error("Message has expired")]
    MessageExpired,

    #[error("Message creation timestamp is too far in the future")]
    TimestampInFuture,

    #[error("Message payload exceeds the configured limit")]
    PayloadTooLarge,

    #[error("Encoded message exceeds the configured limit")]
    EncodedMessageTooLarge,

    #[error("Message serialization failed: {0}")]
    SerializationFailed(String),

    #[error("Message deserialization failed: {0}")]
    DeserializationFailed(String),

    #[error("Message has already been seen")]
    ReplayDetected,

    #[error("Replay-protection capacity has been reached")]
    ReplayStoreFull,

    #[error("System clock is before the Unix epoch")]
    ClockBeforeUnixEpoch,
}

impl ShardMessage {
    pub fn new(
        sender_shard_id: impl Into<String>,
        recipient_shard_id: impl Into<String>,
        kind: ShardMessageKind,
        payload: Vec<u8>,
        now_ms: u64,
        lifetime_ms: u64,
    ) -> Result<Self, ShardMessageError> {
        let lifetime_ms = lifetime_ms.min(DEFAULT_MAX_MESSAGE_LIFETIME_MS);

        let expires_at_ms = now_ms
            .checked_add(lifetime_ms)
            .ok_or(ShardMessageError::InvalidExpirationTimestamp)?;

        let message = Self {
            protocol_version: SHARD_MESSAGE_PROTOCOL_VERSION,
            message_id: ShardMessageId::new(),
            nonce: ShardMessageNonce::new(),
            sender_shard_id: sender_shard_id.into(),
            recipient_shard_id: recipient_shard_id.into(),
            kind,
            created_at_ms: now_ms,
            expires_at_ms,
            payload,
        };

        message.validate_at(now_ms, &ShardMessageLimits::default())?;

        Ok(message)
    }

    pub fn validate_at(
        &self,
        now_ms: u64,
        limits: &ShardMessageLimits,
    ) -> Result<(), ShardMessageError> {
        if self.protocol_version != SHARD_MESSAGE_PROTOCOL_VERSION {
            return Err(ShardMessageError::UnsupportedVersion(
                self.protocol_version,
            ));
        }

        if !valid_shard_id(&self.sender_shard_id)
            || !valid_shard_id(&self.recipient_shard_id)
        {
            return Err(ShardMessageError::InvalidShardIdentifier);
        }

        if self.sender_shard_id == self.recipient_shard_id {
            return Err(ShardMessageError::SameSenderAndRecipient);
        }

        if self.created_at_ms == 0 {
            return Err(ShardMessageError::InvalidCreationTimestamp);
        }

        if self.expires_at_ms <= self.created_at_ms {
            return Err(ShardMessageError::InvalidExpirationTimestamp);
        }

        let lifetime_ms = self
            .expires_at_ms
            .checked_sub(self.created_at_ms)
            .ok_or(ShardMessageError::InvalidExpirationTimestamp)?;

        if lifetime_ms > limits.max_lifetime_ms {
            return Err(ShardMessageError::LifetimeExceeded);
        }

        if self.created_at_ms > now_ms.saturating_add(limits.max_clock_skew_ms) {
            return Err(ShardMessageError::TimestampInFuture);
        }

        if now_ms >= self.expires_at_ms {
            return Err(ShardMessageError::MessageExpired);
        }

        if self.payload.len() > limits.max_payload_bytes {
            return Err(ShardMessageError::PayloadTooLarge);
        }

        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, ShardMessageError> {
        let encoded = serde_json::to_vec(self)
            .map_err(|error| {
                ShardMessageError::SerializationFailed(error.to_string())
            })?;

        if encoded.len() > MAX_SHARD_MESSAGE_BYTES {
            return Err(ShardMessageError::EncodedMessageTooLarge);
        }

        Ok(encoded)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ShardMessageError> {
        if bytes.len() > MAX_SHARD_MESSAGE_BYTES {
            return Err(ShardMessageError::EncodedMessageTooLarge);
        }

        serde_json::from_slice(bytes).map_err(|error| {
            ShardMessageError::DeserializationFailed(error.to_string())
        })
    }

    pub fn is_expired_at(&self, now_ms: u64) -> bool {
        now_ms >= self.expires_at_ms
    }
}

fn valid_shard_id(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= MAX_SHARD_ID_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || byte == b'-'
                || byte == b'_'
                || byte == b'.'
                || byte == b':'
        })
}

/// Tracks message IDs and nonces to reject repeated messages.
///
/// This store is deliberately bounded. It is in-memory, so its contents
/// do not survive a process restart and are not shared between machines.
/// Production deployments need a suitable distributed or persistent replay
/// defense when messages can be accepted by multiple workers or instances.
pub struct ShardReplayGuard {
    entries: HashMap<Uuid, u64>,
    max_entries: usize,
    replay_window_ms: u64,
}

impl ShardReplayGuard {
    pub fn new(
        max_entries: usize,
        replay_window_ms: u64,
    ) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries: max_entries.max(1),
            replay_window_ms: replay_window_ms.max(1),
        }
    }

    pub fn default_limits() -> Self {
        Self::new(
            DEFAULT_MAX_REPLAY_ENTRIES,
            DEFAULT_REPLAY_WINDOW_MS,
        )
    }

    /// Records a message ID and nonce after validation.
    ///
    /// Call this only after the message has passed protocol and authorization
    /// checks. The caller must still authenticate the sender separately.
    pub fn accept(
        &mut self,
        message: &ShardMessage,
        now_ms: u64,
    ) -> Result<(), ShardMessageError> {
        if message.is_expired_at(now_ms) {
            return Err(ShardMessageError::MessageExpired);
        }

        self.remove_expired_entries(now_ms);

        let message_id = message.message_id.as_uuid();
        let nonce = message.nonce.as_uuid();

        if self.entries.contains_key(&message_id)
            || self.entries.contains_key(&nonce)
        {
            return Err(ShardMessageError::ReplayDetected);
        }

        if self.entries.len().saturating_add(2) > self.max_entries {
            return Err(ShardMessageError::ReplayStoreFull);
        }

        let retention_until = now_ms.saturating_add(self.replay_window_ms);

        self.entries.insert(message_id, retention_until);
        self.entries.insert(nonce, retention_until);

        Ok(())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    fn remove_expired_entries(&mut self, now_ms: u64) {
        self.entries
            .retain(|_, retention_until| *retention_until > now_ms);
    }
}

impl Default for ShardReplayGuard {
    fn default() -> Self {
        Self::default_limits()
    }
}

pub fn current_unix_time_ms() -> Result<u64, ShardMessageError> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| ShardMessageError::ClockBeforeUnixEpoch)?;

    u64::try_from(duration.as_millis())
        .map_err(|_| ShardMessageError::InvalidCreationTimestamp)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_message() -> ShardMessage {
        ShardMessage::new(
            "shard-alpha",
            "shard-beta",
            ShardMessageKind::WorkRequest,
            b"work payload".to_vec(),
            1_000,
            10_000,
        )
        .expect("sample message should be valid")
    }

    #[test]
    fn message_round_trips_through_json() {
        let message = sample_message();

        let encoded = message.encode().expect("encoding should succeed");
        let decoded =
            ShardMessage::decode(&encoded).expect("decoding should succeed");

        assert_eq!(decoded, message);
    }

    #[test]
    fn expired_message_is_rejected() {
        let message = sample_message();

        let result = message.validate_at(
            message.expires_at_ms,
            &ShardMessageLimits::default(),
        );

        assert_eq!(result, Err(ShardMessageError::MessageExpired));
    }

    #[test]
    fn repeated_message_is_rejected() {
        let message = sample_message();
        let mut guard = ShardReplayGuard::new(10, 120_000);

        guard
            .accept(&message, 2_000)
            .expect("first acceptance should succeed");

        assert_eq!(
            guard.accept(&message, 2_001),
            Err(ShardMessageError::ReplayDetected)
        );
    }

    #[test]
    fn future_message_is_rejected() {
        let message = sample_message();

        let result = message.validate_at(
            1_000,
            &ShardMessageLimits {
                max_clock_skew_ms: 100,
                ..ShardMessageLimits::default()
            },
        );

        assert_eq!(result, Err(ShardMessageError::TimestampInFuture));
    }

    #[test]
    fn replay_store_enforces_capacity() {
        let first = sample_message();

        let second = ShardMessage::new(
            "shard-alpha",
            "shard-gamma",
            ShardMessageKind::Heartbeat,
            Vec::new(),
            1_000,
            10_000,
        )
        .expect("second message should be valid");

        let mut guard = ShardReplayGuard::new(2, 120_000);

        guard
            .accept(&first, 2_000)
            .expect("first message should fit");

        assert_eq!(
            guard.accept(&second, 2_000),
            Err(ShardMessageError::ReplayStoreFull)
        );
    }

    #[test]
    fn oversized_encoded_message_is_rejected() {
        let bytes = vec![b'x'; MAX_SHARD_MESSAGE_BYTES + 1];

        assert_eq!(
            ShardMessage::decode(&bytes),
            Err(ShardMessageError::EncodedMessageTooLarge)
        );
    }
}
