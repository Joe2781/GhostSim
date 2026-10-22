//! Structured errors for the GhostSim networking engine.
//!
//! Errors are classified so that callers can distinguish invalid input,
//! unavailable connections, authorization failures, and internal failures.
//! Sensitive information such as credentials and encryption keys must never
//! be included in error messages.

use thiserror::Error;

/// Result type used throughout the GhostSim networking engine.
pub type NetworkResult<T> = Result<T, NetworkError>;

/// Errors that can occur within GhostSim's networking engine.
#[derive(Debug, Error)]
pub enum NetworkError {
    /// An operation received invalid input.
    #[error("Invalid network input: {0}")]
    InvalidInput(String),

    /// A peer identifier could not be parsed or validated.
    #[error("Invalid peer identifier")]
    InvalidPeerId,

    /// The requested peer is not known to the local engine.
    #[error("Peer not found")]
    PeerNotFound,

    /// A peer exists but is not currently reachable.
    #[error("Peer is unreachable")]
    PeerUnreachable,

    /// A connection does not exist or is no longer usable.
    #[error("Connection is unavailable")]
    ConnectionUnavailable,

    /// A connection operation exceeded its configured deadline.
    #[error("Connection operation timed out")]
    Timeout,

    /// A requested operation is not authorized.
    #[error("Network operation is not authorized")]
    Unauthorized,

    /// The device owner has not consented to relay participation.
    #[error("Relay participation has not been authorized by the device owner")]
    RelayNotAuthorized,

    /// A device has exceeded a configured resource limit.
    #[error("Device resource limit exceeded")]
    ResourceLimitExceeded,

    /// No usable route to the requested destination was found.
    #[error("No viable network route is available")]
    NoViableRoute,

    /// A proposed route contains an invalid sequence of peers.
    #[error("Invalid network route")]
    InvalidRoute,

    /// A route exceeds the configured hop limit.
    #[error("Network route exceeds the maximum hop count")]
    RouteHopLimitExceeded,

    /// A transport does not support the requested operation.
    #[error("Operation is not supported by this transport")]
    UnsupportedOperation,

    /// A message exceeds the configured size limit.
    #[error("Network message exceeds the permitted size")]
    MessageTooLarge,

    /// A remote peer supplied an incompatible protocol version.
    #[error("Incompatible network protocol version")]
    ProtocolVersionMismatch,

    /// A network message failed structural validation.
    #[error("Invalid network protocol message")]
    InvalidProtocolMessage,

    /// Cryptographic verification failed.
    #[error("Cryptographic verification failed")]
    CryptographicVerificationFailed,

    /// A requested cryptographic operation could not be completed.
    #[error("Cryptographic operation failed")]
    CryptographicOperationFailed,

    /// The engine is shutting down or has stopped.
    #[error("Network engine is shutting down")]
    EngineShuttingDown,

    /// The engine is not in a state that permits the operation.
    #[error("Network engine is not ready")]
    EngineNotReady,

    /// An underlying operating-system or socket operation failed.
    #[error("Network I/O operation failed")]
    Io(#[from] std::io::Error),

    /// A serialization or deserialization operation failed.
    #[error("Network message serialization failed")]
    Serialization(#[from] serde_json::Error),

    /// An internal invariant was violated.
    #[error("Internal network engine error")]
    Internal,
}

impl NetworkError {
    /// Indicates whether retrying the operation might succeed.
    ///
    /// This is a conservative classification. Callers must still apply
    /// bounded retries, backoff, and operation-specific safety checks.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::PeerUnreachable
                | Self::ConnectionUnavailable
                | Self::Timeout
                | Self::Io(_)
                | Self::EngineNotReady
        )
    }

    /// Returns a stable, non-sensitive category suitable for telemetry.
    ///
    /// Do not use arbitrary error strings as metric labels.
    pub fn category(&self) -> &'static str {
        match self {
            Self::InvalidInput(_) => "invalid_input",
            Self::InvalidPeerId => "invalid_peer_id",
            Self::PeerNotFound => "peer_not_found",
            Self::PeerUnreachable => "peer_unreachable",
            Self::ConnectionUnavailable => "connection_unavailable",
            Self::Timeout => "timeout",
            Self::Unauthorized => "unauthorized",
            Self::RelayNotAuthorized => "relay_not_authorized",
            Self::ResourceLimitExceeded => "resource_limit_exceeded",
            Self::NoViableRoute => "no_viable_route",
            Self::InvalidRoute => "invalid_route",
            Self::RouteHopLimitExceeded => "route_hop_limit_exceeded",
            Self::UnsupportedOperation => "unsupported_operation",
            Self::MessageTooLarge => "message_too_large",
            Self::ProtocolVersionMismatch => "protocol_version_mismatch",
            Self::InvalidProtocolMessage => "invalid_protocol_message",
            Self::CryptographicVerificationFailed => {
                "cryptographic_verification_failed"
            }
            Self::CryptographicOperationFailed => {
                "cryptographic_operation_failed"
            }
            Self::EngineShuttingDown => "engine_shutting_down",
            Self::EngineNotReady => "engine_not_ready",
            Self::Io(_) => "io_error",
            Self::Serialization(_) => "serialization_error",
            Self::Internal => "internal_error",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::NetworkError;

    #[test]
    fn transient_connection_errors_are_retryable() {
        assert!(NetworkError::Timeout.is_retryable());
        assert!(NetworkError::PeerUnreachable.is_retryable());
        assert!(NetworkError::ConnectionUnavailable.is_retryable());
    }

    #[test]
    fn authorization_errors_are_not_automatically_retryable() {
        assert!(!NetworkError::Unauthorized.is_retryable());
        assert!(!NetworkError::RelayNotAuthorized.is_retryable());
    }

    #[test]
    fn error_categories_are_stable() {
        assert_eq!(
            NetworkError::NoViableRoute.category(),
            "no_viable_route"
        );

        assert_eq!(
            NetworkError::ResourceLimitExceeded.category(),
            "resource_limit_exceeded"
        );
    }
}
