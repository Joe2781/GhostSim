//! Transport abstractions for GhostSim.
//!
//! A transport moves data between authenticated peers over an available
//! underlying network connection.
//!
//! This module defines the interface and connection metadata. It does not
//! implement a concrete socket transport or packet-forwarding engine.
//! Those implementations must enforce authentication, message-size limits,
//! deadlines, backpressure, and appropriate encryption.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::error::{NetworkError, NetworkResult};
use crate::peer::PeerId;

/// Supported transport categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportKind {
    /// TCP-based connection.
    Tcp,

    /// QUIC-based connection.
    Quic,

    /// Direct connection over a local IP network.
    LocalNetwork,

    /// Wi-Fi Direct, when supported by the platform integration.
    WifiDirect,

    /// Bluetooth transport, when supported by the platform integration.
    Bluetooth,

    /// In-process transport for tests only.
    ///
    /// This is not a production networking transport.
    TestOnly,
}

/// Current state of a transport connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportState {
    /// No connection has been established.
    Disconnected,

    /// The transport is establishing a connection.
    Connecting,

    /// A connection exists but has not completed authentication.
    ConnectedUnauthenticated,

    /// The connection has completed the required authentication handshake.
    ConnectedAuthenticated,

    /// The connection is shutting down.
    Closing,

    /// The connection has closed.
    Closed,
}

/// Configuration limits for an individual transport connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportConfig {
    /// Maximum permitted application frame size in bytes.
    pub max_frame_bytes: usize,

    /// Maximum time allowed for a connection attempt.
    pub connect_timeout: Duration,

    /// Maximum time allowed for an individual send operation.
    pub send_timeout: Duration,

    /// Maximum time allowed for an individual receive operation.
    pub receive_timeout: Duration,

    /// Maximum number of buffered outgoing frames.
    pub max_outbound_queue_frames: usize,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            max_frame_bytes: 1024 * 1024,
            connect_timeout: Duration::from_secs(10),
            send_timeout: Duration::from_secs(15),
            receive_timeout: Duration::from_secs(45),
            max_outbound_queue_frames: 256,
        }
    }
}

impl TransportConfig {
    /// Validates transport limits before a connection is created.
    pub fn validate(&self) -> NetworkResult<()> {
        if self.max_frame_bytes == 0
            || self.connect_timeout.is_zero()
            || self.send_timeout.is_zero()
            || self.receive_timeout.is_zero()
            || self.max_outbound_queue_frames == 0
        {
            return Err(NetworkError::InvalidInput(
                "Transport limits and timeouts must be positive".to_owned(),
            ));
        }

        Ok(())
    }
}

/// Metadata describing a transport connection.
///
/// This structure intentionally excludes authentication tokens,
/// private keys, and other secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportConnectionInfo {
    /// Remote peer identifier.
    pub peer_id: PeerId,

    /// Underlying transport category.
    pub kind: TransportKind,

    /// Current transport state.
    pub state: TransportState,

    /// Negotiated network protocol version.
    pub protocol_version: u16,
}

/// A transport implementation for GhostSim peer communication.
///
/// Implementations must not treat a successful socket write as proof that
/// the remote application received, decrypted, or processed the message.
///
/// The byte methods exchange framed application data. Each implementation
/// must document and enforce its framing rules.
///
/// Implementations must also ensure that connection-specific identity is
/// authenticated before the connection is marked usable.
#[async_trait]
pub trait NetworkTransport: Send + Sync {
    /// Returns the underlying transport category.
    fn kind(&self) -> TransportKind;

    /// Returns the remote peer identifier.
    fn peer_id(&self) -> PeerId;

    /// Returns the current connection state.
    fn state(&self) -> TransportState;

    /// Returns connection metadata.
    fn connection_info(&self) -> TransportConnectionInfo;

    /// Establishes a connection, or completes any pending connection setup.
    ///
    /// Concrete implementations must apply `connect_timeout`.
    async fn connect(&mut self) -> NetworkResult<()>;

    /// Sends one framed application message.
    ///
    /// The method must reject oversized frames and apply `send_timeout`.
    /// A successful return means the transport accepted the send operation;
    /// it does not prove remote application delivery.
    async fn send_frame(&mut self, frame: &[u8]) -> NetworkResult<()>;

    /// Receives one framed application message.
    ///
    /// Implementations must apply `receive_timeout`, enforce frame-size
    /// limits, and reject malformed framing.
    async fn receive_frame(&mut self) -> NetworkResult<Vec<u8>>;

    /// Closes the connection and releases connection-owned resources.
    async fn close(&mut self) -> NetworkResult<()>;
}

/// Validates a frame against the configured size limit.
pub fn validate_frame_size(
    frame: &[u8],
    config: &TransportConfig,
) -> NetworkResult<()> {
    config.validate()?;

    if frame.len() > config.max_frame_bytes {
        return Err(NetworkError::MessageTooLarge);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_transport_configuration_is_valid() {
        assert!(TransportConfig::default().validate().is_ok());
    }

    #[test]
    fn zero_frame_limit_is_rejected() {
        let config = TransportConfig {
            max_frame_bytes: 0,
            ..TransportConfig::default()
        };

        assert!(matches!(
            config.validate(),
            Err(NetworkError::InvalidInput(_))
        ));
    }

    #[test]
    fn oversized_frame_is_rejected() {
        let config = TransportConfig {
            max_frame_bytes: 4,
            ..TransportConfig::default()
        };

        assert!(matches!(
            validate_frame_size(b"12345", &config),
            Err(NetworkError::MessageTooLarge)
        ));
    }

    #[test]
    fn frame_at_limit_is_accepted() {
        let config = TransportConfig {
            max_frame_bytes: 5,
            ..TransportConfig::default()
        };

        assert!(validate_frame_size(b"12345", &config).is_ok());
    }

    #[test]
    fn test_transport_is_explicitly_identified() {
        assert_eq!(
            TransportKind::TestOnly,
            TransportKind::TestOnly
        );
    }
}
