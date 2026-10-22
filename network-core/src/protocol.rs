use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{NetworkError, NetworkResult};
use crate::peer::PeerId;
use crate::{
    MAX_CONTROL_MESSAGE_BYTES,
    MAX_ROUTE_HOPS,
    NETWORK_PROTOCOL_VERSION,
};

/// Maximum permitted identifier length in a control message.
const MAX_IDENTIFIER_LENGTH: usize = 128;

/// Maximum permitted number of advertised capabilities.
const MAX_CAPABILITIES: usize = 64;

/// Maximum permitted length of a textual reason.
const MAX_REASON_LENGTH: usize = 512;

/// Protocol message identifier.
///
/// Each message has a unique identifier so later components can support
/// deduplication, tracing, acknowledgements, and replay protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProtocolMessageId(pub Uuid);

impl ProtocolMessageId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for ProtocolMessageId {
    fn default() -> Self {
        Self::new()
    }
}

/// Unique identifier for a connection handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HandshakeId(pub Uuid);

impl HandshakeId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for HandshakeId {
    fn default() -> Self {
        Self::new()
    }
}

/// Supported control-message categories.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum ControlMessage {
    /// Begin negotiating a connection with another peer.
    Hello(HelloMessage),

    /// Respond to an initial connection negotiation.
    HelloAck(HelloAckMessage),

    /// Exchange network reachability and capability information.
    PeerCapabilities(PeerCapabilitiesMessage),

    /// Report measured connection quality.
    HealthReport(HealthReportMessage),

    /// Request or acknowledge a connection shutdown.
    Disconnect(DisconnectMessage),

    /// Report a protocol-level error.
    Error(ProtocolErrorMessage),
}

/// Common protocol envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolEnvelope {
    pub protocol_version: u16,
    pub message_id: ProtocolMessageId,
    pub message: ControlMessage,
}

impl ProtocolEnvelope {
    pub fn new(message: ControlMessage) -> Self {
        Self {
            protocol_version: NETWORK_PROTOCOL_VERSION,
            message_id: ProtocolMessageId::new(),
            message,
        }
    }

    /// Validate the protocol version and message structure.
    pub fn validate(&self) -> NetworkResult<()> {
        if self.protocol_version != NETWORK_PROTOCOL_VERSION {
            return Err(NetworkError::InvalidMessage(format!(
                "Unsupported protocol version: {}",
                self.protocol_version
            )));
        }

        validate_control_message(&self.message)
    }

    /// Serialize an envelope to JSON while enforcing the message-size limit.
    pub fn encode(&self) -> NetworkResult<Vec<u8>> {
        self.validate()?;

        let encoded = serde_json::to_vec(self).map_err(|error| {
            NetworkError::InvalidMessage(format!(
                "Could not encode protocol envelope: {error}"
            ))
        })?;

        if encoded.len() > MAX_CONTROL_MESSAGE_BYTES {
            return Err(NetworkError::InvalidMessage(
                "Encoded control message exceeds the size limit".to_string(),
            ));
        }

        Ok(encoded)
    }

    /// Decode and validate a received JSON envelope.
    pub fn decode(bytes: &[u8]) -> NetworkResult<Self> {
        if bytes.len() > MAX_CONTROL_MESSAGE_BYTES {
            return Err(NetworkError::InvalidMessage(
                "Received control message exceeds the size limit".to_string(),
            ));
        }

        let envelope: Self =
            serde_json::from_slice(bytes).map_err(|error| {
                NetworkError::InvalidMessage(format!(
                    "Could not decode protocol envelope: {error}"
                ))
            })?;

        envelope.validate()?;

        Ok(envelope)
    }
}

/// Initial peer negotiation message.
///
/// The identity and capabilities in this message are claims, not proof.
/// A separate authenticated handshake must verify the sender.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloMessage {
    pub handshake_id: HandshakeId,
    pub peer_id: PeerId,
    pub supported_protocol_versions: Vec<u16>,
    pub capabilities: Vec<String>,
    pub maximum_route_hops: u8,
}

/// Response to a HelloMessage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloAckMessage {
    pub handshake_id: HandshakeId,
    pub peer_id: PeerId,
    pub selected_protocol_version: u16,
    pub accepted: bool,
    pub reason: Option<String>,
}

/// Advertised peer capabilities.
///
/// These values must not grant permissions by themselves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerCapabilitiesMessage {
    pub peer_id: PeerId,
    pub capabilities: Vec<String>,
    pub can_relay: bool,
    pub can_forward_internet_traffic: bool,
    pub maximum_route_hops: u8,
}

/// Basic measurements used by later route-selection components.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthReportMessage {
    pub peer_id: PeerId,
    pub round_trip_time_ms: u32,
    pub estimated_bandwidth_kbps: u32,
    pub packet_loss_basis_points: u16,
    pub reliability_basis_points: u16,
}

/// Connection shutdown message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisconnectMessage {
    pub peer_id: PeerId,
    pub reason: Option<String>,
}

/// Protocol error sent to a remote peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolErrorMessage {
    pub code: String,
    pub reason: String,
    pub recoverable: bool,
}

/// Validate the structure of a control message.
fn validate_control_message(message: &ControlMessage) -> NetworkResult<()> {
    match message {
        ControlMessage::Hello(hello) => {
            if hello.supported_protocol_versions.is_empty() {
                return invalid_message(
                    "Hello message must advertise a protocol version",
                );
            }

            if hello.supported_protocol_versions.len() > 16 {
                return invalid_message(
                    "Too many protocol versions were advertised",
                );
            }

            if hello.maximum_route_hops == 0
                || hello.maximum_route_hops > MAX_ROUTE_HOPS as u8
            {
                return invalid_message(
                    "Hello message contains an invalid route-hop limit",
                );
            }

            validate_capabilities(&hello.capabilities)
        }

        ControlMessage::HelloAck(ack) => {
            if ack.accepted && ack.selected_protocol_version == 0 {
                return invalid_message(
                    "Accepted handshake must select a protocol version",
                );
            }

            if let Some(reason) = &ack.reason {
                validate_reason(reason)?;
            }

            Ok(())
        }

        ControlMessage::PeerCapabilities(capabilities) => {
            if capabilities.maximum_route_hops == 0
                || capabilities.maximum_route_hops > MAX_ROUTE_HOPS as u8
            {
                return invalid_message(
                    "Peer advertised an invalid route-hop limit",
                );
            }

            validate_capabilities(&capabilities.capabilities)
        }

        ControlMessage::HealthReport(report) => {
            if report.packet_loss_basis_points > 10_000 {
                return invalid_message(
                    "Packet-loss measurement must be between 0 and 10000",
                );
            }

            if report.reliability_basis_points > 10_000 {
                return invalid_message(
                    "Reliability measurement must be between 0 and 10000",
                );
            }

            Ok(())
        }

        ControlMessage::Disconnect(disconnect) => {
            if let Some(reason) = &disconnect.reason {
                validate_reason(reason)?;
            }

            Ok(())
        }

        ControlMessage::Error(error) => {
            validate_identifier(&error.code)?;

            if error.reason.trim().is_empty()
                || error.reason.len() > MAX_REASON_LENGTH
            {
                return invalid_message(
                    "Protocol error reason is empty or too long",
                );
            }

            Ok(())
        }
    }
}

fn validate_capabilities(capabilities: &[String]) -> NetworkResult<()> {
    if capabilities.len() > MAX_CAPABILITIES {
        return invalid_message("Too many capabilities were advertised");
    }

    for capability in capabilities {
        validate_identifier(capability)?;
    }

    Ok(())
}

fn validate_identifier(value: &str) -> NetworkResult<()> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_LENGTH
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return invalid_message("Invalid protocol identifier");
    }

    Ok(())
}

fn validate_reason(reason: &str) -> NetworkResult<()> {
    if reason.len() > MAX_REASON_LENGTH
        || reason.chars().any(char::is_control)
    {
        return invalid_message("Invalid protocol reason");
    }

    Ok(())
}

fn invalid_message<T>(reason: &str) -> NetworkResult<T> {
    Err(NetworkError::InvalidMessage(reason.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_hello() -> HelloMessage {
        HelloMessage {
            handshake_id: HandshakeId::new(),
            peer_id: PeerId::new(),
            supported_protocol_versions: vec![NETWORK_PROTOCOL_VERSION],
            capabilities: vec![
                "tcp".to_string(),
                "health_reports".to_string(),
            ],
            maximum_route_hops: 8,
        }
    }

    #[test]
    fn envelope_round_trips() {
        let envelope = ProtocolEnvelope::new(
            ControlMessage::Hello(sample_hello()),
        );

        let encoded = envelope
            .encode()
            .expect("encoding should succeed");

        let decoded = ProtocolEnvelope::decode(&encoded)
            .expect("decoding should succeed");

        assert_eq!(decoded, envelope);
    }

    #[test]
    fn envelope_rejects_wrong_protocol_version() {
        let mut envelope = ProtocolEnvelope::new(
            ControlMessage::Hello(sample_hello()),
        );

        envelope.protocol_version = NETWORK_PROTOCOL_VERSION + 1;

        assert!(envelope.encode().is_err());
    }

    #[test]
    fn envelope_rejects_excessive_route_hops() {
        let mut hello = sample_hello();
        hello.maximum_route_hops = MAX_ROUTE_HOPS as u8 + 1;

        let envelope = ProtocolEnvelope::new(
            ControlMessage::Hello(hello),
        );

        assert!(envelope.encode().is_err());
    }

    #[test]
    fn envelope_rejects_excessive_packet_loss() {
        let report = HealthReportMessage {
            peer_id: PeerId::new(),
            round_trip_time_ms: 40,
            estimated_bandwidth_kbps: 5000,
            packet_loss_basis_points: 10_001,
            reliability_basis_points: 9500,
        };

        let envelope = ProtocolEnvelope::new(
            ControlMessage::HealthReport(report),
        );

        assert!(envelope.encode().is_err());
    }

    #[test]
    fn envelope_rejects_oversized_input() {
        let bytes = vec![b'a'; MAX_CONTROL_MESSAGE_BYTES + 1];

        assert!(ProtocolEnvelope::decode(&bytes).is_err());
    }
}
