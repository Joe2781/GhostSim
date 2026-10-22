//! Peer identity, capabilities, and connection state.
//!
//! A peer represents a GhostSim device participating in the network.
//! A registered device is not automatically authorized to relay traffic.
//! Relay participation requires explicit owner consent and applicable policy
//! checks before any forwarding operation is permitted.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

use crate::error::{NetworkError, NetworkResult};

/// Internal identifier for a GhostSim peer.
///
/// This UUID is an internal identifier, not a public GhostSim ID.
/// Public identity and internal device identity must remain separate.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    PartialOrd,
    Ord,
)]
#[serde(transparent)]
pub struct PeerId(Uuid);

impl PeerId {
    /// Creates a new random peer identifier.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Creates a peer identifier from an existing UUID.
    pub fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    /// Returns the underlying UUID.
    pub fn as_uuid(&self) -> Uuid {
        self.0
    }

    /// Parses a peer identifier from a UUID string.
    pub fn parse(value: &str) -> NetworkResult<Self> {
        let uuid = Uuid::parse_str(value)
            .map_err(|_| NetworkError::InvalidPeerId)?;

        Ok(Self(uuid))
    }
}

impl Default for PeerId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for PeerId {
    type Err = NetworkError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// The logical role a peer may perform.
///
/// A role describes an intended capability. It does not, by itself,
/// grant permission to forward traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerRole {
    /// A device using GhostSim without providing relay services.
    Client,

    /// A device that may relay authorized traffic when explicitly enabled.
    Relay,

    /// A device with a verified path to an external internet destination.
    ///
    /// Actual gateway eligibility must be established through live
    /// reachability checks and authorization, not this label alone.
    InternetGateway,

    /// A device performing more than one authorized network role.
    MultiRole,
}

/// Current transport connectivity state for a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    /// No active transport connection is available.
    Disconnected,

    /// A connection attempt is in progress.
    Connecting,

    /// A transport connection exists, but the peer has not completed
    /// all required protocol and identity checks.
    ConnectedUnverified,

    /// The connection and peer identity have been verified.
    ConnectedVerified,

    /// The connection is temporarily degraded.
    Degraded,

    /// The peer is unreachable through currently known transports.
    Unreachable,
}

impl ConnectionState {
    /// Whether application data may be considered for transmission.
    ///
    /// Higher-level authorization and route checks are still required.
    pub fn transport_is_usable(self) -> bool {
        matches!(
            self,
            Self::ConnectedVerified | Self::Degraded
        )
    }

    /// Whether the peer should currently be considered for new connections.
    pub fn can_attempt_connection(self) -> bool {
        matches!(
            self,
            Self::Disconnected | Self::Unreachable
        )
    }
}

/// Transport capabilities reported by a peer.
///
/// These are capability claims until verified against the actual transport.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerCapabilities {
    /// Supports ordinary GhostSim application messaging.
    pub messaging: bool,

    /// Supports GhostSim voice-call transport.
    pub voice: bool,

    /// Supports GhostSim video-call transport.
    pub video: bool,

    /// Supports a direct local-network transport.
    pub local_network: bool,

    /// Supports Wi-Fi Direct where the operating system permits it.
    pub wifi_direct: bool,

    /// Supports Bluetooth-based communication where permitted.
    pub bluetooth: bool,

    /// Supports authorized traffic relay.
    ///
    /// This capability must never override the device owner's consent.
    pub relay: bool,

    /// Supports caching eligible, integrity-verified content.
    pub content_cache: bool,

    /// Supports an outbound route to external internet destinations.
    ///
    /// The route must be verified before it is used.
    pub internet_gateway: bool,
}

impl Default for PeerCapabilities {
    fn default() -> Self {
        Self {
            messaging: true,
            voice: true,
            video: false,
            local_network: false,
            wifi_direct: false,
            bluetooth: false,
            relay: false,
            content_cache: false,
            internet_gateway: false,
        }
    }
}

/// Publicly exchangeable metadata for a network peer.
///
/// Authentication keys and session secrets must not be embedded in this
/// structure. Those belong in the authenticated handshake and secure
/// transport implementation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerDescriptor {
    /// Internal peer identifier.
    pub id: PeerId,

    /// Negotiated network protocol version.
    pub protocol_version: u16,

    /// Advertised logical role.
    pub role: PeerRole,

    /// Current observed connection state.
    pub connection_state: ConnectionState,

    /// Advertised capabilities.
    pub capabilities: PeerCapabilities,
}

impl PeerDescriptor {
    /// Creates a peer descriptor with conservative default capabilities.
    pub fn new(id: PeerId, protocol_version: u16) -> Self {
        Self {
            id,
            protocol_version,
            role: PeerRole::Client,
            connection_state: ConnectionState::Disconnected,
            capabilities: PeerCapabilities::default(),
        }
    }

    /// Checks protocol compatibility with the local engine.
    pub fn validate_protocol(&self, local_version: u16) -> NetworkResult<()> {
        if self.protocol_version != local_version {
            return Err(NetworkError::ProtocolVersionMismatch);
        }

        Ok(())
    }

    /// Checks whether this peer advertises the ability to relay.
    ///
    /// This is only a capability check. Actual forwarding additionally
    /// requires explicit consent, authentication, resource checks, and
    /// authorization for the specific route and traffic.
    pub fn advertises_relay_capability(&self) -> bool {
        self.capabilities.relay
            && matches!(
                self.role,
                PeerRole::Relay | PeerRole::MultiRole
            )
    }

    /// Checks whether the peer advertises gateway capability.
    ///
    /// This does not prove that a particular internet destination is
    /// reachable through the peer.
    pub fn advertises_gateway_capability(&self) -> bool {
        self.capabilities.internet_gateway
            && matches!(
                self.role,
                PeerRole::InternetGateway | PeerRole::MultiRole
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_id_round_trips_through_string() {
        let original = PeerId::new();
        let parsed = PeerId::parse(&original.to_string()).unwrap();

        assert_eq!(original, parsed);
    }

    #[test]
    fn invalid_peer_id_is_rejected() {
        assert!(matches!(
            PeerId::parse("not-a-valid-peer-id"),
            Err(NetworkError::InvalidPeerId)
        ));
    }

    #[test]
    fn default_peer_does_not_advertise_relay_or_gateway() {
        let peer = PeerDescriptor::new(
            PeerId::new(),
            crate::NETWORK_PROTOCOL_VERSION,
        );

        assert!(!peer.advertises_relay_capability());
        assert!(!peer.advertises_gateway_capability());
    }

    #[test]
    fn mismatched_protocol_version_is_rejected() {
        let peer = PeerDescriptor::new(PeerId::new(), 999);

        assert!(matches!(
            peer.validate_protocol(crate::NETWORK_PROTOCOL_VERSION),
            Err(NetworkError::ProtocolVersionMismatch)
        ));
    }

    #[test]
    fn unverified_connections_are_not_usable() {
        assert!(
            !ConnectionState::ConnectedUnverified.transport_is_usable()
        );

        assert!(
            ConnectionState::ConnectedVerified.transport_is_usable()
        );
    }
}
