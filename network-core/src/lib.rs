//! GhostSim Network Core
//!
//! The foundation for GhostSim's distributed connectivity engine.
//!
//! Responsibilities:
//! - Peer identity and connection management
//! - Network route evaluation
//! - Transport abstractions
//! - Resource-aware relay participation
//! - Network health and connectivity state
//!
//! This library does not claim to provide internet forwarding by itself.
//! Concrete transports and packet-forwarding implementations will be
//! introduced in subsequent modules.

pub mod error;
pub mod peer;
pub mod route;
pub mod transport;
pub mod resource_policy;

pub use error::{NetworkError, NetworkResult};
pub use peer::{
    ConnectionState,
    PeerCapabilities,
    PeerDescriptor,
    PeerId,
    PeerRole,
};
pub use resource_policy::{
    NetworkResourcePolicy,
    RelayPermission,
};
pub use route::{
    NetworkPath,
    RouteCandidate,
    RouteMetrics,
    RouteSelection,
};
pub use transport::{
    NetworkTransport,
    TransportKind,
    TransportState,
};

/// GhostSim network protocol version.
///
/// Peers with incompatible protocol versions must negotiate compatibility
/// before exchanging application data.
pub const NETWORK_PROTOCOL_VERSION: u16 = 1;

/// Maximum serialized control-message size.
///
/// This limit applies to control messages, not arbitrary internet packets.
pub const MAX_CONTROL_MESSAGE_BYTES: usize = 64 * 1024;

/// Maximum number of peers in a single route candidate.
///
/// This is a defensive limit to prevent unbounded route descriptions.
pub const MAX_ROUTE_HOPS: usize = 16;

/// Default target for detecting an unresponsive connection.
///
/// This is a timeout target, not a guarantee of network latency.
pub const DEFAULT_CONNECTION_TIMEOUT_MS: u64 = 10_000;

/// Default interval between connection health checks.
pub const DEFAULT_HEALTH_CHECK_INTERVAL_MS: u64 = 15_000;

/// Identifies the GhostSim network engine.
pub const ENGINE_NAME: &str = "GhostSim Network Core";
