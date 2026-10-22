use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::{NetworkError, NetworkResult};
use crate::peer::PeerId;
use crate::transport::TransportKind;

/// Maximum number of peers this manager will track.
pub const DEFAULT_MAX_MANAGED_PEERS: usize = 256;

/// Default time after which an inactive peer is considered stale.
pub const DEFAULT_PEER_STALE_AFTER_SECS: u64 = 120;

/// Current lifecycle state of a managed peer connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedConnectionState {
    Connecting,
    Connected,
    Degraded,
    Disconnecting,
    Disconnected,
    Failed,
}

/// Information maintained for a managed peer connection.
#[derive(Debug, Clone)]
pub struct ManagedPeerConnection {
    pub peer_id: PeerId,
    pub remote_address: Option<SocketAddr>,
    pub transport: TransportKind,
    pub state: ManagedConnectionState,
    pub connected_at_unix_ms: Option<u128>,
    pub last_activity_unix_ms: u128,
    pub last_error: Option<String>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub consecutive_failures: u32,
}

impl ManagedPeerConnection {
    fn new(
        peer_id: PeerId,
        remote_address: Option<SocketAddr>,
        transport: TransportKind,
        state: ManagedConnectionState,
    ) -> Self {
        let now = current_time_ms();

        Self {
            peer_id,
            remote_address,
            transport,
            state,
            connected_at_unix_ms: None,
            last_activity_unix_ms: now,
            last_error: None,
            bytes_sent: 0,
            bytes_received: 0,
            consecutive_failures: 0,
        }
    }

    /// Whether the peer is currently marked as connected.
    pub fn is_connected(&self) -> bool {
        self.state == ManagedConnectionState::Connected
    }

    /// Whether this peer can currently be considered for routing.
    ///
    /// Actual route selection must additionally verify reachability,
    /// relay permissions, path quality, and security requirements.
    pub fn is_route_candidate(&self) -> bool {
        self.state == ManagedConnectionState::Connected
    }

    /// Duration since the last recorded activity.
    pub fn inactivity_duration(&self) -> Duration {
        let now = current_time_ms();

        Duration::from_millis(
            now.saturating_sub(self.last_activity_unix_ms)
                .min(u64::MAX as u128) as u64,
        )
    }
}

/// Summary of the connection manager's current state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionManagerStats {
    pub total_peers: usize,
    pub connecting: usize,
    pub connected: usize,
    pub degraded: usize,
    pub disconnecting: usize,
    pub disconnected: usize,
    pub failed: usize,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
}

/// Tracks GhostSim peer connection metadata.
///
/// This manager does not itself establish sockets, authenticate peers,
/// encrypt traffic, or forward packets. It records lifecycle information
/// reported by the networking and security components.
pub struct ConnectionManager {
    peers: HashMap<PeerId, ManagedPeerConnection>,
    max_peers: usize,
}

impl ConnectionManager {
    /// Create a manager with the default peer capacity.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_MAX_MANAGED_PEERS)
    }

    /// Create a manager with an explicitly configured capacity.
    pub fn with_capacity(max_peers: usize) -> Self {
        Self {
            peers: HashMap::new(),
            max_peers: max_peers.max(1),
        }
    }

    /// Register a peer before attempting to establish its connection.
    pub fn register_peer(
        &mut self,
        peer_id: PeerId,
        remote_address: Option<SocketAddr>,
        transport: TransportKind,
    ) -> NetworkResult<()> {
        if self.peers.contains_key(&peer_id) {
            return Err(NetworkError::InvalidState(
                "Peer is already registered".to_string(),
            ));
        }

        if self.peers.len() >= self.max_peers {
            return Err(NetworkError::InvalidState(
                "Connection manager capacity reached".to_string(),
            ));
        }

        let connection = ManagedPeerConnection::new(
            peer_id,
            remote_address,
            transport,
            ManagedConnectionState::Connecting,
        );

        self.peers.insert(peer_id, connection);

        Ok(())
    }

    /// Record a successful connection.
    pub fn mark_connected(
        &mut self,
        peer_id: PeerId,
    ) -> NetworkResult<()> {
        let peer = self.get_peer_mut(peer_id)?;

        peer.state = ManagedConnectionState::Connected;
        peer.connected_at_unix_ms = Some(current_time_ms());
        peer.last_activity_unix_ms = current_time_ms();
        peer.last_error = None;
        peer.consecutive_failures = 0;

        Ok(())
    }

    /// Record that a connection is experiencing degraded performance.
    pub fn mark_degraded(
        &mut self,
        peer_id: PeerId,
        reason: Option<String>,
    ) -> NetworkResult<()> {
        let peer = self.get_peer_mut(peer_id)?;

        peer.state = ManagedConnectionState::Degraded;
        peer.last_activity_unix_ms = current_time_ms();
        peer.last_error = reason;

        Ok(())
    }

    /// Record that a connection is being closed.
    pub fn mark_disconnecting(
        &mut self,
        peer_id: PeerId,
    ) -> NetworkResult<()> {
        let peer = self.get_peer_mut(peer_id)?;

        peer.state = ManagedConnectionState::Disconnecting;

        Ok(())
    }

    /// Record a completed disconnection.
    pub fn mark_disconnected(
        &mut self,
        peer_id: PeerId,
    ) -> NetworkResult<()> {
        let peer = self.get_peer_mut(peer_id)?;

        peer.state = ManagedConnectionState::Disconnected;
        peer.last_activity_unix_ms = current_time_ms();

        Ok(())
    }

    /// Record a connection failure.
    pub fn mark_failed(
        &mut self,
        peer_id: PeerId,
        reason: impl Into<String>,
    ) -> NetworkResult<()> {
        let peer = self.get_peer_mut(peer_id)?;

        peer.state = ManagedConnectionState::Failed;
        peer.last_error = Some(reason.into());
        peer.consecutive_failures =
            peer.consecutive_failures.saturating_add(1);
        peer.last_activity_unix_ms = current_time_ms();

        Ok(())
    }

    /// Record successful outbound traffic.
    pub fn record_bytes_sent(
        &mut self,
        peer_id: PeerId,
        bytes: u64,
    ) -> NetworkResult<()> {
        let peer = self.get_peer_mut(peer_id)?;

        if peer.state != ManagedConnectionState::Connected {
            return Err(NetworkError::InvalidState(
                "Cannot record traffic for a peer that is not connected"
                    .to_string(),
            ));
        }

        peer.bytes_sent = peer.bytes_sent.saturating_add(bytes);
        peer.last_activity_unix_ms = current_time_ms();

        Ok(())
    }

    /// Record successful inbound traffic.
    pub fn record_bytes_received(
        &mut self,
        peer_id: PeerId,
        bytes: u64,
    ) -> NetworkResult<()> {
        let peer = self.get_peer_mut(peer_id)?;

        if peer.state != ManagedConnectionState::Connected {
            return Err(NetworkError::InvalidState(
                "Cannot record traffic for a peer that is not connected"
                    .to_string(),
            ));
        }

        peer.bytes_received = peer.bytes_received.saturating_add(bytes);
        peer.last_activity_unix_ms = current_time_ms();

        Ok(())
    }

    /// Retrieve information about one peer.
    pub fn get_peer(
        &self,
        peer_id: PeerId,
    ) -> Option<&ManagedPeerConnection> {
        self.peers.get(&peer_id)
    }

    /// List all currently managed peers.
    pub fn list_peers(&self) -> Vec<&ManagedPeerConnection> {
        self.peers.values().collect()
    }

    /// List peers marked as connected and eligible for route evaluation.
    pub fn connected_peers(&self) -> Vec<&ManagedPeerConnection> {
        self.peers
            .values()
            .filter(|peer| peer.is_route_candidate())
            .collect()
    }

    /// Remove a peer from the manager.
    ///
    /// The caller is responsible for closing any actual socket first.
    pub fn remove_peer(
        &mut self,
        peer_id: PeerId,
    ) -> Option<ManagedPeerConnection> {
        self.peers.remove(&peer_id)
    }

    /// Return aggregate connection and traffic statistics.
    pub fn stats(&self) -> ConnectionManagerStats {
        let mut stats = ConnectionManagerStats {
            total_peers: self.peers.len(),
            connecting: 0,
            connected: 0,
            degraded: 0,
            disconnecting: 0,
            disconnected: 0,
            failed: 0,
            total_bytes_sent: 0,
            total_bytes_received: 0,
        };

        for peer in self.peers.values() {
            match peer.state {
                ManagedConnectionState::Connecting => {
                    stats.connecting += 1;
                }
                ManagedConnectionState::Connected => {
                    stats.connected += 1;
                }
                ManagedConnectionState::Degraded => {
                    stats.degraded += 1;
                }
                ManagedConnectionState::Disconnecting => {
                    stats.disconnecting += 1;
                }
                ManagedConnectionState::Disconnected => {
                    stats.disconnected += 1;
                }
                ManagedConnectionState::Failed => {
                    stats.failed += 1;
                }
            }

            stats.total_bytes_sent = stats
                .total_bytes_sent
                .saturating_add(peer.bytes_sent);

            stats.total_bytes_received = stats
                .total_bytes_received
                .saturating_add(peer.bytes_received);
        }

        stats
    }

    /// Find connected peers that have not reported activity recently.
    ///
    /// This identifies candidates for health checks; it does not
    /// automatically disconnect them.
    pub fn stale_connected_peers(
        &self,
        stale_after: Duration,
    ) -> Vec<PeerId> {
        self.peers
            .values()
            .filter(|peer| {
                peer.is_connected()
                    && peer.inactivity_duration() >= stale_after
            })
            .map(|peer| peer.peer_id)
            .collect()
    }

    /// Internal mutable peer lookup.
    fn get_peer_mut(
        &mut self,
        peer_id: PeerId,
    ) -> NetworkResult<&mut ManagedPeerConnection> {
        self.peers.get_mut(&peer_id).ok_or_else(|| {
            NetworkError::InvalidState(
                "Peer is not registered with the connection manager"
                    .to_string(),
            )
        })
    }
}

impl Default for ConnectionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Get the current Unix timestamp in milliseconds.
fn current_time_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manager_starts_empty() {
        let manager = ConnectionManager::new();
        let stats = manager.stats();

        assert_eq!(stats.total_peers, 0);
        assert_eq!(stats.connected, 0);
    }

    #[test]
    fn manager_rejects_duplicate_peer_registration() {
        let mut manager = ConnectionManager::new();
        let peer_id = PeerId::new();

        manager
            .register_peer(peer_id, None, TransportKind::Tcp)
            .expect("first registration should succeed");

        let result =
            manager.register_peer(peer_id, None, TransportKind::Tcp);

        assert!(result.is_err());
    }

    #[test]
    fn manager_tracks_connection_state() {
        let mut manager = ConnectionManager::new();
        let peer_id = PeerId::new();

        manager
            .register_peer(peer_id, None, TransportKind::Tcp)
            .expect("registration should succeed");

        manager
            .mark_connected(peer_id)
            .expect("connection state should update");

        assert_eq!(manager.stats().connected, 1);
        assert_eq!(manager.connected_peers().len(), 1);
    }

    #[test]
    fn manager_tracks_traffic() {
        let mut manager = ConnectionManager::new();
        let peer_id = PeerId::new();

        manager
            .register_peer(peer_id, None, TransportKind::Tcp)
            .expect("registration should succeed");

        manager
            .mark_connected(peer_id)
            .expect("connection state should update");

        manager
            .record_bytes_sent(peer_id, 100)
            .expect("outbound traffic should be recorded");

        manager
            .record_bytes_received(peer_id, 250)
            .expect("inbound traffic should be recorded");

        let stats = manager.stats();

        assert_eq!(stats.total_bytes_sent, 100);
        assert_eq!(stats.total_bytes_received, 250);
    }

    #[test]
    fn manager_removes_peer() {
        let mut manager = ConnectionManager::new();
        let peer_id = PeerId::new();

        manager
            .register_peer(peer_id, None, TransportKind::Tcp)
            .expect("registration should succeed");

        assert!(manager.remove_peer(peer_id).is_some());
        assert_eq!(manager.stats().total_peers, 0);
    }
}
