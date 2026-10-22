use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::error::{NetworkError, NetworkResult};
use crate::peer::PeerId;

/// Maximum number of discovered peers retained in memory.
pub const DEFAULT_MAX_DISCOVERED_PEERS: usize = 512;

/// Default period after which an unrefreshed discovery record expires.
pub const DEFAULT_PEER_EXPIRY: Duration = Duration::from_secs(180);

/// Maximum time allowed for a basic TCP reachability check.
pub const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// How a peer endpoint was discovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoverySource {
    /// Added by the user or local configuration.
    Configured,

    /// Received through a future authenticated peer exchange.
    PeerExchange,

    /// Found through a future local-network discovery mechanism.
    LocalNetwork,

    /// Found through an explicitly configured bootstrap service.
    Bootstrap,
}

/// Information about a discovered endpoint.
///
/// A discovery record is not proof of identity, trustworthiness,
/// relay permission, or internet access.
#[derive(Debug, Clone)]
pub struct DiscoveredPeer {
    pub peer_id: PeerId,
    pub address: SocketAddr,
    pub source: DiscoverySource,
    pub first_seen: Instant,
    pub last_seen: Instant,
    pub last_probe_succeeded: Option<Instant>,
    pub consecutive_probe_failures: u32,
}

impl DiscoveredPeer {
    fn new(
        peer_id: PeerId,
        address: SocketAddr,
        source: DiscoverySource,
    ) -> Self {
        let now = Instant::now();

        Self {
            peer_id,
            address,
            source,
            first_seen: now,
            last_seen: now,
            last_probe_succeeded: None,
            consecutive_probe_failures: 0,
        }
    }

    /// How long this record has been known.
    pub fn age(&self) -> Duration {
        self.first_seen.elapsed()
    }

    /// How long since this record was last refreshed.
    pub fn time_since_last_seen(&self) -> Duration {
        self.last_seen.elapsed()
    }

    /// Whether the record has exceeded its expiry period.
    pub fn is_expired(&self, expiry: Duration) -> bool {
        self.time_since_last_seen() >= expiry
    }

    /// Whether a reachability probe has succeeded recently.
    ///
    /// A successful TCP probe does not authenticate the peer.
    pub fn is_reachable_within(&self, max_age: Duration) -> bool {
        self.last_probe_succeeded
            .is_some_and(|time| time.elapsed() <= max_age)
    }
}

/// Statistics about peer discovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryStats {
    pub total_records: usize,
    pub recently_reachable: usize,
    pub expired_records: usize,
}

/// In-memory peer discovery registry.
///
/// This component stores endpoints learned from configured sources.
/// Actual multicast discovery, authenticated peer exchange, and
/// bootstrap-service communication will be implemented separately.
pub struct PeerDiscovery {
    peers: HashMap<PeerId, DiscoveredPeer>,
    max_peers: usize,
    expiry: Duration,
    probe_timeout: Duration,
}

impl PeerDiscovery {
    /// Create a discovery registry using conservative defaults.
    pub fn new() -> Self {
        Self::with_config(
            DEFAULT_MAX_DISCOVERED_PEERS,
            DEFAULT_PEER_EXPIRY,
            DEFAULT_PROBE_TIMEOUT,
        )
    }

    /// Create a registry with explicit limits.
    pub fn with_config(
        max_peers: usize,
        expiry: Duration,
        probe_timeout: Duration,
    ) -> Self {
        Self {
            peers: HashMap::new(),
            max_peers: max_peers.max(1),
            expiry,
            probe_timeout: probe_timeout.max(Duration::from_millis(1)),
        }
    }

    /// Register or refresh a discovered peer endpoint.
    pub fn register(
        &mut self,
        peer_id: PeerId,
        address: SocketAddr,
        source: DiscoverySource,
    ) -> NetworkResult<()> {
        if let Some(peer) = self.peers.get_mut(&peer_id) {
            peer.address = address;
            peer.source = source;
            peer.last_seen = Instant::now();
            return Ok(());
        }

        self.remove_expired();

        if self.peers.len() >= self.max_peers {
            return Err(NetworkError::InvalidState(
                "Peer discovery registry capacity reached".to_string(),
            ));
        }

        self.peers.insert(
            peer_id,
            DiscoveredPeer::new(peer_id, address, source),
        );

        Ok(())
    }

    /// Refresh the last-seen timestamp for a known peer.
    pub fn refresh(&mut self, peer_id: PeerId) -> NetworkResult<()> {
        let peer = self.peers.get_mut(&peer_id).ok_or_else(|| {
            NetworkError::InvalidState(
                "Cannot refresh an unknown discovered peer".to_string(),
            )
        })?;

        peer.last_seen = Instant::now();

        Ok(())
    }

    /// Return a discovered peer record.
    pub fn get(&self, peer_id: PeerId) -> Option<&DiscoveredPeer> {
        self.peers.get(&peer_id)
    }

    /// Return all non-expired peer records.
    pub fn list(&self) -> Vec<&DiscoveredPeer> {
        self.peers
            .values()
            .filter(|peer| !peer.is_expired(self.expiry))
            .collect()
    }

    /// Remove expired records and return the number removed.
    pub fn remove_expired(&mut self) -> usize {
        let expiry = self.expiry;
        let before = self.peers.len();

        self.peers
            .retain(|_, peer| !peer.is_expired(expiry));

        before - self.peers.len()
    }

    /// Remove a particular discovered peer.
    pub fn remove(&mut self, peer_id: PeerId) -> bool {
        self.peers.remove(&peer_id).is_some()
    }

    /// Perform a TCP reachability probe for a discovered peer.
    ///
    /// IMPORTANT:
    /// - This opens a TCP connection and immediately closes it.
    /// - It does not perform the GhostSim protocol handshake.
    /// - It does not establish that the endpoint is trustworthy.
    /// - It does not prove that the peer can reach the public internet.
    pub async fn probe(
        &mut self,
        peer_id: PeerId,
    ) -> NetworkResult<bool> {
        let address = self
            .peers
            .get(&peer_id)
            .map(|peer| peer.address)
            .ok_or_else(|| {
                NetworkError::InvalidState(
                    "Cannot probe an unknown discovered peer".to_string(),
                )
            })?;

        let result = timeout(
            self.probe_timeout,
            TcpStream::connect(address),
        )
        .await;

        let peer = self.peers.get_mut(&peer_id).ok_or_else(|| {
            NetworkError::InvalidState(
                "Peer record disappeared during reachability probe"
                    .to_string(),
            )
        })?;

        match result {
            Ok(Ok(stream)) => {
                drop(stream);

                peer.last_probe_succeeded = Some(Instant::now());
                peer.consecutive_probe_failures = 0;

                Ok(true)
            }

            Ok(Err(_)) | Err(_) => {
                peer.consecutive_probe_failures = peer
                    .consecutive_probe_failures
                    .saturating_add(1);

                Ok(false)
            }
        }
    }

    /// Summarize the current registry.
    pub fn stats(&self) -> DiscoveryStats {
        let now = Instant::now();

        let recently_reachable = self
            .peers
            .values()
            .filter(|peer| {
                peer.last_probe_succeeded.is_some_and(|last_success| {
                    now.duration_since(last_success) <= Duration::from_secs(30)
                })
            })
            .count();

        let expired_records = self
            .peers
            .values()
            .filter(|peer| peer.is_expired(self.expiry))
            .count();

        DiscoveryStats {
            total_records: self.peers.len(),
            recently_reachable,
            expired_records,
        }
    }
}

impl Default for PeerDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_address(port: u16) -> SocketAddr {
        SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
        )
    }

    #[test]
    fn registry_starts_empty() {
        let registry = PeerDiscovery::new();

        assert_eq!(registry.stats().total_records, 0);
    }

    #[test]
    fn registry_registers_peer() {
        let mut registry = PeerDiscovery::new();
        let peer_id = PeerId::new();

        registry
            .register(
                peer_id,
                test_address(8080),
                DiscoverySource::Configured,
            )
            .expect("registration should succeed");

        assert!(registry.get(peer_id).is_some());
        assert_eq!(registry.list().len(), 1);
    }

    #[test]
    fn registry_refreshes_existing_peer() {
        let mut registry = PeerDiscovery::new();
        let peer_id = PeerId::new();

        registry
            .register(
                peer_id,
                test_address(8080),
                DiscoverySource::Configured,
            )
            .expect("registration should succeed");

        registry
            .register(
                peer_id,
                test_address(9090),
                DiscoverySource::PeerExchange,
            )
            .expect("refresh should succeed");

        let peer = registry.get(peer_id).expect("peer should exist");

        assert_eq!(peer.address, test_address(9090));
        assert_eq!(peer.source, DiscoverySource::PeerExchange);
    }

    #[test]
    fn registry_removes_peer() {
        let mut registry = PeerDiscovery::new();
        let peer_id = PeerId::new();

        registry
            .register(
                peer_id,
                test_address(8080),
                DiscoverySource::Configured,
            )
            .expect("registration should succeed");

        assert!(registry.remove(peer_id));
        assert!(registry.get(peer_id).is_none());
    }

    #[test]
    fn registry_enforces_capacity() {
        let mut registry = PeerDiscovery::with_config(
            1,
            Duration::from_secs(180),
            Duration::from_secs(1),
        );

        registry
            .register(
                PeerId::new(),
                test_address(8080),
                DiscoverySource::Configured,
            )
            .expect("first registration should succeed");

        let result = registry.register(
            PeerId::new(),
            test_address(8081),
            DiscoverySource::Configured,
        );

        assert!(result.is_err());
    }
}
