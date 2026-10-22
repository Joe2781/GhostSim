use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{NetworkError, NetworkResult};
use crate::peer::PeerId;

/// Maximum number of capabilities one shard may advertise.
pub const MAX_SHARD_CAPABILITIES: usize = 64;

/// Maximum length of a shard capability identifier.
pub const MAX_SHARD_CAPABILITY_LENGTH: usize = 128;

/// Maximum number of resource units requested by one shard.
pub const MAX_RESOURCE_UNITS: u32 = 1_000_000;

/// Unique identity for a GhostSim shard.
///
/// A shard is a logical unit of network or distributed work.
/// It is not necessarily a separate physical device.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
)]
pub struct ShardId(pub Uuid);

impl ShardId {
    /// Generate a new shard identity.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for ShardId {
    fn default() -> Self {
        Self::new()
    }
}

/// Classification of work a GhostSim shard may perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShardKind {
    /// Coordinates peer connectivity and route measurements.
    NetworkCoordination,

    /// Relays authorized traffic between connected peers.
    TrafficRelay,

    /// Provides an authorized path to a real internet connection.
    InternetGateway,

    /// Stores and serves eligible, verified cached content.
    ContentCache,

    /// Performs distributed, non-network-specific computation.
    DistributedCompute,

    /// Coordinates discovery and peer availability information.
    PeerDiscovery,
}

/// Current lifecycle state of a shard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShardState {
    Created,
    WaitingForAssignment,
    Assigned,
    Starting,
    Running,
    Paused,
    Degraded,
    Stopping,
    Stopped,
    Failed,
}

/// Trust level established by a separate security component.
///
/// These values are metadata only. This file does not authenticate
/// devices or establish trust by itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShardTrustState {
    Unverified,
    PendingVerification,
    Verified,
    Revoked,
}

/// Resource requirements and operational limits for a shard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardResourceLimits {
    /// Relative CPU budget in abstract units.
    pub cpu_units: u32,

    /// Memory budget in bytes.
    pub memory_bytes: u64,

    /// Maximum network throughput allocated to the shard, in bytes/sec.
    pub network_bytes_per_second: u64,

    /// Maximum cumulative network data allocated to the shard, in bytes.
    pub network_bytes_total: u64,

    /// Whether the shard may use battery-powered background resources.
    ///
    /// Permission to use these resources must still be granted by
    /// the host device's resource-policy component.
    pub allow_battery_background_work: bool,
}

impl Default for ShardResourceLimits {
    fn default() -> Self {
        Self {
            cpu_units: 1,
            memory_bytes: 16 * 1024 * 1024,
            network_bytes_per_second: 64 * 1024,
            network_bytes_total: 10 * 1024 * 1024,
            allow_battery_background_work: false,
        }
    }
}

impl ShardResourceLimits {
    /// Validate the configured resource limits.
    pub fn validate(&self) -> NetworkResult<()> {
        if self.cpu_units > MAX_RESOURCE_UNITS {
            return Err(NetworkError::InvalidMessage(
                "Shard CPU budget exceeds the supported limit".to_string(),
            ));
        }

        if self.memory_bytes == 0 {
            return Err(NetworkError::InvalidMessage(
                "Shard memory budget must be greater than zero".to_string(),
            ));
        }

        if self.network_bytes_per_second == 0 {
            return Err(NetworkError::InvalidMessage(
                "Shard network budget must be greater than zero".to_string(),
            ));
        }

        if self.network_bytes_total == 0 {
            return Err(NetworkError::InvalidMessage(
                "Shard total network budget must be greater than zero"
                    .to_string(),
            ));
        }

        Ok(())
    }
}

/// Describes the work assigned to a shard.
///
/// Sensitive payloads and credentials must not be stored in this metadata.
/// Work should be referenced through an authorized task identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardAssignment {
    pub task_id: Uuid,
    pub assigned_by: PeerId,
    pub assigned_at_unix_ms: u128,
    pub expires_at_unix_ms: Option<u128>,
    pub priority: u8,
}

impl ShardAssignment {
    /// Create a new assignment record.
    pub fn new(
        task_id: Uuid,
        assigned_by: PeerId,
        priority: u8,
        expires_at_unix_ms: Option<u128>,
    ) -> NetworkResult<Self> {
        if let Some(expiry) = expires_at_unix_ms {
            if expiry <= current_time_ms() {
                return Err(NetworkError::InvalidMessage(
                    "Shard assignment expiry must be in the future"
                        .to_string(),
                ));
            }
        }

        Ok(Self {
            task_id,
            assigned_by,
            assigned_at_unix_ms: current_time_ms(),
            expires_at_unix_ms,
            priority,
        })
    }

    /// Whether this assignment has expired.
    pub fn is_expired(&self) -> bool {
        self.expires_at_unix_ms
            .is_some_and(|expiry| current_time_ms() >= expiry)
    }
}

/// Health information reported by the shard runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardHealth {
    pub last_heartbeat_unix_ms: u128,
    pub tasks_completed: u64,
    pub tasks_failed: u64,
    pub bytes_processed: u64,
    pub consecutive_failures: u32,
    pub last_error: Option<String>,
}

impl Default for ShardHealth {
    fn default() -> Self {
        Self {
            last_heartbeat_unix_ms: current_time_ms(),
            tasks_completed: 0,
            tasks_failed: 0,
            bytes_processed: 0,
            consecutive_failures: 0,
            last_error: None,
        }
    }
}

/// Full metadata for a managed GhostSim shard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardDescriptor {
    pub id: ShardId,
    pub kind: ShardKind,
    pub state: ShardState,

    /// Host device identity, when a device has been assigned.
    pub host_peer_id: Option<PeerId>,

    /// Identity of the component that created the shard.
    pub created_by: PeerId,

    /// Capabilities this shard declares.
    pub capabilities: Vec<String>,

    /// Trust status reported by the security subsystem.
    pub trust_state: ShardTrustState,

    /// Resource budget allocated to this shard.
    pub resource_limits: ShardResourceLimits,

    /// Current task assignment, if any.
    pub assignment: Option<ShardAssignment>,

    /// Operational health information.
    pub health: ShardHealth,

    pub created_at_unix_ms: u128,
    pub updated_at_unix_ms: u128,
}

impl ShardDescriptor {
    /// Create a new, unassigned shard descriptor.
    ///
    /// Shards begin unverified and are not allowed to run automatically.
    pub fn new(
        kind: ShardKind,
        created_by: PeerId,
        capabilities: Vec<String>,
        resource_limits: ShardResourceLimits,
    ) -> NetworkResult<Self> {
        resource_limits.validate()?;
        validate_capabilities(&capabilities)?;

        let now = current_time_ms();

        Ok(Self {
            id: ShardId::new(),
            kind,
            state: ShardState::Created,
            host_peer_id: None,
            created_by,
            capabilities,
            trust_state: ShardTrustState::Unverified,
            resource_limits,
            assignment: None,
            health: ShardHealth::default(),
            created_at_unix_ms: now,
            updated_at_unix_ms: now,
        })
    }

    /// Assign the shard to a host device.
    ///
    /// Assignment does not imply permission to use the device.
    /// Device consent and resource authorization must be checked
    /// by the scheduler/runtime before execution.
    pub fn assign_host(
        &mut self,
        host_peer_id: PeerId,
    ) -> NetworkResult<()> {
        if matches!(
            self.state,
            ShardState::Running
                | ShardState::Starting
                | ShardState::Stopping
        ) {
            return Err(NetworkError::InvalidState(
                "Cannot change the host of an active shard".to_string(),
            ));
        }

        self.host_peer_id = Some(host_peer_id);
        self.state = ShardState::Assigned;
        self.updated_at_unix_ms = current_time_ms();

        Ok(())
    }

    /// Update the trust state reported by the security subsystem.
    pub fn set_trust_state(
        &mut self,
        trust_state: ShardTrustState,
    ) -> NetworkResult<()> {
        if self.state == ShardState::Running
            && trust_state != ShardTrustState::Verified
        {
            self.state = ShardState::Stopping;
        }

        self.trust_state = trust_state;
        self.updated_at_unix_ms = current_time_ms();

        Ok(())
    }

    /// Attach an authorized task assignment.
    pub fn assign_task(
        &mut self,
        assignment: ShardAssignment,
    ) -> NetworkResult<()> {
        if matches!(
            self.state,
            ShardState::Running
                | ShardState::Starting
                | ShardState::Stopping
                | ShardState::Failed
        ) {
            return Err(NetworkError::InvalidState(
                "Shard cannot accept a task in its current state".to_string(),
            ));
        }

        if self.host_peer_id.is_none() {
            return Err(NetworkError::InvalidState(
                "Shard must have a host before task assignment".to_string(),
            ));
        }

        if assignment.is_expired() {
            return Err(NetworkError::InvalidMessage(
                "Cannot assign an expired task".to_string(),
            ));
        }

        self.assignment = Some(assignment);
        self.state = ShardState::Assigned;
        self.updated_at_unix_ms = current_time_ms();

        Ok(())
    }

    /// Refresh the shard heartbeat.
    pub fn heartbeat(&mut self) {
        self.health.last_heartbeat_unix_ms = current_time_ms();
        self.updated_at_unix_ms = current_time_ms();
    }

    /// Record successful task completion.
    pub fn record_task_success(&mut self, bytes_processed: u64) {
        self.health.tasks_completed =
            self.health.tasks_completed.saturating_add(1);

        self.health.bytes_processed =
            self.health.bytes_processed.saturating_add(bytes_processed);

        self.health.consecutive_failures = 0;
        self.health.last_error = None;
        self.heartbeat();
    }

    /// Record a task failure.
    pub fn record_task_failure(&mut self, reason: String) {
        self.health.tasks_failed =
            self.health.tasks_failed.saturating_add(1);

        self.health.consecutive_failures =
            self.health.consecutive_failures.saturating_add(1);

        self.health.last_error = Some(reason);
        self.heartbeat();
    }

    /// Check whether the shard is eligible to begin execution.
    ///
    /// This is a preliminary metadata check, not a substitute for
    /// device-owner consent, relay authorization, or runtime checks.
    pub fn can_start(&self) -> bool {
        self.host_peer_id.is_some()
            && self.trust_state == ShardTrustState::Verified
            && self.assignment.is_some()
            && self
                .assignment
                .as_ref()
                .is_some_and(|assignment| !assignment.is_expired())
            && matches!(
                self.state,
                ShardState::Assigned
                    | ShardState::Stopped
                    | ShardState::WaitingForAssignment
            )
    }

    /// Validate the shard's metadata.
    pub fn validate(&self) -> NetworkResult<()> {
        self.resource_limits.validate()?;
        validate_capabilities(&self.capabilities)?;

        if self.state == ShardState::Running
            && (self.host_peer_id.is_none()
                || self.trust_state != ShardTrustState::Verified)
        {
            return Err(NetworkError::InvalidState(
                "Running shard lacks a host or verified trust state"
                    .to_string(),
            ));
        }

        if let Some(assignment) = &self.assignment {
            if assignment.is_expired()
                && matches!(
                    self.state,
                    ShardState::Starting | ShardState::Running
                )
            {
                return Err(NetworkError::InvalidState(
                    "Active shard has an expired task assignment".to_string(),
                ));
            }
        }

        Ok(())
    }
}

fn validate_capabilities(capabilities: &[String]) -> NetworkResult<()> {
    if capabilities.len() > MAX_SHARD_CAPABILITIES {
        return Err(NetworkError::InvalidMessage(
            "Shard advertises too many capabilities".to_string(),
        ));
    }

    for capability in capabilities {
        if capability.is_empty()
            || capability.len() > MAX_SHARD_CAPABILITY_LENGTH
            || capability.trim() != capability
            || capability.chars().any(char::is_control)
        {
            return Err(NetworkError::InvalidMessage(
                "Shard contains an invalid capability identifier".to_string(),
            ));
        }
    }

    Ok(())
}

fn current_time_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_limits() -> ShardResourceLimits {
        ShardResourceLimits::default()
    }

    #[test]
    fn shard_starts_unverified() {
        let shard = ShardDescriptor::new(
            ShardKind::TrafficRelay,
            PeerId::new(),
            vec!["tcp".to_string()],
            default_limits(),
        )
        .expect("shard creation should succeed");

        assert_eq!(shard.state, ShardState::Created);
        assert_eq!(shard.trust_state, ShardTrustState::Unverified);
        assert!(!shard.can_start());
    }

    #[test]
    fn shard_requires_host_before_task_assignment() {
        let mut shard = ShardDescriptor::new(
            ShardKind::DistributedCompute,
            PeerId::new(),
            vec!["compute".to_string()],
            default_limits(),
        )
        .expect("shard creation should succeed");

        let assignment = ShardAssignment::new(
            Uuid::new_v4(),
            PeerId::new(),
            5,
            None,
        )
        .expect("assignment creation should succeed");

        assert!(shard.assign_task(assignment).is_err());
    }

    #[test]
    fn shard_can_start_only_after_preconditions_are_met() {
        let mut shard = ShardDescriptor::new(
            ShardKind::TrafficRelay,
            PeerId::new(),
            vec!["tcp".to_string()],
            default_limits(),
        )
        .expect("shard creation should succeed");

        shard
            .assign_host(PeerId::new())
            .expect("host assignment should succeed");

        shard
            .set_trust_state(ShardTrustState::Verified)
            .expect("trust state should update");

        shard
            .assign_task(
                ShardAssignment::new(
                    Uuid::new_v4(),
                    PeerId::new(),
                    5,
                    None,
                )
                .expect("assignment creation should succeed"),
            )
            .expect("task assignment should succeed");

        assert!(shard.can_start());
    }

    #[test]
    fn shard_rejects_zero_memory_budget() {
        let mut limits = default_limits();
        limits.memory_bytes = 0;

        let result = ShardDescriptor::new(
            ShardKind::ContentCache,
            PeerId::new(),
            vec!["cache".to_string()],
            limits,
        );

        assert!(result.is_err());
    }

    #[test]
    fn shard_tracks_success_and_failure_counts() {
        let mut shard = ShardDescriptor::new(
            ShardKind::DistributedCompute,
            PeerId::new(),
            vec!["compute".to_string()],
            default_limits(),
        )
        .expect("shard creation should succeed");

        shard.record_task_success(1024);
        shard.record_task_failure("Temporary failure".to_string());

        assert_eq!(shard.health.tasks_completed, 1);
        assert_eq!(shard.health.tasks_failed, 1);
        assert_eq!(shard.health.bytes_processed, 1024);
        assert_eq!(shard.health.consecutive_failures, 1);
    }
}
