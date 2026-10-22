use std::collections::HashMap;

use crate::error::{NetworkError, NetworkResult};
use crate::peer::PeerId;
use crate::shard::{
    ShardDescriptor,
    ShardId,
    ShardKind,
    ShardState,
    ShardTrustState,
};

/// Maximum number of shard records managed by one registry.
pub const DEFAULT_MAX_SHARDS: usize = 10_000;

/// Central in-memory registry for GhostSim shards.
///
/// The registry manages shard metadata and lifecycle records.
/// It does not execute shard tasks or independently authorize
/// devices to relay traffic.
pub struct ShardRegistry {
    shards: HashMap<ShardId, ShardDescriptor>,
    max_shards: usize,
}

impl ShardRegistry {
    /// Create a registry using the default capacity.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_MAX_SHARDS)
    }

    /// Create a registry with an explicit capacity.
    pub fn with_capacity(max_shards: usize) -> Self {
        Self {
            shards: HashMap::new(),
            max_shards: max_shards.max(1),
        }
    }

    /// Register a new shard descriptor.
    pub fn register(
        &mut self,
        shard: ShardDescriptor,
    ) -> NetworkResult<ShardId> {
        shard.validate()?;

        if self.shards.contains_key(&shard.id) {
            return Err(NetworkError::InvalidState(
                "Shard ID is already registered".to_string(),
            ));
        }

        if self.shards.len() >= self.max_shards {
            return Err(NetworkError::InvalidState(
                "Shard registry capacity reached".to_string(),
            ));
        }

        let shard_id = shard.id;
        self.shards.insert(shard_id, shard);

        Ok(shard_id)
    }

    /// Retrieve a shard by its ID.
    pub fn get(&self, shard_id: ShardId) -> Option<&ShardDescriptor> {
        self.shards.get(&shard_id)
    }

    /// Retrieve a mutable shard descriptor.
    ///
    /// Callers should validate state transitions before modifying
    /// lifecycle fields.
    pub fn get_mut(
        &mut self,
        shard_id: ShardId,
    ) -> Option<&mut ShardDescriptor> {
        self.shards.get_mut(&shard_id)
    }

    /// Return the number of registered shards.
    pub fn len(&self) -> usize {
        self.shards.len()
    }

    /// Return whether the registry contains no shards.
    pub fn is_empty(&self) -> bool {
        self.shards.is_empty()
    }

    /// List every registered shard.
    pub fn list(&self) -> Vec<&ShardDescriptor> {
        self.shards.values().collect()
    }

    /// List shards by kind.
    pub fn list_by_kind(
        &self,
        kind: ShardKind,
    ) -> Vec<&ShardDescriptor> {
        self.shards
            .values()
            .filter(|shard| shard.kind == kind)
            .collect()
    }

    /// List shards currently assigned to a particular host device.
    pub fn list_by_host(
        &self,
        host_peer_id: PeerId,
    ) -> Vec<&ShardDescriptor> {
        self.shards
            .values()
            .filter(|shard| shard.host_peer_id == Some(host_peer_id))
            .collect()
    }

    /// List shards in a specified lifecycle state.
    pub fn list_by_state(
        &self,
        state: ShardState,
    ) -> Vec<&ShardDescriptor> {
        self.shards
            .values()
            .filter(|shard| shard.state == state)
            .collect()
    }

    /// List shards eligible for the scheduler to consider.
    ///
    /// The scheduler must still check device consent, available
    /// resources, task compatibility, and authorization.
    pub fn schedulable_shards(&self) -> Vec<&ShardDescriptor> {
        self.shards
            .values()
            .filter(|shard| shard.can_start())
            .collect()
    }

    /// Update a shard's lifecycle state.
    ///
    /// This method enforces a basic transition graph rather than
    /// permitting arbitrary state changes.
    pub fn transition(
        &mut self,
        shard_id: ShardId,
        next_state: ShardState,
    ) -> NetworkResult<()> {
        let shard = self.shards.get_mut(&shard_id).ok_or_else(|| {
            NetworkError::InvalidState(
                "Shard is not registered".to_string(),
            )
        })?;

        if shard.state == next_state {
            return Ok(());
        }

        if !is_transition_allowed(shard.state, next_state) {
            return Err(NetworkError::InvalidState(format!(
                "Invalid shard state transition: {:?} -> {:?}",
                shard.state, next_state
            )));
        }

        if next_state == ShardState::Starting && !shard.can_start() {
            return Err(NetworkError::InvalidState(
                "Shard does not meet the preconditions to start".to_string(),
            ));
        }

        if matches!(next_state, ShardState::Running)
            && shard.trust_state != ShardTrustState::Verified
        {
            return Err(NetworkError::InvalidState(
                "An unverified shard cannot enter the running state"
                    .to_string(),
            ));
        }

        shard.state = next_state;
        shard.updated_at_unix_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();

        shard.validate()?;

        Ok(())
    }

    /// Remove a stopped or failed shard from the registry.
    ///
    /// Active shards cannot be removed until they have stopped.
    pub fn remove(
        &mut self,
        shard_id: ShardId,
    ) -> NetworkResult<ShardDescriptor> {
        let shard = self.shards.get(&shard_id).ok_or_else(|| {
            NetworkError::InvalidState(
                "Shard is not registered".to_string(),
            )
        })?;

        if !matches!(
            shard.state,
            ShardState::Created
                | ShardState::Stopped
                | ShardState::Failed
        ) {
            return Err(NetworkError::InvalidState(
                "Shard must be inactive before removal".to_string(),
            ));
        }

        self.shards.remove(&shard_id).ok_or_else(|| {
            NetworkError::InvalidState(
                "Shard disappeared during removal".to_string(),
            )
        })
    }

    /// Remove all inactive shards.
    ///
    /// Returns the number of removed records.
    pub fn remove_inactive(&mut self) -> usize {
        let before = self.shards.len();

        self.shards.retain(|_, shard| {
            !matches!(
                shard.state,
                ShardState::Stopped | ShardState::Failed
            )
        });

        before - self.shards.len()
    }
}

impl Default for ShardRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Determine whether a shard lifecycle transition is permitted.
fn is_transition_allowed(
    current: ShardState,
    next: ShardState,
) -> bool {
    match current {
        ShardState::Created => matches!(
            next,
            ShardState::WaitingForAssignment
                | ShardState::Assigned
                | ShardState::Stopped
                | ShardState::Failed
        ),

        ShardState::WaitingForAssignment => matches!(
            next,
            ShardState::Assigned
                | ShardState::Stopped
                | ShardState::Failed
        ),

        ShardState::Assigned => matches!(
            next,
            ShardState::Starting
                | ShardState::WaitingForAssignment
                | ShardState::Stopped
                | ShardState::Failed
        ),

        ShardState::Starting => matches!(
            next,
            ShardState::Running
                | ShardState::Stopping
                | ShardState::Failed
        ),

        ShardState::Running => matches!(
            next,
            ShardState::Paused
                | ShardState::Degraded
                | ShardState::Stopping
                | ShardState::Failed
        ),

        ShardState::Paused => matches!(
            next,
            ShardState::Running
                | ShardState::Stopping
                | ShardState::Failed
        ),

        ShardState::Degraded => matches!(
            next,
            ShardState::Running
                | ShardState::Paused
                | ShardState::Stopping
                | ShardState::Failed
        ),

        ShardState::Stopping => matches!(
            next,
            ShardState::Stopped | ShardState::Failed
        ),

        ShardState::Stopped => matches!(
            next,
            ShardState::WaitingForAssignment
                | ShardState::Assigned
                | ShardState::Failed
        ),

        ShardState::Disconnected => false,

        ShardState::Failed => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shard::ShardResourceLimits;

    fn create_shard() -> ShardDescriptor {
        ShardDescriptor::new(
            ShardKind::TrafficRelay,
            PeerId::new(),
            vec!["tcp".to_string()],
            ShardResourceLimits::default(),
        )
        .expect("shard creation should succeed")
    }

    #[test]
    fn registry_starts_empty() {
        let registry = ShardRegistry::new();

        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn registry_registers_and_retrieves_shard() {
        let mut registry = ShardRegistry::new();
        let shard = create_shard();
        let shard_id = shard.id;

        registry
            .register(shard)
            .expect("registration should succeed");

        assert!(registry.get(shard_id).is_some());
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn registry_enforces_capacity() {
        let mut registry = ShardRegistry::with_capacity(1);

        registry
            .register(create_shard())
            .expect("first registration should succeed");

        assert!(registry.register(create_shard()).is_err());
    }

    #[test]
    fn registry_rejects_invalid_start_transition() {
        let mut registry = ShardRegistry::new();
        let shard_id = registry
            .register(create_shard())
            .expect("registration should succeed");

        assert!(
            registry
                .transition(shard_id, ShardState::Starting)
                .is_err()
        );
    }

    #[test]
    fn registry_prevents_removing_active_shards() {
        let mut registry = ShardRegistry::new();
        let shard_id = registry
            .register(create_shard())
            .expect("registration should succeed");

        assert!(registry.remove(shard_id).is_ok());

        let shard_id = registry
            .register(create_shard())
            .expect("registration should succeed");

        registry
            .transition(shard_id, ShardState::Stopped)
            .expect("created shard may stop");

        assert!(registry.remove(shard_id).is_ok());
    }

    #[test]
    fn registry_lists_shards_by_kind() {
        let mut registry = ShardRegistry::new();

        registry
            .register(create_shard())
            .expect("registration should succeed");

        assert_eq!(
            registry
                .list_by_kind(ShardKind::TrafficRelay)
                .len(),
            1
        );

        assert_eq!(
            registry
                .list_by_kind(ShardKind::ContentCache)
                .len(),
            0
        );
    }
}
