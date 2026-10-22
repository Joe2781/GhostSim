use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::shard::{
    ShardDescriptor,
    ShardId,
    ShardState,
};

/// Maximum number of shard lifecycle records managed by one runtime.
pub const MAX_RUNTIME_SHARDS: usize = 10_000;

/// Default heartbeat interval for running shards.
pub const DEFAULT_SHARD_HEARTBEAT_INTERVAL: Duration =
    Duration::from_secs(15);

/// How long a running shard may go without a heartbeat before it is stale.
pub const DEFAULT_SHARD_HEARTBEAT_TIMEOUT: Duration =
    Duration::from_secs(60);

/// Maximum number of consecutive runtime-level failures before a shard
/// is marked as failed by runtime policy.
pub const DEFAULT_MAX_CONSECUTIVE_FAILURES: u32 = 5;

/// Errors produced by the shard runtime.
#[derive(Debug, Error)]
pub enum ShardRuntimeError {
    #[error("Shard capacity limit reached")]
    CapacityExceeded,

    #[error("Shard {0} is already registered")]
    AlreadyRegistered(String),

    #[error("Shard {0} was not found")]
    NotFound(String),

    #[error("Shard {shard_id} cannot perform operation {operation} from state {state}")]
    InvalidState {
        shard_id: String,
        operation: String,
        state: String,
    },

    #[error("Shard {0} has been revoked and cannot be started")]
    TrustRevoked(String),

    #[error("Shard {0} has no valid assignment")]
    MissingAssignment(String),

    #[error("System clock returned an invalid timestamp")]
    ClockError,

    #[error("Shard descriptor validation failed: {0}")]
    Validation(String),
}

/// Result type used by the shard runtime.
pub type ShardRuntimeResult<T> = Result<T, ShardRuntimeError>;

/// Operations the runtime can request for a shard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShardRuntimeOperation {
    Start,
    Pause,
    Resume,
    Stop,
    Restart,
}

/// Runtime lifecycle record for a single shard.
///
/// This record tracks lifecycle coordination only. It does not claim that
/// the shard has opened sockets, forwarded packets, or executed work.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardRuntimeRecord {
    pub shard_id: ShardId,
    pub desired_state: ShardState,
    pub observed_state: ShardState,
    pub last_heartbeat_unix_ms: Option<u64>,
    pub last_transition_unix_ms: u64,
    pub consecutive_failures: u32,
    pub restart_requested: bool,
    pub last_error: Option<String>,
}

/// Summary of the runtime's current state.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ShardRuntimeStats {
    pub total: usize,
    pub created: usize,
    pub waiting_for_assignment: usize,
    pub assigned: usize,
    pub starting: usize,
    pub running: usize,
    pub paused: usize,
    pub degraded: usize,
    pub stopping: usize,
    pub stopped: usize,
    pub failed: usize,
    pub restart_requested: usize,
}

/// Configuration for shard lifecycle management.
#[derive(Debug, Clone)]
pub struct ShardRuntimeConfig {
    pub max_shards: usize,
    pub heartbeat_interval: Duration,
    pub heartbeat_timeout: Duration,
    pub max_consecutive_failures: u32,
    pub require_assignment_before_start: bool,
}

impl Default for ShardRuntimeConfig {
    fn default() -> Self {
        Self {
            max_shards: MAX_RUNTIME_SHARDS,
            heartbeat_interval: DEFAULT_SHARD_HEARTBEAT_INTERVAL,
            heartbeat_timeout: DEFAULT_SHARD_HEARTBEAT_TIMEOUT,
            max_consecutive_failures: DEFAULT_MAX_CONSECUTIVE_FAILURES,
            require_assignment_before_start: true,
        }
    }
}

/// Coordinates shard lifecycle requests and runtime observations.
///
/// The runtime deliberately separates desired state from observed state:
/// requesting a start does not mean the shard is already running.
/// A worker/executor must perform the operation and report the outcome.
pub struct ShardRuntime {
    config: ShardRuntimeConfig,
    records: HashMap<ShardId, ShardRuntimeRecord>,
}

impl ShardRuntime {
    /// Create a runtime with the default configuration.
    pub fn new() -> Self {
        Self::with_config(ShardRuntimeConfig::default())
    }

    /// Create a runtime with a custom configuration.
    pub fn with_config(config: ShardRuntimeConfig) -> Self {
        Self {
            config,
            records: HashMap::new(),
        }
    }

    /// Return the runtime configuration.
    pub fn config(&self) -> &ShardRuntimeConfig {
        &self.config
    }

    /// Register a shard descriptor with the runtime.
    pub fn register(
        &mut self,
        descriptor: &ShardDescriptor,
    ) -> ShardRuntimeResult<()> {
        let id = descriptor.id.clone();

        if self.records.contains_key(&id) {
            return Err(ShardRuntimeError::AlreadyRegistered(
                id.to_string(),
            ));
        }

        if self.records.len() >= self.config.max_shards {
            return Err(ShardRuntimeError::CapacityExceeded);
        }

        let now = now_unix_ms()?;

        let record = ShardRuntimeRecord {
            shard_id: id.clone(),
            desired_state: descriptor.state,
            observed_state: descriptor.state,
            last_heartbeat_unix_ms: None,
            last_transition_unix_ms: now,
            consecutive_failures: 0,
            restart_requested: false,
            last_error: None,
        };

        self.records.insert(id, record);

        Ok(())
    }

    /// Return a shard's runtime record.
    pub fn get(
        &self,
        shard_id: &ShardId,
    ) -> Option<&ShardRuntimeRecord> {
        self.records.get(shard_id)
    }

    /// Return a mutable shard runtime record.
    pub fn get_mut(
        &mut self,
        shard_id: &ShardId,
    ) -> Option<&mut ShardRuntimeRecord> {
        self.records.get_mut(shard_id)
    }

    /// Return the number of registered shards.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Return whether the runtime has no registered shards.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Request that a shard start.
    ///
    /// The caller must later report whether startup succeeded.
    pub fn request_start(
        &mut self,
        shard_id: &ShardId,
        descriptor: &ShardDescriptor,
    ) -> ShardRuntimeResult<()> {
        let record = self.record_mut(shard_id)?;

        if record.observed_state == ShardState::Running
            || record.observed_state == ShardState::Starting
        {
            return Ok(());
        }

        if record.observed_state == ShardState::Stopping {
            return Err(invalid_state(
                shard_id,
                ShardRuntimeOperation::Start,
                record.observed_state,
            ));
        }

        if record.observed_state == ShardState::Failed {
            return Err(invalid_state(
                shard_id,
                ShardRuntimeOperation::Start,
                record.observed_state,
            ));
        }

        if self.config.require_assignment_before_start
            && descriptor.assignment.is_none()
        {
            return Err(ShardRuntimeError::MissingAssignment(
                shard_id.to_string(),
            ));
        }

        if descriptor.trust_state
            == crate::shard::ShardTrustState::Revoked
        {
            return Err(ShardRuntimeError::TrustRevoked(
                shard_id.to_string(),
            ));
        }

        let now = now_unix_ms()?;
        let record = self.record_mut(shard_id)?;

        record.desired_state = ShardState::Running;
        record.observed_state = ShardState::Starting;
        record.last_transition_unix_ms = now;
        record.restart_requested = false;
        record.last_error = None;

        Ok(())
    }

    /// Request that a running shard pause.
    pub fn request_pause(
        &mut self,
        shard_id: &ShardId,
    ) -> ShardRuntimeResult<()> {
        let current = self.record(shard_id)?.observed_state;

        if current != ShardState::Running
            && current != ShardState::Degraded
        {
            return Err(invalid_state(
                shard_id,
                ShardRuntimeOperation::Pause,
                current,
            ));
        }

        let now = now_unix_ms()?;
        let record = self.record_mut(shard_id)?;

        record.desired_state = ShardState::Paused;
        record.observed_state = ShardState::Paused;
        record.last_transition_unix_ms = now;

        Ok(())
    }

    /// Request that a paused shard resume.
    pub fn request_resume(
        &mut self,
        shard_id: &ShardId,
    ) -> ShardRuntimeResult<()> {
        let current = self.record(shard_id)?.observed_state;

        if current != ShardState::Paused {
            return Err(invalid_state(
                shard_id,
                ShardRuntimeOperation::Resume,
                current,
            ));
        }

        let now = now_unix_ms()?;
        let record = self.record_mut(shard_id)?;

        record.desired_state = ShardState::Running;
        record.observed_state = ShardState::Starting;
        record.last_transition_unix_ms = now;
        record.last_error = None;

        Ok(())
    }

    /// Request that a shard stop.
    pub fn request_stop(
        &mut self,
        shard_id: &ShardId,
    ) -> ShardRuntimeResult<()> {
        let current = self.record(shard_id)?.observed_state;

        if current == ShardState::Stopped {
            return Ok(());
        }

        if current == ShardState::Created
            || current == ShardState::WaitingForAssignment
            || current == ShardState::Assigned
        {
            let now = now_unix_ms()?;
            let record = self.record_mut(shard_id)?;

            record.desired_state = ShardState::Stopped;
            record.observed_state = ShardState::Stopped;
            record.last_transition_unix_ms = now;

            return Ok(());
        }

        let now = now_unix_ms()?;
        let record = self.record_mut(shard_id)?;

        record.desired_state = ShardState::Stopped;
        record.observed_state = ShardState::Stopping;
        record.last_transition_unix_ms = now;

        Ok(())
    }

    /// Report that a shard has successfully started.
    ///
    /// A worker must call this only after its startup procedure succeeds.
    pub fn report_started(
        &mut self,
        shard_id: &ShardId,
    ) -> ShardRuntimeResult<()> {
        let current = self.record(shard_id)?.observed_state;

        if current != ShardState::Starting {
            return Err(invalid_state(
                shard_id,
                ShardRuntimeOperation::Start,
                current,
            ));
        }

        let now = now_unix_ms()?;
        let record = self.record_mut(shard_id)?;

        record.observed_state = ShardState::Running;
        record.desired_state = ShardState::Running;
        record.last_transition_unix_ms = now;
        record.last_heartbeat_unix_ms = Some(now);
        record.consecutive_failures = 0;
        record.last_error = None;

        Ok(())
    }

    /// Report that a shard has successfully stopped.
    pub fn report_stopped(
        &mut self,
        shard_id: &ShardId,
    ) -> ShardRuntimeResult<()> {
        let current = self.record(shard_id)?.observed_state;

        if current != ShardState::Stopping
            && current != ShardState::Running
            && current != ShardState::Paused
            && current != ShardState::Degraded
            && current != ShardState::Starting
        {
            return Err(invalid_state(
                shard_id,
                ShardRuntimeOperation::Stop,
                current,
            ));
        }

        let now = now_unix_ms()?;
        let record = self.record_mut(shard_id)?;

        record.desired_state = ShardState::Stopped;
        record.observed_state = ShardState::Stopped;
        record.last_transition_unix_ms = now;
        record.last_heartbeat_unix_ms = None;
        record.restart_requested = false;

        Ok(())
    }

    /// Record a successful heartbeat from a running shard.
    pub fn heartbeat(
        &mut self,
        shard_id: &ShardId,
    ) -> ShardRuntimeResult<()> {
        let current = self.record(shard_id)?.observed_state;

        if current != ShardState::Running
            && current != ShardState::Degraded
        {
            return Err(invalid_state(
                shard_id,
                ShardRuntimeOperation::Resume,
                current,
            ));
        }

        let now = now_unix_ms()?;
        let record = self.record_mut(shard_id)?;

        record.last_heartbeat_unix_ms = Some(now);
        record.consecutive_failures = 0;

        if record.observed_state == ShardState::Degraded {
            record.observed_state = ShardState::Running;
            record.desired_state = ShardState::Running;
            record.last_transition_unix_ms = now;
        }

        Ok(())
    }

    /// Report a runtime or worker failure.
    pub fn report_failure(
        &mut self,
        shard_id: &ShardId,
        reason: impl Into<String>,
    ) -> ShardRuntimeResult<()> {
        let now = now_unix_ms()?;
        let max_failures = self.config.max_consecutive_failures;
        let record = self.record_mut(shard_id)?;

        record.consecutive_failures =
            record.consecutive_failures.saturating_add(1);
        record.last_error = Some(reason.into());
        record.last_transition_unix_ms = now;

        if record.consecutive_failures >= max_failures {
            record.observed_state = ShardState::Failed;
            record.desired_state = ShardState::Failed;
            record.restart_requested = false;
        } else {
            record.observed_state = ShardState::Degraded;
        }

        Ok(())
    }

    /// Mark shards with stale heartbeats as degraded.
    ///
    /// This method only updates runtime state. It does not perform network
    /// probes or restart workers.
    pub fn mark_stale_shards(
        &mut self,
    ) -> ShardRuntimeResult<Vec<ShardId>> {
        let now = now_unix_ms()?;
        let timeout_ms = duration_to_ms(self.config.heartbeat_timeout);

        let mut stale = Vec::new();

        for record in self.records.values_mut() {
            if record.observed_state != ShardState::Running {
                continue;
            }

            let last_heartbeat = match record.last_heartbeat_unix_ms {
                Some(value) => value,
                None => continue,
            };

            if now.saturating_sub(last_heartbeat) > timeout_ms {
                record.observed_state = ShardState::Degraded;
                record.last_transition_unix_ms = now;
                record.last_error =
                    Some("Shard heartbeat timed out".to_string());

                stale.push(record.shard_id.clone());
            }
        }

        Ok(stale)
    }

    /// Request a restart for a failed or degraded shard.
    ///
    /// The scheduler/executor must process the request and carry out the
    /// necessary recovery steps. This method does not restart a process.
    pub fn request_restart(
        &mut self,
        shard_id: &ShardId,
    ) -> ShardRuntimeResult<()> {
        let current = self.record(shard_id)?.observed_state;

        if current != ShardState::Failed
            && current != ShardState::Degraded
            && current != ShardState::Stopped
        {
            return Err(invalid_state(
                shard_id,
                ShardRuntimeOperation::Restart,
                current,
            ));
        }

        let now = now_unix_ms()?;
        let record = self.record_mut(shard_id)?;

        record.desired_state = ShardState::Running;
        record.restart_requested = true;
        record.last_transition_unix_ms = now;

        Ok(())
    }

    /// Return and clear all pending restart requests.
    pub fn take_restart_requests(&mut self) -> Vec<ShardId> {
        let mut requests = Vec::new();

        for record in self.records.values_mut() {
            if record.restart_requested {
                requests.push(record.shard_id.clone());
                record.restart_requested = false;
            }
        }

        requests
    }

    /// Return a snapshot of runtime statistics.
    pub fn stats(&self) -> ShardRuntimeStats {
        let mut stats = ShardRuntimeStats {
            total: self.records.len(),
            ..ShardRuntimeStats::default()
        };

        for record in self.records.values() {
            match record.observed_state {
                ShardState::Created => stats.created += 1,
                ShardState::WaitingForAssignment => {
                    stats.waiting_for_assignment += 1;
                }
                ShardState::Assigned => stats.assigned += 1,
                ShardState::Starting => stats.starting += 1,
                ShardState::Running => stats.running += 1,
                ShardState::Paused => stats.paused += 1,
                ShardState::Degraded => stats.degraded += 1,
                ShardState::Stopping => stats.stopping += 1,
                ShardState::Stopped => stats.stopped += 1,
                ShardState::Failed => stats.failed += 1,
            }

            if record.restart_requested {
                stats.restart_requested += 1;
            }
        }

        stats
    }

    fn record(
        &self,
        shard_id: &ShardId,
    ) -> ShardRuntimeResult<&ShardRuntimeRecord> {
        self.records
            .get(shard_id)
            .ok_or_else(|| {
                ShardRuntimeError::NotFound(shard_id.to_string())
            })
    }

    fn record_mut(
        &mut self,
        shard_id: &ShardId,
    ) -> ShardRuntimeResult<&mut ShardRuntimeRecord> {
        self.records
            .get_mut(shard_id)
            .ok_or_else(|| {
                ShardRuntimeError::NotFound(shard_id.to_string())
            })
    }
}

impl Default for ShardRuntime {
    fn default() -> Self {
        Self::new()
    }
}

fn invalid_state(
    shard_id: &ShardId,
    operation: ShardRuntimeOperation,
    state: ShardState,
) -> ShardRuntimeError {
    ShardRuntimeError::InvalidState {
        shard_id: shard_id.to_string(),
        operation: format!("{operation:?}"),
        state: format!("{state:?}"),
    }
}

fn now_unix_ms() -> ShardRuntimeResult<u64> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ShardRuntimeError::ClockError)?;

    Ok(elapsed.as_millis().min(u64::MAX as u128) as u64)
}

fn duration_to_ms(duration: Duration) -> u64 {
    duration.as_millis().min(u64::MAX as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_starts_empty() {
        let runtime = ShardRuntime::new();

        assert!(runtime.is_empty());
        assert_eq!(runtime.len(), 0);
        assert_eq!(runtime.stats().total, 0);
    }

    #[test]
    fn runtime_capacity_is_configurable() {
        let runtime = ShardRuntime::with_config(
            ShardRuntimeConfig {
                max_shards: 25,
                ..ShardRuntimeConfig::default()
            },
        );

        assert_eq!(runtime.config().max_shards, 25);
    }

    #[test]
    fn timestamp_conversion_does_not_overflow() {
        assert_eq!(
            duration_to_ms(Duration::from_millis(500)),
            500
        );
    }
}
