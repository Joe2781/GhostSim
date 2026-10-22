use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::shard::ShardId;
use crate::shard_scheduler::ShardResourceSnapshot;

/// Maximum number of shard resource records tracked by one monitor.
pub const DEFAULT_MAX_MONITORED_SHARDS: usize = 10_000;

/// Default telemetry freshness window.
pub const DEFAULT_TELEMETRY_TTL_MS: u64 = 30_000;

/// Default maximum acceptable CPU usage for an individual shard.
pub const DEFAULT_MAX_CPU_USAGE_PERCENT: u8 = 80;

/// Default maximum acceptable memory usage for an individual shard.
pub const DEFAULT_MAX_MEMORY_USAGE_PERCENT: u8 = 85;

/// Errors produced by the resource monitor.
#[derive(Debug, Error)]
pub enum ShardResourceMonitorError {
    #[error("Resource monitor capacity limit reached")]
    CapacityExceeded,

    #[error("Resource data for shard {0} was not found")]
    NotFound(String),

    #[error("Invalid resource measurement: {0}")]
    InvalidMeasurement(String),

    #[error("Invalid monitor configuration: {0}")]
    InvalidConfiguration(String),

    #[error("System clock returned an invalid timestamp")]
    ClockError,
}

/// Result type used by the resource monitor.
pub type ShardResourceMonitorResult<T> =
    Result<T, ShardResourceMonitorError>;

/// Resource measurements reported by a participating device.
///
/// These are reported measurements, not guaranteed operating-system
/// measurements. A platform-specific collector must supply real values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceResourceMeasurement {
    pub device_id: String,

    /// CPU usage from 0 to 100.
    pub cpu_usage_percent: u8,

    /// Memory currently used by the participating workload, in MB.
    pub memory_used_mb: u64,

    /// Memory available to the participating workload, in MB.
    pub memory_available_mb: u64,

    /// Approximate outbound bandwidth available to GhostSim, in Kbps.
    pub available_bandwidth_kbps: u64,

    /// Battery percentage, if this is a battery-powered device.
    pub battery_percent: Option<u8>,

    /// Whether the device is connected to external power.
    pub charging: bool,

    /// Whether the device currently has a usable network path.
    pub network_available: bool,

    /// Whether the device owner has authorized relay participation.
    pub relay_authorized: bool,

    /// Whether the operating system currently permits background work.
    pub background_execution_allowed: bool,

    /// Measurement time in Unix milliseconds.
    pub measured_at_unix_ms: u64,
}

impl DeviceResourceMeasurement {
    /// Validate measurement ranges and required identifiers.
    pub fn validate(&self) -> ShardResourceMonitorResult<()> {
        if self.device_id.trim().is_empty() {
            return Err(
                ShardResourceMonitorError::InvalidMeasurement(
                    "device_id cannot be empty".to_string(),
                ),
            );
        }

        if self.cpu_usage_percent > 100 {
            return Err(
                ShardResourceMonitorError::InvalidMeasurement(
                    "cpu_usage_percent must be between 0 and 100"
                        .to_string(),
                ),
            );
        }

        if self
            .battery_percent
            .map(|value| value > 100)
            .unwrap_or(false)
        {
            return Err(
                ShardResourceMonitorError::InvalidMeasurement(
                    "battery_percent must be between 0 and 100"
                        .to_string(),
                ),
            );
        }

        Ok(())
    }

    /// Calculate remaining memory from reported values.
    ///
    /// Saturating subtraction prevents malformed measurements from
    /// causing arithmetic underflow.
    pub fn remaining_memory_mb(&self) -> u64 {
        self.memory_available_mb
            .saturating_sub(self.memory_used_mb)
    }
}

/// Reason a device should not receive additional relay work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceRestriction {
    RelayNotAuthorized,
    BackgroundExecutionUnavailable,
    NetworkUnavailable,
    CpuUsageTooHigh,
    MemoryTooLow,
    BandwidthTooLow,
    BatteryTooLow,
    TelemetryStale,
    DeviceOffline,
}

/// Decision about whether a device may receive additional work.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceEligibility {
    pub eligible: bool,
    pub restrictions: Vec<ResourceRestriction>,
    pub recommended_max_cpu_percent: u8,
    pub recommended_max_concurrent_tasks: u16,
}

/// Resource policy configuration.
#[derive(Debug, Clone)]
pub struct ShardResourceMonitorConfig {
    pub max_monitored_shards: usize,
    pub telemetry_ttl_ms: u64,
    pub max_cpu_usage_percent: u8,
    pub min_free_memory_mb: u64,
    pub min_bandwidth_kbps: u64,
    pub min_battery_percent: u8,
    pub allow_relay_while_charging_with_low_battery: bool,
    pub require_relay_authorization: bool,
    pub require_background_execution_permission: bool,
}

impl Default for ShardResourceMonitorConfig {
    fn default() -> Self {
        Self {
            max_monitored_shards: DEFAULT_MAX_MONITORED_SHARDS,
            telemetry_ttl_ms: DEFAULT_TELEMETRY_TTL_MS,
            max_cpu_usage_percent: DEFAULT_MAX_CPU_USAGE_PERCENT,
            min_free_memory_mb: 128,
            min_bandwidth_kbps: 256,
            min_battery_percent: 25,
            allow_relay_while_charging_with_low_battery: true,
            require_relay_authorization: true,
            require_background_execution_permission: true,
        }
    }
}

/// Resource information associated with a shard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoredShardResources {
    pub shard_id: ShardId,
    pub device_id: String,
    pub measurement: DeviceResourceMeasurement,
    pub updated_at_unix_ms: u64,
}

/// Snapshot of resource monitor statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ShardResourceMonitorStats {
    pub monitored_shards: usize,
    pub fresh_measurements: usize,
    pub stale_measurements: usize,
    pub eligible_devices: usize,
    pub restricted_devices: usize,
}

/// Monitors reported device resources and evaluates participation eligibility.
///
/// The monitor never enables relay participation itself. A device must
/// already have explicit owner authorization and satisfy the configured
/// resource policy.
pub struct ShardResourceMonitor {
    config: ShardResourceMonitorConfig,
    measurements: HashMap<ShardId, MonitoredShardResources>,
    device_online: HashMap<String, bool>,
}

impl ShardResourceMonitor {
    /// Create a monitor with conservative default settings.
    pub fn new() -> Self {
        Self::with_config(ShardResourceMonitorConfig::default())
    }

    /// Create a monitor with a custom configuration.
    pub fn with_config(
        config: ShardResourceMonitorConfig,
    ) -> Self {
        Self {
            config,
            measurements: HashMap::new(),
            device_online: HashMap::new(),
        }
    }

    /// Return the active configuration.
    pub fn config(&self) -> &ShardResourceMonitorConfig {
        &self.config
    }

    /// Record whether a device is currently considered online.
    pub fn set_device_online(
        &mut self,
        device_id: impl Into<String>,
        online: bool,
    ) {
        self.device_online.insert(device_id.into(), online);
    }

    /// Return the recorded online state for a device.
    pub fn is_device_online(&self, device_id: &str) -> bool {
        self.device_online
            .get(device_id)
            .copied()
            .unwrap_or(false)
    }

    /// Register or update resource measurements for a shard.
    pub fn update_measurement(
        &mut self,
        shard_id: ShardId,
        measurement: DeviceResourceMeasurement,
    ) -> ShardResourceMonitorResult<()> {
        measurement.validate()?;

        if !self.measurements.contains_key(&shard_id)
            && self.measurements.len()
                >= self.config.max_monitored_shards
        {
            return Err(
                ShardResourceMonitorError::CapacityExceeded,
            );
        }

        let updated_at_unix_ms = current_time_ms()?;

        self.device_online
            .entry(measurement.device_id.clone())
            .or_insert(measurement.network_available);

        self.measurements.insert(
            shard_id.clone(),
            MonitoredShardResources {
                shard_id,
                device_id: measurement.device_id.clone(),
                measurement,
                updated_at_unix_ms,
            },
        );

        Ok(())
    }

    /// Return the latest record for a shard.
    pub fn get(
        &self,
        shard_id: &ShardId,
    ) -> Option<&MonitoredShardResources> {
        self.measurements.get(shard_id)
    }

    /// Remove measurements associated with a shard.
    pub fn remove(
        &mut self,
        shard_id: &ShardId,
    ) -> Option<MonitoredShardResources> {
        self.measurements.remove(shard_id)
    }

    /// Return the number of monitored shards.
    pub fn len(&self) -> usize {
        self.measurements.len()
    }

    /// Return whether the monitor has no recorded shards.
    pub fn is_empty(&self) -> bool {
        self.measurements.is_empty()
    }

    /// Determine whether a measurement is recent enough to trust.
    pub fn is_fresh(
        &self,
        record: &MonitoredShardResources,
        now_unix_ms: u64,
    ) -> bool {
        now_unix_ms.saturating_sub(
            record.measurement.measured_at_unix_ms,
        ) <= self.config.telemetry_ttl_ms
    }

    /// Evaluate whether a device may receive additional relay work.
    pub fn evaluate(
        &self,
        shard_id: &ShardId,
        now_unix_ms: u64,
    ) -> ShardResourceMonitorResult<ResourceEligibility> {
        let record = self.measurements.get(shard_id).ok_or_else(|| {
            ShardResourceMonitorError::NotFound(
                shard_id.to_string(),
            )
        })?;

        let measurement = &record.measurement;
        let mut restrictions = Vec::new();

        if self.config.require_relay_authorization
            && !measurement.relay_authorized
        {
            restrictions.push(
                ResourceRestriction::RelayNotAuthorized,
            );
        }

        if self.config.require_background_execution_permission
            && !measurement.background_execution_allowed
        {
            restrictions.push(
                ResourceRestriction::BackgroundExecutionUnavailable,
            );
        }

        if !measurement.network_available {
            restrictions.push(
                ResourceRestriction::NetworkUnavailable,
            );
        }

        if !self.is_device_online(&record.device_id) {
            restrictions.push(
                ResourceRestriction::DeviceOffline,
            );
        }

        if measurement.cpu_usage_percent
            > self.config.max_cpu_usage_percent
        {
            restrictions.push(
                ResourceRestriction::CpuUsageTooHigh,
            );
        }

        if measurement.remaining_memory_mb()
            < self.config.min_free_memory_mb
        {
            restrictions.push(
                ResourceRestriction::MemoryTooLow,
            );
        }

        if measurement.available_bandwidth_kbps
            < self.config.min_bandwidth_kbps
        {
            restrictions.push(
                ResourceRestriction::BandwidthTooLow,
            );
        }

        if let Some(battery_percent) = measurement.battery_percent {
            if battery_percent < self.config.min_battery_percent
                && !(measurement.charging
                    && self.config
                        .allow_relay_while_charging_with_low_battery)
            {
                restrictions.push(
                    ResourceRestriction::BatteryTooLow,
                );
            }
        }

        if !self.is_fresh(record, now_unix_ms) {
            restrictions.push(
                ResourceRestriction::TelemetryStale,
            );
        }

        let eligible = restrictions.is_empty();

        let recommended_max_cpu_percent =
            if eligible {
                self.config.max_cpu_usage_percent
                    .saturating_sub(measurement.cpu_usage_percent)
            } else {
                0
            };

        let recommended_max_concurrent_tasks =
            if eligible {
                let cpu_capacity =
                    recommended_max_cpu_percent / 10;

                let memory_capacity =
                    (measurement.remaining_memory_mb() / 128)
                        .min(u16::MAX as u64) as u16;

                cpu_capacity.min(memory_capacity)
            } else {
                0
            };

        Ok(ResourceEligibility {
            eligible,
            restrictions,
            recommended_max_cpu_percent,
            recommended_max_concurrent_tasks,
        })
    }

    /// Convert fresh measurements into scheduler resource snapshots.
    ///
    /// This is an adapter for scheduling. It does not prove that a device
    /// is trustworthy or that its self-reported measurements are genuine.
    pub fn scheduler_snapshot(
        &self,
        shard_id: &ShardId,
        now_unix_ms: u64,
    ) -> ShardResourceMonitorResult<ShardResourceSnapshot> {
        let record = self.measurements.get(shard_id).ok_or_else(|| {
            ShardResourceMonitorError::NotFound(
                shard_id.to_string(),
            )
        })?;

        let measurement = &record.measurement;
        let eligibility = self.evaluate(shard_id, now_unix_ms)?;

        let available_cpu_percent =
            if eligibility.eligible {
                100_u8.saturating_sub(
                    measurement.cpu_usage_percent,
                )
            } else {
                0
            };

        let workload_score = measurement
            .cpu_usage_percent
            .saturating_add(
                if measurement.remaining_memory_mb() < 256 {
                    20
                } else {
                    0
                },
            )
            .min(100);

        Ok(ShardResourceSnapshot {
            shard_id: shard_id.clone(),
            available_cpu_percent,
            available_memory_mb: measurement
                .remaining_memory_mb(),
            available_bandwidth_kbps: measurement
                .available_bandwidth_kbps,
            workload_score,
            online: eligibility.eligible,
            last_updated_unix_ms: measurement
                .measured_at_unix_ms,
        })
    }

    /// Produce a summary of current telemetry.
    pub fn stats(
        &self,
        now_unix_ms: u64,
    ) -> ShardResourceMonitorStats {
        let mut stats = ShardResourceMonitorStats {
            monitored_shards: self.measurements.len(),
            ..ShardResourceMonitorStats::default()
        };

        for record in self.measurements.values() {
            if self.is_fresh(record, now_unix_ms) {
                stats.fresh_measurements += 1;
            } else {
                stats.stale_measurements += 1;
            }

            if self
                .evaluate(&record.shard_id, now_unix_ms)
                .map(|result| result.eligible)
                .unwrap_or(false)
            {
                stats.eligible_devices += 1;
            } else {
                stats.restricted_devices += 1;
            }
        }

        stats
    }
}

impl Default for ShardResourceMonitor {
    fn default() -> Self {
        Self::new()
    }
}

fn current_time_ms() -> ShardResourceMonitorResult<u64> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ShardResourceMonitorError::ClockError)?;

    Ok(elapsed.as_millis().min(u64::MAX as u128) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_measurement() -> DeviceResourceMeasurement {
        DeviceResourceMeasurement {
            device_id: "device-test".to_string(),
            cpu_usage_percent: 20,
            memory_used_mb: 128,
            memory_available_mb: 1024,
            available_bandwidth_kbps: 10_000,
            battery_percent: Some(80),
            charging: false,
            network_available: true,
            relay_authorized: true,
            background_execution_allowed: true,
            measured_at_unix_ms: 10_000,
        }
    }

    #[test]
    fn monitor_starts_empty() {
        let monitor = ShardResourceMonitor::new();

        assert!(monitor.is_empty());
        assert_eq!(monitor.len(), 0);
    }

    #[test]
    fn measurement_rejects_empty_device_id() {
        let mut measurement = sample_measurement();
        measurement.device_id = String::new();

        assert!(measurement.validate().is_err());
    }

    #[test]
    fn measurement_rejects_invalid_cpu_percentage() {
        let mut measurement = sample_measurement();
        measurement.cpu_usage_percent = 101;

        assert!(measurement.validate().is_err());
    }

    #[test]
    fn remaining_memory_never_underflows() {
        let mut measurement = sample_measurement();
        measurement.memory_used_mb = 500;
        measurement.memory_available_mb = 100;

        assert_eq!(measurement.remaining_memory_mb(), 0);
    }

    #[test]
    fn offline_devices_are_not_eligible() {
        let mut monitor = ShardResourceMonitor::new();
        let shard_id = ShardId::new();

        monitor
            .update_measurement(
                shard_id.clone(),
                sample_measurement(),
            )
            .unwrap();

        monitor.set_device_online("device-test", false);

        let result = monitor.evaluate(&shard_id, 10_000).unwrap();

        assert!(!result.eligible);
        assert!(
            result
                .restrictions
                .contains(&ResourceRestriction::DeviceOffline)
        );
    }

    #[test]
    fn unauthorized_devices_are_not_eligible() {
        let mut monitor = ShardResourceMonitor::new();
        let shard_id = ShardId::new();
        let mut measurement = sample_measurement();

        measurement.relay_authorized = false;

        monitor
            .update_measurement(shard_id.clone(), measurement)
            .unwrap();

        let result = monitor.evaluate(&shard_id, 10_000).unwrap();

        assert!(!result.eligible);
        assert!(
            result
                .restrictions
                .contains(&ResourceRestriction::RelayNotAuthorized)
        );
    }

    #[test]
    fn stale_measurements_are_restricted() {
        let mut monitor = ShardResourceMonitor::new();
        let shard_id = ShardId::new();

        monitor
            .update_measurement(
                shard_id.clone(),
                sample_measurement(),
            )
            .unwrap();

        let result = monitor.evaluate(&shard_id, 100_000).unwrap();

        assert!(!result.eligible);
        assert!(
            result
                .restrictions
                .contains(&ResourceRestriction::TelemetryStale)
        );
    }
}
