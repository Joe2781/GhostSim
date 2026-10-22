//! Resource limits and owner-consent policy for GhostSim.
//!
//! A device must never become a relay merely because it has joined GhostSim.
//! Relay participation requires explicit owner consent, enabled policy,
//! available resources, and authorization for the requested operation.
//!
//! These checks establish local policy. A production deployment must also
//! enforce equivalent authorization at the authenticated network boundary.

use serde::{Deserialize, Serialize};

use crate::error::{NetworkError, NetworkResult};

/// The permission granted by the device owner for relay participation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayPermission {
    /// The device must not forward traffic for other devices.
    Disabled,

    /// The device may relay when all policy and resource checks pass.
    Enabled,
}

/// Network resource limits configured for a participating device.
///
/// Limits are expressed in explicit units to avoid ambiguity.
/// These settings are policy limits, not proof that the operating system
/// will enforce the same values automatically.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkResourcePolicy {
    /// Whether the owner has explicitly enabled relay participation.
    pub relay_permission: RelayPermission,

    /// Maximum permitted concurrent relay connections.
    pub max_relay_connections: u16,

    /// Maximum permitted aggregate relay throughput in bytes per second.
    pub max_relay_bytes_per_second: u64,

    /// Maximum relay traffic the device may forward during a UTC day.
    pub max_daily_relay_bytes: u64,

    /// Maximum number of bytes the device may retain for eligible cached
    /// content managed by GhostSim.
    pub max_cache_bytes: u64,

    /// Whether relaying is allowed while the device is on battery power.
    pub allow_relay_on_battery: bool,

    /// Whether relaying is allowed while the device is using metered
    /// connectivity.
    pub allow_relay_on_metered_network: bool,

    /// Whether the owner has allowed the device to cache eligible content.
    pub allow_content_cache: bool,

    /// Whether the device should restrict relaying while thermal pressure
    /// or system resource pressure is elevated.
    pub reduce_activity_under_system_pressure: bool,
}

impl Default for NetworkResourcePolicy {
    /// Conservative defaults: no relay participation or content caching.
    fn default() -> Self {
        Self {
            relay_permission: RelayPermission::Disabled,
            max_relay_connections: 0,
            max_relay_bytes_per_second: 0,
            max_daily_relay_bytes: 0,
            max_cache_bytes: 0,
            allow_relay_on_battery: false,
            allow_relay_on_metered_network: false,
            allow_content_cache: false,
            reduce_activity_under_system_pressure: true,
        }
    }
}

impl NetworkResourcePolicy {
    /// Creates a policy that permits relay participation only within
    /// explicitly configured limits.
    ///
    /// The caller must still obtain and persist the owner's actual consent
    /// before using this policy in production.
    pub fn relay_enabled(
        max_connections: u16,
        max_bytes_per_second: u64,
        max_daily_bytes: u64,
    ) -> NetworkResult<Self> {
        if max_connections == 0
            || max_bytes_per_second == 0
            || max_daily_bytes == 0
        {
            return Err(NetworkError::InvalidInput(
                "Relay limits must all be greater than zero".to_owned(),
            ));
        }

        Ok(Self {
            relay_permission: RelayPermission::Enabled,
            max_relay_connections: max_connections,
            max_relay_bytes_per_second: max_bytes_per_second,
            max_daily_relay_bytes: max_daily_bytes,
            ..Self::default()
        })
    }

    /// Validates that configured limits are internally consistent.
    pub fn validate(&self) -> NetworkResult<()> {
        match self.relay_permission {
            RelayPermission::Disabled => {
                if self.max_relay_connections != 0
                    || self.max_relay_bytes_per_second != 0
                    || self.max_daily_relay_bytes != 0
                {
                    return Err(NetworkError::InvalidInput(
                        "Disabled relay policy must have zero relay limits"
                            .to_owned(),
                    ));
                }
            }
            RelayPermission::Enabled => {
                if self.max_relay_connections == 0
                    || self.max_relay_bytes_per_second == 0
                    || self.max_daily_relay_bytes == 0
                {
                    return Err(NetworkError::InvalidInput(
                        "Enabled relay policy requires positive relay limits"
                            .to_owned(),
                    ));
                }
            }
        }

        if !self.allow_content_cache && self.max_cache_bytes != 0 {
            return Err(NetworkError::InvalidInput(
                "Cache storage must be zero when content caching is disabled"
                    .to_owned(),
            ));
        }

        Ok(())
    }

    /// Determines whether this policy permits any relay activity.
    ///
    /// This does not establish that the owner has actually consented.
    /// Consent must be obtained and verified by the platform integration.
    pub fn relay_is_configured(&self) -> bool {
        self.relay_permission == RelayPermission::Enabled
            && self.max_relay_connections > 0
            && self.max_relay_bytes_per_second > 0
            && self.max_daily_relay_bytes > 0
    }

    /// Determines whether the current network conditions satisfy
    /// the policy's basic relay restrictions.
    pub fn evaluate_relay_conditions(
        &self,
        owner_consent_verified: bool,
        on_battery: bool,
        metered_network: bool,
        under_system_pressure: bool,
        active_relay_connections: u16,
        daily_bytes_already_forwarded: u64,
    ) -> NetworkResult<()> {
        self.validate()?;

        if !owner_consent_verified {
            return Err(NetworkError::RelayNotAuthorized);
        }

        if !self.relay_is_configured() {
            return Err(NetworkError::RelayNotAuthorized);
        }

        if on_battery && !self.allow_relay_on_battery {
            return Err(NetworkError::ResourceLimitExceeded);
        }

        if metered_network && !self.allow_relay_on_metered_network {
            return Err(NetworkError::ResourceLimitExceeded);
        }

        if under_system_pressure && self.reduce_activity_under_system_pressure {
            return Err(NetworkError::ResourceLimitExceeded);
        }

        if active_relay_connections >= self.max_relay_connections {
            return Err(NetworkError::ResourceLimitExceeded);
        }

        if daily_bytes_already_forwarded >= self.max_daily_relay_bytes {
            return Err(NetworkError::ResourceLimitExceeded);
        }

        Ok(())
    }

    /// Determines whether the policy permits content caching.
    pub fn evaluate_cache_permission(
        &self,
        owner_consent_verified: bool,
        requested_cache_bytes: u64,
        currently_used_cache_bytes: u64,
    ) -> NetworkResult<()> {
        if !owner_consent_verified || !self.allow_content_cache {
            return Err(NetworkError::Unauthorized);
        }

        if self.max_cache_bytes == 0 {
            return Err(NetworkError::ResourceLimitExceeded);
        }

        let projected_usage = currently_used_cache_bytes
            .checked_add(requested_cache_bytes)
            .ok_or(NetworkError::ResourceLimitExceeded)?;

        if projected_usage > self.max_cache_bytes {
            return Err(NetworkError::ResourceLimitExceeded);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_disables_relay_and_cache() {
        let policy = NetworkResourcePolicy::default();

        assert_eq!(policy.relay_permission, RelayPermission::Disabled);
        assert!(!policy.relay_is_configured());
        assert!(!policy.allow_content_cache);
        assert_eq!(policy.max_cache_bytes, 0);
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn relay_requires_verified_owner_consent() {
        let policy =
            NetworkResourcePolicy::relay_enabled(4, 1024 * 1024, 100_000_000)
                .unwrap();

        let result = policy.evaluate_relay_conditions(
            false,
            false,
            false,
            false,
            0,
            0,
        );

        assert!(matches!(
            result,
            Err(NetworkError::RelayNotAuthorized)
        ));
    }

    #[test]
    fn relay_respects_connection_limit() {
        let policy =
            NetworkResourcePolicy::relay_enabled(2, 1024, 10_000).unwrap();

        let result = policy.evaluate_relay_conditions(
            true,
            false,
            false,
            false,
            2,
            0,
        );

        assert!(matches!(
            result,
            Err(NetworkError::ResourceLimitExceeded)
        ));
    }

    #[test]
    fn relay_respects_daily_data_limit() {
        let policy =
            NetworkResourcePolicy::relay_enabled(2, 1024, 10_000).unwrap();

        let result = policy.evaluate_relay_conditions(
            true,
            false,
            false,
            false,
            0,
            10_000,
        );

        assert!(matches!(
            result,
            Err(NetworkError::ResourceLimitExceeded)
        ));
    }

    #[test]
    fn cache_cannot_exceed_configured_capacity() {
        let policy = NetworkResourcePolicy {
            allow_content_cache: true,
            max_cache_bytes: 1_000,
            ..NetworkResourcePolicy::default()
        };

        let result =
            policy.evaluate_cache_permission(true, 200, 900);

        assert!(matches!(
            result,
            Err(NetworkError::ResourceLimitExceeded)
        ));
    }

    #[test]
    fn disabled_relay_cannot_have_nonzero_limits() {
        let policy = NetworkResourcePolicy {
            max_relay_connections: 2,
            ..NetworkResourcePolicy::default()
        };

        assert!(matches!(
            policy.validate(),
            Err(NetworkError::InvalidInput(_))
        ));
    }
}
