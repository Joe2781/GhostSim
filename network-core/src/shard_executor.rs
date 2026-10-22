use std::collections::HashSet;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpStream};
use tokio::time::timeout;

use crate::shard::ShardKind;
use crate::shard_worker::{
    ShardExecutionContext,
    ShardExecutionFuture,
    ShardExecutor,
    ShardWorkItem,
    ShardWorkOutput,
    ShardWorkerError,
    ShardWorkerResult,
};

/// Maximum permitted request data sent to a destination.
pub const MAX_TCP_REQUEST_BYTES: usize = 256 * 1024;

/// Maximum response size accepted from a destination.
pub const MAX_TCP_RESPONSE_BYTES: usize = 1024 * 1024;

/// Default TCP connection timeout.
pub const DEFAULT_TCP_CONNECT_TIMEOUT: Duration =
    Duration::from_secs(5);

/// Default maximum time for an entire TCP exchange.
pub const DEFAULT_TCP_EXCHANGE_TIMEOUT: Duration =
    Duration::from_secs(15);

/// Maximum number of destination addresses examined for one request.
pub const MAX_RESOLVED_DESTINATIONS: usize = 16;

/// Errors produced by the TCP executor.
#[derive(Debug, Error)]
pub enum ShardExecutorError {
    #[error("Invalid TCP exchange request: {0}")]
    InvalidRequest(String),

    #[error("Destination is not permitted: {0}")]
    DestinationNotAllowed(String),

    #[error("Destination resolution failed: {0}")]
    ResolutionFailed(String),

    #[error("No permitted destination address was found")]
    NoPermittedAddress,

    #[error("TCP connection failed: {0}")]
    ConnectionFailed(String),

    #[error("TCP exchange timed out")]
    Timeout,

    #[error("TCP exchange failed: {0}")]
    Io(String),

    #[error("Response exceeded the configured limit")]
    ResponseTooLarge,

    #[error("Response was incomplete")]
    IncompleteResponse,
}

/// A permitted remote TCP destination.
///
/// Hostnames must be explicitly configured. Port permissions are
/// destination-specific; allowing a hostname does not automatically
/// permit every port on that host.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AllowedTcpDestination {
    pub hostname: String,
    pub port: u16,
}

impl AllowedTcpDestination {
    pub fn new(
        hostname: impl Into<String>,
        port: u16,
    ) -> ShardExecutorResult<Self> {
        let destination = Self {
            hostname: hostname.into().trim().to_ascii_lowercase(),
            port,
        };

        if destination.hostname.is_empty() {
            return Err(ShardWorkerError::InvalidRequest(
                "Destination hostname cannot be empty".to_string(),
            ));
        }

        if destination.port == 0 {
            return Err(ShardWorkerError::InvalidRequest(
                "Destination port cannot be zero".to_string(),
            ));
        }

        if destination.hostname.contains('/') 
            || destination.hostname.contains('\\')
            || destination.hostname.contains('@')
            || destination.hostname.contains(':')
        {
            return Err(ShardWorkerError::InvalidRequest(
                "Configure a hostname without a scheme, credentials, or port"
                    .to_string(),
            ));
        }

        if destination.hostname.parse::<IpAddr>().is_ok() {
            return Err(ShardWorkerError::InvalidRequest(
                "Configure a DNS hostname rather than a raw IP address"
                    .to_string(),
            ));
        }

        Ok(destination)
    }
}

/// Request format accepted by the TCP exchange executor.
///
/// The request and response payloads are serialized as JSON at the
/// executor boundary. The bytes sent to the destination are the exact
/// contents of `request_data`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpExchangeRequest {
    pub hostname: String,
    pub port: u16,
    pub request_data: Vec<u8>,
    pub max_response_bytes: usize,
}

impl TcpExchangeRequest {
    pub fn validate(&self) -> ShardExecutorResult<()> {
        if self.hostname.trim().is_empty() {
            return Err(ShardWorkerError::InvalidRequest(
                "hostname cannot be empty".to_string(),
            ));
        }

        if self.hostname.contains('/')
            || self.hostname.contains('\\')
            || self.hostname.contains('@')
            || self.hostname.contains(':')
        {
            return Err(ShardWorkerError::InvalidRequest(
                "hostname must not contain a scheme, credentials, or port"
                    .to_string(),
            ));
        }

        if self.hostname.parse::<IpAddr>().is_ok() {
            return Err(ShardWorkerError::InvalidRequest(
                "Raw IP destinations are not accepted".to_string(),
            ));
        }

        if self.port == 0 {
            return Err(ShardWorkerError::InvalidRequest(
                "port cannot be zero".to_string(),
            ));
        }

        if self.request_data.len() > MAX_TCP_REQUEST_BYTES {
            return Err(ShardWorkerError::InvalidRequest(
                "request_data exceeds the configured maximum".to_string(),
            ));
        }

        if self.max_response_bytes == 0
            || self.max_response_bytes > MAX_TCP_RESPONSE_BYTES
        {
            return Err(ShardWorkerError::InvalidRequest(
                "max_response_bytes is outside the permitted range"
                    .to_string(),
            ));
        }

        Ok(())
    }
}

/// Response produced after a real TCP exchange.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpExchangeResponse {
    pub hostname: String,
    pub port: u16,
    pub remote_address: String,
    pub request_bytes_sent: usize,
    pub response_data: Vec<u8>,
    pub response_bytes_received: usize,
}

/// Configuration for the concrete TCP executor.
#[derive(Debug, Clone)]
pub struct TcpExecutorConfig {
    pub allowed_destinations: Vec<AllowedTcpDestination>,
    pub connect_timeout: Duration,
    pub exchange_timeout: Duration,
    pub max_response_bytes: usize,
    pub require_public_ip_addresses: bool,
}

impl Default for TcpExecutorConfig {
    fn default() -> Self {
        Self {
            allowed_destinations: Vec::new(),
            connect_timeout: DEFAULT_TCP_CONNECT_TIMEOUT,
            exchange_timeout: DEFAULT_TCP_EXCHANGE_TIMEOUT,
            max_response_bytes: MAX_TCP_RESPONSE_BYTES,
            require_public_ip_addresses: true,
        }
    }
}

/// Executes bounded outbound TCP exchanges against explicitly authorized
/// destinations.
///
/// This is a concrete network executor, not a simulator. It opens real
/// TCP connections. It is not a general-purpose TCP tunnel, TLS proxy,
/// VPN, or complete internet gateway.
pub struct TcpExchangeExecutor {
    config: TcpExecutorConfig,
    allowed_destinations: HashSet<AllowedTcpDestination>,
}

impl TcpExchangeExecutor {
    /// Create an executor using an explicit destination allowlist.
    pub fn new(
        config: TcpExecutorConfig,
    ) -> ShardExecutorResult<Self> {
        if config.connect_timeout.is_zero() {
            return Err(ShardWorkerError::InvalidRequest(
                "connect_timeout must be greater than zero".to_string(),
            ));
        }

        if config.exchange_timeout.is_zero() {
            return Err(ShardWorkerError::InvalidRequest(
                "exchange_timeout must be greater than zero".to_string(),
            ));
        }

        if config.max_response_bytes == 0
            || config.max_response_bytes > MAX_TCP_RESPONSE_BYTES
        {
            return Err(ShardWorkerError::InvalidRequest(
                "max_response_bytes is outside the permitted range"
                    .to_string(),
            ));
        }

        let mut allowed_destinations = HashSet::new();

        for destination in &config.allowed_destinations {
            let normalized = AllowedTcpDestination::new(
                destination.hostname.clone(),
                destination.port,
            )?;

            allowed_destinations.insert(normalized);
        }

        Ok(Self {
            config,
            allowed_destinations,
        })
    }

    /// Return the number of explicitly authorized destinations.
    pub fn allowed_destination_count(&self) -> usize {
        self.allowed_destinations.len()
    }

    /// Execute one real TCP exchange.
    pub async fn execute_exchange(
        &self,
        request: TcpExchangeRequest,
    ) -> Result<TcpExchangeResponse, ShardExecutorError> {
        request
            .validate()
            .map_err(|error| {
                ShardExecutorError::InvalidRequest(error.to_string())
            })?;

        let normalized_hostname =
            request.hostname.trim().to_ascii_lowercase();

        let destination = AllowedTcpDestination {
            hostname: normalized_hostname.clone(),
            port: request.port,
        };

        if !self.allowed_destinations.contains(&destination) {
            return Err(
                ShardExecutorError::DestinationNotAllowed(
                    format!(
                        "{}:{}",
                        normalized_hostname,
                        request.port
                    ),
                ),
            );
        }

        let resolution = timeout(
            self.config.connect_timeout,
            lookup_host((
                normalized_hostname.as_str(),
                request.port,
            )),
        )
        .await
        .map_err(|_| ShardExecutorError::Timeout)?
        .map_err(|error| {
            ShardExecutorError::ResolutionFailed(
                error.to_string(),
            )
        })?;

        let mut permitted_addresses: Vec<SocketAddr> = resolution
            .filter(|address| {
                !self.config.require_public_ip_addresses
                    || is_public_destination_ip(address.ip())
            })
            .take(MAX_RESOLVED_DESTINATIONS)
            .collect();

        permitted_addresses.sort();
        permitted_addresses.dedup();

        if permitted_addresses.is_empty() {
            return Err(ShardExecutorError::NoPermittedAddress);
        }

        let mut stream = None;
        let mut last_connection_error = None;

        for address in permitted_addresses {
            let connection = timeout(
                self.config.connect_timeout,
                TcpStream::connect(address),
            )
            .await;

            match connection {
                Ok(Ok(connected_stream)) => {
                    stream = Some((connected_stream, address));
                    break;
                }

                Ok(Err(error)) => {
                    last_connection_error =
                        Some(error.to_string());
                }

                Err(_) => {
                    last_connection_error =
                        Some("connection timed out".to_string());
                }
            }
        }

        let (mut stream, remote_address) = stream.ok_or_else(|| {
            ShardExecutorError::ConnectionFailed(
                last_connection_error.unwrap_or_else(|| {
                    "No destination could be reached".to_string()
                }),
            )
        })?;

        let request_bytes_sent = request.request_data.len();

        let exchange = async {
            stream
                .write_all(&request.request_data)
                .await
                .map_err(|error| {
                    ShardExecutorError::Io(error.to_string())
                })?;

            stream.shutdown().await.map_err(|error| {
                ShardExecutorError::Io(error.to_string())
            })?;

            let response_limit = request
                .max_response_bytes
                .min(self.config.max_response_bytes);

            let mut response_data =
                Vec::with_capacity(response_limit.min(8192));

            let mut buffer = [0_u8; 8192];

            loop {
                let remaining = response_limit
                    .saturating_sub(response_data.len());

                // Read one additional byte when the limit is reached
                // to detect oversized responses.
                let read_capacity = if remaining == 0 {
                    1
                } else {
                    remaining.min(buffer.len())
                };

                let bytes_read = stream
                    .read(&mut buffer[..read_capacity])
                    .await
                    .map_err(|error| {
                        ShardExecutorError::Io(error.to_string())
                    })?;

                if bytes_read == 0 {
                    break;
                }

                if response_data.len() + bytes_read > response_limit {
                    return Err(
                        ShardExecutorError::ResponseTooLarge
                    );
                }

                response_data.extend_from_slice(
                    &buffer[..bytes_read],
                );
            }

            Ok(TcpExchangeResponse {
                hostname: normalized_hostname,
                port: request.port,
                remote_address: remote_address.to_string(),
                request_bytes_sent,
                response_bytes_received: response_data.len(),
                response_data,
            })
        };

        timeout(self.config.exchange_timeout, exchange)
            .await
            .map_err(|_| ShardExecutorError::Timeout)?
    }
}

impl ShardExecutor for TcpExchangeExecutor {
    fn kind(&self) -> ShardKind {
        ShardKind::TrafficRelay
    }

    fn execute<'a>(
        &'a self,
        _context: ShardExecutionContext,
        work: ShardWorkItem,
    ) -> ShardExecutionFuture<'a> {
        Box::pin(async move {
            if work.required_kind != ShardKind::TrafficRelay {
                return Err(ShardWorkerError::InvalidRequest(
                    "TCP exchange executor only accepts TrafficRelay work"
                        .to_string(),
                ));
            }

            let request: TcpExchangeRequest =
                serde_json::from_slice(&work.payload).map_err(
                    |error| {
                        ShardWorkerError::InvalidRequest(
                            format!(
                                "Invalid TCP exchange payload: {error}"
                            ),
                        )
                    },
                )?;

            let response = self
                .execute_exchange(request)
                .await
                .map_err(|error| {
                    ShardWorkerError::ExecutionFailed(
                        error.to_string(),
                    )
                })?;

            let payload = serde_json::to_vec(&response).map_err(
                |error| {
                    ShardWorkerError::ExecutionFailed(
                        format!(
                            "Failed to serialize TCP response: {error}"
                        ),
                    )
                },
            )?;

            Ok(ShardWorkOutput {
                work_id: work.work_id,
                payload,
                completed_at_unix_ms: current_time_ms()?,
            })
        })
    }
}

/// Reject non-public address ranges by default.
///
/// This is a defense-in-depth check, not a replacement for network-level
/// egress filtering. Production deployments should also enforce outbound
/// network policy at the operating-system or infrastructure boundary.
fn is_public_destination_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => is_public_ipv4(ipv4),
        IpAddr::V6(ipv6) => is_public_ipv6(ipv6),
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();

    // Unspecified, private, loopback, link-local, and shared address space.
    if octets[0] == 0
        || octets[0] == 10
        || octets[0] == 127
        || (octets[0] == 100
            && (64..=127).contains(&octets[1]))
        || (octets[0] == 169 && octets[1] == 254)
        || (octets[0] == 172
            && (16..=31).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 168)
        || octets[0] >= 224
    {
        return false;
    }

    // Additional special-purpose ranges.
    if (octets[0] == 192 && octets[1] == 0)
        || (octets[0] == 192
            && octets[1] == 0
            && octets[2] == 2)
        || (octets[0] == 198
            && (octets[1] == 18 || octets[1] == 19))
        || (octets[0] == 198
            && octets[1] == 51
            && octets[2] == 100)
        || (octets[0] == 203
            && octets[1] == 0
            && octets[2] == 113)
    {
        return false;
    }

    true
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    if ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_unique_local()
        || ip.is_unicast_link_local()
    {
        return false;
    }

    // IPv4-mapped IPv6 addresses must be evaluated using the IPv4 rules.
    if let Some(ipv4) = ip.to_ipv4_mapped() {
        return is_public_ipv4(ipv4);
    }

    // Only globally routable unicast addresses are allowed.
    let segments = ip.segments();

    // Global unicast is currently allocated from 2000::/3.
    segments[0] & 0xe000 == 0x2000
}

fn current_time_ms() -> ShardWorkerResult<u64> {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| {
            ShardWorkerError::ExecutionFailed(
                "System clock returned an invalid timestamp".to_string(),
            )
        })?;

    Ok(elapsed.as_millis().min(u64::MAX as u128) as u64)
}

/// Helper for constructing a shared executor.
pub fn shared_tcp_executor(
    config: TcpExecutorConfig,
) -> ShardWorkerResult<Arc<TcpExchangeExecutor>> {
    Ok(Arc::new(TcpExchangeExecutor::new(config)?))
}
