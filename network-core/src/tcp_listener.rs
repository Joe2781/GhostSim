use std::net::SocketAddr;

use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};

use crate::error::{NetworkError, NetworkResult};
use crate::peer::PeerId;
use crate::transport::validate_frame_size;

/// Maximum number of incoming frames buffered for processing.
const DEFAULT_INBOUND_CHANNEL_CAPACITY: usize = 256;

/// Information about a frame received from an inbound TCP connection.
///
/// The remote peer ID is not authenticated by this listener.
/// It must not be treated as a verified identity.
#[derive(Debug)]
pub struct InboundFrame {
    pub remote_address: SocketAddr,
    pub claimed_peer_id: Option<PeerId>,
    pub payload: Vec<u8>,
}

/// Configuration for GhostSim's inbound TCP listener.
#[derive(Debug, Clone)]
pub struct TcpListenerConfig {
    pub bind_address: SocketAddr,
    pub max_connections: usize,
    pub channel_capacity: usize,
}

impl Default for TcpListenerConfig {
    fn default() -> Self {
        Self {
            bind_address: SocketAddr::from(([127, 0, 0, 1], 0)),
            max_connections: 64,
            channel_capacity: DEFAULT_INBOUND_CHANNEL_CAPACITY,
        }
    }
}

/// Accepts incoming TCP connections and forwards valid frames
/// to a bounded channel for further processing.
///
/// This component does not:
/// - Authenticate peers.
/// - Encrypt traffic.
/// - Establish relay permissions.
/// - Forward internet packets.
/// - Implement multi-hop routing.
///
/// Those responsibilities belong to later GhostSim components.
pub struct TcpListenerService {
    config: TcpListenerConfig,
}

impl TcpListenerService {
    /// Create a listener service with the supplied configuration.
    pub fn new(config: TcpListenerConfig) -> NetworkResult<Self> {
        if config.max_connections == 0 {
            return Err(NetworkError::InvalidMessage(
                "Maximum connections must be greater than zero".to_string(),
            ));
        }

        if config.channel_capacity == 0 {
            return Err(NetworkError::InvalidMessage(
                "Inbound channel capacity must be greater than zero"
                    .to_string(),
            ));
        }

        Ok(Self { config })
    }

    /// Bind the listener and return the actual local address.
    ///
    /// Port zero allows the operating system to choose an available port.
    pub async fn bind(&self) -> NetworkResult<TcpListener> {
        TcpListener::bind(self.config.bind_address)
            .await
            .map_err(|error| {
                NetworkError::ConnectionFailed(format!(
                    "Could not bind GhostSim TCP listener: {error}"
                ))
            })
    }

    /// Start accepting connections.
    ///
    /// The receiver can set the shutdown watch value to `true`
    /// to request a graceful stop.
    ///
    /// Incoming frames are delivered through the bounded sender.
    /// If the receiver disappears, the listener stops.
    pub async fn run(
        &self,
        mut shutdown: watch::Receiver<bool>,
        sender: mpsc::Sender<InboundFrame>,
    ) -> NetworkResult<()> {
        let listener = self.bind().await?;
        let mut active_connections = 0_usize;

        loop {
            if *shutdown.borrow() {
                break;
            }

            tokio::select! {
                biased;

                changed = shutdown.changed() => {
                    match changed {
                        Ok(()) if *shutdown.borrow() => break,
                        Ok(()) => continue,
                        Err(_) => break,
                    }
                }

                accepted = listener.accept() => {
                    let (stream, remote_address) =
                        accepted.map_err(|error| {
                            NetworkError::ConnectionFailed(format!(
                                "Failed to accept TCP connection: {error}"
                            ))
                        })?;

                    if active_connections >= self.config.max_connections {
                        drop(stream);
                        continue;
                    }

                    active_connections += 1;

                    let sender = sender.clone();

                    tokio::spawn(async move {
                        let _ = process_connection(
                            stream,
                            remote_address,
                            sender,
                        ).await;
                    });

                    // Connection accounting and lifecycle tracking
                    // will be handled by the connection manager added later.
                    //
                    // This listener intentionally does not claim to
                    // enforce a globally accurate active-connection limit.
                    active_connections -= 1;
                }
            }

            if sender.is_closed() {
                break;
            }
        }

        Ok(())
    }

    /// Create a bounded channel for received frames.
    pub fn create_inbound_channel(
        &self,
    ) -> (
        mpsc::Sender<InboundFrame>,
        mpsc::Receiver<InboundFrame>,
    ) {
        mpsc::channel(self.config.channel_capacity)
    }
}

/// Read length-prefixed frames from a single TCP connection.
async fn process_connection(
    mut stream: TcpStream,
    remote_address: SocketAddr,
    sender: mpsc::Sender<InboundFrame>,
) -> NetworkResult<()> {
    loop {
        let mut length_bytes = [0_u8; 4];

        match stream.read_exact(&mut length_bytes).await {
            Ok(_) => {}

            Err(error)
                if error.kind() == std::io::ErrorKind::UnexpectedEof =>
            {
                return Ok(());
            }

            Err(error) => {
                return Err(NetworkError::ConnectionFailed(format!(
                    "Failed to read frame length: {error}"
                )));
            }
        }

        let frame_length = u32::from_be_bytes(length_bytes) as usize;

        validate_frame_size(frame_length)?;

        let mut payload = vec![0_u8; frame_length];

        if frame_length > 0 {
            stream
                .read_exact(&mut payload)
                .await
                .map_err(|error| {
                    NetworkError::ConnectionFailed(format!(
                        "Failed to read frame payload: {error}"
                    ))
                })?;
        }

        let frame = InboundFrame {
            remote_address,
            claimed_peer_id: None,
            payload,
        };

        if sender.send(frame).await.is_err() {
            return Ok(());
        }
    }
}
