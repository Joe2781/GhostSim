use std::net::SocketAddr;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::error::{NetworkError, NetworkResult};
use crate::peer::PeerId;
use crate::transport::{
    NetworkTransport,
    TransportConfig,
    TransportConnectionInfo,
    TransportKind,
    TransportState,
    validate_frame_size,
};

/// TCP transport for GhostSim's Rust networking engine.
///
/// Responsibilities:
/// - Establish a TCP connection to a remote peer.
/// - Send and receive length-prefixed frames.
/// - Enforce connection, send, and receive timeouts.
/// - Reject frames that exceed the configured size limit.
///
/// Security:
/// TCP alone does not encrypt or authenticate traffic.
/// Do not transmit private messages, credentials, keys, or other
/// sensitive production data over this transport until an
/// authenticated, encrypted transport layer is implemented.
pub struct TcpTransport {
    config: TransportConfig,
    state: TransportState,
    peer_id: Option<PeerId>,
    stream: Option<TcpStream>,
    remote_addr: Option<SocketAddr>,
}

impl TcpTransport {
    /// Create a disconnected TCP transport.
    pub fn new(config: TransportConfig) -> Self {
        Self {
            config,
            state: TransportState::Disconnected,
            peer_id: None,
            stream: None,
            remote_addr: None,
        }
    }

    /// Return the current transport state.
    pub fn state(&self) -> TransportState {
        self.state
    }

    /// Return the currently associated peer, if one exists.
    pub fn peer_id(&self) -> Option<PeerId> {
        self.peer_id
    }

    /// Return the connected remote address, if available.
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.remote_addr
    }

    /// Connect to a remote TCP endpoint.
    ///
    /// The peer ID is supplied by the caller. This function does not
    /// authenticate that the remote endpoint actually owns that ID.
    pub async fn connect_to(
        &mut self,
        peer_id: PeerId,
        address: SocketAddr,
    ) -> NetworkResult<()> {
        if self.stream.is_some() {
            return Err(NetworkError::InvalidState(
                "TCP transport is already connected".to_string(),
            ));
        }

        self.state = TransportState::Connecting;

        let connect_timeout = Duration::from_millis(
            self.config.connect_timeout_ms.max(1),
        );

        let connection_result = timeout(
            connect_timeout,
            TcpStream::connect(address),
        )
        .await;

        let mut stream = match connection_result {
            Ok(Ok(stream)) => stream,

            Ok(Err(error)) => {
                self.state = TransportState::Failed;

                return Err(NetworkError::ConnectionFailed(
                    error.to_string(),
                ));
            }

            Err(_) => {
                self.state = TransportState::Failed;

                return Err(NetworkError::Timeout(
                    "TCP connection attempt timed out".to_string(),
                ));
            }
        };

        if let Err(error) = stream.set_nodelay(true) {
            self.state = TransportState::Failed;

            return Err(NetworkError::ConnectionFailed(
                format!("Could not configure TCP socket: {error}"),
            ));
        }

        self.peer_id = Some(peer_id);
        self.remote_addr = Some(address);
        self.stream = Some(stream);
        self.state = TransportState::Connected;

        Ok(())
    }

    /// Send one complete frame.
    ///
    /// Wire format:
    /// - First 4 bytes: unsigned frame length in network byte order.
    /// - Remaining bytes: frame payload.
    ///
    /// Both peers must implement this same framing protocol.
    pub async fn send_frame(
        &mut self,
        payload: &[u8],
    ) -> NetworkResult<()> {
        if self.state != TransportState::Connected {
            return Err(NetworkError::InvalidState(
                "Cannot send data while TCP transport is disconnected"
                    .to_string(),
            ));
        }

        validate_frame_size(payload.len())?;

        let payload_length = u32::try_from(payload.len()).map_err(|_| {
            NetworkError::InvalidMessage(
                "Frame length exceeds the supported protocol range"
                    .to_string(),
            )
        })?;

        let stream = self.stream.as_mut().ok_or_else(|| {
            NetworkError::InvalidState(
                "TCP stream is unavailable".to_string(),
            )
        })?;

        let send_timeout = Duration::from_millis(
            self.config.send_timeout_ms.max(1),
        );

        let result = timeout(send_timeout, async {
            stream
                .write_all(&payload_length.to_be_bytes())
                .await?;

            stream.write_all(payload).await?;

            stream.flush().await
        })
        .await;

        match result {
            Ok(Ok(())) => Ok(()),

            Ok(Err(error)) => {
                self.state = TransportState::Failed;
                self.stream = None;

                Err(NetworkError::ConnectionFailed(
                    format!("TCP send failed: {error}"),
                ))
            }

            Err(_) => {
                self.state = TransportState::Failed;
                self.stream = None;

                Err(NetworkError::Timeout(
                    "TCP send timed out".to_string(),
                ))
            }
        }
    }

    /// Receive one complete frame.
    ///
    /// The length prefix is checked before allocating the payload buffer.
    pub async fn receive_frame(&mut self) -> NetworkResult<Vec<u8>> {
        if self.state != TransportState::Connected {
            return Err(NetworkError::InvalidState(
                "Cannot receive data while TCP transport is disconnected"
                    .to_string(),
            ));
        }

        let stream = self.stream.as_mut().ok_or_else(|| {
            NetworkError::InvalidState(
                "TCP stream is unavailable".to_string(),
            )
        })?;

        let receive_timeout = Duration::from_millis(
            self.config.receive_timeout_ms.max(1),
        );

        let result = timeout(receive_timeout, async {
            let mut length_bytes = [0_u8; 4];

            stream.read_exact(&mut length_bytes).await?;

            let frame_length =
                u32::from_be_bytes(length_bytes) as usize;

            validate_frame_size(frame_length)
                .map_err(|error| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        error.to_string(),
                    )
                })?;

            let mut payload = vec![0_u8; frame_length];

            if frame_length > 0 {
                stream.read_exact(&mut payload).await?;
            }

            Ok::<Vec<u8>, std::io::Error>(payload)
        })
        .await;

        match result {
            Ok(Ok(payload)) => Ok(payload),

            Ok(Err(error)) => {
                self.state = TransportState::Failed;
                self.stream = None;

                Err(NetworkError::ConnectionFailed(
                    format!("TCP receive failed: {error}"),
                ))
            }

            Err(_) => {
                self.state = TransportState::Failed;
                self.stream = None;

                Err(NetworkError::Timeout(
                    "TCP receive timed out".to_string(),
                ))
            }
        }
    }

    /// Close the connection and clear its peer association.
    pub async fn disconnect(&mut self) -> NetworkResult<()> {
        if let Some(mut stream) = self.stream.take() {
            let _ = stream.shutdown().await;
        }

        self.peer_id = None;
        self.remote_addr = None;
        self.state = TransportState::Disconnected;

        Ok(())
    }
}

#[async_trait]
impl NetworkTransport for TcpTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::Tcp
    }

    fn state(&self) -> TransportState {
        self.state
    }

    async fn connect(
        &mut self,
        connection: &TransportConnectionInfo,
    ) -> NetworkResult<()> {
        let address: SocketAddr = connection
            .remote_address
            .parse()
            .map_err(|error| {
                NetworkError::InvalidMessage(
                    format!("Invalid TCP address: {error}"),
                )
            })?;

        self.connect_to(connection.peer_id, address).await
    }

    async fn send(&mut self, data: &[u8]) -> NetworkResult<()> {
        self.send_frame(data).await
    }

    async fn receive(&mut self) -> NetworkResult<Vec<u8>> {
        self.receive_frame().await
    }

    async fn close(&mut self) -> NetworkResult<()> {
        self.disconnect().await
    }
}
