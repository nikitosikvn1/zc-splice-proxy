//! High-level tunnel abstractions for proxy connections.
//!
//! This module provides the [`Tunnel`] abstraction that encapsulates a complete
//! relay operation, including the connections and the strategy for transferring
//! data between them.
//!
//! # Tunnel Types
//!
//! - [`TcpTunnel`] - Bidirectional relay for CONNECT / BIND commands
//! - [`UdpTunnel`] - Packet relay for UDP_ASSOCIATE command
//!
//! # Usage Pattern
//!
//! Tunnels are created by the SOCKS5 handler after successfully establishing
//! connections, then executed to completion:
//!
//! 1. Handler creates tunnel with appropriate strategy and connections
//! 2. Tunnel is returned to the server layer
//! 3. Server calls `run()` to execute the relay until completion
use std::io;

use tokio::net::{TcpStream, UdpSocket};
use tracing::instrument;

use crate::relay::strategy::{Traffic, TcpRelayStrategy, UdpRelayStrategy};

/// A tunnel for relaying data between client and target.
///
/// This enum wraps either a TCP or UDP tunnel, allowing the handler to return
/// different tunnel types based on the SOCKS5 command (CONNECT vs UDP_ASSOCIATE).
pub enum Tunnel<TR, UR> {
    /// TCP tunnel for CONNECT / BIND command.
    Tcp(TcpTunnel<TR>),
    /// UDP tunnel for UDP_ASSOCIATE command.
    Udp(UdpTunnel<UR>),
}

impl<TR: TcpRelayStrategy, UR: UdpRelayStrategy> Tunnel<TR, UR> {
    /// Executes the tunnel relay operation.
    ///
    /// This method runs the appropriate relay based on the tunnel type,
    /// blocking until the relay completes or encounters an error.
    ///
    /// # Returns
    ///
    /// Traffic statistics on success, or an I/O error on failure.
    #[instrument(skip_all, name = "tunnel")]
    pub async fn run(self) -> io::Result<Traffic> {
        match self {
            Self::Tcp(tcp) => tcp.run().await,
            Self::Udp(udp) => udp.run().await,
        }
    }
}

/// TCP tunnel for bidirectional stream relay.
///
/// Encapsulates a TCP relay operation with client and target connections
/// and the strategy for transferring data between them.
pub struct TcpTunnel<R> {
    /// Strategy for relaying TCP data.
    strategy: R,
    /// Client (downstream) TCP connection.
    downstream: TcpStream,
    /// Target server (upstream) TCP connection.
    upstream: TcpStream,
}

impl<R> TcpTunnel<R> {
    /// Creates a new TCP tunnel.
    pub fn new(strategy: R, downstream: TcpStream, upstream: TcpStream) -> Self {
        Self {
            strategy,
            downstream,
            upstream,
        }
    }
}

impl<R: TcpRelayStrategy> TcpTunnel<R> {
    /// Executes the TCP relay operation.
    ///
    /// Relays data bidirectionally between client and target until both
    /// directions are closed, then returns traffic statistics.
    pub async fn run(self) -> io::Result<Traffic> {
        let traffic: Traffic = self.strategy.relay(self.downstream, self.upstream).await?;

        Ok(traffic)
    }
}

/// UDP tunnel for packet relay with control connection.
///
/// Encapsulates a UDP association relay operation according to RFC 1928.
/// The control connection (TCP) signals when the association should terminate.
pub struct UdpTunnel<R> {
    /// Strategy for relaying UDP packets.
    strategy: R,
    /// TCP control connection that signals association lifetime.
    control_connection: TcpStream,
    /// UDP socket for receiving packets from client.
    downstream_socket: UdpSocket,
    /// UDP socket for sending/receiving packets to/from targets.
    upstream_socket: UdpSocket,
}

impl<R> UdpTunnel<R> {
    /// Creates a new UDP tunnel.
    pub fn new(
        strategy: R,
        control_connection: TcpStream,
        downstream_socket: UdpSocket,
        upstream_socket: UdpSocket,
    ) -> Self {
        Self {
            strategy,
            control_connection,
            downstream_socket,
            upstream_socket,
        }
    }
}

impl<R: UdpRelayStrategy> UdpTunnel<R> {
    /// Executes the UDP relay operation.
    ///
    /// Relays UDP packets bidirectionally while monitoring the control connection.
    /// When the control connection closes, the association terminates.
    pub async fn run(self) -> io::Result<Traffic> {
        let traffic: Traffic = self
            .strategy
            .relay(
                self.control_connection,
                self.downstream_socket,
                self.upstream_socket,
            )
            .await?;

        Ok(traffic)
    }
}
