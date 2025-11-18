//! Relay strategies for bidirectional data transfer.
//!
//! This module defines the strategy traits and implementations for relaying data
//! between client and target connections. Different strategies can be selected
//! based on platform capabilities and performance requirements.
//!
//! # Strategy Pattern
//!
//! The relay system uses the strategy pattern with two traits:
//!
//! - [`TcpRelayStrategy`] - Bidirectional TCP stream relay
//! - [`UdpRelayStrategy`] - UDP packet relay with control connection
//!
//! # Available Implementations
//!
//! ## TCP Strategies
//!
//! - [`SpliceRelay`] (Linux only) - Zero-copy relay using the `splice()` system call.
//!   This is the most efficient implementation as it avoids copying data between
//!   kernel and userspace, significantly reducing CPU usage and improving throughput.
//!
//! - [`CopyRelay`] - Standard relay using `tokio::io::copy_bidirectional()`.
//!   This is a portable fallback that works on all platforms but requires copying
//!   data through userspace buffers.
//!
//! ## UDP Strategies
//!
//! - [`StandardUdpRelay`] - UDP packet relay implementation (currently unimplemented).
//!
//! # Platform Selection
//!
//! The optimal strategy is typically selected at compile time:
//!
//! ```rust,ignore
//! #[cfg(target_os = "linux")]
//! use noxen_proxy::relay::strategy::SpliceRelay as TcpRelay;
//!
//! #[cfg(not(target_os = "linux"))]
//! use noxen_proxy::relay::strategy::CopyRelay as TcpRelay;
//! ```
use std::io;

use tokio::net::{TcpStream, UdpSocket};
use async_trait::async_trait;
#[cfg(target_os = "linux")]
use tokio_splice2::traffic::TrafficResult;

/// Traffic statistics for a completed relay operation.
///
/// Tracks the total number of bytes transferred in each direction during
/// a bidirectional relay session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Traffic {
    /// Bytes transmitted from downstream (client) to upstream (target).
    pub tx_bytes: u64,
    /// Bytes received from upstream (target) to downstream (client).
    pub rx_bytes: u64,
}

impl Traffic {
    /// Creates a new traffic statistics record.
    pub const fn new(tx_bytes: u64, rx_bytes: u64) -> Self {
        Self { tx_bytes, rx_bytes }
    }

    /// Returns total bytes transferred (tx + rx).
    pub const fn total(&self) -> u64 {
        self.tx_bytes.saturating_add(self.rx_bytes)
    }
}

impl From<(u64, u64)> for Traffic {
    fn from((tx_bytes, rx_bytes): (u64, u64)) -> Self {
        Self { tx_bytes, rx_bytes }
    }
}

/// Strategy for relaying bidirectional TCP stream data.
///
/// Implementations of this trait define how data is copied between the client
/// (downstream) and target server (upstream) TCP connections. Different strategies
/// can use different underlying mechanisms for optimal performance.
///
/// # Contract
///
/// The relay operation should:
/// - Copy data bidirectionally until both directions are closed
/// - Return traffic statistics upon completion
/// - Propagate any I/O errors encountered during relay
#[async_trait]
pub trait TcpRelayStrategy: Send + Sync {
    /// Relays data bidirectionally between downstream and upstream TCP streams.
    ///
    /// This method blocks until both directions of the connection are closed,
    /// either normally (EOF) or due to an error.
    async fn relay(&self, downstream: TcpStream, upstream: TcpStream) -> io::Result<Traffic>;
}

/// Strategy for relaying UDP packets between client and target.
///
/// UDP relay in SOCKS5 is more complex than TCP as it involves:
/// - A control connection (TCP) that signals when to close the association
/// - A downstream UDP socket for receiving client packets
/// - An upstream UDP socket for forwarding to target servers
///
/// # Contract
///
/// The relay operation should:
/// - Forward UDP packets bidirectionally
/// - Monitor the control connection for closure
/// - Return traffic statistics when the association ends
#[async_trait]
pub trait UdpRelayStrategy: Send + Sync {
    /// Relays UDP packets bidirectionally while monitoring the control connection.
    async fn relay(
        &self,
        control: TcpStream,
        downstream: UdpSocket,
        upstream: UdpSocket,
    ) -> io::Result<Traffic>;
}

/// Zero-copy TCP relay strategy using Linux `splice()` system call.
///
/// This strategy provides optimal performance on Linux by using the `splice()`
/// system call to transfer data directly between socket buffers in kernel space,
/// avoiding costly copies to userspace.
///
/// # Performance
///
/// Benchmarks typically show 30-50% reduction in CPU usage compared to [`CopyRelay`]
/// for high-throughput connections, with throughput improvements for CPU-bound scenarios.
///
/// # Platform
///
/// Only available on Linux (`target_os = "linux"`).
#[cfg(target_os = "linux")]
#[derive(Default, Clone, Copy)]
pub struct SpliceRelay;

#[cfg(target_os = "linux")]
#[async_trait]
impl TcpRelayStrategy for SpliceRelay {
    async fn relay(
        &self,
        mut downstream: TcpStream,
        mut upstream: TcpStream,
    ) -> io::Result<Traffic> {
        let traffic: TrafficResult =
            tokio_splice2::copy_bidirectional(&mut downstream, &mut upstream).await?;

        Ok(Traffic::new(traffic.tx as u64, traffic.rx as u64))
    }
}

/// Standard TCP relay strategy using Tokio's copy operations.
///
/// This strategy uses `tokio::io::copy_bidirectional()` to relay data between
/// connections. While not as efficient as [`SpliceRelay`], it works on all
/// platforms and provides good performance for most use cases.
///
/// # Performance
///
/// Uses optimized buffer sizes and async I/O, but requires copying data through
/// userspace buffers. Suitable for most workloads unless CPU becomes the bottleneck.
///
/// # Platform
///
/// Available on all platforms.
#[derive(Default, Clone, Copy)]
pub struct CopyRelay;

#[async_trait]
impl TcpRelayStrategy for CopyRelay {
    async fn relay(
        &self,
        mut downstream: TcpStream,
        mut upstream: TcpStream,
    ) -> io::Result<Traffic> {
        let (tx, rx) = tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await?;

        Ok(Traffic::new(tx, rx))
    }
}

/// Standard UDP relay strategy for SOCKS5 UDP ASSOCIATE.
///
/// # Status
///
/// This implementation is currently a placeholder and will panic if called.
/// UDP ASSOCIATE support is planned for a future release.
#[derive(Default, Clone, Copy)]
pub struct StandardUdpRelay;

#[async_trait]
impl UdpRelayStrategy for StandardUdpRelay {
    async fn relay(
        &self,
        _control: TcpStream,
        _downstream: UdpSocket,
        _upstream: UdpSocket,
    ) -> io::Result<Traffic> {
        unimplemented!("UDP relay is not yet implemented")
    }
}
