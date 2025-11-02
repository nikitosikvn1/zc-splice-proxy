//! Data relay infrastructure for proxy connections.
//!
//! This module provides the core abstractions for relaying data between clients
//! and target servers in the proxy. It uses a strategy pattern to allow different
//! relay implementations optimized for different platforms and use cases.
//!
//! # Module Organization
//!
//! - [`strategy`] - Relay strategy traits and platform-specific implementations
//! - [`tunnel`] - High-level tunnel abstractions for TCP and UDP connections
//!
//! # Architecture
//!
//! The relay system is built on two key concepts:
//!
//! 1. **Strategies** ([`TcpRelayStrategy`], [`UdpRelayStrategy`]) - Define how data
//!    is copied between sockets. Different implementations can use different system
//!    calls (e.g., `splice()` on Linux for zero-copy, or standard `copy_bidirectional()`).
//!
//! 2. **Tunnels** ([`TcpTunnel`], [`UdpTunnel`]) - Encapsulate the connections and
//!    strategy, providing a unified interface for executing the relay operation.
//!
//! This separation allows the proxy to:
//! - Select optimal relay methods at compile time based on platform
//! - Track traffic statistics consistently across different implementations
//! - Test relay logic independently of the underlying system calls
//!
//! [`TcpRelayStrategy`]: strategy::TcpRelayStrategy
//! [`UdpRelayStrategy`]: strategy::UdpRelayStrategy
//! [`TcpTunnel`]: tunnel::TcpTunnel
//! [`UdpTunnel`]: tunnel::UdpTunnel
pub mod tunnel;
pub mod strategy;
