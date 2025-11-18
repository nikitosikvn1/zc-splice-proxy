//! Shared context for SOCKS5 connection handlers.
//!
//! This module defines the [`Socks5Context`] structure that holds configuration
//! and dependencies shared across all SOCKS5 connection handlers. The context
//! is created once at server startup and passed to each handler via `Arc`.
use std::sync::Arc;

use crate::config::Socks5Config;
use crate::auth::auth_provider::AuthProvider;

/// Shared configuration and strategies for SOCKS5 connection handling.
///
/// This structure contains all the dependencies needed by a SOCKS5 handler
/// to process client connections. It is designed to be shared across multiple
/// concurrent connections via `Arc`, avoiding duplication of configuration
/// and strategy objects.
///
/// # Generic Parameters
///
/// - `TR`: TCP relay strategy implementation ([`TcpRelayStrategy`])
/// - `UR`: UDP relay strategy implementation ([`UdpRelayStrategy`])
///
/// These strategy types are provided at compile time and determine how
/// data is relayed between client and target (e.g., using `splice()` on
/// Linux or standard `copy_bidirectional()` on other platforms).
///
/// # Fields
///
/// - `tcp_relay_strategy`: Strategy for relaying TCP connection data
/// - `udp_relay_strategy`: Strategy for relaying UDP association data
/// - `auth_provider`: Provider for validating client authentication credentials
/// - `config`: SOCKS5-specific configuration (timeouts, limits, etc.)
///
/// [`TcpRelayStrategy`]: crate::relay::strategy::TcpRelayStrategy
/// [`UdpRelayStrategy`]: crate::relay::strategy::UdpRelayStrategy
pub struct Socks5Context<TR, UR> {
    pub tcp_relay_strategy: TR,
    pub udp_relay_strategy: UR,
    pub auth_provider: Arc<dyn AuthProvider>,
    pub config: Socks5Config,
}
