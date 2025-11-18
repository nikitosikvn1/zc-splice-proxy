//! Happy Eyeballs Version 2 (RFC 8305) implementation
//!
//! This module provides an efficient, production-ready implementation of the Happy Eyeballs v2
//! algorithm for establishing TCP connections with dual-stack hosts.
//!
//! # Algorithm Overview
//!
//! The Happy Eyeballs v2 algorithm improves connection establishment performance in dual-stack
//! networks (IPv4 and IPv6) by attempting connections in parallel with intelligent timing:
//!
//! 1. **DNS Resolution with Staggered Timing**:
//!    - Start IPv6 (AAAA) DNS lookup immediately
//!    - Wait 50ms (configurable) for IPv6 resolution
//!    - Start IPv4 (A) DNS lookup in parallel after delay or if IPv6 completes early
//!
//! 2. **Address Sorting**:
//!    - Sort addresses by preference according to RFC 6724 heuristics
//!    - Prefer loopback > private/unique local > global addresses
//!
//! 3. **Address Interleaving**:
//!    - Alternate between IPv6 and IPv4 addresses
//!    - Pattern: IPv6₁, IPv4₁, IPv6₂, IPv4₂, ...
//!
//! 4. **Staggered Connection Attempts**:
//!    - Start first connection attempt immediately
//!    - Wait 250ms (configurable) before starting next attempt
//!    - Continue with remaining addresses at 250ms intervals
//!
//! 5. **First Success Wins**:
//!    - Return first successful connection
//!    - Cancel all pending connection attempts
//!
//! # References
//!
//! - [RFC 8305: Happy Eyeballs Version 2](https://datatracker.ietf.org/doc/html/rfc8305)
//! - [RFC 6724: Default Address Selection for IPv6](https://datatracker.ietf.org/doc/html/rfc6724)
use std::io;
use std::time::Duration;
use std::sync::LazyLock;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use tokio::time;
use tokio::net::TcpStream;
use futures::stream::{StreamExt, FuturesUnordered};
use thiserror::Error;
use smallvec::{SmallVec, IntoIter};
use hickory_resolver::{Resolver, TokioResolver, ResolveError};

/// Errors that can occur during Happy Eyeballs connection establishment
#[derive(Error, Debug)]
pub enum HappyEyeballsError {
    /// An I/O error occurred during connection establishment
    ///
    /// This typically indicates a low-level socket error.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// DNS resolution failed
    ///
    /// This error occurs when the DNS resolver cannot resolve the hostname
    /// to any IP addresses, possibly due to network issues or invalid hostname.
    #[error("DNS resolution failed: {0}")]
    DnsResolution(#[from] ResolveError),

    /// Connection attempt timed out
    ///
    /// The connection attempt exceeded the configured timeout period.
    #[error("Connection attempt timed out")]
    Timeout,

    /// No addresses were resolved for the hostname
    ///
    /// DNS resolution succeeded but returned no IP addresses (neither IPv4 nor IPv6).
    #[error("No IP addresses found for hostname: {0}")]
    NoAddressesResolved(String),

    /// All connection attempts failed
    ///
    /// Every attempted connection to all resolved addresses failed.
    /// Contains all the individual connection errors for diagnostics.
    #[error("All connection attempts failed")]
    AllAttemptsFailed(Vec<io::Error>),
}

/// Result type for Happy Eyeballs operations
pub type HappyEyeballsResult<T> = std::result::Result<T, HappyEyeballsError>;

/// Configuration for Happy Eyeballs connection behavior
///
/// This configuration allows fine-tuning the Happy Eyeballs algorithm timing
/// parameters. The defaults are based on RFC 8305 recommendations and should
/// work well for most scenarios.
#[derive(Debug, Clone)]
pub struct HappyEyeballsConfig {
    /// Time to wait for preferred address family (AAAA) before starting fallback (A)
    /// RFC 8305 recommends 50ms
    pub resolution_delay: Duration,

    /// Delay between parallel connection attempts to different addresses
    /// RFC 8305 recommends 250ms
    pub connection_attempt_delay: Duration,

    /// Overall timeout for a single connection attempt
    pub connect_timeout: Duration,

    /// Maximum time to wait for the first address family resolution
    pub first_address_family_timeout: Duration,
}

impl Default for HappyEyeballsConfig {
    fn default() -> Self {
        Self {
            resolution_delay: Duration::from_millis(50),
            connection_attempt_delay: Duration::from_millis(250),
            connect_timeout: Duration::from_secs(10),
            first_address_family_timeout: Duration::from_secs(5),
        }
    }
}

/// Resolved IP addresses, optimized for typical case of 1-4 addresses per family
///
/// Uses `SmallVec` to avoid heap allocation when there are 4 or fewer addresses
/// per address family, which covers the vast majority of real-world scenarios.
#[derive(Debug, Default)]
struct ResolvedAddresses {
    /// IPv6 addresses (AAAA records)
    ipv6: SmallVec<[IpAddr; 4]>,

    /// IPv4 addresses (A records)
    ipv4: SmallVec<[IpAddr; 4]>,
}

impl ResolvedAddresses {
    /// Returns total number of addresses (IPv4 + IPv6)
    #[inline]
    fn len(&self) -> usize {
        self.ipv4.len() + self.ipv6.len()
    }

    /// Returns true if no addresses were resolved
    #[inline]
    fn is_empty(&self) -> bool {
        self.ipv6.is_empty() && self.ipv4.is_empty()
    }

    /// Sort addresses by preference according to RFC 6724 heuristics
    ///
    /// Sorting order (highest to lowest priority):
    /// - IPv6: loopback > unique local > link local > global
    /// - IPv4: loopback > private > public
    ///
    /// This ensures that more reliable/faster addresses are tried first.
    fn sort_by_preference(&mut self) {
        // Sort IPv6: loopback > unique local > link local > global
        self.ipv6.sort_by_key(|addr| {
            match addr {
                IpAddr::V6(v6) => {
                    if v6.is_loopback() {
                        return 0;
                    }
                    if is_unique_local(v6) {
                        return 1;
                    }
                    if is_link_local(v6) {
                        return 2;
                    }
                    3 // Global
                }
                _ => unreachable!("IPv6 vec contains non-IPv6 address"),
            }
        });

        // Sort IPv4: loopback > private > public
        self.ipv4.sort_by_key(|addr| {
            match addr {
                IpAddr::V4(v4) => {
                    if v4.is_loopback() {
                        return 0;
                    }
                    if v4.is_private() {
                        return 1;
                    }
                    2 // Public
                }
                _ => unreachable!("IPv4 vec contains non-IPv4 address"),
            }
        });
    }

    /// Consume and convert into an interleaved iterator
    fn interleave(self) -> InterleavedAddressesIter {
        InterleavedAddressesIter::new(self.ipv6, self.ipv4)
    }
}

/// Check if IPv6 address is unique local (fc00::/7)
///
/// Unique Local Addresses (ULA) are similar to private IPv4 addresses.
/// They are routable within a site but not on the global internet.
#[inline]
fn is_unique_local(addr: &Ipv6Addr) -> bool {
    addr.segments()[0] & 0xFE00 == 0xFC00
}

/// Check if IPv6 address is link local (fe80::/10)
///
/// Link-local addresses are only valid on a single network link.
/// They are not routable beyond the local network segment.
#[inline]
fn is_link_local(addr: &Ipv6Addr) -> bool {
    addr.segments()[0] & 0xFFC0 == 0xFE80
}

/// Iterator that interleaves IPv6 and IPv4 addresses
///
/// This iterator implements the RFC 8305 address interleaving algorithm,
/// which alternates between IPv6 and IPv4 addresses to give both address
/// families a fair chance at connecting quickly.
///
/// # Algorithm
///
/// Starting with IPv6 preference, the iterator alternates:
/// - IPv6₁, IPv4₁, IPv6₂, IPv4₂, IPv6₃, IPv4₃, ...
///
/// If one family runs out of addresses, the iterator continues with
/// the remaining family.
pub struct InterleavedAddressesIter {
    ipv6: IntoIter<[IpAddr; 4]>,
    ipv4: IntoIter<[IpAddr; 4]>,
    ipv6_turn: bool,
}

impl InterleavedAddressesIter {
    /// Create a new interleaved iterator from IPv6 and IPv4 address lists
    fn new(ipv6: SmallVec<[IpAddr; 4]>, ipv4: SmallVec<[IpAddr; 4]>) -> Self {
        Self {
            ipv6: ipv6.into_iter(),
            ipv4: ipv4.into_iter(),
            ipv6_turn: true, // Start with IPv6 (RFC 8305 preference)
        }
    }
}

impl Iterator for InterleavedAddressesIter {
    type Item = IpAddr;

    fn next(&mut self) -> Option<Self::Item> {
        // Try preferred family first (alternates between IPv6 and IPv4)
        let (primary, secondary) = if self.ipv6_turn {
            (&mut self.ipv6, &mut self.ipv4)
        } else {
            (&mut self.ipv4, &mut self.ipv6)
        };

        // If primary has an address, use it and flip the flag for next iteration
        if let Some(addr) = primary.next() {
            self.ipv6_turn = !self.ipv6_turn;
            return Some(addr);
        }

        // Primary exhausted, drain the secondary iterator
        secondary.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let (v6_lower, v6_upper) = self.ipv6.size_hint();
        let (v4_lower, v4_upper) = self.ipv4.size_hint();

        let lower: usize = v6_lower + v4_lower;
        let upper: Option<usize> = match (v6_upper, v4_upper) {
            (Some(v6), Some(v4)) => Some(v6 + v4),
            _ => None,
        };

        (lower, upper)
    }
}

impl ExactSizeIterator for InterleavedAddressesIter {
    fn len(&self) -> usize {
        self.ipv6.len() + self.ipv4.len()
    }
}

/// Builder for configuring a [`HappyEyeballsConnector`]
///
/// This builder allows fine-grained control over the Happy Eyeballs connector
/// configuration. All parameters are optional and will use sensible defaults
/// if not specified.
#[derive(Debug, Default)]
pub struct HappyEyeballsConnectorBuilder {
    resolver: Option<TokioResolver>,
    resolution_delay: Option<Duration>,
    connection_attempt_delay: Option<Duration>,
    connect_timeout: Option<Duration>,
    first_address_family_timeout: Option<Duration>,
}

impl HappyEyeballsConnectorBuilder {
    /// Set a custom DNS resolver
    ///
    /// If not specified, a resolver will be created using the system's DNS
    /// configuration (typically `/etc/resolv.conf` on Unix systems).
    pub fn resolver(mut self, resolver: TokioResolver) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// Set the resolution delay (RFC 8305 Resolution Delay)
    ///
    /// This is the time to wait for IPv6 (AAAA) resolution before starting
    /// IPv4 (A) resolution. RFC 8305 recommends 50ms.
    ///
    /// Default: 50ms
    pub fn resolution_delay(mut self, delay: Duration) -> Self {
        self.resolution_delay = Some(delay);
        self
    }

    /// Set the connection timeout for individual connection attempts
    ///
    /// This is the maximum time to wait for a single `TcpStream::connect()`
    /// to complete. If a connection takes longer than this, it will be
    /// considered failed and the next address will be tried.
    ///
    /// Default: 10 seconds
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = Some(timeout);
        self
    }

    /// Set the connection attempt delay (RFC 8305 Connection Attempt Delay)
    ///
    /// This is the delay between starting parallel connection attempts.
    /// RFC 8305 recommends 250ms as a balance between parallelism and
    /// not overwhelming the network.
    ///
    /// Default: 250ms
    pub fn connection_attempt_delay(mut self, delay: Duration) -> Self {
        self.connection_attempt_delay = Some(delay);
        self
    }

    /// Set the maximum time to wait for DNS resolution
    ///
    /// This timeout applies to the entire DNS resolution phase for the
    /// first address family (typically IPv6).
    ///
    /// Default: 5 seconds
    pub fn first_address_family_timeout(mut self, timeout: Duration) -> Self {
        self.first_address_family_timeout = Some(timeout);
        self
    }

    /// Build the [`HappyEyeballsConnector`]
    pub fn build(self) -> Result<HappyEyeballsConnector, HappyEyeballsError> {
        let resolver: TokioResolver = match self.resolver {
            Some(r) => r,
            None => Resolver::builder_tokio()?.build(),
        };

        let defaults = HappyEyeballsConfig::default();
        let config = HappyEyeballsConfig {
            resolution_delay: self.resolution_delay.unwrap_or(defaults.resolution_delay),
            connection_attempt_delay: self
                .connection_attempt_delay
                .unwrap_or(defaults.connection_attempt_delay),
            connect_timeout: self.connect_timeout.unwrap_or(defaults.connect_timeout),
            first_address_family_timeout: self
                .first_address_family_timeout
                .unwrap_or(defaults.first_address_family_timeout),
        };

        Ok(HappyEyeballsConnector { resolver, config })
    }
}

/// Happy Eyeballs v2 (RFC 8305) connector for dual-stack TCP connections
///
/// This connector implements the complete Happy Eyeballs v2 algorithm for establishing
/// TCP connections to dual-stack hosts with optimal performance and reliability.
pub struct HappyEyeballsConnector {
    resolver: TokioResolver,
    config: HappyEyeballsConfig,
}

impl HappyEyeballsConnector {
    /// Create a new connector with default configuration
    ///
    /// Uses the system's DNS resolver configuration (typically `/etc/resolv.conf`
    /// on Unix systems).
    pub fn new() -> Result<Self, HappyEyeballsError> {
        Ok(Self {
            resolver: TokioResolver::builder_tokio()?.build(),
            config: HappyEyeballsConfig::default(),
        })
    }

    pub fn builder() -> HappyEyeballsConnectorBuilder {
        HappyEyeballsConnectorBuilder::default()
    }

    /// Connect to a hostname using Happy Eyeballs v2 algorithm
    ///
    /// This is the main entry point for establishing connections. It performs
    /// DNS resolution, address sorting, interleaving, and staggered connection
    /// attempts according to RFC 8305.
    pub async fn connect(&self, hostname: &str, port: u16) -> HappyEyeballsResult<TcpStream> {
        // TODO: add fast paths for direct IP and single address
        tracing::debug!(host = hostname, port, "Starting Happy Eyeballs connection");

        // Step 1: Resolve DNS with RFC 8305 timing
        let mut addrs: ResolvedAddresses = self.resolve_with_delay(hostname).await?;
        if addrs.is_empty() {
            return Err(HappyEyeballsError::NoAddressesResolved(hostname.into()));
        }

        tracing::debug!(
            total = addrs.len(),
            ipv4 = addrs.ipv4.len(),
            ipv6 = addrs.ipv6.len(),
            "Resolved addresses"
        );
        // Step 2: Sort addresses by preference (RFC 6724)
        addrs.sort_by_preference();

        // Step 3: Interleave addresses (IPv6 first, then alternate)
        let interleaved: InterleavedAddressesIter = addrs.interleave();

        // Step 4: Attempt connections with staggered delays
        self.connect_to_addresses(interleaved, port).await
    }

    /// Resolve DNS with RFC 8305 timing: IPv6 first, then IPv4 after delay
    ///
    /// This method implements the DNS resolution timing specified in RFC 8305:
    /// 1. Start IPv6 (AAAA) lookup immediately
    /// 2. Wait up to `resolution_delay` (default 50ms)
    /// 3. Start IPv4 (A) lookup
    /// 4. Wait for both with timeout
    ///
    /// # Early Completion Optimization
    ///
    /// If IPv6 completes before the delay expires, IPv4 lookup starts immediately
    async fn resolve_with_delay(&self, hostname: &str) -> HappyEyeballsResult<ResolvedAddresses> {
        let mut addrs = ResolvedAddresses::default();
        let ipv6_lookup = self.resolver.ipv6_lookup(hostname);
        tokio::pin!(ipv6_lookup);

        // Wait for resolution delay OR IPv6 completion (whichever comes first)
        let should_start_ipv4_immediately: bool = tokio::select! {
            ipv6_result = &mut ipv6_lookup => {
                // IPv6 completed before delay
                if let Ok(lookup) = ipv6_result {
                    addrs.ipv6.extend(lookup.into_iter().map(|ip| IpAddr::V6(ip.0)));
                    tracing::trace!(count = addrs.ipv6.len(), "IPv6 resolved early");
                } else {
                    tracing::trace!("IPv6 resolution failed");
                }
                false // IPv6 already resolved, start IPv4 now
            }
            _ = time::sleep(self.config.resolution_delay) => {
                tracing::trace!("Resolution delay expired, starting IPv4");
                true // Delay expired, start IPv4 in parallel with IPv6
            }
        };

        // Start IPv4 resolution
        let ipv4_lookup = self.resolver.ipv4_lookup(hostname);
        if should_start_ipv4_immediately {
            // IPv6 is still pending, wait for both with timeout
            let combined = async {
                let (v6_result, v4_result) = tokio::join!(ipv6_lookup, ipv4_lookup);

                if let Ok(lookup) = v6_result {
                    addrs
                        .ipv6
                        .extend(lookup.into_iter().map(|ip| IpAddr::V6(ip.0)));
                }
                if let Ok(lookup) = v4_result {
                    addrs
                        .ipv4
                        .extend(lookup.into_iter().map(|ip| IpAddr::V4(ip.0)));
                }
            };

            if time::timeout(self.config.first_address_family_timeout, combined)
                .await
                .is_err()
            {
                tracing::warn!(%hostname, "DNS resolution timed out");
            }
        } else {
            // IPv6 already done, just wait for IPv4
            match time::timeout(self.config.first_address_family_timeout, ipv4_lookup).await {
                Ok(Ok(lookup)) => {
                    addrs
                        .ipv4
                        .extend(lookup.into_iter().map(|ip| IpAddr::V4(ip.0)));
                    tracing::trace!(count = addrs.ipv4.len(), "IPv4 resolved");
                }
                Ok(Err(e)) => tracing::trace!(error = %e, "IPv4 resolution failed"),
                Err(_) => tracing::trace!("IPv4 resolution timed out"),
            }
        }

        Ok(addrs)
    }

    /// Attempt connections to multiple addresses with staggered delays
    ///
    /// This method implements the staggered connection algorithm from RFC 8305:
    /// 1. Start first connection immediately
    /// 2. Wait `connection_attempt_delay` (default 250ms)
    /// 3. Start next connection
    /// 4. Repeat until success or all attempts exhausted
    ///
    /// # Connection Prioritization
    ///
    /// Uses `biased` select to prioritize checking connection results over
    /// starting new attempts, ensuring we don't waste resources on unnecessary
    /// connections.
    ///
    /// # Cancellation
    ///
    /// When a connection succeeds, all pending connection attempts are automatically
    /// cancelled by dropping the `FuturesUnordered` collection.
    async fn connect_to_addresses<I>(&self, addrs: I, port: u16) -> HappyEyeballsResult<TcpStream>
    where
        I: Iterator<Item = IpAddr>,
    {
        let mut addrs = addrs.peekable();
        let mut futures = FuturesUnordered::new();
        let mut errors: Vec<io::Error> = Vec::new();

        // Start with the first address
        if let Some(addr) = addrs.next() {
            let socket_addr = SocketAddr::new(addr, port);
            tracing::trace!(%socket_addr, "Starting initial connection attempt");

            futures.push(Self::connect_with_timeout(
                socket_addr,
                self.config.connect_timeout,
            ));
        } else {
            tracing::warn!("No addresses to connect to");
            return Err(HappyEyeballsError::AllAttemptsFailed(errors));
        }

        loop {
            tokio::select! {
                // Prioritize connection results over starting new attempts
                biased;
                // Check if any connection succeeded or failed
                result = futures.next(), if !futures.is_empty() => {
                    match result {
                        Some(Ok(stream)) => {
                            tracing::debug!(addr = ?stream.peer_addr().ok(), "Connection established");
                            return Ok(stream);
                        }
                        Some(Err(e)) => {
                            tracing::trace!(error = ?e, "Connection attempt failed");
                            errors.push(e);
                        }
                        None => break,
                    }
                }
                // Start next connection attempt after delay
                _ = time::sleep(self.config.connection_attempt_delay), if addrs.peek().is_some() => {
                    if let Some(addr) = addrs.next() {
                        let socket_addr = SocketAddr::new(addr, port);
                        tracing::trace!(%socket_addr, "Starting staggered connection attempt");

                        futures.push(Self::connect_with_timeout(
                            socket_addr,
                            self.config.connect_timeout,
                        ));
                    }
                }
                // No more work to do
                else => break,
            }
        }

        Err(HappyEyeballsError::AllAttemptsFailed(errors))
    }

    /// Connect to a single address with timeout
    ///
    /// This is a helper method that wraps `TcpStream::connect` with a timeout.
    async fn connect_with_timeout(addr: SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
        time::timeout(timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Connection timed out"))?
    }
}

/// Global default connector instance
///
/// This is a lazily-initialized global connector that can be used via the
/// [`connect`] function for convenience. It uses default configuration and
/// system DNS resolver.
///
/// # Panics
///
/// Panics if system DNS configuration cannot be read (e.g., `/etc/resolv.conf`
/// is missing or invalid on Unix systems).
static DEFAULT_CONNECTOR: LazyLock<HappyEyeballsConnector> = LazyLock::new(|| {
    HappyEyeballsConnector::new()
        .expect("Failed to read system configuration (\"/etc/resolv.conf\")")
});

/// Connect to a hostname using the default Happy Eyeballs connector
///
/// This is a convenience function that uses a global [`HappyEyeballsConnector`]
/// instance with default configuration. For custom configuration or better
/// control, create your own connector instance.
pub async fn connect(hostname: &str, port: u16) -> Result<TcpStream, HappyEyeballsError> {
    DEFAULT_CONNECTOR.connect(hostname, port).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use smallvec::smallvec;

    // TODO: add more tests

    #[test]
    fn test_is_unique_local_detection_correct() {
        // Unique local addresses (fc00::/7)
        assert!(is_unique_local(&"fc00::1".parse().unwrap()));
        assert!(is_unique_local(&"fd00::1".parse().unwrap()));
        assert!(is_unique_local(
            &"fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()
        ));

        // Not unique local
        assert!(!is_unique_local(&"fe80::1".parse().unwrap())); // Link local
        assert!(!is_unique_local(&"2001:db8::1".parse().unwrap())); // Documentation
        assert!(!is_unique_local(&"::1".parse().unwrap())); // Loopback
    }

    #[test]
    fn test_is_link_local_detection_correct() {
        // Link local addresses (fe80::/10)
        assert!(is_link_local(&"fe80::1".parse().unwrap()));
        assert!(is_link_local(&"fe80::dead:beef".parse().unwrap()));
        assert!(is_link_local(
            &"febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()
        ));

        // Not link local
        assert!(!is_link_local(&"fc00::1".parse().unwrap())); // Unique local
        assert!(!is_link_local(&"2001:db8::1".parse().unwrap())); // Documentation
        assert!(!is_link_local(&"::1".parse().unwrap())); // Loopback
    }

    #[test]
    fn test_resolved_addresses_interleave_correct_order() {
        // Given
        let mut addrs = ResolvedAddresses::default();
        addrs.ipv6 = smallvec![
            "2001:db8::1".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
        ];
        addrs.ipv4 = smallvec!["192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap()];

        // When
        let interleaved: Vec<IpAddr> = addrs.interleave().collect();

        // Then
        assert_eq!(interleaved.len(), 4);
        assert!(interleaved[0].is_ipv6()); // First IPv6
        assert!(interleaved[1].is_ipv4()); // Then IPv4
        assert!(interleaved[2].is_ipv6()); // Then IPv6
        assert!(interleaved[3].is_ipv4()); // Then IPv4
    }

    #[test]
    fn test_resolved_addresses_interleave_unbalanced_correct_order() {
        // Given
        let mut addrs = ResolvedAddresses::default();
        addrs.ipv6 = smallvec!["2001:db8::1".parse().unwrap()];
        addrs.ipv4 = smallvec![
            "192.0.2.1".parse().unwrap(),
            "192.0.2.2".parse().unwrap(),
            "192.0.2.3".parse().unwrap(),
        ];

        // When
        let interleaved: Vec<IpAddr> = addrs.interleave().collect();

        // Then
        assert_eq!(interleaved.len(), 4);
        assert!(interleaved[0].is_ipv6()); // First IPv6
        assert!(interleaved[1].is_ipv4()); // Then IPv4
        assert!(interleaved[2].is_ipv4()); // Rest are IPv4
        assert!(interleaved[3].is_ipv4());
    }

    #[test]
    fn test_resolved_addresses_interleave_ipv6_only() {
        // Given
        let mut addrs = ResolvedAddresses::default();
        addrs.ipv6 = smallvec![
            "2001:db8::1".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
        ];

        // When
        let interleaved: Vec<IpAddr> = addrs.interleave().collect();

        // Then
        assert_eq!(interleaved.len(), 2);
        assert!(interleaved.iter().all(IpAddr::is_ipv6));
    }

    #[test]
    fn test_resolved_addresses_interleave_ipv4_only() {
        // Given
        let mut addrs = ResolvedAddresses::default();
        addrs.ipv4 = smallvec!["192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap()];

        // When
        let interleaved: Vec<IpAddr> = addrs.interleave().collect();

        // Then
        assert_eq!(interleaved.len(), 2);
        assert!(interleaved.iter().all(IpAddr::is_ipv4));
    }
}
