//! SOCKS5 protocol implementation.
//!
//! This module provides a complete implementation of the SOCKS5 protocol
//! as defined in [RFC 1928] and [RFC 1929].
//!
//! # Protocol Overview
//!
//! SOCKS5 is a protocol for proxy servers that allows clients to establish
//! TCP connections or UDP associations through the proxy. The protocol consists
//! of three main phases:
//!
//! 1. **Method Selection** - Client and server negotiate authentication method
//! 2. **Authentication** (optional) - Username/password or other authentication
//! 3. **Request/Response** - Client requests connection, server responds with status
//!
//! # Module Organization
//!
//! - [`types`] - Protocol enums, constants, and error types
//! - [`messages`] - Protocol message structure definitions
//! - [`codecs`] - Tokio codec implementations for encoding/decoding frames
//!
//! [RFC 1928]: https://datatracker.ietf.org/doc/html/rfc1928
//! [RFC 1929]: https://datatracker.ietf.org/doc/html/rfc1929
pub mod types;
pub mod messages;
pub mod codecs;

// Re-export commonly used types for convenience
pub use messages::{
    ClientGreeting, ServerGreeting, AuthRequest, AuthResponse, ClientRequest, ServerResponse,
};
pub use types::{AuthMethod, AuthStatus, AddressType, Command, Reply, Address, ProtocolError};
