//! SOCKS5 protocol handler implementation.
//!
//! This module provides a complete, production-ready implementation of a SOCKS5
//! connection handler with type-safe state machine enforcement, authentication
//! support, and flexible relay strategies.
//!
//! # Module Organization
//!
//! - [`state`] - Type-safe state machine for SOCKS5 protocol phases
//! - [`context`] - Shared configuration and strategies for connection handling
//! - [`error`] - Error types specific to SOCKS5 connection handling
//!
//! # Overview
//!
//! The handler implements the full SOCKS5 protocol flow:
//!
//! 1. **Method Selection** - Negotiate authentication method with client
//! 2. **Authentication** (optional) - Validate client credentials
//! 3. **Request Processing** - Handle CONNECT, BIND, or UDP_ASSOCIATE commands
//! 4. **Data Relay** - Establish tunnel for bidirectional data transfer
//!
//! # RFC References
//!
//! - [RFC 1928: SOCKS Protocol Version 5](https://datatracker.ietf.org/doc/html/rfc1928)
//! - [RFC 1929: Username/Password Authentication for SOCKS V5](https://datatracker.ietf.org/doc/html/rfc1929)
pub mod state;
pub mod context;
pub mod error;
