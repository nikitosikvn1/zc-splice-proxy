//! Error types for SOCKS5 connection handling.
//!
//! This module defines [`Socks5Error`], which represents all errors that can
//! occur during SOCKS5 protocol processing, from initial handshake through
//! target connection establishment.
//!
//! # Error Categories
//!
//! Errors are categorized by their source and meaning in the SOCKS5 protocol:
//!
//! - **I/O errors** - Low-level socket read/write failures
//! - **Protocol errors** - Client violated SOCKS5 wire format specification
//! - **Authentication errors** - Credential validation failures
//! - **Connection errors** - Failures connecting to target servers
//! - **DNS errors** - Domain name resolution failures
//!
//! Each error variant includes appropriate context and can be converted to
//! a SOCKS5 [`Reply`] code for sending to the client.
//!
//! [`Reply`]: crate::proto::socks5::types::Reply
use std::io::{self, ErrorKind};

use thiserror::Error;

use crate::auth::auth_provider::AuthError;
use crate::net::happy_eyeballs::HappyEyeballsError;
use crate::proto::socks5::types::{ProtocolError, Reply};
use crate::proto::socks5::codecs::Socks5CodecError;

/// Errors that can occur during SOCKS5 connection handling.
#[derive(Debug, Error)]
pub enum Socks5Error {
    /// Underlying I/O error.
    ///
    /// This represents failures in reading from or writing to the client
    /// or target sockets (connection reset, broken pipe, etc.).
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Protocol violation: client sent malformed or invalid data.
    ///
    /// This indicates the client violated the SOCKS5 specification at the
    /// wire format level (invalid version bytes, malformed addresses, etc.).
    #[error("Protocol error: {0}")]
    Protocol(#[from] ProtocolError),

    /// Authentication failed: invalid credentials or policy rejection.
    ///
    /// The client provided credentials, but they were rejected by the
    /// authentication provider. This is business logic, not a protocol error.
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(#[from] AuthError),

    /// No mutually acceptable authentication method found.
    ///
    /// This occurs when the server's authentication requirements don't match
    /// any of the methods proposed by the client. This is normal SOCKS5
    /// behavior, not a protocol violation.
    ///
    /// The server sends `NoAcceptableMethods` (0xFF) and closes the connection.
    #[error("No mutually acceptable authentication method")]
    NoAcceptableMethod,

    /// Command not supported by this server.
    ///
    /// The client requested a valid SOCKS5 command (e.g., UDP_ASSOCIATE),
    /// but this server doesn't support it. This is policy, not protocol.
    #[error("Command not supported")]
    CommandNotSupported,

    /// Connection to target server failed.
    ///
    /// The proxy successfully parsed the request but couldn't establish
    /// a connection to the target (network unreachable, connection refused, etc.).
    #[error("Target connection failed: {0}")]
    TargetConnectionFailed(io::Error),

    /// DNS resolution failed for target domain.
    ///
    /// The proxy couldn't resolve the domain name provided by the client.
    #[error("DNS resolution failed: {0}")]
    DnsResolutionFailed(String),

    /// Operation timeout.
    ///
    /// A connection attempt or other operation exceeded its timeout.
    #[error("Operation timeout")]
    Timeout,
}

impl Socks5Error {
    pub fn to_reply(&self) -> Reply {
        match self {
            Self::TargetConnectionFailed(e) | Self::Io(e) => match e.kind() {
                ErrorKind::ConnectionRefused => Reply::ConnectionRefused,
                ErrorKind::NotFound | ErrorKind::AddrNotAvailable => Reply::HostUnreachable,
                ErrorKind::NetworkUnreachable => Reply::NetworkUnreachable,
                _ => Reply::GeneralFailure,
            },
            Self::Timeout | Self::DnsResolutionFailed(_) => Reply::HostUnreachable,
            _ => Reply::GeneralFailure,
        }
    }
}

impl From<Socks5CodecError> for Socks5Error {
    fn from(error: Socks5CodecError) -> Self {
        match error {
            Socks5CodecError::Io(e) => Self::Io(e),
            Socks5CodecError::Protocol(e) => Self::Protocol(e),
        }
    }
}

impl From<HappyEyeballsError> for Socks5Error {
    fn from(error: HappyEyeballsError) -> Self {
        match error {
            HappyEyeballsError::Io(e) => Self::TargetConnectionFailed(e),
            HappyEyeballsError::DnsResolution(e) => Self::DnsResolutionFailed(e.to_string()),
            HappyEyeballsError::Timeout => Self::Timeout,
            HappyEyeballsError::NoAddressesResolved(hostname) => {
                Self::DnsResolutionFailed(format!("No addresses resolved for {}", hostname))
            }
            HappyEyeballsError::AllAttemptsFailed(errors) => {
                // Analyze all errors to determine the most appropriate classification
                // Priority: ConnectionRefused > NetworkUnreachable > other errors
                if errors.is_empty() {
                    return Self::TargetConnectionFailed(io::Error::other(
                        "All connection attempts failed (no details)",
                    ));
                }

                let priority_order: [ErrorKind; 3] = [
                    ErrorKind::ConnectionRefused,
                    ErrorKind::NetworkUnreachable,
                    ErrorKind::TimedOut,
                ];

                let representative_error: &io::Error = priority_order
                    .iter()
                    .find_map(|&kind| errors.iter().find(|e| e.kind() == kind))
                    .unwrap_or_else(|| &errors[0]);

                Self::TargetConnectionFailed(io::Error::new(
                    representative_error.kind(),
                    format!(
                        "All {} connection attempt(s) failed: {}",
                        errors.len(),
                        representative_error
                    ),
                ))
            }
        }
    }
}

impl From<Socks5Error> for io::Error {
    fn from(error: Socks5Error) -> Self {
        match error {
            Socks5Error::Io(e) => e,
            Socks5Error::TargetConnectionFailed(e) => e,
            Socks5Error::DnsResolutionFailed(e) => Self::new(ErrorKind::NotFound, e),
            Socks5Error::Timeout => Self::new(ErrorKind::TimedOut, "Operation timeout"),
            _ => Self::other(error),
        }
    }
}
