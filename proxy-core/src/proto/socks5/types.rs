//! SOCKS5 protocol types and constants.
//!
//! This module provides type definitions for the SOCKS5 protocol as specified in:
//! - [RFC 1928] - SOCKS Protocol Version 5
//! - [RFC 1929] - Username/Password Authentication for SOCKS V5
//!
//! # Contents
//!
//! ## Protocol Types
//!
//! These types directly represent wire format fields defined in the SOCKS5 specification:
//!
//! - [`SOCKS5_VER`], [`SOCKS5_AUTH_VER`], [`SOCKS5_RSV`] - Protocol constants
//! - [`AuthMethod`] - Authentication method identifiers (METHOD field)
//! - [`AuthStatus`] - Authentication result codes (STATUS field)
//! - [`AddressType`] - Address type identifiers (ATYP field)
//! - [`Command`] - Client command codes (CMD field)
//! - [`Reply`] - Server reply codes (REP field)
//! - [`ProtocolError`] - Wire format validation errors
//!
//! ## Address Abstraction
//!
//! The [`Address`] enum is a higher-level abstraction that combines the address type (ATYP),
//! address data, and port into a single convenient type. While not a direct protocol entity,
//! it closely models the address representation in SOCKS5 messages and provides utility methods.
//!
//! [RFC 1928]: https://datatracker.ietf.org/doc/html/rfc1928
//! [RFC 1929]: https://datatracker.ietf.org/doc/html/rfc1929
use std::io;
use std::vec::IntoIter;
use std::iter::{self, Once};
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};

use thiserror::Error;

/// SOCKS5 protocol version (0x05).
///
/// This constant represents the version field in SOCKS5 messages.
/// All SOCKS5 messages must start with this version byte.
///
/// # RFC Reference
///
/// See [RFC 1928 Section 3](https://datatracker.ietf.org/doc/html/rfc1928#section-3).
pub const SOCKS5_VER: u8 = 0x05;

/// Username/Password authentication subprotocol version (0x01).
///
/// This constant represents the version field in username/password
/// authentication messages (RFC 1929).
///
/// # RFC Reference
///
/// See [RFC 1929 Section 2](https://datatracker.ietf.org/doc/html/rfc1929#section-2).
pub const SOCKS5_AUTH_VER: u8 = 0x01;

/// Reserved field value (0x00).
///
/// This constant represents the expected value for reserved (RSV) fields
/// in SOCKS5 messages. Reserved fields must be set to 0x00.
///
/// # RFC Reference
///
/// See [RFC 1929 Section 4](https://datatracker.ietf.org/doc/html/rfc1929#section-4).
pub const SOCKS5_RSV: u8 = 0x00;

/// Errors that occur during parsing and validation of SOCKS5 protocol messages.
///
/// These errors represent violations of the SOCKS5 protocol specification
/// (RFC 1928, RFC 1929) at the wire format level. They indicate that the
/// client sent malformed or invalid data that cannot be correctly decoded.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProtocolError {
    /// Version byte (VER) is not a valid SOCKS5 version.
    #[error("Invalid SOCKS version byte")]
    InvalidVersion,

    /// Authentication subprotocol version (VER) byte is not a valid SOCKS5 version.
    #[error("Invalid authentication version byte")]
    InvalidAuthVersion,

    /// Authentication method byte (METHOD) is not a valid SOCKS5 authentication method.
    #[error("Invalid authentication method byte")]
    InvalidAuthMethod,

    /// Address type byte (ATYP) is not a valid SOCKS5 address type.
    #[error("Invalid address type byte")]
    InvalidAddressType,

    /// Reserved field byte (RSV) is not a valid SOCKS5 reserved field value.
    #[error("Invalid reserved field value")]
    InvalidReserved,

    /// Command byte (CMD) is not a valid SOCKS5 command.
    #[error("Invalid command byte")]
    InvalidCommand,

    /// Reply code byte (REP) is not a valid SOCKS5 reply.
    #[error("Invalid reply code byte")]
    InvalidReply,

    /// Number of authentication methods field (NMETHODS) is set to zero.
    #[error("No authentication methods provided")]
    EmptyMethodsList,

    /// Username length field (ULEN) is set to zero.
    #[error("Username length is zero")]
    EmptyUsername,

    /// Password length field (PLEN) is set to zero.
    #[error("Password length is zero")]
    EmptyPassword,

    /// Frame size exceeds maximum allowed length for message type.
    #[error("Frame size exceeds maximum allowed length")]
    FrameTooLarge,

    /// Domain name field contains invalid or malformed bytes.
    #[error("Invalid domain name field encoding")]
    InvalidDomainEncoding,

    /// Username field (UNAME) contains invalid or malformed bytes.
    #[error("Invalid username field encoding")]
    InvalidUsernameEncoding,

    /// Password field (PASSWD) contains invalid or malformed bytes.
    #[error("Invalid password field encoding")]
    InvalidPasswordEncoding,
}

/// Authentication methods supported by SOCKS5.
///
/// This enum represents the METHOD field in the negotiation phase and
/// authentication responses.
///
/// # Wire Format
///
/// Each variant corresponds to a single byte value in the protocol:
/// - `0x00` - No authentication required
/// - `0x01` - GSSAPI
/// - `0x02` - Username/Password
/// - `0xFF` - No acceptable methods (server response only)
///
/// # RFC Reference
///
/// See [RFC 1928 Section 3](https://datatracker.ietf.org/doc/html/rfc1928#section-3).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    /// No authentication required (0x00).
    ///
    /// The client can proceed directly to sending the connection request
    /// without any authentication exchange.
    NoAuthenticationRequired = 0x00,

    /// GSSAPI authentication (0x01).
    ///
    /// Generic Security Services Application Program Interface authentication.
    /// This method is defined in RFC 1961 but is rarely used in practice.
    Gssapi = 0x01,

    /// Username/Password authentication (0x02).
    ///
    /// Simple username/password authentication as defined in RFC 1929.
    /// This is the most commonly used authentication method.
    UsernamePassword = 0x02,

    /// No acceptable methods (0xFF).
    ///
    /// Server response indicating that none of the client's proposed
    /// authentication methods are acceptable. The server will close
    /// the connection after sending this response.
    NoAcceptableMethods = 0xFF,
}

impl TryFrom<u8> for AuthMethod {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::NoAuthenticationRequired),
            0x01 => Ok(Self::Gssapi),
            0x02 => Ok(Self::UsernamePassword),
            0xFF => Ok(Self::NoAcceptableMethods),
            _ => Err(ProtocolError::InvalidAuthMethod),
        }
    }
}

/// Status code for username/password authentication.
///
/// This enum represents the STATUS field in the authentication response
/// message defined in RFC 1929.
///
/// # RFC Reference
///
/// See [RFC 1929 Section 2](https://datatracker.ietf.org/doc/html/rfc1929#section-2).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthStatus {
    /// Authentication succeeded (0x00).
    ///
    /// The provided credentials are valid. The client may proceed
    /// to send the connection request.
    Success = 0x00,

    /// Authentication failed (any non-zero value).
    ///
    /// The provided credentials are invalid. The server will close
    /// the connection after sending this response.
    Failure = 0x01,
}

impl From<u8> for AuthStatus {
    fn from(value: u8) -> Self {
        match value {
            0x00 => Self::Success,
            _ => Self::Failure,
        }
    }
}

/// Address type field (ATYP) values.
///
/// This enum specifies the format of the address field in SOCKS5 messages.
///
/// # RFC Reference
///
/// See [RFC 1928 Section 5](https://datatracker.ietf.org/doc/html/rfc1928#section-5).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressType {
    /// IPv4 address (0x01).
    ///
    /// Address is 4 octets representing an IPv4 address.
    Ipv4 = 0x01,

    /// Domain name (0x03).
    ///
    /// Address is a variable-length domain name. First octet contains
    /// the length, followed by the domain name octets (no null terminator).
    Domain = 0x03,

    /// IPv6 address (0x04).
    ///
    /// Address is 16 octets representing an IPv6 address.
    Ipv6 = 0x04,
}

impl TryFrom<u8> for AddressType {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Ipv4),
            0x03 => Ok(Self::Domain),
            0x04 => Ok(Self::Ipv6),
            _ => Err(ProtocolError::InvalidAddressType),
        }
    }
}

/// SOCKS5 commands.
///
/// This enum represents the CMD field in client connection requests.
///
/// # RFC Reference
///
/// See [RFC 1928 Section 4](https://datatracker.ietf.org/doc/html/rfc1928#section-4).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Establish a TCP/IP stream connection (0x01).
    ///
    /// The most common command. Requests the server to establish a
    /// connection to the specified destination and relay data bidirectionally.
    Connect = 0x01,

    /// Establish a TCP/IP port binding (0x02).
    ///
    /// Requests the server to bind to a port and listen for incoming
    /// connections. Used for protocols that require inbound connections
    /// (e.g., FTP active mode).
    Bind = 0x02,

    /// Associate a UDP relay (0x03).
    ///
    /// Requests the server to associate a UDP relay. Used for protocols
    /// that need to send/receive UDP datagrams through the proxy.
    UdpAssociate = 0x03,
}

impl TryFrom<u8> for Command {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Connect),
            0x02 => Ok(Self::Bind),
            0x03 => Ok(Self::UdpAssociate),
            _ => Err(ProtocolError::InvalidCommand),
        }
    }
}

/// Server reply codes.
///
/// This enum represents the REP field in server responses to client requests.
/// It indicates the status of the requested operation.
///
/// # RFC Reference
///
/// See [RFC 1928 Section 6](https://datatracker.ietf.org/doc/html/rfc1928#section-6).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    /// Request succeeded (0x00).
    Succeeded = 0x00,

    /// General SOCKS server failure (0x01).
    ///
    /// An unspecified error occurred on the server.
    GeneralFailure = 0x01,

    /// Connection not allowed by ruleset (0x02).
    ///
    /// The server's access control rules prohibit this connection.
    ConnectionNotAllowed = 0x02,

    /// Network unreachable (0x03).
    ///
    /// The destination network cannot be reached.
    NetworkUnreachable = 0x03,

    /// Host unreachable (0x04).
    ///
    /// The destination host cannot be reached.
    HostUnreachable = 0x04,

    /// Connection refused (0x05).
    ///
    /// The destination host actively refused the connection.
    ConnectionRefused = 0x05,

    /// TTL expired (0x06).
    ///
    /// The time-to-live expired during connection attempt.
    TtlExpired = 0x06,

    /// Command not supported (0x07).
    ///
    /// The server does not support the requested command.
    CommandNotSupported = 0x07,

    /// Address type not supported (0x08).
    ///
    /// The server does not support the requested address type.
    AddressTypeNotSupported = 0x08,
}

impl TryFrom<u8> for Reply {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::Succeeded),
            0x01 => Ok(Self::GeneralFailure),
            0x02 => Ok(Self::ConnectionNotAllowed),
            0x03 => Ok(Self::NetworkUnreachable),
            0x04 => Ok(Self::HostUnreachable),
            0x05 => Ok(Self::ConnectionRefused),
            0x06 => Ok(Self::TtlExpired),
            0x07 => Ok(Self::CommandNotSupported),
            0x08 => Ok(Self::AddressTypeNotSupported),
            _ => Err(ProtocolError::InvalidReply),
        }
    }
}

/// Network address abstraction for SOCKS5 protocol.
///
/// This enum provides a unified representation of the three address types supported
/// by SOCKS5: IPv4, IPv6, and domain names. While not a direct wire format entity,
/// it encapsulates the combination of address type ([`AddressType`]), address data,
/// and port number that appears in SOCKS5 messages.
///
/// # Design Note
///
/// In the wire format, addresses are represented as separate fields:
/// - ATYP (1 byte) - address type
/// - Address data (variable length, depending on ATYP)
/// - Port (2 bytes)
///
/// This enum combines these fields into a single convenient type for easier
/// manipulation and provides utility methods for address resolution and conversion.
///
/// # Examples
///
/// ```
/// use std::net::{SocketAddrV4, Ipv4Addr};
/// use proxy_core::proto::socks5::types::{Address, AddressType};
///
/// // IPv4 address
/// let addr = Address::Ipv4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 8080));
/// assert_eq!(addr.atyp(), AddressType::Ipv4);
/// assert_eq!(addr.port(), 8080);
///
/// // Domain name
/// let addr = Address::Domain("example.com".to_string(), 443);
/// assert_eq!(addr.atyp(), AddressType::Domain);
/// assert_eq!(addr.port(), 443);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    /// IPv4 address with port.
    ///
    /// In the wire format, this is represented as:
    /// - ATYP: 0x01
    /// - Address: 4 octets (IPv4 address)
    /// - Port: 2 octets (network byte order)
    Ipv4(SocketAddrV4),

    /// Domain name with port.
    ///
    /// The domain name must be valid UTF-8. In the wire format, this is represented as:
    /// - ATYP: 0x03
    /// - Address: 1 octet (domain length, 1-255) + domain octets (no null terminator)
    /// - Port: 2 octets (network byte order)
    Domain(String, u16),

    /// IPv6 address with port.
    ///
    /// In the wire format, this is represented as:
    /// - ATYP: 0x04
    /// - Address: 16 octets (IPv6 address)
    /// - Port: 2 octets (network byte order)
    Ipv6(SocketAddrV6),
}

impl ToSocketAddrs for Address {
    type Iter = AddressIter;

    fn to_socket_addrs(&self) -> io::Result<Self::Iter> {
        match self {
            Self::Ipv4(addr) => Ok(AddressIter::One(iter::once(SocketAddr::V4(*addr)))),
            Self::Ipv6(addr) => Ok(AddressIter::One(iter::once(SocketAddr::V6(*addr)))),
            Self::Domain(domain, port) => {
                let iter: IntoIter<SocketAddr> = (domain.as_str(), *port).to_socket_addrs()?;
                Ok(AddressIter::Many(iter))
            }
        }
    }
}

impl Address {
    /// Returns the address type (ATYP) for this address.
    ///
    /// # Examples
    ///
    /// ```
    /// use proxy_core::proto::socks5::types::{Address, AddressType};
    ///
    /// let addr = Address::Domain("example.com".to_string(), 80);
    /// assert_eq!(addr.atyp(), AddressType::Domain);
    /// ```
    pub fn atyp(&self) -> AddressType {
        match self {
            Self::Ipv4(_) => AddressType::Ipv4,
            Self::Ipv6(_) => AddressType::Ipv6,
            Self::Domain(_, _) => AddressType::Domain,
        }
    }

    /// Returns the address bytes for wire format encoding.
    ///
    /// - For IPv4: returns 4 bytes (the IPv4 address octets)
    /// - For IPv6: returns 16 bytes (the IPv6 address octets)
    /// - For Domain: returns the domain name as UTF-8 bytes (without length prefix)
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::{SocketAddrV4, Ipv4Addr};
    /// use proxy_core::proto::socks5::types::Address;
    ///
    /// let addr = Address::Ipv4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080));
    /// assert_eq!(addr.addr(), vec![127, 0, 0, 1]);
    /// ```
    pub fn addr(&self) -> Vec<u8> {
        match self {
            Self::Ipv4(addr) => addr.ip().octets().to_vec(),
            Self::Ipv6(addr) => addr.ip().octets().to_vec(),
            Self::Domain(domain, _) => domain.as_bytes().to_vec(),
        }
    }

    /// Returns the port number in host byte order.
    ///
    /// # Examples
    ///
    /// ```
    /// use proxy_core::proto::socks5::types::Address;
    ///
    /// let addr = Address::Domain("example.com".to_string(), 443);
    /// assert_eq!(addr.port(), 443);
    /// ```
    pub fn port(&self) -> u16 {
        match self {
            Self::Ipv4(addr) => addr.port(),
            Self::Ipv6(addr) => addr.port(),
            Self::Domain(_, port) => *port,
        }
    }
}

/// Iterator over socket addresses produced by [`Address`] resolution.
///
/// This type is returned by [`Address::to_socket_addrs`].
/// It handles both single-address cases (IPv4/IPv6) and multi-address cases
/// (domain names that may resolve to multiple IPs).
#[derive(Debug)]
pub enum AddressIter {
    /// Iterator over a single socket address (for IP addresses).
    One(Once<SocketAddr>),

    /// Iterator over multiple socket addresses (for domain names).
    Many(IntoIter<SocketAddr>),
}

impl Iterator for AddressIter {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::One(iter) => iter.next(),
            Self::Many(iter) => iter.next(),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            Self::One(iter) => iter.size_hint(),
            Self::Many(iter) => iter.size_hint(),
        }
    }
}
