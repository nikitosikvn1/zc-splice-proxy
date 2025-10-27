use std::io::Error as IoError;
use std::net::{SocketAddrV4, SocketAddrV6};

use thiserror::Error;

/// SOCKS5 protocol version
pub const SOCKS5_VER: u8 = 0x05;
/// Username/Password subnegotiation version
pub const SOCKS5_AUTH_VER: u8 = 0x01;
/// Reserved byte value
pub const SOCKS5_RSV: u8 = 0x00;

#[non_exhaustive]
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Server reports no acceptable authentication methods from those offered by client.
    #[error("No acceptable authentication method")]
    NoAcceptableAuthMethod,

    /// User credentials were rejected during authentication phase.
    #[error("Authentication failed")]
    AuthenticationFailed,

    /// Connection to the target host could not be established.
    #[error("Connection failed")]
    ConnectionFailed,

    /// Client sent an incorrect SOCKS version (expected 0x05).
    #[error("Invalid SOCKS version")]
    InvalidSocksVersion,

    /// Client sent an incorrect authentication subprotocol version.
    #[error("Invalid authentication subprotocol version")]
    InvalidAuthVersion,

    /// Client did not provide any authentication methods.
    #[error("No authentication methods provided")]
    NoAuthMethods,

    /// None of the client's offered authentication methods are supported.
    #[error("No supported authentication methods provided")]
    NoSupportedAuthMethods,

    /// The authentication method byte value is not recognized.
    #[error("Invalid authentication method")]
    InvalidAuthMethod,

    /// The command byte is not a valid SOCKS5 command.
    #[error("Invalid command")]
    InvalidCommand,

    /// The address type byte is not a valid SOCKS5 address type.
    #[error("Invalid address type")]
    InvalidAddressType,

    /// The reply byte is not a valid SOCKS5 reply code.
    #[error("Invalid reply")]
    InvalidReply,

    /// The reserved field contains a non-zero value.
    #[error("Invalid reserved value")]
    InvalidRsvValue,

    /// The domain name contains invalid UTF-8 encoding.
    #[error("Invalid domain encoding")]
    InvalidDomainEncoding,

    /// The username contains invalid UTF-8 encoding.
    #[error("Invalid username encoding")]
    InvalidUsernameEncoding,

    /// The password contains invalid UTF-8 encoding.
    #[error("Invalid password encoding")]
    InvalidPasswordEncoding,

    /// The username exceeds maximum allowed length (255 bytes).
    #[error("Username too long")]
    UsernameTooLong,

    /// The password exceeds maximum allowed length (255 bytes).
    #[error("Password too long")]
    PasswordTooLong,

    /// The username length field (ULEN) is set to 0.
    #[error("Username length is zero")]
    UsernameEmpty,

    /// The password length field (PLEN) is set to 0.
    #[error("Password length is zero")]
    PasswordEmpty,

    /// Client offered more than 255 authentication methods.
    #[error("Too many authentication methods")]
    TooManyAuthMethods,

    /// The buffer exceeds maximum allowed length.
    #[error("Buffer too large")]
    BufferTooLarge,
}

impl From<Error> for IoError {
    fn from(error: Error) -> Self {
        IoError::other(error)
    }
}

/// Authentication methods
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    NoAuthenticationRequired = 0x00,
    Gssapi = 0x01,
    UsernamePassword = 0x02,
    NoAcceptableMethods = 0xFF,
}

impl TryFrom<u8> for AuthMethod {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::NoAuthenticationRequired),
            0x01 => Ok(Self::Gssapi),
            0x02 => Ok(Self::UsernamePassword),
            0xFF => Ok(Self::NoAcceptableMethods),
            _ => Err(Error::InvalidAuthMethod),
        }
    }
}

/// Authentication status
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthStatus {
    Success = 0x00,
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

/// Address types
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressType {
    Ipv4 = 0x01,
    Domain = 0x03,
    Ipv6 = 0x04,
}

impl TryFrom<u8> for AddressType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Ipv4),
            0x03 => Ok(Self::Domain),
            0x04 => Ok(Self::Ipv6),
            _ => Err(Error::InvalidAddressType),
        }
    }
}

/// Commands
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssociate = 0x03,
}

impl TryFrom<u8> for Command {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Connect),
            0x02 => Ok(Self::Bind),
            0x03 => Ok(Self::UdpAssociate),
            _ => Err(Error::InvalidCommand),
        }
    }
}

/// Server reply codes
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    Succeeded = 0x00,
    GeneralFailure = 0x01,
    ConnectionNotAllowed = 0x02,
    NetworkUnreachable = 0x03,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    TtlExpired = 0x06,
    CommandNotSupported = 0x07,
    AddressTypeNotSupported = 0x08,
}

impl TryFrom<u8> for Reply {
    type Error = Error;

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
            _ => Err(Error::InvalidReply),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    Ipv4(SocketAddrV4),
    Domain(String, u16),
    Ipv6(SocketAddrV6),
}

impl Address {
    pub fn atyp(&self) -> AddressType {
        match self {
            Self::Ipv4(_) => AddressType::Ipv4,
            Self::Ipv6(_) => AddressType::Ipv6,
            Self::Domain(_, _) => AddressType::Domain,
        }
    }

    pub fn addr(&self) -> Vec<u8> {
        match self {
            Self::Ipv4(addr) => addr.ip().octets().to_vec(),
            Self::Ipv6(addr) => addr.ip().octets().to_vec(),
            Self::Domain(domain, _) => domain.as_bytes().to_vec(),
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            Self::Ipv4(addr) => addr.port(),
            Self::Ipv6(addr) => addr.port(),
            Self::Domain(_, port) => *port,
        }
    }
}
