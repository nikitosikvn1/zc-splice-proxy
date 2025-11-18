use thiserror::Error;

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
