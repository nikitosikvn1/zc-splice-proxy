//! SOCKS5 protocol message structures.
//!
//! This module defines the data structures representing SOCKS5 protocol messages
//! exchanged between client and server. Each structure corresponds to a specific
//! phase of the SOCKS5 handshake and request/response cycle.
//!
//! # Protocol Flow
//!
//! The typical SOCKS5 connection follows this sequence:
//!
//! 1. **Method Selection Phase**
//!    - Client → [`ClientGreeting`]: Proposes authentication methods
//!    - Server → [`ServerGreeting`]: Selects authentication method
//!
//! 2. **Authentication Phase** (if required)
//!    - Client → [`AuthRequest`]: Provides credentials
//!    - Server → [`AuthResponse`]: Accepts or rejects authentication
//!
//! 3. **Request/Response Phase**
//!    - Client → [`ClientRequest`]: Requests connection to target
//!    - Server → [`ServerResponse`]: Reports connection status
//!
//! 4. **Data Transfer Phase**
//!    - Bidirectional relay of application data (not defined in this module)
//!
//! # Wire Format
//!
//! All messages use network byte order (big-endian) for multi-byte fields.
//! String fields (username, password, domain names) are UTF-8 encoded.
use crate::types::{AuthMethod, AuthStatus, Command, Reply, Address};

/// Maximum size for greeting frame in bytes.
///
/// Calculated as: VER (1) + NMETHODS (1) + METHODS (up to 255) = 257 bytes
///
/// This limit is used for DoS protection to prevent clients from sending
/// excessively large greeting messages.
pub(super) const MAX_GREETING_FRAME_SIZE: usize = 257;

/// Maximum size for authentication frame in bytes.
///
/// Calculated as: VER (1) + ULEN (1) + UNAME (up to 255) + PLEN (1) + PASSWD (up to 255) = 513 bytes
///
/// This represents the worst case where both username and password are at
/// their maximum allowed lengths (255 bytes each).
pub(super) const MAX_AUTH_FRAME_SIZE: usize = 513;

/// Maximum size for request/response frame in bytes.
///
/// Calculated as: VER (1) + CMD/REP (1) + RSV (1) + ATYP (1) + DLEN (1) + DOMAIN (up to 255) + PORT (2) = 262 bytes
///
/// Note: This assumes domain name addresses (ATYP=0x03), which have the largest
/// variable component. IPv4 (4 bytes) and IPv6 (16 bytes) addresses are smaller.
pub(super) const MAX_REQUEST_FRAME_SIZE: usize = 262;

/// Client greeting message for method selection negotiation.
///
/// This is the first message sent by the client to the server. It contains
/// a list of authentication methods that the client supports. The server
/// will respond with a [`ServerGreeting`] indicating which method to use.
///
/// # Wire Format
///
/// ```text
/// +----+----------+----------+
/// |VER | NMETHODS | METHODS  |
/// +----+----------+----------+
/// | 1  |    1     | 1 to 255 |
/// +----+----------+----------+
/// ```
///
/// - `VER` - Protocol version (must be 0x05)
/// - `NMETHODS` - Number of method identifier octets (1-255)
/// - `METHODS` - List of authentication method identifiers
///
/// # RFC Reference
///
/// See [RFC 1928 Section 3](https://datatracker.ietf.org/doc/html/rfc1928#section-3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientGreeting {
    /// List of authentication methods supported by the client.
    ///
    /// Must contain at least one method. Order indicates client preference.
    pub methods: Vec<AuthMethod>,
}

/// Server greeting response for method selection negotiation.
///
/// This is the server's response to a [`ClientGreeting`]. It indicates which
/// authentication method the server has selected from those offered by the client.
///
/// # Wire Format
///
/// ```text
/// +----+--------+
/// |VER | METHOD |
/// +----+--------+
/// | 1  |   1    |
/// +----+--------+
/// ```
///
/// - `VER` - Protocol version (must be 0x05)
/// - `METHOD` - Selected authentication method
///
/// # Special Behavior
///
/// If the server selects [`AuthMethod::NoAcceptableMethods`] (0xFF), it indicates
/// that none of the client's proposed methods are acceptable. The server will
/// close the connection immediately after sending this message.
///
/// # RFC Reference
///
/// See [RFC 1928 Section 3](https://datatracker.ietf.org/doc/html/rfc1928#section-3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerGreeting {
    /// Authentication method selected by the server.
    pub method: AuthMethod,
}

/// Client authentication request using username/password method.
///
/// This message is sent by the client if the server selected
/// [`AuthMethod::UsernamePassword`] during method negotiation.
///
/// # Wire Format
///
/// ```text
/// +----+------+----------+------+----------+
/// |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
/// +----+------+----------+------+----------+
/// | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
/// +----+------+----------+------+----------+
/// ```
///
/// - `VER` - Subnegotiation version (must be 0x01)
/// - `ULEN` - Username length (1-255)
/// - `UNAME` - Username bytes (UTF-8 encoded)
/// - `PLEN` - Password length (1-255)
/// - `PASSWD` - Password bytes (UTF-8 encoded)
///
/// # RFC Reference
///
/// See [RFC 1929 Section 2](https://datatracker.ietf.org/doc/html/rfc1929#section-2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRequest {
    /// Username for authentication (1-255 bytes, UTF-8 encoded).
    pub username: String,
    /// Password for authentication (1-255 bytes, UTF-8 encoded).
    pub password: String,
}

/// Server authentication response for username/password method.
///
/// This is the server's response to an [`AuthRequest`]. It indicates whether
/// the provided credentials were accepted.
///
/// # Wire Format
///
/// ```text
/// +----+--------+
/// |VER | STATUS |
/// +----+--------+
/// | 1  |   1    |
/// +----+--------+
/// ```
///
/// - `VER` - Subnegotiation version (must be 0x01)
/// - `STATUS` - 0x00 for success, any other value for failure
///
/// # Special Behavior
///
/// If authentication fails ([`AuthStatus::Failure`]), the server will close
/// the connection after sending this response.
///
/// # RFC Reference
///
/// See [RFC 1929 Section 2](https://datatracker.ietf.org/doc/html/rfc1929#section-2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthResponse {
    /// Authentication result status.
    pub status: AuthStatus,
}

/// Client connection request.
///
/// This message is sent by the client after successful authentication
/// (or immediately after method selection if no authentication is required).
/// It specifies what operation the client wants to perform and the target address.
///
/// # Wire Format
///
/// ```text
/// +----+-----+-------+------+----------+----------+
/// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
/// +----+-----+-------+------+----------+----------+
/// | 1  |  1  | X'00' |  1   | Variable |    2     |
/// +----+-----+-------+------+----------+----------+
/// ```
///
/// - `VER` - Protocol version (must be 0x05)
/// - `CMD` - Command code ([`Command`])
/// - `RSV` - Reserved (must be 0x00)
/// - `ATYP` - Address type (part of [`Address`])
/// - `DST.ADDR` - Destination address (format depends on ATYP)
/// - `DST.PORT` - Destination port in network byte order
///
/// # RFC Reference
///
/// See [RFC 1928 Section 4](https://datatracker.ietf.org/doc/html/rfc1928#section-4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRequest {
    /// Requested command (CONNECT, BIND, or UDP ASSOCIATE).
    pub command: Command,
    /// Target address for the requested operation.
    pub dst_address: Address,
}

/// Server response to client request.
///
/// This message is sent by the server in response to a [`ClientRequest`].
/// It indicates whether the requested operation succeeded and provides
/// the bound address/port information.
///
/// # Wire Format
///
/// ```text
/// +----+-----+-------+------+----------+----------+
/// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
/// +----+-----+-------+------+----------+----------+
/// | 1  |  1  | X'00' |  1   | Variable |    2     |
/// +----+-----+-------+------+----------+----------+
/// ```
///
/// - `VER` - Protocol version (must be 0x05)
/// - `REP` - Reply code ([`Reply`]) indicating success or failure reason
/// - `RSV` - Reserved (must be 0x00)
/// - `ATYP` - Address type (part of [`Address`])
/// - `BND.ADDR` - Server bound address
/// - `BND.PORT` - Server bound port in network byte order
///
/// # Bound Address Semantics
///
/// The meaning of `BND.ADDR` and `BND.PORT` depends on the command:
///
/// - **CONNECT**: Server's outgoing connection address (often set to 0.0.0.0:0)
/// - **BIND**: Address/port where server is listening for incoming connections
/// - **UDP ASSOCIATE**: Address/port where server is listening for UDP packets
///
/// # RFC Reference
///
/// See [RFC 1928 Section 6](https://datatracker.ietf.org/doc/html/rfc1928#section-6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerResponse {
    /// Reply code indicating the status of the requested operation.
    pub reply: Reply,
    /// Server bound address.
    ///
    /// For CONNECT commands, this is often set to 0.0.0.0:0.
    /// For BIND and UDP ASSOCIATE, this contains the actual bound address.
    pub bnd_address: Address,
}
