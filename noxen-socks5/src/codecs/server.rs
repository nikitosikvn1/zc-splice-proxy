//! Tokio codec implementations for SOCKS5 protocol messages.
//!
//! This module provides [`Encoder`] and [`Decoder`] implementations for all SOCKS5
//! protocol messages using the [`tokio_util::codec`] framework. These codecs handle
//! the low-level details of parsing and serializing protocol frames.
//!
//! # Codecs
//!
//! - [`GreetingCodec`] - Encodes/decodes method selection messages
//! - [`AuthCodec`] - Encodes/decodes username/password authentication messages
//! - [`RequestResponseCodec`] - Encodes/decodes client requests and server responses
//!
//! # Error Handling
//!
//! All codecs return [`Socks5CodecError`] which wraps:
//! - [`ProtocolError`] - Protocol violations (invalid data format)
//! - [`io::Error`] - I/O errors during encoding/decoding
use std::net::{SocketAddrV4, SocketAddrV6};

use tokio_util::bytes::{Buf, BufMut, BytesMut};
use tokio_util::codec::{Encoder, Decoder};

use crate::hex;
use crate::error::ProtocolError;
use crate::types::{SOCKS5_VER, SOCKS5_AUTH_VER, SOCKS5_RSV, AuthMethod, AddressType, Command, Address};
use crate::messages::{
    MAX_GREETING_FRAME_SIZE, MAX_AUTH_FRAME_SIZE, MAX_REQUEST_FRAME_SIZE, ClientGreeting,
    ServerGreeting, AuthRequest, AuthResponse, ClientRequest, ServerResponse,
};
use crate::codecs::error::CodecError;

/// Codec for method selection negotiation phase.
///
/// This codec handles encoding and decoding of [`ClientGreeting`] and
/// [`ServerGreeting`] messages during the initial method selection phase
/// of the SOCKS5 handshake.
///
/// # Decoding
///
/// Decodes [`ClientGreeting`] from client → server.
/// - Validates protocol version (must be 0x05)
/// - Validates method count (must be > 0)
/// - Filters out unknown authentication methods with warnings
/// - Enforces maximum frame size for DoS protection
///
/// # Encoding
///
/// Encodes [`ServerGreeting`] from server → client.
/// - Writes protocol version (0x05)
/// - Writes selected authentication method
///
/// # Frame Format
///
/// ```text
/// Client: +----+----------+----------+
///         |VER | NMETHODS | METHODS  |
///         +----+----------+----------+
///         | 1  |    1     | 1 to 255 |
///         +----+----------+----------+
///
/// Server: +----+--------+
///         |VER | METHOD |
///         +----+--------+
///         | 1  |   1    |
///         +----+--------+
/// ```
pub struct GreetingCodec;

impl Decoder for GreetingCodec {
    type Item = ClientGreeting;
    type Error = CodecError;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // DoS protection: Reject frames that exceed maximum expected size
        if buf.len() > MAX_GREETING_FRAME_SIZE {
            tracing::error!(
                size = buf.len(),
                max = MAX_GREETING_FRAME_SIZE,
                "Frame exceeds maximum allowed size"
            );
            return Err(ProtocolError::FrameTooLarge.into());
        }

        // Need at least: VER (1) + NMETHODS (1)
        if buf.len() < 2 {
            // Incomplete frame: need more data
            return Ok(None);
        }

        // Peek VER
        let ver: u8 = buf[0];
        if ver != SOCKS5_VER {
            tracing::error!(ver = %hex!(ver), expected = %hex!(SOCKS5_VER), "Invalid SOCKS5 version");
            return Err(ProtocolError::InvalidVersion.into());
        }

        // Peek NMETHODS
        let nmethods: usize = buf[1] as usize;
        if nmethods == 0 {
            tracing::error!(nmethods = %hex!(0), "Client offered zero auth methods");
            return Err(ProtocolError::EmptyMethodsList.into());
        }

        // Total frame length: VER (1) + NMETHODS (1) + METHODS (nmethods)
        let total_len: usize = 2 + nmethods;

        // Check if we have received the complete frame
        if buf.len() < total_len {
            // Incomplete frame: need more data
            return Ok(None);
        }

        // Extract method bytes from offset 2 to (2 + nmethods)
        let method_bytes: &[u8] = &buf[2..total_len];

        // Parse methods, filtering out unknown values
        let methods: Vec<AuthMethod> = method_bytes
            .iter()
            .filter_map(|&b| {
                AuthMethod::try_from(b)
                    .inspect_err(
                        |_| tracing::warn!(method = %hex!(b), "Client offered unknown auth method"),
                    )
                    .ok()
            })
            .collect();

        // Consume the parsed bytes from the buffer only after successful decoding
        buf.advance(total_len);

        Ok(Some(ClientGreeting { methods }))
    }
}

impl Encoder<ServerGreeting> for GreetingCodec {
    type Error = CodecError;

    fn encode(&mut self, item: ServerGreeting, buf: &mut BytesMut) -> Result<(), Self::Error> {
        // Reserve exact space needed: VER (1) + METHOD (1)
        buf.reserve(2);
        // VER
        buf.put_u8(SOCKS5_VER);
        // METHOD
        buf.put_u8(item.method as u8);

        Ok(())
    }
}

/// Codec for username/password authentication phase.
///
/// This codec handles encoding and decoding of [`AuthRequest`] and
/// [`AuthResponse`] messages for RFC 1929 username/password authentication.
///
/// # Decoding
///
/// Decodes [`AuthRequest`] from client → server.
/// - Validates authentication subprotocol version (must be 0x01)
/// - Validates username and password lengths (must be > 0)
/// - Validates UTF-8 encoding of username and password
/// - Enforces maximum frame size for DoS protection
///
/// # Encoding
///
/// Encodes [`AuthResponse`] from server → client.
/// - Writes subprotocol version (0x01)
/// - Writes authentication status (0x00 = success, other = failure)
///
/// # Frame Format
///
/// ```text
/// Request:  +----+------+----------+------+----------+
///           |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
///           +----+------+----------+------+----------+
///           | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
///           +----+------+----------+------+----------+
///
/// Response: +----+--------+
///           |VER | STATUS |
///           +----+--------+
///           | 1  |   1    |
///           +----+--------+
/// ```
pub struct AuthCodec;

impl Decoder for AuthCodec {
    type Item = AuthRequest;
    type Error = CodecError;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // DoS protection: Reject frames that exceed maximum expected size
        if buf.len() > MAX_AUTH_FRAME_SIZE {
            tracing::error!(
                size = buf.len(),
                max = MAX_AUTH_FRAME_SIZE,
                "Frame exceeds maximum allowed size"
            );
            return Err(ProtocolError::FrameTooLarge.into());
        }

        // Need at least: VER (1) + ULEN (1)
        if buf.len() < 2 {
            // Incomplete frame: need more data
            return Ok(None);
        }

        // Peek VER
        let ver: u8 = buf[0];
        if ver != SOCKS5_AUTH_VER {
            tracing::error!(ver = %hex!(ver), expected = %hex!(SOCKS5_AUTH_VER), "Invalid SOCKS5 auth subprotocol version");
            return Err(ProtocolError::InvalidAuthVersion.into());
        }

        // Peek ULEN
        let ulen: usize = buf[1] as usize;
        if ulen == 0 {
            tracing::error!(ulen = %hex!(0), "Invalid username length");
            return Err(ProtocolError::EmptyUsername.into());
        }

        // PLEN offset: header (2 bytes) + UNAME (ulen bytes)
        let plen_offset: usize = 2 + ulen;

        // Need at least: VER (1) + ULEN (1) + UNAME (ulen) + PLEN (1)
        if buf.len() < plen_offset + 1 {
            // Incomplete frame: need more data
            return Ok(None);
        }

        // Peek PLEN
        let plen: usize = buf[plen_offset] as usize;
        if plen == 0 {
            tracing::error!(plen = %hex!(0), "Invalid password length");
            return Err(ProtocolError::EmptyPassword.into());
        }

        // Total frame length: VER (1) + ULEN (1) + UNAME (ulen) + PLEN (1) + PASSWD (plen)
        let total_len: usize = plen_offset + 1 + plen;

        // Check if we have received the complete frame
        if buf.len() < total_len {
            // Incomplete frame: need more data
            return Ok(None);
        }

        // Parse UTF-8 encoded fields
        let username: String = str::from_utf8(&buf[2..plen_offset])
            .inspect_err(|e| tracing::error!(error = ?e, "Invalid UTF-8 encoding in username"))
            .map_err(|_| ProtocolError::InvalidUsernameEncoding)?
            .to_string();

        let password: String = str::from_utf8(&buf[(plen_offset + 1)..total_len])
            .inspect_err(|e| tracing::error!(error = ?e, "Invalid UTF-8 encoding in password"))
            .map_err(|_| ProtocolError::InvalidPasswordEncoding)?
            .to_string();

        // Consume the parsed bytes from the buffer only after successful decoding
        buf.advance(total_len);

        Ok(Some(AuthRequest { username, password }))
    }
}

impl Encoder<AuthResponse> for AuthCodec {
    type Error = CodecError;

    fn encode(&mut self, item: AuthResponse, buf: &mut BytesMut) -> Result<(), Self::Error> {
        // Reserve exact space needed: VER (1) + STATUS (1)
        buf.reserve(2);
        // VER
        buf.put_u8(SOCKS5_AUTH_VER);
        // STATUS
        buf.put_u8(item.status as u8);

        Ok(())
    }
}

/// Codec for request/response phase.
///
/// This codec handles encoding and decoding of [`ClientRequest`] and
/// [`ServerResponse`] messages during the main request/response phase.
///
/// # Decoding
///
/// Decodes [`ClientRequest`] from client → server.
/// - Validates protocol version (must be 0x05)
/// - Validates command byte (CONNECT, BIND, or UDP ASSOCIATE)
/// - Validates reserved field (must be 0x00)
/// - Validates address type and parses address accordingly
/// - Validates UTF-8 encoding for domain names
/// - Enforces maximum frame size for DoS protection
///
/// # Encoding
///
/// Encodes [`ServerResponse`] from server → client.
/// - Writes protocol version (0x05)
/// - Writes reply code (success or error reason)
/// - Writes reserved field (0x00)
/// - Writes bound address and port
///
/// # Frame Format
///
/// ```text
/// Request:  +----+-----+-------+------+----------+----------+
///           |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
///           +----+-----+-------+------+----------+----------+
///           | 1  |  1  | X'00' |  1   | Variable |    2     |
///           +----+-----+-------+------+----------+----------+
///
/// Response: +----+-----+-------+------+----------+----------+
///           |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
///           +----+-----+-------+------+----------+----------+
///           | 1  |  1  | X'00' |  1   | Variable |    2     |
///           +----+-----+-------+------+----------+----------+
/// ```
///
/// Address field formats:
/// - IPv4: 4 bytes
/// - IPv6: 16 bytes
/// - Domain: 1 byte length + N bytes domain name
pub struct RequestResponseCodec;

impl Decoder for RequestResponseCodec {
    type Item = ClientRequest;
    type Error = CodecError;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // DoS protection: Reject frames that exceed maximum expected size
        if buf.len() > MAX_REQUEST_FRAME_SIZE {
            tracing::error!(
                size = buf.len(),
                max = MAX_REQUEST_FRAME_SIZE,
                "Frame exceeds maximum allowed size"
            );
            return Err(ProtocolError::FrameTooLarge.into());
        }

        // Need at least: VER (1) + CMD (1) + RSV (1) + ATYP (1)
        if buf.len() < 4 {
            // Incomplete frame: need more data
            return Ok(None);
        }

        // Peek VER
        let ver: u8 = buf[0];
        if ver != SOCKS5_VER {
            tracing::error!(ver = %hex!(ver), expected = %hex!(SOCKS5_VER), "Invalid SOCKS5 version");
            return Err(ProtocolError::InvalidVersion.into());
        }

        // Peek CMD
        let cmd: u8 = buf[1];
        let command = Command::try_from(cmd)
            .inspect_err(|_| tracing::error!(cmd = %hex!(cmd), "Invalid command"))?;

        // Peek RSV
        let rsv: u8 = buf[2];
        if rsv != SOCKS5_RSV {
            tracing::error!(rsv = %hex!(rsv), expected = %hex!(SOCKS5_RSV), "Invalid reserved field");
            return Err(ProtocolError::InvalidReserved.into());
        }

        // Peek ATYP
        let atyp: u8 = buf[3];
        let address_type = AddressType::try_from(atyp)
            .inspect_err(|_| tracing::error!(atyp = %hex!(atyp), "Invalid address type"))?;

        // Determine address field length based on type
        let address_len: usize = match address_type {
            // IPv4: 4 bytes (32-bit address)
            AddressType::Ipv4 => 4,
            // IPv6: 16 bytes (128-bit address)
            AddressType::Ipv6 => 16,
            // Domain: 1 byte length + N bytes domain name
            // TODO: validate domain length (DLEN > 0)
            AddressType::Domain => {
                // Need at least 5 bytes to read domain length: VER + CMD + RSV + ATYP + DLEN
                if buf.len() < 5 {
                    // Incomplete frame: need more data
                    return Ok(None);
                }
                // DLEN (1) + domain bytes
                1 + buf[4] as usize
            }
        };

        // Total frame length: VER (1) + CMD (1) + RSV (1) + ATYP (1) + ADDRESS (address_len) + PORT (2)
        let total_len: usize = 4 + address_len + 2;

        // Check if we have received the complete frame
        if buf.len() < total_len {
            // Incomplete frame: need more data
            return Ok(None);
        }

        // Extract address data: Offset 4..(4+address_len)
        let address_data: &[u8] = &buf[4..4 + address_len];

        // SAFETY: total_len calculation guarantees exactly 2 bytes for port
        let port_bytes: [u8; 2] = buf[4 + address_len..total_len]
            .try_into()
            .expect("port slice must be exactly 2 bytes");
        let port = u16::from_be_bytes(port_bytes);

        // Parse address based on type
        let dst_address: Address = match address_type {
            AddressType::Ipv4 => {
                // SAFETY: address_len is 4 for IPv4
                let ip_bytes: [u8; 4] = address_data[..4]
                    .try_into()
                    .expect("ipv4 address slice must be exactly 4 bytes");
                Address::Ipv4(SocketAddrV4::new(ip_bytes.into(), port))
            }
            AddressType::Ipv6 => {
                // SAFETY: address_len is 16 for IPv6
                let ip_bytes: [u8; 16] = address_data[..16]
                    .try_into()
                    .expect("ipv6 address slice must be exactly 16 bytes");
                Address::Ipv6(SocketAddrV6::new(ip_bytes.into(), port, 0, 0))
            }
            AddressType::Domain => {
                let dlen: usize = address_data[0] as usize;
                let domain: &[u8] = &address_data[1..1 + dlen];
                let domain: String = str::from_utf8(domain)
                    .inspect_err(
                        |e| tracing::error!(error = ?e, "Invalid UTF-8 encoding in domain"),
                    )
                    .map_err(|_| ProtocolError::InvalidDomainEncoding)?
                    .to_string();
                Address::Domain(domain, port)
            }
        };

        // Consume the parsed bytes from the buffer only after successful decoding
        buf.advance(total_len);

        Ok(Some(ClientRequest {
            command,
            dst_address,
        }))
    }
}

impl Encoder<ServerResponse> for RequestResponseCodec {
    type Error = CodecError;

    fn encode(&mut self, item: ServerResponse, buf: &mut BytesMut) -> Result<(), Self::Error> {
        // Calculate exact size needed to avoid reallocation
        let addr_size: usize = match &item.bnd_address {
            Address::Ipv4(_) => 4,
            Address::Ipv6(_) => 16,
            Address::Domain(domain, _) => 1 + domain.len(),
        };
        // VER (1) + REP (1) + RSV (1) + ATYP (1) + BND.ADDR + BND.PORT (2)
        buf.reserve(6 + addr_size);

        // VER
        buf.put_u8(SOCKS5_VER);
        // REP
        buf.put_u8(item.reply as u8);
        // RSV
        buf.put_u8(SOCKS5_RSV);
        // ATYP
        buf.put_u8(item.bnd_address.atyp() as u8);
        // BND.ADDR
        // Encode address based on type
        match &item.bnd_address {
            Address::Ipv4(addr) => {
                buf.put_slice(&addr.ip().octets());
            }
            Address::Ipv6(addr) => {
                buf.put_slice(&addr.ip().octets());
            }
            Address::Domain(domain, _) => {
                let bytes: &[u8] = domain.as_bytes();
                buf.put_u8(bytes.len() as u8); // DLEN prefix
                buf.put_slice(bytes);
            }
        }
        // BND.PORT
        buf.put_u16(item.bnd_address.port());

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    use crate::types::{AuthStatus, Reply};

    // GreetingCodec decoder tests
    #[test]
    fn test_decoder_greeting_success() {
        // Given
        let message: &[u8] = &[
            0x05, // VER (SOCKS5)
            0x02, // NMETHODS (2)
            0x01, // METHOD (GSSAPI)
            0x02, // METHOD (USERNAME_PASSWORD)
        ];
        let mut buf = BytesMut::new();
        buf.extend_from_slice(message);

        // When
        let greeting: ClientGreeting = GreetingCodec
            .decode(&mut buf)
            .expect("Decoder failed")
            .expect("Incomplete frame");

        // Then
        assert!(buf.is_empty());
        assert_eq!(greeting.methods.len(), 2);
        assert!(greeting.methods.contains(&AuthMethod::Gssapi));
        assert!(greeting.methods.contains(&AuthMethod::UsernamePassword));
    }

    #[test]
    fn test_decoder_greeting_preserves_extra_data() {
        // Given
        let message: &[u8] = &[
            0x05, // VER (SOCKS5)
            0x01, // NMETHODS (1)
            0x02, // METHOD (USERNAME_PASSWORD)
            0x05, 0x10, // extra data
        ];
        let mut buf = BytesMut::new();
        buf.extend_from_slice(message);

        // When
        let greeting: ClientGreeting = GreetingCodec
            .decode(&mut buf)
            .expect("Decoder failed")
            .expect("Incomplete frame");

        // Then
        assert_eq!(&buf[..], &[0x05, 0x10]);
        assert_eq!(greeting.methods.len(), 1);
        assert!(greeting.methods.contains(&AuthMethod::UsernamePassword));
    }

    #[test]
    fn test_decoder_greeting_incomplete_header() {
        // Given
        let message: &[u8] = &[
            0x05, // VER (SOCKS5)
        ];
        let mut buf = BytesMut::new();
        buf.extend_from_slice(message);

        // When
        let greeting: Option<ClientGreeting> =
            GreetingCodec.decode(&mut buf).expect("Decoder failed");

        // Then
        assert_eq!(&buf[..], message);
        assert!(greeting.is_none());
    }

    #[test]
    fn test_decoder_greeting_incomplete_methods() {
        // Given
        let message: &[u8] = &[
            0x05, // VER (SOCKS5)
            0x02, // NMETHODS (2)
            0x01, // METHOD (GSSAPI - only 1 byte)
        ];
        let mut buf = BytesMut::new();
        buf.extend_from_slice(message);

        // When
        let greeting: Option<ClientGreeting> =
            GreetingCodec.decode(&mut buf).expect("Decoder failed");

        // Then
        assert_eq!(&buf[..], message);
        assert!(greeting.is_none());
    }

    #[test]
    fn test_decoder_greeting_buffer_overflow() {
        // Given
        let message: &[u8] = &[
            0x05, // VER (SOCKS5)
            0xFF, // NMETHODS (255)
        ];
        let mut buf = BytesMut::new();
        buf.extend_from_slice(message);
        buf.extend_from_slice(&[0x00; 256]); // METHOD (256 times "NO_AUTHENTICATION_REQUIRED" - overflow)

        // When
        let greeting: Result<Option<ClientGreeting>, CodecError> = GreetingCodec.decode(&mut buf);

        // Then
        assert!(buf.len() > MAX_GREETING_FRAME_SIZE);
        assert!(
            greeting
                .is_err_and(|e| matches!(e, CodecError::Protocol(ProtocolError::FrameTooLarge)))
        )
    }

    #[test]
    fn test_decoder_greeting_invalid_version() {
        // Given
        let message: &[u8] = &[
            0x04, // VER (invalid)
            0x01, // NMETHODS (1)
            0x02, // METHOD (USERNAME_PASSWORD)
        ];
        let mut buf = BytesMut::new();
        buf.extend_from_slice(message);

        // When
        let greeting: Result<Option<ClientGreeting>, CodecError> = GreetingCodec.decode(&mut buf);

        // Then
        assert_eq!(&buf[..], message);
        assert!(
            greeting
                .is_err_and(|e| matches!(e, CodecError::Protocol(ProtocolError::InvalidVersion)))
        )
    }

    #[test]
    fn test_decoder_greeting_empty_methods_list() {
        // Given
        let message: &[u8] = &[
            0x05, // VER (SOCKS5)
            0x00, // NMETHODS (0)
        ];
        let mut buf = BytesMut::new();
        buf.extend_from_slice(message);

        // When
        let greeting: Result<Option<ClientGreeting>, CodecError> = GreetingCodec.decode(&mut buf);

        // Then
        assert_eq!(&buf[..], message);
        assert!(
            greeting
                .is_err_and(|e| matches!(e, CodecError::Protocol(ProtocolError::EmptyMethodsList)))
        )
    }

    #[test]
    fn test_decoder_greeting_filters_unknown_methods() {
        // Given
        let message: &[u8] = &[
            0x05, // VER (SOCKS5)
            0x04, // NMETHODS (4)
            0x02, // METHOD (USERNAME_PASSWORD)
            0x10, // METHOD (invalid)
            0x2D, // METHOD (invalid)
            0x01, // METHOD (GSSAPI)
        ];
        let mut buf = BytesMut::new();
        buf.extend_from_slice(message);

        // When
        let greeting: ClientGreeting = GreetingCodec
            .decode(&mut buf)
            .expect("Decoder failed")
            .expect("Incomplete frame");

        // Then
        assert!(buf.is_empty());
        assert_eq!(greeting.methods.len(), 2);
        assert!(greeting.methods.contains(&AuthMethod::UsernamePassword));
        assert!(greeting.methods.contains(&AuthMethod::Gssapi));
    }

    #[test]
    fn test_decoder_greeting_all_methods_unknown() {
        // Given
        let message: &[u8] = &[
            0x05, // VER (SOCKS5)
            0x02, // NMETHODS (2)
            0x10, // METHOD (invalid)
            0x2D, // METHOD (invalid)
        ];
        let mut buf = BytesMut::new();
        buf.extend_from_slice(message);

        // When
        let greeting = GreetingCodec
            .decode(&mut buf)
            .expect("Decoder failed")
            .expect("Incomplete frame");

        // Then
        assert!(buf.is_empty());
        assert!(greeting.methods.is_empty());
    }

    // GreetingCodec encoder tests
    #[test]
    fn test_encoder_greeting_username_password() {
        // Given
        let greeting = ServerGreeting {
            method: AuthMethod::UsernamePassword,
        };
        let mut buf = BytesMut::new();
        let message: &[u8] = &[
            0x05, // VER (SOCKS5)
            0x02, // METHOD (USERNAME_PASSWORD)
        ];

        // When
        GreetingCodec
            .encode(greeting, &mut buf)
            .expect("Encoder failed");

        // Then
        assert_eq!(&buf[..], message);
    }

    #[test]
    fn test_encoder_greeting_no_acceptable() {
        // Given
        let greeting = ServerGreeting {
            method: AuthMethod::NoAcceptableMethods,
        };
        let mut buf = BytesMut::new();
        let message: &[u8] = &[
            0x05, // VER (SOCKS5)
            0xFF, // METHOD (NO_ACCEPTABLE_METHODS)
        ];

        // When
        GreetingCodec
            .encode(greeting, &mut buf)
            .expect("Encoder failed");

        // Then
        assert_eq!(&buf[..], message);
    }

    // AuthCodec decoder tests
    #[test]
    fn test_decoder_auth_success() {
        // Given
        let message: &[u8] = &[
            0x01, // VER (SOCKS5 auth subprotocol)
            0x05, // ULEN (5)
            b'u', b'n', b'a', b'm', b'e', // UNAME
            0x06, // PLEN (6)
            b'p', b'a', b's', b's', b'w', b'd', // PASSWD
        ];
        let mut buf = BytesMut::new();
        buf.extend_from_slice(message);

        // When
        let auth: AuthRequest = AuthCodec
            .decode(&mut buf)
            .expect("Decoder failed")
            .expect("Incomplete frame");

        // Then
        assert!(buf.is_empty());
        assert_eq!(auth.username, "uname");
        assert_eq!(auth.password, "passwd");
    }

    #[test]
    fn test_decoder_auth_preserves_extra_data() {
        // Given
        let message: &[u8] = &[
            0x01, // VER (SOCKS5 auth subprotocol)
            0x05, // ULEN (5)
            b'u', b'n', b'a', b'm', b'e', // UNAME
            0x06, // PLEN (6)
            b'p', b'a', b's', b's', b'w', b'd', // PASSWD
            0x01, 0x02, 0x03, // extra data
        ];
        let mut buf = BytesMut::new();
        buf.extend_from_slice(message);

        // When
        let auth: AuthRequest = AuthCodec
            .decode(&mut buf)
            .expect("Decoder failed")
            .expect("Incomplete frame");

        // Then
        assert_eq!(&buf[..], &[0x01, 0x02, 0x03]);
        assert_eq!(auth.username, "uname");
        assert_eq!(auth.password, "passwd");
    }

    #[test]
    fn test_decoder_auth_incomplete_header() {
        // Given
        let message: &[u8] = &[
            0x01, // VER (SOCKS5 auth subprotocol)
        ];
        let mut buf = BytesMut::new();
        buf.extend_from_slice(message);

        // When
        let auth: Option<AuthRequest> = AuthCodec.decode(&mut buf).expect("Decoder failed");

        // Then
        assert_eq!(&buf[..], message);
        assert!(auth.is_none());
    }

    #[test]
    fn test_decoder_auth_incomplete_username() {
        // Given
        let message: &[u8] = &[
            0x01, // VER (SOCKS5 auth subprotocol)
            0x06, // ULEN (6)
            b'u', b'n', b'a', b'm', b'e', // UNAME (only 5 bytes)
        ];
        let mut buf = BytesMut::new();
        buf.extend_from_slice(message);

        // When
        let auth: Option<AuthRequest> = AuthCodec.decode(&mut buf).expect("Decoder failed");

        // Then
        assert_eq!(&buf[..], message);
        assert!(auth.is_none());
    }

    #[test]
    fn test_decoder_auth_incomplete_password_length() {
        // Given
        let message: &[u8] = &[
            0x01, // VER (SOCKS5 auth subprotocol)
            0x05, // ULEN (5)
            b'u', b'n', b'a', b'm', b'e', // UNAME
        ];
        let mut buf = BytesMut::new();
        buf.extend_from_slice(message);

        // When
        let auth: Option<AuthRequest> = AuthCodec.decode(&mut buf).expect("Decoder failed");

        // Then
        assert_eq!(&buf[..], message);
        assert!(auth.is_none());
    }

    #[test]
    fn test_decoder_auth_incomplete_password() {
        // Given
        let message: &[u8] = &[
            0x01, // VER (SOCKS5 auth subprotocol)
            0x05, // ULEN (5)
            b'u', b'n', b'a', b'm', b'e', // UNAME
            0x07, // PLEN (7)
            b'p', b'a', b's', b's', b'w', b'd', // PASSWD (only 6 bytes)
        ];
        let mut buf = BytesMut::new();
        buf.extend_from_slice(message);

        // When
        let auth: Option<AuthRequest> = AuthCodec.decode(&mut buf).expect("Decoder failed");

        // Then
        assert_eq!(&buf[..], message);
        assert!(auth.is_none());
    }

    #[test]
    fn test_decoder_auth_buffer_overflow() {
        // Given
        let message: &[u8] = &[
            0x01, // VER (SOCKS5 auth subprotocol)
            0xFF, // ULEN (255)
        ];
        let mut buf = BytesMut::new();
        buf.extend_from_slice(message);
        buf.extend_from_slice(&[b'a'; 255]); // UNAME (255 times 'a')
        buf.put_u8(0xFF); // PLEN (255)
        buf.extend_from_slice(&[b'b'; 256]); // PASSWD (256 times 'b' - overflow)

        // When
        let auth: Result<Option<AuthRequest>, CodecError> = AuthCodec.decode(&mut buf);

        // Then
        assert!(buf.len() > MAX_AUTH_FRAME_SIZE);
        assert!(
            auth.is_err_and(|e| matches!(e, CodecError::Protocol(ProtocolError::FrameTooLarge)))
        )
    }

    #[test]
    fn test_decoder_auth_invalid_version() {
        // Given
        let message: &[u8] = &[
            0x02, // VER (invalid)
            0x05, // ULEN (5)
            b'u', b'n', b'a', b'm', b'e', // UNAME
            0x06, // PLEN (6)
            b'p', b'a', b's', b's', b'w', b'd', // PASSWD
        ];
        let mut buf = BytesMut::new();
        buf.extend_from_slice(message);

        // When
        let auth: Result<Option<AuthRequest>, CodecError> = AuthCodec.decode(&mut buf);

        // Then
        assert_eq!(&buf[..], message);
        assert!(
            auth.is_err_and(|e| matches!(
                e,
                CodecError::Protocol(ProtocolError::InvalidAuthVersion)
            ))
        )
    }

    #[test]
    fn test_decoder_auth_invalid_username_encoding_utf8() {
        // Given
        let message: &[u8] = &[
            0x01, // VER (SOCKS5 auth subprotocol)
            0x03, // ULEN (3)
            0x75, 0x73, 0xC3, // UNAME (not a valid UTF-8 sequence)
            0x06, // PLEN (6)
            b'p', b'a', b's', b's', b'w', b'd', // PASSWD
        ];
        let mut buf = BytesMut::new();
        buf.extend_from_slice(message);

        // When
        let auth: Result<Option<AuthRequest>, CodecError> = AuthCodec.decode(&mut buf);

        // Then
        assert_eq!(&buf[..], message);
        assert!(auth.is_err_and(|e| matches!(
            e,
            CodecError::Protocol(ProtocolError::InvalidUsernameEncoding)
        )))
    }

    #[test]
    fn test_decoder_auth_invalid_password_encoding_utf8() {
        // Given
        let message: &[u8] = &[
            0x01, // VER (SOCKS5 auth subprotocol)
            0x05, // ULEN (5)
            b'u', b'n', b'a', b'm', b'e', // UNAME
            0x03, // PLEN (3)
            0x70, 0x77, 0xE2, // PASSWD (not a valid UTF-8 sequence)
        ];
        let mut buf = BytesMut::new();
        buf.extend_from_slice(message);

        // When
        let auth: Result<Option<AuthRequest>, CodecError> = AuthCodec.decode(&mut buf);

        // Then
        assert_eq!(&buf[..], message);
        assert!(auth.is_err_and(|e| matches!(
            e,
            CodecError::Protocol(ProtocolError::InvalidPasswordEncoding)
        )))
    }

    #[test]
    fn test_decoder_auth_empty_username() {
        // Given
        let message: &[u8] = &[
            0x01, // VER (SOCKS5 auth subprotocol)
            0x00, // ULEN (0)
            b'u', b'n', b'a', b'm', b'e', // UNAME
            0x06, // PLEN (6)
            b'p', b'a', b's', b's', b'w', b'd', // PASSWD
        ];
        let mut buf = BytesMut::new();
        buf.extend_from_slice(message);

        // When
        let auth: Result<Option<AuthRequest>, CodecError> = AuthCodec.decode(&mut buf);

        // Then
        assert_eq!(&buf[..], message);
        assert!(
            auth.is_err_and(|e| matches!(e, CodecError::Protocol(ProtocolError::EmptyUsername)))
        )
    }

    #[test]
    fn test_decoder_auth_empty_password() {
        // Given
        let message: &[u8] = &[
            0x01, // VER (SOCKS5 auth subprotocol)
            0x05, // ULEN (5)
            b'u', b'n', b'a', b'm', b'e', // UNAME
            0x00, // PLEN (0)
            b'p', b'a', b's', b's', b'w', b'd', // PASSWD
        ];
        let mut buf = BytesMut::new();
        buf.extend_from_slice(message);

        // When
        let auth: Result<Option<AuthRequest>, CodecError> = AuthCodec.decode(&mut buf);

        // Then
        assert_eq!(&buf[..], message);
        assert!(
            auth.is_err_and(|e| matches!(e, CodecError::Protocol(ProtocolError::EmptyPassword)))
        )
    }

    #[test]
    fn test_decoder_auth_max_lengths() {
        // Given
        let message: &[u8] = &[
            0x01, // VER (SOCKS5 auth subprotocol)
            0xFF, // ULEN (255)
        ];
        let mut buf = BytesMut::new();
        buf.extend_from_slice(message);
        buf.extend_from_slice(&[b'a'; 255]); // UNAME (255 times 'a')
        buf.put_u8(0xFF); // PLEN (255)
        buf.extend_from_slice(&[b'b'; 255]); // PASSWD (255 times 'b')

        // When
        let auth: AuthRequest = AuthCodec
            .decode(&mut buf)
            .expect("Decoder failed")
            .expect("Incomplete frame");

        // Then
        assert!(buf.is_empty());
        assert_eq!(auth.username.len(), 255);
        assert_eq!(auth.password.len(), 255);
    }

    // AuthCodec encoder tests
    #[test]
    fn test_encoder_auth_success() {
        // Given
        let auth = AuthResponse {
            status: AuthStatus::Success,
        };
        let mut buf = BytesMut::new();
        let message: &[u8] = &[
            0x01, // VER (SOCKS5 auth subprotocol)
            0x00, // STATUS (SUCCESS)
        ];

        // When
        AuthCodec.encode(auth, &mut buf).expect("Encoder failed");

        // Then
        assert_eq!(&buf[..], message);
    }

    #[test]
    fn test_encoder_auth_failure() {
        // Given
        let auth = AuthResponse {
            status: AuthStatus::Failure,
        };
        let mut buf = BytesMut::new();
        let message: &[u8] = &[
            0x01, // VER (SOCKS5 auth subprotocol)
            0x01, // STATUS (FAILURE)
        ];

        // When
        AuthCodec.encode(auth, &mut buf).expect("Encoder failed");

        // Then
        assert_eq!(&buf[..], message);
    }

    // RequestResponseCodec decoder tests
    #[test]
    fn test_decoder_request_ipv4_connect() {
        // Given
        let message: &[u8] = &[
            0x05, // VER (SOCKS5)
            0x01, // CMD (CONNECT)
            0x00, // RSV
            0x01, // ATYP (IPv4)
            127, 0, 0, 1, // DST.ADDR (127.0.0.1)
            0x1F, 0x90, // DST.PORT (8080)
        ];
        let mut buf = BytesMut::new();
        buf.extend_from_slice(message);

        // When
        let request: ClientRequest = RequestResponseCodec
            .decode(&mut buf)
            .expect("Decoder failed")
            .expect("Incomplete frame");

        // Then
        assert!(buf.is_empty());
        assert_eq!(request.command, Command::Connect);
        assert_eq!(request.dst_address.atyp(), AddressType::Ipv4);
        assert_eq!(request.dst_address.addr(), Ipv4Addr::LOCALHOST.octets());
        assert_eq!(request.dst_address.port(), 8080);
    }

    #[test]
    fn test_decoder_request_ipv6_bind() {
        // Given
        let message: &[u8] = &[
            0x05, // VER (SOCKS5)
            0x02, // CMD (BIND)
            0x00, // RSV
            0x04, // ATYP (IPv6)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, // DST.ADDR ([::1])
            0xFF, 0xFF, // DST.PORT (65535)
        ];
        let mut buf = BytesMut::new();
        buf.extend_from_slice(message);

        // When
        let request: ClientRequest = RequestResponseCodec
            .decode(&mut buf)
            .expect("Decoder failed")
            .expect("Incomplete frame");

        // Then
        assert!(buf.is_empty());
        assert_eq!(request.command, Command::Bind);
        assert_eq!(request.dst_address.atyp(), AddressType::Ipv6);
        assert_eq!(request.dst_address.addr(), Ipv6Addr::LOCALHOST.octets());
        assert_eq!(request.dst_address.port(), 65535);
    }

    #[test]
    fn test_decoder_request_domain_udp_associate() {
        // Given
        let message: &[u8] = &[
            0x05, // VER (SOCKS5)
            0x03, // CMD (UDP_ASSOCIATE)
            0x00, // RSV
            0x03, // ATYP (DOMAIN)
            0x0A, // DLEN (10)
            b'g', b'o', b'o', b'g', b'l', b'e', b'.', b'c', b'o',
            b'm', // DST.ADDR ("google.com")
            0x01, 0xBB, // DST.PORT (443)
        ];
        let mut buf = BytesMut::new();
        buf.extend_from_slice(message);

        // When
        let request: ClientRequest = RequestResponseCodec
            .decode(&mut buf)
            .expect("Decoder failed")
            .expect("Incomplete frame");

        // Then
        assert!(buf.is_empty());
        assert_eq!(request.command, Command::UdpAssociate);
        assert_eq!(request.dst_address.atyp(), AddressType::Domain);
        assert_eq!(request.dst_address.addr(), b"google.com");
        assert_eq!(request.dst_address.port(), 443);
    }

    #[test]
    fn test_decoder_request_preserves_extra_data() {
        // Given
        let message: &[u8] = &[
            0x05, // VER (SOCKS5)
            0x01, // CMD (CONNECT)
            0x00, // RSV
            0x01, // ATYP (IPv4)
            127, 0, 0, 1, // DST.ADDR (127.0.0.1)
            0x1F, 0x90, // DST.PORT (8080)
            0x00, 0x01, 0x02, // extra data
        ];
        let mut buf = BytesMut::new();
        buf.extend_from_slice(message);

        // When
        let request: ClientRequest = RequestResponseCodec
            .decode(&mut buf)
            .expect("Decoder failed")
            .expect("Incomplete frame");

        // Then
        assert_eq!(&buf[..], &[0x00, 0x01, 0x02]);
        assert_eq!(request.command, Command::Connect);
        assert_eq!(request.dst_address.atyp(), AddressType::Ipv4);
        assert_eq!(request.dst_address.addr(), Ipv4Addr::LOCALHOST.octets());
        assert_eq!(request.dst_address.port(), 8080);
    }

    #[test]
    fn test_decoder_request_incomplete_domain_length() {
        // Given
        let message: &[u8] = &[
            0x05, // VER (SOCKS5)
            0x03, // CMD (UDP_ASSOCIATE)
            0x00, // RSV
            0x03, // ATYP (DOMAIN)
        ];
        let mut buf = BytesMut::new();
        buf.extend_from_slice(message);

        // When
        let request: Option<ClientRequest> = RequestResponseCodec
            .decode(&mut buf)
            .expect("Decoder failed");

        // Then
        assert_eq!(&buf[..], message);
        assert!(request.is_none());
    }

    #[test]
    fn test_decoder_request_incomplete_domain() {
        // Given
        let message: &[u8] = &[
            0x05, // VER (SOCKS5)
            0x03, // CMD (UDP_ASSOCIATE)
            0x00, // RSV
            0x03, // ATYP (DOMAIN)
            0x0A, // DLEN (10)
            0x67, 0x6F, 0x6F, 0x67, 0x6C, 0x65, 0x2E, 0x63, 0x6F, // DST.ADDR ("google.co")
        ];
        let mut buf = BytesMut::new();
        buf.extend_from_slice(message);

        // When
        let request: Option<ClientRequest> = RequestResponseCodec
            .decode(&mut buf)
            .expect("Decoder failed");

        // Then
        assert_eq!(&buf[..], message);
        assert!(request.is_none());
    }

    #[test]
    fn test_decoder_request_incomplete_port() {
        // Given
        let message: &[u8] = &[
            0x05, // VER (SOCKS5)
            0x01, // CMD (CONNECT)
            0x00, // RSV
            0x01, // ATYP (IPv4)
            127, 0, 0, 1,    // DST.ADDR (127.0.0.1)
            0xFA, // DST.PORT (250)
        ];
        let mut buf = BytesMut::new();
        buf.extend_from_slice(message);

        // When
        let request: Option<ClientRequest> = RequestResponseCodec
            .decode(&mut buf)
            .expect("Decoder failed");

        // Then
        assert_eq!(&buf[..], message);
        assert!(request.is_none());
    }

    #[test]
    fn test_decoder_request_buffer_overflow() {
        // Given
        let message: &[u8] = &[
            0x05, // VER (SOCKS5)
            0x01, // CMD (CONNECT)
            0x00, // RSV
            0x03, // ATYP (DOMAIN)
            0xFF, // DLEN
        ];
        let mut buf = BytesMut::new();
        buf.extend_from_slice(message);
        buf.extend_from_slice(&[0x00; 258]); // DST.ADDR + DST.PORT (258 bytes - overflow)

        // When
        let request: Result<Option<ClientRequest>, CodecError> =
            RequestResponseCodec.decode(&mut buf);

        // Then
        assert!(buf.len() > MAX_REQUEST_FRAME_SIZE);
        assert!(
            request.is_err_and(|e| matches!(e, CodecError::Protocol(ProtocolError::FrameTooLarge)))
        )
    }

    #[test]
    fn test_decoder_request_invalid_version() {
        // Given
        let message: &[u8] = &[
            0x01, // VER (invalid)
            0x01, // CMD (CONNECT)
            0x00, // RSV
            0x01, // ATYP (IPv4)
            127, 0, 0, 1, // DST.ADDR (127.0.0.1)
            0x1F, 0x90, // DST.PORT (8080)
        ];
        let mut buf = BytesMut::new();
        buf.extend_from_slice(message);

        // When
        let request: Result<Option<ClientRequest>, CodecError> =
            RequestResponseCodec.decode(&mut buf);

        // Then
        assert_eq!(&buf[..], message);
        assert!(
            request
                .is_err_and(|e| matches!(e, CodecError::Protocol(ProtocolError::InvalidVersion)))
        )
    }

    #[test]
    fn test_decoder_request_invalid_reserved() {
        // Given
        let message: &[u8] = &[
            0x05, // VER (SOCKS5)
            0x01, // CMD (CONNECT)
            0x01, // RSV (invalid)
            0x01, // ATYP (IPv4)
            127, 0, 0, 1, // DST.ADDR (127.0.0.1)
            0x1F, 0x90, // DST.PORT (8080)
        ];
        let mut buf = BytesMut::new();
        buf.extend_from_slice(message);

        // When
        let request: Result<Option<ClientRequest>, CodecError> =
            RequestResponseCodec.decode(&mut buf);

        // Then
        assert_eq!(&buf[..], message);
        assert!(
            request
                .is_err_and(|e| matches!(e, CodecError::Protocol(ProtocolError::InvalidReserved)))
        )
    }

    #[test]
    fn test_decoder_request_invalid_command() {
        // Given
        let message: &[u8] = &[
            0x05, // VER (SOCKS5)
            0x0A, // CMD (invalid)
            0x00, // RSV
            0x01, // ATYP (IPv4)
            127, 0, 0, 1, // DST.ADDR (127.0.0.1)
            0x1F, 0x90, // DST.PORT (8080)
        ];
        let mut buf = BytesMut::new();
        buf.extend_from_slice(message);

        // When
        let request: Result<Option<ClientRequest>, CodecError> =
            RequestResponseCodec.decode(&mut buf);

        // Then
        assert_eq!(&buf[..], message);
        assert!(
            request
                .is_err_and(|e| matches!(e, CodecError::Protocol(ProtocolError::InvalidCommand)))
        )
    }

    #[test]
    fn test_decoder_request_invalid_address_type() {
        // Given
        let message: &[u8] = &[
            0x05, // VER (SOCKS5)
            0x01, // CMD (CONNECT)
            0x00, // RSV
            0x05, // ATYP (invalid)
            127, 0, 0, 1, // DST.ADDR (127.0.0.1)
            0x1F, 0x90, // DST.PORT (8080)
        ];
        let mut buf = BytesMut::new();
        buf.extend_from_slice(message);

        // When
        let request: Result<Option<ClientRequest>, CodecError> =
            RequestResponseCodec.decode(&mut buf);

        // Then
        assert_eq!(&buf[..], message);
        assert!(
            request.is_err_and(|e| matches!(
                e,
                CodecError::Protocol(ProtocolError::InvalidAddressType)
            ))
        )
    }

    #[test]
    fn test_decoder_request_invalid_domain_encoding_utf8() {
        // Given
        let message: &[u8] = &[
            0x05, // VER (SOCKS5)
            0x01, // CMD (CONNECT)
            0x00, // RSV
            0x03, // ATYP (DOMAIN)
            0x07, // DLEN
            0x66, 0x6F, 0x80, 0x80, 0x67, 0x6C, 0x65, // DST.ADDR (not a valid utf-8 sequence)
            0x1F, 0x90, // DST.PORT (8080)
        ];
        let mut buf = BytesMut::new();
        buf.extend_from_slice(message);

        // When
        let request: Result<Option<ClientRequest>, CodecError> =
            RequestResponseCodec.decode(&mut buf);

        // Then
        assert_eq!(&buf[..], message);
        assert!(request.is_err_and(|e| matches!(
            e,
            CodecError::Protocol(ProtocolError::InvalidDomainEncoding)
        )))
    }

    #[test]
    fn test_decoder_request_domain_max_length() {
        // Given
        let message: &[u8] = &[
            0x05, // VER (SOCKS5)
            0x01, // CMD (CONNECT)
            0x00, // RSV
            0x03, // ATYP (DOMAIN)
            0xFF, // DLEN (255)
        ];
        let mut buf = BytesMut::new();
        buf.extend_from_slice(message);
        buf.extend_from_slice(&[b'a'; 255]); // DST.ADDR (255 times 'a')
        buf.extend_from_slice(&[0x1F, 0x90]); // DST.PORT (8080)

        // When
        let request: ClientRequest = RequestResponseCodec
            .decode(&mut buf)
            .expect("Decoder failed")
            .expect("Incomplete frame");

        // Then
        assert!(buf.is_empty());
        assert_eq!(request.dst_address.addr(), "a".repeat(255).as_bytes());
        assert_eq!(request.dst_address.port(), 8080);
    }

    // RequestResponseCodec encoder tests
    #[test]
    fn test_encoder_response_ipv4_succeeded() {
        // Given
        let response = ServerResponse {
            reply: Reply::Succeeded,
            bnd_address: Address::Ipv4("10.0.0.1:8080".parse().unwrap()),
        };
        let mut buf = BytesMut::new();
        let message: &[u8] = &[
            0x05, // VER (SOCKS5)
            0x00, // REP (SUCCEEDED)
            0x00, // RSV
            0x01, // ATYP (IPv4)
            0x0A, 0x00, 0x00, 0x01, // BND.ADDR (10.0.0.1)
            0x1F, 0x90, // BND.PORT (8080)
        ];

        // When
        RequestResponseCodec
            .encode(response, &mut buf)
            .expect("Encoder failed");

        // Then
        assert_eq!(&buf[..], message);
    }

    #[test]
    fn test_encoder_response_ipv6_connection_not_allowed() {
        // Given
        let response = ServerResponse {
            reply: Reply::ConnectionNotAllowed,
            bnd_address: Address::Ipv6("[::1]:8080".parse().unwrap()),
        };
        let mut buf = BytesMut::new();
        let message: &[u8] = &[
            0x05, // VER (SOCKS5)
            0x02, // REP (CONNECTION_NOT_ALLOWED)
            0x00, // RSV
            0x04, // ATYP (IPv6)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, // BND.ADDR ([::1])
            0x1F, 0x90, // BND.PORT (8080)
        ];

        // When
        RequestResponseCodec
            .encode(response, &mut buf)
            .expect("Encoder failed");

        // Then
        assert_eq!(&buf[..], message);
    }

    #[test]
    fn test_encoder_response_domain_general_failure() {
        // Given
        let response = ServerResponse {
            reply: Reply::GeneralFailure,
            bnd_address: Address::Domain("google.com".into(), 443),
        };
        let mut buf = BytesMut::new();
        let message: &[u8] = &[
            0x05, // VER (SOCKS5)
            0x01, // REP (GENERAL_FAILURE)
            0x00, // RSV
            0x03, // ATYP (DOMAIN)
            0x0A, // DLEN (10)
            0x67, 0x6F, 0x6F, 0x67, 0x6C, 0x65, 0x2E, 0x63, 0x6F,
            0x6D, // DOMAIN ("google.com")
            0x01, 0xBB, // BND.PORT (443)
        ];

        // When
        RequestResponseCodec
            .encode(response, &mut buf)
            .expect("Encoder failed");

        // Then
        assert_eq!(&buf[..], message);
    }
}
