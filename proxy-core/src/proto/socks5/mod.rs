pub mod types;
pub mod codecs;

use crate::proto::socks5::types::{AuthMethod, AuthStatus, Command, Reply, Address};

/// Maximum greeting frame size: VER (1) + NMETHODS (1) + METHODS (up to 255)
const MAX_GREETING_FRAME_SIZE: usize = 257;

/// Maximum auth frame size: VER (1) + ULEN (1) + UNAME (up to 255) + PLEN (1) + PASSWD (up to 255)
const MAX_AUTH_FRAME_SIZE: usize = 513;

/// Maximum request frame size: VER (1) + CMD (1) + RSV (1) + ATYP (1) + DLEN (1) + DOMAIN (up to 255) + PORT (2)
const MAX_REQUEST_FRAME_SIZE: usize = 262;

/// Client greeting request
/// https://datatracker.ietf.org/doc/html/rfc1928#section-3
///
/// ```text
/// +----+----------+----------+
/// |VER | NMETHODS | METHODS  |
/// +----+----------+----------+
/// | 1  |    1     | 1 to 255 |
/// +----+----------+----------+
/// ```
#[derive(Debug, Clone)]
pub struct ClientGreeting {
    pub methods: Vec<AuthMethod>,
}

/// Server greeting response
/// https://datatracker.ietf.org/doc/html/rfc1928#section-3
///
/// ```text
/// +----+--------+
/// |VER | METHOD |
/// +----+--------+
/// | 1  |   1    |
/// +----+--------+
/// ```
#[derive(Debug, Clone)]
pub struct ServerGreeting {
    pub method: AuthMethod,
}

/// Client username-password authentication request
/// https://datatracker.ietf.org/doc/html/rfc1929#section-2
///
/// ```text
/// +----+------+----------+------+----------+
/// |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
/// +----+------+----------+------+----------+
/// | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
/// +----+------+----------+------+----------+
/// ```
#[derive(Debug, Clone)]
pub struct AuthRequest {
    pub username: String,
    pub password: String,
}

/// Server username-password authentication response
/// https://datatracker.ietf.org/doc/html/rfc1929#section-2
///
/// ```text
/// +----+--------+
/// |VER | STATUS |
/// +----+--------+
/// | 1  |   1    |
/// +----+--------+
/// ```
#[derive(Debug, Clone)]
pub struct AuthResponse {
    pub status: AuthStatus,
}

/// Client request
/// https://datatracker.ietf.org/doc/html/rfc1928#section-4
///
/// ```text
/// +----+-----+-------+------+----------+----------+
/// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
/// +----+-----+-------+------+----------+----------+
/// | 1  |  1  | X'00' |  1   | Variable |    2     |
/// +----+-----+-------+------+----------+----------+
/// ```
#[derive(Debug, Clone)]
pub struct ClientRequest {
    pub command: Command,
    pub dst_address: Address,
}

/// Server response
/// https://datatracker.ietf.org/doc/html/rfc1928#section-4
///
/// ```text
/// +----+-----+-------+------+----------+----------+
/// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
/// +----+-----+-------+------+----------+----------+
/// | 1  |  1  | X'00' |  1   | Variable |    2     |
/// +----+-----+-------+------+----------+----------+
/// ```
#[derive(Debug, Clone)]
pub struct ServerResponse {
    pub reply: Reply,
    pub bnd_address: Address,
}
