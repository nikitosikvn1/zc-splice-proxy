use std::io;

use thiserror::Error;

use crate::error::ProtocolError;

/// Error type for SOCKS5 codec operations.
///
/// This error can represent either a protocol violation (malformed data)
/// or an I/O error during encoding/decoding operations.
#[derive(Debug, Error)]
pub enum CodecError {
    /// Protocol violation: client sent invalid or malformed data.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),

    /// I/O error during read or write operations.
    #[error(transparent)]
    Io(#[from] io::Error),
}
