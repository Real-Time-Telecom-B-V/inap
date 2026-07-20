//! Errors for INAP operation encoding/decoding.

/// An error encoding or decoding an INAP operation.
#[derive(Debug, thiserror::Error)]
pub enum InapError {
    /// BER encoding failed.
    #[error("INAP encode error: {0}")]
    Encode(String),
    /// BER decoding failed.
    #[error("INAP decode error: {0}")]
    Decode(String),
    /// The operation code is not a known INAP operation.
    #[error("unknown INAP operation code: {0}")]
    UnknownOperation(i64),
    /// An address digit string could not be encoded.
    #[error("invalid address: {0}")]
    InvalidAddress(String),
}
