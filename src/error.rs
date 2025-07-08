//! Defines the custom error type for the `seal-kit` crate.

use seal_flow::prelude::KeyProviderError;
use thiserror::Error;


/// The main error type for the `seal-kit` crate.
#[derive(Debug, Error)]
pub enum Error {
    #[error("key provider error: {0}")]
    KeyProvider(#[from] KeyProviderError),

    #[error("Rotation error: {0}")]
    RotationError(String),
    #[error("Peer error: {0}")]
    PeerNotFound(String),
    #[error("Peer error: {0}")]
    PeerError(String),
    #[error("IO error")]
    Io(#[from] std::io::Error),

    #[error("serialization failed: {0}")]
    SerializeError(#[from] serde_json::Error),

    #[error("deserialization failed: {0}")]
    DeserializeError(serde_json::Error),

    #[error("decoding from Base64 failed: {0}")]
    Base64DecodeError(#[from] base64::DecodeError),

    #[error("encryption or decryption failed: {0}")]
    CryptoError(#[from] seal_flow::crypto::errors::Error),

    #[error("seal flow error: {0}")]
    FlowError(#[from] seal_flow::Error),

    #[error("invalid data format: {0}")]
    FormatError(String),

    #[error("operation failed: {0}")]
    Operation(String),

    
}