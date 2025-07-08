//! Defines the data structures used for communication between the server and client.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Defines the cryptographic suite used for an operation.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct EncryptionSuite {
    /// The name of the asymmetric algorithm (e.g., "Kyber1024").
    pub asymmetric: String,
    /// The name of the symmetric algorithm (e.g., "Aes256Gcm").
    pub symmetric: String,
}

/// A data structure that contains all the information a client needs for encryption.
/// It is designed to be self-contained and immutable.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PublicKeyBundle {
    /// The unique identifier for the key, which will be attached to the ciphertext.
    /// Example: "kyber1024-20231027T100000Z"
    pub key_id: String,

    /// The cryptographic suite this key should be used with.
    pub suite: EncryptionSuite,

    /// The Base64-encoded public key.
    pub public_key: String,

    /// The time (UTC) when this public key was issued.
    pub issued_at: DateTime<Utc>,

    /// The time (UTC) until which the client should cache this public key.
    /// The server sets this value based on its rotation policy.
    pub expires_at: DateTime<Utc>,
} 