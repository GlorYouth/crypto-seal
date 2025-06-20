//! The storage module, defining how vaults are persisted.
// English: The storage module, defining how vaults are persisted.

pub mod traits;

#[cfg(feature = "secure-storage")]
pub mod container;

#[cfg(feature = "secure-storage")]
pub mod encrypted_store;

pub mod plaintext_store;

pub use container::EncryptedKeyContainer;
