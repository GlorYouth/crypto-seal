//! Provides a high-level, seamless API for encryption and decryption using key rotation.
pub mod symmetric;

use std::sync::Arc;

use crate::error::Error;
use crate::rotation::RotatingKeyManager;
use seal_flow::seal::SymmetricSeal;

/// The main entry point for performing cryptographic operations with automatic key rotation.
/// It acts as a factory for `Sealer` and `Unsealer` objects.
#[derive(Clone)]
pub struct SealRotator {
    manager: Arc<RotatingKeyManager>,
}

use symmetric::{SymmetricSealer, SymmetricUnsealer};

impl SealRotator {
    /// Creates a new `SealRotator`.
    ///
    /// # Arguments
    ///
    /// * `manager`: The `RotatingKeyManager` to use for key rotation.
    ///
    /// # Returns
    ///
    /// A `SealRotator` instance.
    pub fn new(manager: Arc<RotatingKeyManager>) -> Self {
        Self { manager }
    }

    /// Prepares an encryption operation by providing a `Sealer` instance.
    /// The `Sealer` is configured with the current primary key.
    ///
    /// # Returns
    ///
    /// A `Sealer` instance.
    pub fn symmetric_sealer(&self) -> Result<SymmetricSealer, Error> {
        let (metadata, key) = self.manager.get_encryption_key()?;
        Ok(SymmetricSealer {
            inner: SymmetricSeal::new()
            .encrypt(key, metadata.id),
        })
    }

    /// Prepares a decryption operation by providing an `Unsealer` instance.
    ///
    /// # Returns
    ///
    /// An `Unsealer` instance.
    pub fn symmetric_unsealer(&self) -> SymmetricUnsealer {
        SymmetricUnsealer {
            inner: SymmetricSeal::new()
            .decrypt()
            .with_key_provider(self.manager.clone()),
        }
    }
}

