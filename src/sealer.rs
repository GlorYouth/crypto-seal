//! Provides a high-level, seamless API for encryption and decryption using key rotation.
pub mod symmetric;
pub mod hybrid;

use std::sync::Arc;

use crate::error::Error;
use crate::rotation::RotatingKeyManager;
use seal_flow::algorithms::traits::{AsymmetricAlgorithm, SymmetricAlgorithm};
use seal_flow::seal::{hybrid::HybridSeal, symmetric::SymmetricSeal};

/// The main entry point for performing cryptographic operations with automatic key rotation.
/// It acts as a factory for `Sealer` and `Unsealer` objects.
#[derive(Clone)]
pub struct SealRotator {
    manager: Arc<RotatingKeyManager>,
}

use hybrid::{HybridSealer, HybridUnsealer};
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
    pub fn symmetric_sealer<S: SymmetricAlgorithm>(&self) -> Result<SymmetricSealer, Error> {
        let (metadata, key) = self.manager.get_encryption_key(S::name().as_str())?;
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

    /// Prepares an encryption operation by providing a `Sealer` instance.
    /// The `Sealer` is configured with the current primary key.
    ///
    /// # Returns
    ///
    /// A `Sealer` instance.
    pub fn hybrid_sealer<A: AsymmetricAlgorithm, S: SymmetricAlgorithm>(&self) -> Result<HybridSealer<A, S>, Error> {
        let (metadata, pk) = self.manager.get_encryption_public_key::<A>()?;
        Ok(HybridSealer {
            inner: HybridSeal::new().encrypt(pk, metadata.id),
            _marker: Default::default(),
        })
    }


    /// Prepares a decryption operation by providing an `Unsealer` instance.
    ///
    /// # Returns
    ///
    /// An `Unsealer` instance.
    pub fn hybrid_unsealer(&self) -> HybridUnsealer {
        HybridUnsealer {
            inner: HybridSeal::new().decrypt().with_key_provider(self.manager.clone()),
        }
    }

}

