//! Provides a high-level, seamless API for encryption and decryption using key rotation.
pub mod symmetric;
pub mod hybrid;

use std::sync::Arc;

use crate::error::Error;
use crate::common::rotation::RotatingKeyManager;
use seal_flow::algorithms::traits::{AsymmetricAlgorithm, SymmetricAlgorithm};
use seal_flow::seal::{hybrid::HybridSeal, symmetric::SymmetricSeal};
use base64::{engine::general_purpose, Engine as _};
use crate::contract::PublicKeyBundle;

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

    /// Returns the public key bundle for the current primary key.
    pub fn get_public_key_bundle<A: AsymmetricAlgorithm>(&self) -> Result<PublicKeyBundle, Error> {
        let (metadata, public_key) = self.manager.get_encryption_public_key::<A>()?;
        Ok(PublicKeyBundle {
            key_id: metadata.id,
            algorithm: A::name().to_string(),
            public_key: general_purpose::URL_SAFE_NO_PAD.encode(&*public_key.0),
            issued_at: metadata.created_at,
            expires_at: metadata.expires_at,
        })
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

