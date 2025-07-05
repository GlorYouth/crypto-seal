//! Provides a high-level, seamless API for encryption and decryption using key rotation.
use std::io::{Read, Write};
use std::sync::Arc;

use crate::error::Error;
use crate::prelude::*;
use crate::rotation::RotatingKeyManager;
use seal_flow::algorithms::symmetric::Aes256Gcm;
use seal_flow::seal::SymmetricSeal;

/// The main entry point for performing cryptographic operations with automatic key rotation.
/// It acts as a factory for `Sealer` and `Unsealer` objects.
#[derive(Clone)]
pub struct SealRotator {
    manager: Arc<RotatingKeyManager>,
}

impl SealRotator {
    /// Creates a new `SealRotator`.
    pub fn new(manager: Arc<RotatingKeyManager>) -> Self {
        Self { manager }
    }

    /// Prepares an encryption operation by providing a `Sealer` instance.
    /// The `Sealer` is configured with the current primary key.
    pub fn sealer(&self) -> Result<Sealer, Error> {
        let (metadata, key) = self.manager.get_encryption_key()?;
        Ok(Sealer {
            key,
            key_id: metadata.id,
        })
    }

    /// Prepares a decryption operation by providing an `Unsealer` instance.
    pub fn unsealer(&self) -> Unsealer {
        Unsealer {
            manager: self.manager.clone(),
        }
    }
}

/// An operator for performing encryption, pre-configured with a specific (primary) key.
pub struct Sealer {
    key: SymmetricKey,
    key_id: String,
}

impl Sealer {
    /// Encrypts a block of data using the configured primary key.
    /// `seal-flow` will automatically prepend the key_id to the ciphertext.
    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        SymmetricSeal::new()
            .encrypt(self.key.clone(), self.key_id.clone())
            .to_vec::<Aes256Gcm>(plaintext)
            .map_err(Error::from)
    }

    /// Returns a `Write` stream that will encrypt data written to it.
    /// `seal-flow` will automatically write the key_id to the stream first.
    pub fn seal_stream<W: Write>(&self, writer: W) -> Result<impl Write, Error> {
        SymmetricSeal::new()
            .encrypt(self.key.clone(), self.key_id.clone())
            .into_writer::<Aes256Gcm, _>(writer)
            .map_err(Error::from)
    }
}

/// An operator for performing decryption.
pub struct Unsealer {
    manager: Arc<RotatingKeyManager>,
}

impl Unsealer {
    /// Decrypts a block of data.
    /// It uses the internal `RotatingKeyManager` as a `KeyProvider` to find
    /// the correct decryption key based on the `key_id` stored in the blob.
    pub fn unseal(&self, blob: &[u8]) -> Result<Vec<u8>, Error> {
        SymmetricSeal::new()
            .decrypt()
            .with_key_provider(self.manager.as_ref())
            .slice(blob)
            .map_err(Error::from)?
            .resolve_and_decrypt()
            .map_err(Error::from)
    }

    /// Returns a `Read` stream that will decrypt data from an underlying reader.
    /// It uses the internal `RotatingKeyManager` as a `KeyProvider`.
    pub fn unseal_stream<'a, R: Read + 'a>(&self, reader: R) -> Result<impl Read + 'a, Error> {
        SymmetricSeal::new()
            .decrypt()
            .with_key_provider(self.manager.as_ref())
            .reader(reader)
            .map_err(Error::from)?
            .resolve_and_decrypt()
            .map_err(Error::from)
    }
} 