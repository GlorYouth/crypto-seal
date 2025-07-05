//! Provides a high-level, seamless API for encryption and decryption using key rotation.
use std::io::{Read, Write};
use std::marker::PhantomData;
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
            inner: SymmetricSeal::new()
            .encrypt(key, metadata.id),
        })
    }

    /// Prepares a decryption operation by providing an `Unsealer` instance.
    pub fn unsealer(&self) -> Unsealer {
        Unsealer {
            inner: SymmetricSeal::new()
            .decrypt()
            .with_key_provider(self.manager.clone()),
        }
    }
}

/// An operator for performing encryption, pre-configured with a specific (primary) key.
pub struct Sealer {
    inner: seal_flow::seal::symmetric::encryptor::SymmetricEncryptor,
}

impl Sealer {
    /// Sets the associated data (AAD) for the encryption operation.
    ///
    /// # Arguments
    ///
    /// * `aad`: The associated data to be authenticated.
    ///
    /// # Returns
    pub fn with_aad(self, aad: impl Into<Vec<u8>>) -> Self {
        Sealer {
            inner: self.inner.with_aad(aad),
        }
    }

    /// Encrypts a block of data using the configured primary key.
    /// `seal-flow` will automatically prepend the key_id to the ciphertext.
    pub fn seal(self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        self.inner.to_vec::<Aes256Gcm>(plaintext)
            .map_err(Error::from)
    }

    /// Returns a `Write` stream that will encrypt data written to it.
    /// `seal-flow` will automatically write the key_id to the stream first.
    pub fn seal_stream<W: Write>(self, writer: W) -> Result<impl Write, Error> {
        self.inner.into_writer::<Aes256Gcm, _>(writer)
            .map_err(Error::from)
    }
}

/// An operator for performing decryption.
pub struct Unsealer {
    inner: seal_flow::seal::symmetric::decryptor::SymmetricDecryptorBuilder,
}

use seal_flow::seal::symmetric::decryptor::PendingInMemoryDecryptor;

pub struct PendingInMemoryDecryptorWrapper<'a> {
    inner: PendingInMemoryDecryptor<'a>,
}

impl<'a> PendingInMemoryDecryptorWrapper<'a> {
    pub fn with_aad(self, aad: impl Into<Vec<u8>>) -> Self {
        PendingInMemoryDecryptorWrapper {
            inner: self.inner.with_aad(aad),
        }
    }

    pub fn finalize(self) -> Result<Vec<u8>, Error> {
        self.inner.resolve_and_decrypt().map_err(Error::from)
    }
}

use seal_flow::seal::symmetric::decryptor::PendingStreamingDecryptor;

pub struct PendingStreamingDecryptorWrapper<'a, R: Read + 'a> {
    inner: PendingStreamingDecryptor<R>,
    _marker: PhantomData<&'a ()>,
}

impl<'a, R: Read + 'a> PendingStreamingDecryptorWrapper<'a, R> {

    pub fn with_aad(self, aad: impl Into<Vec<u8>>) -> Self {
        PendingStreamingDecryptorWrapper {
            inner: self.inner.with_aad(aad),
            _marker: PhantomData,
        }
    }

    pub fn finalize(self) -> Result<Box<dyn Read + 'a>, Error> {
        self.inner.resolve_and_decrypt().map_err(Error::from)
    }
}

impl Unsealer {
    /// Decrypts a block of data.
    /// It uses the internal `RotatingKeyManager` as a `KeyProvider` to find
    /// the correct decryption key based on the `key_id` stored in the blob.
    ///
    /// # Arguments
    ///
    /// * `blob`: The encrypted data to be decrypted.
    ///
    /// # Returns
    ///
    /// A `PendingDecryptor` that can be used to decrypt the data.
    
    pub fn unseal(self, blob: &[u8]) -> Result<PendingInMemoryDecryptorWrapper, Error> {
        Ok(PendingInMemoryDecryptorWrapper {
            inner: self.inner.slice(blob)?,
        })
    }

    /// Returns a `Read` stream that will decrypt data from an underlying reader.
    /// It uses the internal `RotatingKeyManager` as a `KeyProvider`.
    pub fn unseal_stream<'a, R: Read + 'a>(self, reader: R) -> Result<PendingStreamingDecryptorWrapper<'a, R>, Error> {
        Ok(PendingStreamingDecryptorWrapper {
            inner: self.inner.reader(reader)?,
            _marker: PhantomData,
        })
    }
} 