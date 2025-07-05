//! Provides a high-level, seamless API for encryption and decryption using key rotation.
use std::io::{Read, Write};
use std::marker::PhantomData;
use std::sync::Arc;

use crate::error::Error;
use crate::rotation::RotatingKeyManager;
use seal_flow::algorithms::symmetric::Aes256Gcm;
use seal_flow::seal::SymmetricSeal;
#[cfg(feature = "async")]
use seal_flow::tokio::io::{AsyncRead, AsyncWrite};

/// The main entry point for performing cryptographic operations with automatic key rotation.
/// It acts as a factory for `Sealer` and `Unsealer` objects.
#[derive(Clone)]
pub struct SealRotator {
    manager: Arc<RotatingKeyManager>,
}

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
    pub fn sealer(&self) -> Result<Sealer, Error> {
        let (metadata, key) = self.manager.get_encryption_key()?;
        Ok(Sealer {
            inner: SymmetricSeal::new()
            .encrypt(key, metadata.id),
        })
    }

    /// Prepares a decryption operation by providing an `Unsealer` instance.
    ///
    /// # Returns
    ///
    /// An `Unsealer` instance.
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
    ///
    /// A `Sealer` with the associated data (AAD) set.
    pub fn with_aad(self, aad: impl Into<Vec<u8>>) -> Self {
        Sealer {
            inner: self.inner.with_aad(aad),
        }
    }

    /// Encrypts a block of data using the configured primary key.
    /// `seal-flow` will automatically prepend the key_id to the ciphertext.
    ///
    /// # Arguments
    ///
    /// * `plaintext`: The plaintext data to be encrypted.
    ///
    /// # Returns
    pub fn seal(self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        self.inner.to_vec::<Aes256Gcm>(plaintext)
            .map_err(Error::from)
    }

    /// Encrypts a block of data in parallel using the configured primary key.
    /// `seal-flow` will automatically prepend the key_id to the ciphertext.
    ///
    /// # Arguments
    ///
    /// * `plaintext`: The plaintext data to be encrypted.
    ///
    /// # Returns
    pub fn seal_parallel(self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        self.inner.to_vec_parallel::<Aes256Gcm>(plaintext)
            .map_err(Error::from)
    }

    /// Returns a `Write` stream that will encrypt data written to it.
    /// `seal-flow` will automatically write the key_id to the stream first.
    ///
    /// # Arguments
    ///
    /// * `writer`: The writer to which the encrypted data will be written.
    ///
    /// # Returns
    pub fn seal_stream<W: Write>(self, writer: W) -> Result<impl Write, Error> {
        self.inner.into_writer::<Aes256Gcm, _>(writer)
            .map_err(Error::from)
    }

    /// Encrypts data from a reader and writes to a writer using parallel processing.
    /// `seal-flow` will automatically write the key_id to the stream first.
    ///
    /// # Arguments
    ///
    /// * `reader`: The reader from which the data will be read.
    /// * `writer`: The writer to which the encrypted data will be written.
    ///
    /// # Returns
    ///
    pub fn seal_pipe_parallel<R, W>(self, reader: R, writer: W) -> Result<(), Error>
    where
        R: Read + Send,
        W: Write,
    {
        self.inner
            .pipe_parallel::<Aes256Gcm, R, W>(reader, writer)
            .map_err(Error::from)
    }

    /// Returns an `AsyncWrite` stream that will encrypt data written to it.
    /// `seal-flow` will automatically write the key_id to the stream first.
    ///
    /// # Arguments
    ///
    /// * `writer`: The writer to which the encrypted data will be written.
    ///
    /// # Returns
    ///
    /// A `Result` that contains the encrypted data.
    #[cfg(feature = "async")]
    pub async fn seal_stream_async<W: AsyncWrite + Unpin + Send>(
        self,
        writer: W,
    ) -> Result<impl AsyncWrite + Unpin + Send, Error> {
        self.inner
            .into_async_writer::<Aes256Gcm, _>(writer)
            .await
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
    /// Sets the associated data (AAD) for the decryption operation.
    ///
    /// # Arguments
    ///
    /// * `aad`: The associated data to be authenticated.
    ///
    /// # Returns
    pub fn with_aad(self, aad: impl Into<Vec<u8>>) -> Self {
        PendingInMemoryDecryptorWrapper {
            inner: self.inner.with_aad(aad),
        }
    }

    /// Finalizes the decryption operation and returns the decrypted data.
    ///
    /// # Returns
    ///
    /// The decrypted data.
    pub fn finalize(self) -> Result<Vec<u8>, Error> {
        self.inner.resolve_and_decrypt().map_err(Error::from)
    }
}

use seal_flow::seal::symmetric::decryptor::PendingInMemoryParallelDecryptor;

pub struct PendingInMemoryParallelDecryptorWrapper<'a> {
    inner: PendingInMemoryParallelDecryptor<'a>,
}

impl<'a> PendingInMemoryParallelDecryptorWrapper<'a> {
    /// Sets the associated data (AAD) for the decryption operation.
    ///
    /// # Arguments
    ///
    /// * `aad`: The associated data to be authenticated.
    ///
    /// # Returns
    pub fn with_aad(self, aad: impl Into<Vec<u8>>) -> Self {
        PendingInMemoryParallelDecryptorWrapper {
            inner: self.inner.with_aad(aad),
        }
    }

    /// Finalizes the decryption operation and returns the decrypted data.
    ///
    /// # Returns
    ///
    /// The decrypted data.
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

    /// Sets the associated data (AAD) for the decryption operation.
    ///
    /// # Arguments
    ///
    /// * `aad`: The associated data to be authenticated.
    ///
    /// # Returns
    pub fn with_aad(self, aad: impl Into<Vec<u8>>) -> Self {
        PendingStreamingDecryptorWrapper {
            inner: self.inner.with_aad(aad),
            _marker: PhantomData,
        }
    }

    /// Finalizes the decryption operation and returns a `Read` stream.
    ///
    /// # Returns
    ///
    /// A `Box<dyn Read + 'a>` that can be used to read the decrypted data.
    pub fn finalize(self) -> Result<Box<dyn Read + 'a>, Error> {
        self.inner.resolve_and_decrypt().map_err(Error::from)
    }
}

use seal_flow::seal::symmetric::decryptor::PendingParallelStreamingDecryptor;

pub struct PendingParallelStreamingDecryptorWrapper<'a, R: Read + Send + 'a> {
    inner: PendingParallelStreamingDecryptor<R>,
    _marker: PhantomData<&'a ()>,
}

impl<'a, R: Read + Send + 'a> PendingParallelStreamingDecryptorWrapper<'a, R> {
    /// Sets the associated data (AAD) for the decryption operation.
    ///
    /// # Arguments
    ///
    /// * `aad`: The associated data to be authenticated.
    ///
    /// # Returns
    pub fn with_aad(self, aad: impl Into<Vec<u8>>) -> Self {
        PendingParallelStreamingDecryptorWrapper {
            inner: self.inner.with_aad(aad),
            _marker: PhantomData,
        }
    }

    /// Finalizes the decryption operation and writes the decrypted data to a `Write` stream.
    ///
    /// # Arguments
    ///
    /// * `writer`: The writer to which the decrypted data will be written.
    pub fn finalize_to_writer<W: Write>(self, writer: W) -> Result<(), Error> {
        self.inner.resolve_and_decrypt_to_writer(writer).map_err(Error::from)
    }
}


#[cfg(feature = "async")]
use seal_flow::seal::symmetric::decryptor::PendingAsyncStreamingDecryptor;

#[cfg(feature = "async")]
pub struct PendingAsyncStreamingDecryptorWrapper<'a, R: AsyncRead + Unpin + 'a> {
    inner: PendingAsyncStreamingDecryptor<R>,
    _marker: PhantomData<&'a ()>,
}

#[cfg(feature = "async")]
impl<'a, R: AsyncRead + Unpin + 'a> PendingAsyncStreamingDecryptorWrapper<'a, R> {
    /// Sets the associated data (AAD) for the decryption operation.
    ///
    /// # Arguments
    ///
    /// * `aad`: The associated data to be authenticated.
    ///
    /// # Returns
    pub fn with_aad(self, aad: impl Into<Vec<u8>>) -> Self {
        PendingAsyncStreamingDecryptorWrapper {
            inner: self.inner.with_aad(aad),
            _marker: PhantomData,
        }
    }

    /// Finalizes the decryption operation and returns a `AsyncRead` stream.
    ///
    /// # Returns
    ///
    /// A `Box<dyn AsyncRead + Unpin + 'a>` that can be used to read the decrypted data.
    pub fn finalize(self) -> Result<Box<dyn AsyncRead + Unpin + 'a>, Error> {
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

    /// Decrypts a block of data in parallel.
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
    pub fn unseal_parallel(self, blob: &[u8]) -> Result<PendingInMemoryParallelDecryptorWrapper, Error> {
        Ok(PendingInMemoryParallelDecryptorWrapper {
            inner: self.inner.slice_parallel(blob)?,
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

    /// Returns a `PendingParallelStreamingDecryptorWrapper` that will decrypt data from an underlying reader in parallel.
    /// It uses the internal `RotatingKeyManager` as a `KeyProvider`.
    pub fn unseal_stream_parallel<'a, R: Read + Send + 'a>(self, reader: R) -> Result<PendingParallelStreamingDecryptorWrapper<'a, R>, Error> {
        Ok(PendingParallelStreamingDecryptorWrapper {
            inner: self.inner.reader_parallel(reader)?,
            _marker: PhantomData,
        })
    }

    /// Returns a `AsyncRead` stream that will decrypt data from an underlying async reader.
    /// It uses the internal `RotatingKeyManager` as a `KeyProvider`.
    #[cfg(feature = "async")]
    pub async fn unseal_stream_async<'a, R: AsyncRead + Unpin + 'a>(self, reader: R) -> Result<PendingAsyncStreamingDecryptorWrapper<'a, R>, Error> {
        Ok(PendingAsyncStreamingDecryptorWrapper {
            inner: self.inner.async_reader(reader).await?,
            _marker: PhantomData,
        })
    }
} 