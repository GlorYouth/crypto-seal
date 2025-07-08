#[cfg(feature = "async")]
use seal_flow::tokio::io::{AsyncRead, AsyncWrite};
use seal_flow::seal::symmetric::decryptor::{PendingAsyncStreamingDecryptor, PendingInMemoryDecryptor, PendingInMemoryParallelDecryptor, PendingParallelStreamingDecryptor, PendingStreamingDecryptor};
use std::marker::PhantomData;
use std::io::{Read, Write};
use seal_flow::algorithms::traits::SymmetricAlgorithm;
use crate::error::Error;
use seal_flow::prelude::*;

/// An operator for performing encryption, pre-configured with a specific (primary) key.
pub struct SymmetricSealer {
    pub(crate) inner: seal_flow::seal::symmetric::encryptor::SymmetricEncryptor,
}

impl SymmetricSealer {
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
        SymmetricSealer {
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
    pub fn seal<S: SymmetricAlgorithm>(self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        self.inner.to_vec::<S>(plaintext)
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
    pub fn seal_parallel<S: SymmetricAlgorithm>(self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        self.inner.to_vec_parallel::<S>(plaintext)
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
    pub fn seal_stream<S: SymmetricAlgorithm, W: Write>(self, writer: W) -> Result<impl Write, Error> {
        self.inner.into_writer::<S, _>(writer)
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
    pub fn seal_pipe_parallel<S: SymmetricAlgorithm, R, W>(self, reader: R, writer: W) -> Result<(), Error>
    where
        R: Read + Send,
        W: Write,
    {
        self.inner
            .pipe_parallel::<S, R, W>(reader, writer)
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
    pub async fn seal_stream_async<S: SymmetricAlgorithm, W: AsyncWrite + Unpin + Send>(
        self,
        writer: W,
    ) -> Result<impl AsyncWrite + Unpin + Send, Error> {
        self.inner
            .into_async_writer::<S, _>(writer)
            .await
            .map_err(Error::from)
    }
}

/// An operator for performing decryption.
pub struct SymmetricUnsealer {
    pub(crate) inner: seal_flow::seal::symmetric::decryptor::SymmetricDecryptorBuilder,
}

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

impl SymmetricUnsealer {
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