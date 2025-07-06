use crate::error::Error;
#[cfg(feature = "async")]
use seal_flow::tokio::io::{AsyncRead, AsyncWrite};
use seal_flow::{
    algorithms::traits::{AsymmetricAlgorithm, SymmetricAlgorithm},
    prelude::*,
    seal::hybrid::{
        decryptor::{
            PendingAsyncStreamingDecryptor, PendingInMemoryDecryptor, PendingInMemoryParallelDecryptor,
            PendingParallelStreamingDecryptor, PendingStreamingDecryptor,
        },
        encryptor::HybridEncryptor,
        suites::PqcEncryptor,
        HybridSeal,
    },
};
use std::{
    io::{Read, Write},
    marker::PhantomData,
};

/// An operator for performing hybrid encryption.
pub struct HybridSealer<S: SymmetricAlgorithm> {
    pub(crate) inner: HybridEncryptor<S>,
}

/// An operator for performing hybrid encryption using a PQC suite.
pub struct PqcHybridSealer {
    pub(crate) inner: PqcEncryptor,
}

impl<S: SymmetricAlgorithm> HybridSealer<S> {
    /// Creates a new `HybridSealer`.
    pub fn new(pk: AsymmetricPublicKey, kek_id: String) -> Self {
        Self {
            inner: HybridSeal::new().encrypt(pk, kek_id),
        }
    }

    /// Sets the associated data (AAD) for the encryption operation.
    pub fn with_aad(self, aad: impl Into<Vec<u8>>) -> Self {
        Self {
            inner: self.inner.with_aad(aad),
        }
    }

    /// Encrypts a block of data.
    pub fn seal<A: AsymmetricAlgorithm>(self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        self.inner.with_algorithm::<A>().to_vec(plaintext).map_err(Error::from)
    }

    /// Encrypts a block of data in parallel.
    pub fn seal_parallel<A: AsymmetricAlgorithm>(
        self,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        self.inner
            .with_algorithm::<A>()
            .to_vec_parallel(plaintext)
            .map_err(Error::from)
    }

    /// Returns a `Write` stream that will encrypt data written to it.
    pub fn seal_stream<A: AsymmetricAlgorithm, W: Write>(
        self,
        writer: W,
    ) -> Result<impl Write, Error> {
        self.inner
            .with_algorithm::<A>()
            .into_writer(writer)
            .map_err(Error::from)
    }

    /// Encrypts data from a reader and writes to a writer using parallel processing.
    pub fn seal_pipe_parallel<A: AsymmetricAlgorithm, R, W>(
        self,
        reader: R,
        writer: W,
    ) -> Result<(), Error>
    where
        R: Read + Send,
        W: Write,
    {
        self.inner
            .with_algorithm::<A>()
            .pipe_parallel::<R, W>(reader, writer)
            .map_err(Error::from)
    }

    /// Returns an `AsyncWrite` stream that will encrypt data written to it.
    #[cfg(feature = "async")]
    pub async fn seal_stream_async<A: AsymmetricAlgorithm + Send + Sync, W: AsyncWrite + Unpin + Send>(
        self,
        writer: W,
    ) -> Result<impl AsyncWrite + Unpin + Send, Error> {
        self.inner
            .with_algorithm::<A>()
            .into_async_writer(writer)
            .await
            .map_err(Error::from)
    }
}

impl PqcHybridSealer {
    /// Creates a new `PqcHybridSealer`.
    pub fn new(pk: AsymmetricPublicKey, kek_id: String) -> Self {
        Self {
            inner: HybridSeal::new().encrypt_pqc_suite(pk, kek_id),
        }
    }

    /// Sets the associated data (AAD) for the encryption operation.
    pub fn with_aad(self, aad: impl Into<Vec<u8>>) -> Self {
        Self {
            inner: self.inner.with_aad(aad),
        }
    }

    /// Encrypts a block of data using the PQC suite.
    pub fn seal(self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        self.inner.to_vec(plaintext).map_err(Error::from)
    }

    /// Encrypts a block of data in parallel using the PQC suite.
    pub fn seal_parallel(self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        self.inner.to_vec_parallel(plaintext).map_err(Error::from)
    }

    /// Returns a `Write` stream that will encrypt data written to it using the PQC suite.
    pub fn seal_stream<W: Write>(self, writer: W) -> Result<impl Write, Error> {
        self.inner.into_writer(writer).map_err(Error::from)
    }

    /// Encrypts data from a reader and writes to a writer using parallel processing with the PQC suite.
    pub fn seal_pipe_parallel<R: Read + Send, W: Write>(self, reader: R, writer: W) -> Result<(), Error>
    where
        R: Read + Send,
        W: Write,
    {
        self.inner.pipe_parallel::<R, W>(reader, writer)
            .map_err(Error::from)
    }


    /// Returns an `AsyncWrite` stream that will encrypt data written to it using the PQC suite.
    #[cfg(feature = "async")]
    pub async fn seal_stream_async<W: AsyncWrite + Unpin + Send>(
        self,
        writer: W,
    ) -> Result<impl AsyncWrite + Unpin + Send, Error> {
        self.inner
            .into_async_writer(writer)
            .await
            .map_err(Error::from)
    }
}

/// An operator for performing hybrid decryption.
pub struct HybridUnsealer {
    pub(crate) inner: seal_flow::seal::hybrid::decryptor::HybridDecryptorBuilder,
}

pub struct PendingInMemoryDecryptorWrapper<'a> {
    inner: PendingInMemoryDecryptor<'a>,
}

impl<'a> PendingInMemoryDecryptorWrapper<'a> {
    /// Sets the associated data (AAD) for the decryption operation.
    pub fn with_aad(self, aad: impl Into<Vec<u8>>) -> Self {
        Self {
            inner: self.inner.with_aad(aad),
        }
    }

    /// Finalizes the decryption by providing the private key.
    pub fn finalize(self, sk: AsymmetricPrivateKey) -> Result<Vec<u8>, Error> {
        self.inner.with_key(sk).map_err(Error::from)
    }
}

pub struct PendingInMemoryParallelDecryptorWrapper<'a> {
    inner: PendingInMemoryParallelDecryptor<'a>,
}

impl<'a> PendingInMemoryParallelDecryptorWrapper<'a> {
    /// Sets the associated data (AAD) for the decryption operation.
    pub fn with_aad(self, aad: impl Into<Vec<u8>>) -> Self {
        Self {
            inner: self.inner.with_aad(aad),
        }
    }

    /// Finalizes the decryption by providing the private key.
    pub fn finalize(self, sk: AsymmetricPrivateKey) -> Result<Vec<u8>, Error> {
        self.inner.with_key(sk).map_err(Error::from)
    }
}

pub struct PendingStreamingDecryptorWrapper<'a, R: Read + 'a> {
    inner: PendingStreamingDecryptor<R>,
    _marker: PhantomData<&'a ()>,
}

impl<'a, R: Read + 'a> PendingStreamingDecryptorWrapper<'a, R> {
    /// Sets the associated data (AAD) for the decryption operation.
    pub fn with_aad(self, aad: impl Into<Vec<u8>>) -> Self {
        Self {
            inner: self.inner.with_aad(aad),
            _marker: PhantomData,
        }
    }

    /// Finalizes the decryption by providing the private key and returns a `Read` stream.
    pub async fn finalize(
        self,
        sk: AsymmetricPrivateKey,
    ) -> Result<Box<dyn Read + 'a>, Error> {
        self.inner.with_key(sk).map_err(Error::from)
    }
}

pub struct PendingParallelStreamingDecryptorWrapper<'a, R: Read + Send + 'a> {
    inner: PendingParallelStreamingDecryptor<R>,
    _marker: PhantomData<&'a ()>,
}

impl<'a, R: Read + Send + 'a> PendingParallelStreamingDecryptorWrapper<'a, R> {
    /// Sets the associated data (AAD) for the decryption operation.
    pub fn with_aad(self, aad: impl Into<Vec<u8>>) -> Self {
        Self {
            inner: self.inner.with_aad(aad),
            _marker: PhantomData,
        }
    }

    /// Finalizes the decryption by providing the private key and writes the decrypted data to a `Write` stream.
    pub fn finalize_to_writer<W: Write>(self, sk: AsymmetricPrivateKey, writer: W) -> Result<(), Error> {
        self.inner.with_key_to_writer(sk, writer).map_err(Error::from)
    }
}

#[cfg(feature = "async")]
pub struct PendingAsyncStreamingDecryptorWrapper<'a, R: AsyncRead + Unpin + Send + 'a> {
    inner: PendingAsyncStreamingDecryptor<R>,
    _marker: PhantomData<&'a ()>,
}

#[cfg(feature = "async")]
impl<'a, R: AsyncRead + Unpin + Send + 'a> PendingAsyncStreamingDecryptorWrapper<'a, R> {
    /// Sets the associated data (AAD) for the decryption operation.
    pub fn with_aad(self, aad: impl Into<Vec<u8>>) -> Self {
        Self {
            inner: self.inner.with_aad(aad),
            _marker: PhantomData,
        }
    }

    /// Finalizes the decryption by providing the private key and returns an `AsyncRead` stream.
    pub async fn finalize(
        self,
        sk: AsymmetricPrivateKey,
    ) -> Result<Box<dyn AsyncRead + Unpin + Send + 'a>, Error> {
        self.inner
            .with_key(sk)
            .await
            .map_err(Error::from)
    }
}

impl HybridUnsealer {
    /// Decrypts a block of data.
    pub fn unseal(self, blob: &[u8]) -> Result<PendingInMemoryDecryptorWrapper, Error> {
        Ok(PendingInMemoryDecryptorWrapper {
            inner: self.inner.slice(blob)?,
        })
    }

    /// Decrypts a block of data in parallel.
    pub fn unseal_parallel(self, blob: &[u8]) -> Result<PendingInMemoryParallelDecryptorWrapper, Error> {
        Ok(PendingInMemoryParallelDecryptorWrapper {
            inner: self.inner.slice_parallel(blob)?,
        })
    }

    /// Returns a `Read` stream that will decrypt data from an underlying reader.
    pub fn unseal_stream<'a, R: Read + 'a>(
        self,
        reader: R,
    ) -> Result<PendingStreamingDecryptorWrapper<'a, R>, Error> {
        Ok(PendingStreamingDecryptorWrapper {
            inner: self.inner.reader(reader)?,
            _marker: PhantomData,
        })
    }

    /// Returns a `PendingParallelStreamingDecryptorWrapper` that will decrypt data from an underlying reader in parallel.
    pub fn unseal_stream_parallel<'a, R: Read + Send + 'a>(
        self,
        reader: R,
    ) -> Result<PendingParallelStreamingDecryptorWrapper<'a, R>, Error> {
        Ok(PendingParallelStreamingDecryptorWrapper {
            inner: self.inner.reader_parallel(reader)?,
            _marker: PhantomData,
        })
    }

    /// Returns an `AsyncRead` stream that will decrypt data from an underlying async reader.
    #[cfg(feature = "async")]
    pub async fn unseal_stream_async<'a, R: AsyncRead + Unpin + Send + 'a>(
        self,
        reader: R,
    ) -> Result<PendingAsyncStreamingDecryptorWrapper<'a, R>, Error> {
        Ok(PendingAsyncStreamingDecryptorWrapper {
            inner: self.inner.async_reader(reader).await?,
            _marker: PhantomData,
        })
    }
}
