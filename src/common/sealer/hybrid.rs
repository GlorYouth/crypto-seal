use crate::error::Error;
#[cfg(feature = "async")]
use seal_flow::tokio::io::{AsyncRead, AsyncWrite};
use seal_flow::{
    algorithms::traits::{
        AsymmetricAlgorithm, KdfAlgorithm, SignatureAlgorithm, SymmetricAlgorithm, XofAlgorithm,
    },
    prelude::*,
    seal::{
        hybrid::{
            decryptor::{
                PendingAsyncStreamingDecryptor, PendingInMemoryDecryptor,
                PendingInMemoryParallelDecryptor, PendingParallelStreamingDecryptor,
                PendingStreamingDecryptor,
            },
            encryptor::HybridEncryptor,
            suites::PqcEncryptor,
            HybridSeal,
        },
        traits::{WithAad, WithVerificationKey},
    },
};
use std::{
    io::{Read, Write},
    marker::PhantomData,
};

/// An operator for performing hybrid encryption.
pub struct HybridSealer<A: AsymmetricAlgorithm, S: SymmetricAlgorithm> {
    pub(crate) inner: HybridEncryptor<S>,
    pub(crate) _marker: PhantomData<A>,
}

/// An operator for performing hybrid encryption using a PQC suite.
pub struct PqcHybridSealer {
    pub(crate) inner: PqcEncryptor,
}

impl<A: AsymmetricAlgorithm + Send + Sync, S: SymmetricAlgorithm> HybridSealer<A, S> {

    /// Sets the associated data (AAD) for the encryption operation.
    pub fn with_aad(self, aad: impl Into<Vec<u8>>) -> Self {
        Self {
            inner: self.inner.with_aad(aad),
            _marker: PhantomData,
        }
    }

    pub fn with_kdf<Kdf: KdfAlgorithm>(self, deriver: Kdf,
        salt: Option<impl Into<Vec<u8>>>,
        info: Option<impl Into<Vec<u8>>>,
        output_len: u32,) -> Self {
        Self {
            inner: self.inner.with_kdf(deriver, salt, info, output_len),
            _marker: PhantomData,
        }
    }

    pub fn with_xof<Xof: XofAlgorithm>(self, deriver: Xof,
        salt: Option<impl Into<Vec<u8>>>,
        info: Option<impl Into<Vec<u8>>>,
        output_len: u32,) -> Self {
        Self {
            inner: self.inner.with_xof(deriver, salt, info, output_len),
            _marker: PhantomData,
        }
    }

    pub fn with_signer<Sig: SignatureAlgorithm>(self,
        signing_key: AsymmetricPrivateKey,
        signer_key_id: String
    ) -> Self {
        Self {
            inner: self.inner.with_signer::<Sig>(signing_key, signer_key_id),
            _marker: PhantomData,
        }
    }

    pub fn with_options(self, options: HybridEncryptionOptions) -> Self {
        Self {
            inner: self.inner.with_options(options),
            _marker: PhantomData,
        }
    }

    /// Encrypts a block of data.
    pub fn seal(self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        self.inner.with_algorithm::<A>().to_vec(plaintext).map_err(Error::from)
    }

    /// Encrypts a block of data in parallel.
    pub fn seal_parallel(
        self,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        self.inner
            .with_algorithm::<A>()
            .to_vec_parallel(plaintext)
            .map_err(Error::from)
    }

    /// Returns a `Write` stream that will encrypt data written to it.
    pub fn seal_stream<W: Write>(
        self,
        writer: W,
    ) -> Result<impl Write, Error> {
        self.inner
            .with_algorithm::<A>()
            .into_writer(writer)
            .map_err(Error::from)
    }

    /// Encrypts data from a reader and writes to a writer using parallel processing.
    pub fn seal_pipe_parallel<R, W>(
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
    pub async fn seal_stream_async<W: AsyncWrite + Unpin + Send>(
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
            inner: HybridSeal::new().encrypt_pqc_suite().with_recipient(pk, kek_id),
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

pub struct PendingDecryptorWrapper<T> {
    inner: T,
}

impl<T> PendingDecryptorWrapper<T> {
    /// Sets the associated data (AAD) for the decryption operation.
    pub fn with_aad(self, aad: impl Into<Vec<u8>>) -> Self
    where
        T: WithAad,
    {
        Self {
            inner: self.inner.with_aad(aad),
        }
    }

    /// Supplies a verification key.
    pub fn with_verification_key(self, verification_key: SignaturePublicKey) -> Self
    where
        T: WithVerificationKey,
    {
        Self {
            inner: self.inner.with_verification_key(verification_key),
        }
    }
}

pub type PendingInMemoryDecryptorWrapper<'a> = PendingDecryptorWrapper<PendingInMemoryDecryptor<'a>>;

impl<'a> PendingInMemoryDecryptorWrapper<'a> {
    /// Finalizes the decryption by providing the private key.
    pub fn finalize(self) -> Result<Vec<u8>, Error> {
        self.inner.resolve_and_decrypt().map_err(Error::from)
    }
}

pub type PendingInMemoryParallelDecryptorWrapper<'a> =
    PendingDecryptorWrapper<PendingInMemoryParallelDecryptor<'a>>;

impl<'a> PendingInMemoryParallelDecryptorWrapper<'a> {
    /// Finalizes the decryption by providing the private key.
    pub fn finalize(self) -> Result<Vec<u8>, Error> {
        self.inner.resolve_and_decrypt().map_err(Error::from)
    }
}

pub type PendingStreamingDecryptorWrapper<'a, R> =
    PendingDecryptorWrapper<PendingStreamingDecryptor<R>>;

impl<'a, R: Read + 'a> PendingStreamingDecryptorWrapper<'a, R> {
    /// Finalizes the decryption by providing the private key and returns a `Read` stream.
    pub fn finalize(self) -> Result<Box<dyn Read + 'a>, Error> {
        self.inner.resolve_and_decrypt().map_err(Error::from)
    }
}

pub type PendingParallelStreamingDecryptorWrapper<'a, R> =
    PendingDecryptorWrapper<PendingParallelStreamingDecryptor<R>>;

impl<'a, R: Read + Send + 'a> PendingParallelStreamingDecryptorWrapper<'a, R> {
    /// Finalizes the decryption by providing the private key and writes the decrypted data to a `Write` stream.
    pub fn finalize_to_writer<W: Write>(
        self,
        writer: W,
    ) -> Result<(), Error> {
        self.inner
            .resolve_and_decrypt_to_writer(writer)
            .map_err(Error::from)
    }
}

#[cfg(feature = "async")]
pub type PendingAsyncStreamingDecryptorWrapper<'a, R> =
    PendingDecryptorWrapper<PendingAsyncStreamingDecryptor<R>>;

#[cfg(feature = "async")]
impl<'a, R: AsyncRead + Unpin + Send + 'a> PendingAsyncStreamingDecryptorWrapper<'a, R> {
    /// Finalizes the decryption by providing the private key and returns an `AsyncRead` stream.
    pub async fn finalize(
        self,
    ) -> Result<Box<dyn AsyncRead + Unpin + Send + 'a>, Error> {
        self.inner.resolve_and_decrypt().await.map_err(Error::from)
    }
}

impl HybridUnsealer {
    /// Decrypts a block of data.
    pub fn unseal(self, blob: &[u8]) -> Result<PendingInMemoryDecryptorWrapper, Error> {
        Ok(PendingDecryptorWrapper {
            inner: self.inner.slice(blob)?,
        })
    }

    /// Decrypts a block of data in parallel.
    pub fn unseal_parallel(
        self,
        blob: &[u8],
    ) -> Result<PendingInMemoryParallelDecryptorWrapper, Error> {
        Ok(PendingDecryptorWrapper {
            inner: self.inner.slice_parallel(blob)?,
        })
    }

    /// Returns a `Read` stream that will decrypt data from an underlying reader.
    pub fn unseal_stream<'a, R: Read + 'a>(
        self,
        reader: R,
    ) -> Result<PendingStreamingDecryptorWrapper<'a, R>, Error> {
        Ok(PendingDecryptorWrapper {
            inner: self.inner.reader(reader)?,
        })
    }

    /// Returns a `PendingParallelStreamingDecryptorWrapper` that will decrypt data from an underlying reader in parallel.
    pub fn unseal_stream_parallel<'a, R: Read + Send + 'a>(
        self,
        reader: R,
    ) -> Result<PendingParallelStreamingDecryptorWrapper<'a, R>, Error> {
        Ok(PendingDecryptorWrapper {
            inner: self.inner.reader_parallel(reader)?,
        })
    }

    /// Returns an `AsyncRead` stream that will decrypt data from an underlying async reader.
    #[cfg(feature = "async")]
    pub async fn unseal_stream_async<'a, R: AsyncRead + Unpin + Send + 'a>(
        self,
        reader: R,
    ) -> Result<PendingAsyncStreamingDecryptorWrapper<'a, R>, Error> {
        Ok(PendingDecryptorWrapper {
            inner: self.inner.async_reader(reader).await?,
        })
    }
}
