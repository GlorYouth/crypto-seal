#![cfg(feature = "async-engine")]

use crate::asymmetric::traits::{AsymmetricCryptographicSystem, AsyncStreamingSystem};
use crate::common::errors::Error;
use crate::common::streaming::StreamingResult;
use crate::symmetric::primitives::async_streaming::{
    AsyncStreamingDecryptor as SymmetricAsyncDecryptor,
    AsyncStreamingEncryptor as SymmetricAsyncEncryptor,
};
use crate::symmetric::traits::SymmetricAsyncStreamingSystem;
use std::marker::PhantomData;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use crate::common::config::StreamingConfig;

/// 异步混合流式加密器
pub struct AsyncStreamingEncryptor<'a, C, R, W>
where
    C: AsymmetricCryptographicSystem,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    reader: R,
    writer: W,
    public_key: &'a C::PublicKey,
    config: StreamingConfig,
    additional_data: Option<Vec<u8>>,
    _phantom: PhantomData<C>,
}

impl<'a, C, R, W> AsyncStreamingEncryptor<'a, C, R, W>
where
    C: AsymmetricCryptographicSystem,
    C::Error: Send + Sync,
    C::PublicKey: Send + Sync,
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    pub fn new(
        reader: R,
        writer: W,
        public_key: &'a C::PublicKey,
        config: StreamingConfig,
        additional_data: Option<&[u8]>,
    ) -> Self {
        Self {
            reader,
            writer,
            public_key,
            config,
            additional_data: additional_data.map(|d| d.to_vec()),
            _phantom: PhantomData,
        }
    }

    pub async fn process<S>(mut self) -> Result<StreamingResult, Error>
    where
        S: SymmetricAsyncStreamingSystem,
        S::Key: Send + Sync,
        S::Error: Send,
        Error: From<C::Error> + From<S::Error>,
    {
        // 1. 生成一次性对称密钥
        let symmetric_key = S::generate_key(&Default::default())?;

        // 2. 封装对称密钥
        let exported_key = S::export_key(&symmetric_key)?;
        let encrypted_symmetric_key = C::encrypt(self.public_key, exported_key.as_bytes(), None)?;

        // 3. 写入头部
        let encrypted_key_bytes = encrypted_symmetric_key.to_string().into_bytes();
        let key_len = encrypted_key_bytes.len() as u32;
        self.writer.write_all(&key_len.to_le_bytes()).await?;
        self.writer.write_all(&encrypted_key_bytes).await?;

        // 4. 委托给对称异步流加密器
        let symmetric_encryptor = SymmetricAsyncEncryptor::<S, _, _>::new(
            self.reader,
            self.writer,
            &symmetric_key,
            self.config,
            self.additional_data.as_deref(),
        );

        symmetric_encryptor.process().await
    }
}

/// 异步混合流式解密器
pub struct AsyncStreamingDecryptor<'a, C, R, W>
where
    C: AsymmetricCryptographicSystem,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    reader: R,
    writer: W,
    private_key: &'a C::PrivateKey,
    config: StreamingConfig,
    additional_data: Option<Vec<u8>>,
    _phantom: PhantomData<C>,
}

impl<'a, C, R, W> AsyncStreamingDecryptor<'a, C, R, W>
where
    C: AsymmetricCryptographicSystem,
    C::Error: Send + Sync,
    C::PrivateKey: Send + Sync,
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    pub fn new(
        reader: R,
        writer: W,
        private_key: &'a C::PrivateKey,
        config: StreamingConfig,
        additional_data: Option<&[u8]>,
    ) -> Self {
        Self {
            reader,
            writer,
            private_key,
            config,
            additional_data: additional_data.map(|d| d.to_vec()),
            _phantom: PhantomData,
        }
    }

    pub async fn process<S>(mut self) -> Result<StreamingResult, Error>
    where
        S: SymmetricAsyncStreamingSystem,
        S::Key: Send + Sync,
        S::Error: Send,
        Error: From<C::Error> + From<S::Error>,
    {
        // 1. 读取头部
        let key_len = self.reader.read_u32_le().await? as usize;
        let mut encrypted_key_buf = vec![0u8; key_len];
        self.reader.read_exact(&mut encrypted_key_buf).await?;

        let encrypted_key_str = String::from_utf8(encrypted_key_buf)
            .map_err(|e| Error::Format(format!("无效的UTF-8密钥: {}", e)))?;

        // 2. 恢复对称密钥
        let decrypted_key_bytes = C::decrypt(self.private_key, &encrypted_key_str, None)?;

        let key_str = String::from_utf8(decrypted_key_bytes)
            .map_err(|e| Error::Format(format!("无效的UTF-8密钥: {}", e)))?;

        let symmetric_key = S::import_key(&key_str)?;

        // 3. 委托给对称异步流解密器
        let symmetric_decryptor = SymmetricAsyncDecryptor::<S, _, _>::new(
            self.reader,
            self.writer,
            &symmetric_key,
            self.config,
            self.additional_data.as_deref(),
        );

        symmetric_decryptor.process().await
    }
}

#[async_trait::async_trait]
impl<T> AsyncStreamingSystem for T
where
    T: AsymmetricCryptographicSystem + Send + Sync,
    T::Error: Send + Sync,
    T::PublicKey: Send + Sync,
    T::PrivateKey: Send + Sync,
    Error: From<T::Error>,
{
    async fn encrypt_stream_async<S, R, W>(
        public_key: &Self::PublicKey,
        reader: R,
        writer: W,
        config: &StreamingConfig,
        additional_data: Option<&[u8]>,
    ) -> Result<StreamingResult, Error>
    where
        S: SymmetricAsyncStreamingSystem,
        S::Key: Send + Sync,
        S::Error: Send,
        Error: From<S::Error>,
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send,
    {
        AsyncStreamingEncryptor::<Self, R, W>::new(
            reader,
            writer,
            public_key,
            config.clone(),
            additional_data,
        )
        .process::<S>()
        .await
    }

    async fn decrypt_stream_async<S, R, W>(
        private_key: &Self::PrivateKey,
        reader: R,
        writer: W,
        config: &StreamingConfig,
        additional_data: Option<&[u8]>,
    ) -> Result<StreamingResult, Error>
    where
        S: SymmetricAsyncStreamingSystem,
        S::Key: Send + Sync,
        S::Error: Send,
        Error: From<S::Error>,
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send,
    {
        AsyncStreamingDecryptor::<Self, R, W>::new(
            reader,
            writer,
            private_key,
            config.clone(),
            additional_data,
        )
        .process::<S>()
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asymmetric::systems::hybrid::rsa_kyber::RsaKyberCryptoSystem;
    use crate::common::config::CryptoConfig;
    use crate::symmetric::systems::aes_gcm::AesGcmSystem;
    use std::io::Cursor;
    use tokio::io::BufReader;

    #[tokio::test]
    async fn test_async_hybrid_streaming_roundtrip() {
        let (pk, sk) = RsaKyberCryptoSystem::generate_keypair(&CryptoConfig::default()).unwrap();
        let config = StreamingConfig {
            buffer_size: 256,
            ..Default::default()
        };
        let original_data =
            b"This is a long test string for async hybrid streaming encryption.".to_vec();

        // Encrypt
        let source = BufReader::new(Cursor::new(original_data.clone()));
        let mut encrypted_dest = Vec::new();
        RsaKyberCryptoSystem::encrypt_stream_async::<AesGcmSystem, _, _>(
            &pk,
            source,
            &mut encrypted_dest,
            &config,
            None,
        )
        .await
        .unwrap();

        // Decrypt
        let encrypted_source = BufReader::new(Cursor::new(encrypted_dest));
        let mut decrypted_dest = Vec::new();
        RsaKyberCryptoSystem::decrypt_stream_async::<AesGcmSystem, _, _>(
            &sk,
            encrypted_source,
            &mut decrypted_dest,
            &config,
            None,
        )
        .await
        .unwrap();

        assert_eq!(original_data, decrypted_dest);
    }

    #[tokio::test]
    async fn test_async_hybrid_streaming_with_aad() {
        let (pk, sk) = RsaKyberCryptoSystem::generate_keypair(&CryptoConfig::default()).unwrap();
        let config = StreamingConfig {
            buffer_size: 256,
            ..Default::default()
        };
        let original_data = b"Some data to be protected by async streaming with AAD.".to_vec();
        let aad = b"additional authenticated data for the async stream";

        // Encrypt
        let source = BufReader::new(Cursor::new(original_data.clone()));
        let mut encrypted_dest = Vec::new();
        RsaKyberCryptoSystem::encrypt_stream_async::<AesGcmSystem, _, _>(
            &pk,
            source,
            &mut encrypted_dest,
            &config,
            Some(aad),
        )
        .await
        .unwrap();

        // Decrypt
        let encrypted_source = BufReader::new(Cursor::new(encrypted_dest));
        let mut decrypted_dest = Vec::new();
        RsaKyberCryptoSystem::decrypt_stream_async::<AesGcmSystem, _, _>(
            &sk,
            encrypted_source,
            &mut decrypted_dest,
            &config,
            Some(aad),
        )
        .await
        .unwrap();

        assert_eq!(original_data, decrypted_dest);
    }

    #[tokio::test]
    async fn test_async_hybrid_streaming_tampered_header_fails() {
        let (pk, sk) = RsaKyberCryptoSystem::generate_keypair(&CryptoConfig::default()).unwrap();
        let config = StreamingConfig {
            buffer_size: 256,
            ..Default::default()
        };
        let original_data = b"Tampering the header must lead to failure.".to_vec();

        // Encrypt
        let source = BufReader::new(Cursor::new(original_data.clone()));
        let mut encrypted_dest = Vec::new();
        RsaKyberCryptoSystem::encrypt_stream_async::<AesGcmSystem, _, _>(
            &pk,
            source,
            &mut encrypted_dest,
            &config,
            None,
        )
        .await
        .unwrap();

        // Tamper with the header (encrypted symmetric key)
        let mut tampered_data = encrypted_dest;
        if tampered_data.len() > 10 {
            tampered_data[10] ^= 0xff; // Flip a bit in the encrypted key part
        }

        // Decrypt should fail
        let tampered_source = BufReader::new(Cursor::new(tampered_data));
        let mut decrypted_dest = Vec::new();
        let result = RsaKyberCryptoSystem::decrypt_stream_async::<AesGcmSystem, _, _>(
            &sk,
            tampered_source,
            &mut decrypted_dest,
            &config,
            None,
        )
        .await;

        assert!(
            result.is_err(),
            "Decryption with tampered header should have failed"
        );
    }

    #[tokio::test]
    async fn test_async_hybrid_streaming_tampered_body_fails() {
        let (pk, sk) = RsaKyberCryptoSystem::generate_keypair(&CryptoConfig::default()).unwrap();
        let config = StreamingConfig {
            buffer_size: 256,
            ..Default::default()
        };
        let original_data = b"Tampering the body must lead to failure.".to_vec();

        // Encrypt
        let source = BufReader::new(Cursor::new(original_data.clone()));
        let mut encrypted_dest = Vec::new();
        RsaKyberCryptoSystem::encrypt_stream_async::<AesGcmSystem, _, _>(
            &pk,
            source,
            &mut encrypted_dest,
            &config,
            None,
        )
        .await
        .unwrap();

        // Tamper with the body
        let mut tampered_data = encrypted_dest;
        let data_len = tampered_data.len();
        if data_len > 0 {
            tampered_data[data_len - 10] ^= 0xff; // Flip a bit towards the end of the stream
        }

        // Decrypt should fail
        let tampered_source = BufReader::new(Cursor::new(tampered_data));
        let mut decrypted_dest = Vec::new();
        let result = RsaKyberCryptoSystem::decrypt_stream_async::<AesGcmSystem, _, _>(
            &sk,
            tampered_source,
            &mut decrypted_dest,
            &config,
            None,
        )
        .await;

        assert!(
            result.is_err(),
            "Decryption with tampered body should have failed"
        );
    }
}
