#![cfg(feature = "parallel")]

//! 使用混合加密实现并行流式加解密。
//!
//! 这个模块重用了对称加密的并行流处理器来处理数据主体部分，
//! 而自身只负责处理一次性的对称密钥的封装和恢复。

use crate::asymmetric::traits::{AsymmetricCryptographicSystem, AsymmetricParallelStreamingSystem};
use crate::common::errors::Error;
use crate::common::streaming::{StreamingConfig, StreamingResult};
use crate::symmetric::traits::SymmetricCryptographicSystem;
use std::io::{Read, Write};

/// 为所有 `AsymmetricCryptographicSystem` 实现 `AsymmetricParallelStreamingSystem`。
impl<T> AsymmetricParallelStreamingSystem for T
where
    T: AsymmetricCryptographicSystem,
    Error: From<T::Error>,
{
    /// 执行混合并行流式加密操作
    fn par_encrypt_stream<S, R, W>(
        public_key: &Self::PublicKey,
        reader: R,
        mut writer: W,
        config: &StreamingConfig,
        additional_data: Option<&[u8]>,
    ) -> Result<StreamingResult, Error>
    where
        S: crate::symmetric::traits::SymmetricParallelStreamingSystem,
        Error: From<S::Error>,
        R: Read + Send,
        W: Write + Send,
    {
        // 1. 生成一次性对称密钥
        let symmetric_key = S::generate_key(&Default::default())?;

        // 2. 使用非对称公钥加密对称密钥
        let exported_key = S::export_key(&symmetric_key)?;
        let encrypted_symmetric_key = T::encrypt(public_key, exported_key.as_bytes(), None)?;

        // 3. 写入头部
        let encrypted_key_bytes = encrypted_symmetric_key.to_string().into_bytes();
        let key_len = encrypted_key_bytes.len() as u32;
        writer.write_all(&key_len.to_le_bytes())?;
        writer.write_all(&encrypted_key_bytes)?;

        // 4. **关键**: 使用对称并行流加密器处理剩余的数据流
        S::par_encrypt_stream(&symmetric_key, reader, writer, config, additional_data)
    }

    /// 执行混合并行流式解密操作
    fn par_decrypt_stream<S, R, W>(
        private_key: &Self::PrivateKey,
        mut reader: R,
        writer: W,
        config: &StreamingConfig,
        additional_data: Option<&[u8]>,
    ) -> Result<StreamingResult, Error>
    where
        S: crate::symmetric::traits::SymmetricParallelStreamingSystem,
        Error: From<S::Error>,
        R: Read + Send,
        W: Write + Send,
    {
        // 1. 读取头部
        let mut key_len_buf = [0u8; 4];
        reader.read_exact(&mut key_len_buf)?;
        let key_len = u32::from_le_bytes(key_len_buf) as usize;

        let mut encrypted_key_buf = vec![0u8; key_len];
        reader.read_exact(&mut encrypted_key_buf)?;

        let encrypted_key_str = String::from_utf8(encrypted_key_buf)
            .map_err(|e| Error::Format(format!("无效的UTF-8密钥: {}", e)))?;

        // 2. 解密对称密钥
        let decrypted_key_bytes = T::decrypt(private_key, &encrypted_key_str, None)?;
        let key_str = String::from_utf8(decrypted_key_bytes)
            .map_err(|e| Error::Format(format!("无效的UTF-8密钥: {}", e)))?;
        let symmetric_key = S::import_key(&key_str)?;

        // 3. **关键**: 使用对称并行流解密器处理剩余的数据流
        S::par_decrypt_stream(&symmetric_key, reader, writer, config, additional_data)
    }
}

#[cfg(all(feature = "parallel", feature = "async-engine"))]
mod async_impl {
    use super::*;
    use crate::asymmetric::traits::AsymmetricAsyncParallelStreamingSystem;
    use crate::symmetric::traits::SymmetricAsyncParallelStreamingSystem;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

    #[async_trait::async_trait]
    impl<T> AsymmetricAsyncParallelStreamingSystem for T
    where
        T: AsymmetricCryptographicSystem + Send + Sync,
        T::PublicKey: Send + Sync + 'static,
        T::PrivateKey: Send + Sync + 'static,
        T::Error: Send,
        Error: From<T::Error>,
    {
        async fn par_encrypt_stream_async<S, R, W>(
            public_key: &Self::PublicKey,
            reader: R,
            mut writer: W,
            config: &StreamingConfig,
            additional_data: Option<&[u8]>,
        ) -> Result<(StreamingResult, W), Error>
        where
            S: SymmetricAsyncParallelStreamingSystem + 'static,
            S::Key: Send + Sync,
            S::Error: Send,
            Error: From<S::Error>,
            R: AsyncRead + Unpin + Send + 'static,
            W: AsyncWrite + Unpin + Send + 'static,
        {
            let symmetric_key = S::generate_key(&Default::default())?;
            let exported_key = S::export_key(&symmetric_key)?;
            let encrypted_symmetric_key = T::encrypt(public_key, exported_key.as_bytes(), None)?;

            let encrypted_key_bytes = encrypted_symmetric_key.to_string().into_bytes();
            let key_len = (encrypted_key_bytes.len() as u32).to_le_bytes();
            writer.write_all(&key_len).await?;
            writer.write_all(&encrypted_key_bytes).await?;

            S::par_encrypt_stream_async(&symmetric_key, reader, writer, config, additional_data)
                .await
        }

        async fn par_decrypt_stream_async<S, R, W>(
            private_key: &Self::PrivateKey,
            mut reader: R,
            writer: W,
            config: &StreamingConfig,
            additional_data: Option<&[u8]>,
        ) -> Result<(StreamingResult, W), Error>
        where
            S: SymmetricAsyncParallelStreamingSystem + 'static,
            S::Key: Send + Sync,
            S::Error: Send,
            Error: From<S::Error>,
            R: AsyncRead + Unpin + Send + 'static,
            W: AsyncWrite + Unpin + Send + 'static,
        {
            let mut key_len_buf = [0u8; 4];
            reader.read_exact(&mut key_len_buf).await?;
            let key_len = u32::from_le_bytes(key_len_buf) as usize;

            let mut encrypted_key_buf = vec![0u8; key_len];
            reader.read_exact(&mut encrypted_key_buf).await?;

            let encrypted_key_str = String::from_utf8(encrypted_key_buf)?;
            let decrypted_key_bytes = T::decrypt(private_key, &encrypted_key_str, None)?;

            let key_str = String::from_utf8(decrypted_key_bytes)?;
            let symmetric_key = S::import_key(&key_str)?;

            S::par_decrypt_stream_async(&symmetric_key, reader, writer, config, additional_data)
                .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asymmetric::systems::hybrid::rsa_kyber::RsaKyberCryptoSystem;
    use crate::common::utils::CryptoConfig;
    use crate::symmetric::systems::aes_gcm::AesGcmSystem;
    use std::io::Cursor;

    #[test]
    fn test_hybrid_parallel_streaming_roundtrip() {
        // Setup
        let (pk, sk) = RsaKyberCryptoSystem::generate_keypair(&CryptoConfig::default()).unwrap();
        let config = StreamingConfig {
            buffer_size: 2048, // Use a small buffer to ensure multiple chunks
            ..Default::default()
        };
        let original_data = vec![0xFE; config.buffer_size * 4 + 777]; // Data larger than buffer

        // Encrypt in parallel
        let mut source = Cursor::new(original_data.clone());
        let mut encrypted_dest = Cursor::new(Vec::new());
        let enc_result = RsaKyberCryptoSystem::par_encrypt_stream::<AesGcmSystem, _, _>(
            &pk,
            &mut source,
            &mut encrypted_dest,
            &config,
            None,
        )
        .unwrap();

        assert_eq!(enc_result.bytes_processed, original_data.len() as u64);

        // Decrypt in parallel
        let mut encrypted_source = Cursor::new(encrypted_dest.into_inner());
        let mut decrypted_dest = Cursor::new(Vec::new());
        let dec_result = RsaKyberCryptoSystem::par_decrypt_stream::<AesGcmSystem, _, _>(
            &sk,
            &mut encrypted_source,
            &mut decrypted_dest,
            &config,
            None,
        )
        .unwrap();

        let decrypted_data = decrypted_dest.into_inner();
        assert_eq!(dec_result.bytes_processed, original_data.len() as u64);
        assert_eq!(decrypted_data, original_data);
    }
}
