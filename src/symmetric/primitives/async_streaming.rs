#![cfg(feature = "async-engine")]

use std::marker::PhantomData;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use crate::common::errors::Error;
use crate::common::streaming::{StreamingConfig, StreamingResult};
use crate::symmetric::traits::{SymmetricCryptographicSystem, SymmetricAsyncStreamingSystem};
use crate::common::utils;

/// 异步对称流式加密器
pub struct AsyncStreamingEncryptor<'a, C, R, W>
where
    C: SymmetricCryptographicSystem,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    Error: From<C::Error>,
{
    reader: R,
    writer: W,
    key: &'a C::Key,
    config: StreamingConfig,
    additional_data: Option<&'a [u8]>,
    _phantom: PhantomData<C>,
}

impl<'a, C, R, W> AsyncStreamingEncryptor<'a, C, R, W>
where
    C: SymmetricCryptographicSystem,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    Error: From<C::Error>,
{
    pub fn new(
        reader: R,
        writer: W,
        key: &'a C::Key,
        config: StreamingConfig,
        additional_data: Option<&'a [u8]>,
    ) -> Self {
        Self { reader, writer, key, config, additional_data, _phantom: PhantomData }
    }

    pub async fn process(mut self) -> Result<StreamingResult, Error> {
        let mut buffer = vec![0u8; self.config.buffer_size];
        let mut total_written = 0;
        let mut bytes_processed = 0;

        while let Ok(read_bytes) = self.reader.read(&mut buffer).await {
            if read_bytes == 0 { break; }
            bytes_processed += read_bytes as u64;
            
            let plaintext = &buffer[..read_bytes];
            let ciphertext_obj = C::encrypt(self.key, plaintext, self.additional_data)?;
            let ciphertext_bytes = ciphertext_obj.to_string().into_bytes();
            
            let len = (ciphertext_bytes.len() as u32).to_le_bytes();
            self.writer.write_all(&len).await.map_err(Error::Io)?;
            self.writer.write_all(&ciphertext_bytes).await.map_err(Error::Io)?;
            total_written += read_bytes as u64;

            if let Some(cb) = &self.config.progress_callback {
                cb(bytes_processed, self.config.total_bytes);
            }
        }
        self.writer.flush().await.map_err(Error::Io)?;
        Ok(StreamingResult { bytes_processed: total_written, buffer: None })
    }
}

/// 异步对称流式解密器
pub struct AsyncStreamingDecryptor<'a, C, R, W>
where
    C: SymmetricCryptographicSystem,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    Error: From<C::Error>,
{
    reader: R,
    writer: W,
    key: &'a C::Key,
    config: StreamingConfig,
    additional_data: Option<&'a [u8]>,
    _phantom: PhantomData<C>,
}

impl<'a, C, R, W> AsyncStreamingDecryptor<'a, C, R, W>
where
    C: SymmetricCryptographicSystem,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    Error: From<C::Error>,
{
    pub fn new(
        reader: R,
        writer: W,
        key: &'a C::Key,
        config: StreamingConfig,
        additional_data: Option<&'a [u8]>,
    ) -> Self {
        Self { reader, writer, key, config, additional_data, _phantom: PhantomData }
    }

    pub async fn process(mut self) -> Result<StreamingResult, Error> {
        let mut total_written = 0;
        let mut bytes_processed = 0;
        let mut len_buf = [0u8; 4];

        while self.reader.read_exact(&mut len_buf).await.is_ok() {
            let block_size = u32::from_le_bytes(len_buf) as usize;
            let mut ciphertext_buffer = vec![0u8; block_size];
            self.reader.read_exact(&mut ciphertext_buffer).await.map_err(Error::Io)?;
            bytes_processed += (4 + block_size) as u64;
            
            let ciphertext_str = String::from_utf8(ciphertext_buffer)
                .map_err(|e| Error::Format(format!("无效的UTF-8密文: {}", e)))?;
            
            let plaintext = C::decrypt(self.key, &ciphertext_str, self.additional_data)?;
            
            self.writer.write_all(&plaintext).await.map_err(Error::Io)?;
            total_written += plaintext.len() as u64;

            if let Some(cb) = &self.config.progress_callback {
                cb(bytes_processed, self.config.total_bytes);
            }
        }
        self.writer.flush().await.map_err(Error::Io)?;
        Ok(StreamingResult { bytes_processed: total_written, buffer: None })
    }
}

/// 为所有实现 `SymmetricCryptographicSystem` 的类型提供 `SymmetricAsyncStreamingSystem` 的默认实现
#[async_trait::async_trait]
impl<T> SymmetricAsyncStreamingSystem for T
where
    T: SymmetricCryptographicSystem + Send + Sync,
    T::Key: Send + Sync,
    T::Error: Send,
    Error: From<T::Error>,
{
    async fn encrypt_stream_async<R, W>(
        key: &Self::Key,
        reader: R,
        writer: W,
        config: &StreamingConfig,
        additional_data: Option<&[u8]>,
    ) -> Result<StreamingResult, Error>
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send,
    {
        AsyncStreamingEncryptor::<Self, R, W>::new(reader, writer, key, config.clone(), additional_data).process().await
    }

    async fn decrypt_stream_async<R, W>(
        key: &Self::Key,
        reader: R,
        writer: W,
        config: &StreamingConfig,
        additional_data: Option<&[u8]>,
    ) -> Result<StreamingResult, Error>
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send,
    {
        AsyncStreamingDecryptor::<Self, R, W>::new(reader, writer, key, config.clone(), additional_data).process().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::utils::CryptoConfig;
    use crate::symmetric::systems::aes_gcm::AesGcmSystem;
    use tokio::io::BufReader;
    use std::io::Cursor;

    fn get_test_key_and_config() -> (
        <AesGcmSystem as SymmetricCryptographicSystem>::Key,
        StreamingConfig,
    ) {
        let key = AesGcmSystem::generate_key(&CryptoConfig::default()).unwrap();
        let config = StreamingConfig {
            buffer_size: 256,
            ..Default::default()
        };
        (key, config)
    }

    #[tokio::test]
    async fn test_async_streaming_roundtrip() {
        let (key, config) = get_test_key_and_config();
        let original_data = b"This is a test for async streaming encryption.".to_vec();

        // Encrypt
        let source = BufReader::new(Cursor::new(original_data.clone()));
        let mut encrypted_dest = Vec::new();
        AesGcmSystem::encrypt_stream_async(&key, source, &mut encrypted_dest, &config, None)
            .await
            .unwrap();

        // Decrypt
        let encrypted_source = BufReader::new(Cursor::new(encrypted_dest));
        let mut decrypted_dest = Vec::new();
        AesGcmSystem::decrypt_stream_async(&key, encrypted_source, &mut decrypted_dest, &config, None)
            .await
            .unwrap();

        assert_eq!(original_data, decrypted_dest);
    }

    #[tokio::test]
    async fn test_async_streaming_with_aad() {
        let (key, config) = get_test_key_and_config();
        let original_data = b"Async streaming with AAD.".to_vec();
        let aad = b"my_aad";

        // Encrypt
        let source = BufReader::new(Cursor::new(original_data.clone()));
        let mut encrypted_dest = Vec::new();
        AesGcmSystem::encrypt_stream_async(&key, source, &mut encrypted_dest, &config, Some(aad))
            .await
            .unwrap();

        // Decrypt
        let encrypted_source = BufReader::new(Cursor::new(encrypted_dest));
        let mut decrypted_dest = Vec::new();
        AesGcmSystem::decrypt_stream_async(&key, encrypted_source, &mut decrypted_dest, &config, Some(aad))
            .await
            .unwrap();
        
        assert_eq!(original_data, decrypted_dest);
    }

    #[tokio::test]
    async fn test_async_streaming_tampered_fails() {
        let (key, config) = get_test_key_and_config();
        let original_data = b"This data will be tampered.".to_vec();
        let aad = b"some_aad_here";

        // Encrypt
        let source = BufReader::new(Cursor::new(original_data.clone()));
        let mut encrypted_dest = Vec::new();
        AesGcmSystem::encrypt_stream_async(&key, source, &mut encrypted_dest, &config, Some(aad))
            .await
            .unwrap();

        // Tamper
        let len = encrypted_dest.len();
        if len > 0 {
            encrypted_dest[len / 2] ^= 0xff;
        }

        // Decrypt
        let encrypted_source = BufReader::new(Cursor::new(encrypted_dest));
        let mut decrypted_dest = Vec::new();
        let result =
            AesGcmSystem::decrypt_stream_async(&key, encrypted_source, &mut decrypted_dest, &config, Some(aad))
                .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_async_streaming_empty_input() {
        let (key, config) = get_test_key_and_config();
        let original_data = b"".to_vec();

        let source = BufReader::new(Cursor::new(original_data.clone()));
        let mut encrypted_dest = Vec::new();
        AesGcmSystem::encrypt_stream_async(&key, source, &mut encrypted_dest, &config, None)
            .await
            .unwrap();

        let encrypted_source = BufReader::new(Cursor::new(encrypted_dest));
        let mut decrypted_dest = Vec::new();
        AesGcmSystem::decrypt_stream_async(&key, encrypted_source, &mut decrypted_dest, &config, None)
            .await
            .unwrap();

        assert_eq!(original_data, decrypted_dest);
    }
    
    #[tokio::test]
    async fn test_async_streaming_multiple_buffer_sizes() {
        let (key, mut config) = get_test_key_and_config();
        config.buffer_size = 64;

        let data_cases = vec![
            vec![1u8; 32],
            vec![2u8; 64],
            vec![3u8; 150],
        ];

        for original_data in data_cases {
            let source = BufReader::new(Cursor::new(original_data.clone()));
            let mut encrypted_dest = Vec::new();
            AesGcmSystem::encrypt_stream_async(&key, source, &mut encrypted_dest, &config, None)
                .await
                .unwrap();

            let encrypted_source = BufReader::new(Cursor::new(encrypted_dest));
            let mut decrypted_dest = Vec::new();
            AesGcmSystem::decrypt_stream_async(&key, encrypted_source, &mut decrypted_dest, &config, None)
                .await
                .unwrap();

            assert_eq!(original_data, decrypted_dest);
        }
    }
    
    #[tokio::test]
    async fn test_async_streaming_progress_callback() {
        use std::sync::{Arc, Mutex};

        let (key, mut config) = get_test_key_and_config();
        let original_data = vec![0u8; 1024];
        config.buffer_size = 256;
        config.total_bytes = Some(original_data.len() as u64);

        let progress_calls = Arc::new(Mutex::new(Vec::new()));
        let progress_calls_clone = progress_calls.clone();

        config.progress_callback = Some(Arc::new(move |processed, total| {
            progress_calls_clone.lock().unwrap().push((processed, total));
        }));
        
        let source = BufReader::new(Cursor::new(original_data));
        let mut encrypted_dest = Vec::new();
        AesGcmSystem::encrypt_stream_async(&key, source, &mut encrypted_dest, &config, None)
            .await
            .unwrap();

        let calls = progress_calls.lock().unwrap();
        assert_eq!(calls.len(), 4);
        assert_eq!(calls[3], (1024, Some(1024)));
    }
    
    #[tokio::test]
    async fn test_async_streaming_incomplete_data_fails() {
        let (key, config) = get_test_key_and_config();
        
        let mut encrypted_data = (100u32).to_le_bytes().to_vec();
        encrypted_data.extend_from_slice(&[0u8; 50]);
        let encrypted_source = BufReader::new(Cursor::new(encrypted_data));
        let mut decrypted_dest = Vec::new();
        let result = AesGcmSystem::decrypt_stream_async(&key, encrypted_source, &mut decrypted_dest, &config, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_async_streaming_wrong_aad_fails() {
        let (key, config) = get_test_key_and_config();
        let original_data = b"some data".to_vec();
        let aad1 = b"correct aad";
        let aad2 = b"wrong aad";

        let source = BufReader::new(Cursor::new(original_data));
        let mut encrypted_dest = Vec::new();
        AesGcmSystem::encrypt_stream_async(&key, source, &mut encrypted_dest, &config, Some(aad1))
            .await
            .unwrap();

        let encrypted_source = BufReader::new(Cursor::new(encrypted_dest));
        let mut decrypted_dest = Vec::new();
        let result = AesGcmSystem::decrypt_stream_async(&key, encrypted_source, &mut decrypted_dest, &config, Some(aad2)).await;
        assert!(result.is_err());
    }
} 