#![cfg(feature = "async-engine")]

//! Implements asynchronous streaming for symmetric encryption using Tokio.
// English: Implements asynchronous streaming for symmetric encryption using Tokio.

use crate::common::config::StreamingConfig;
use crate::common::streaming::StreamingResult;
use crate::symmetric::errors::SymmetricError;
use crate::symmetric::traits::{SymmetricAsyncStreamingSystem, SymmetricCryptographicSystem};
use std::marker::PhantomData;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// `AsyncStreamingEncryptor` handles the process of encrypting a stream of data asynchronously.
/// It reads data in chunks from an `AsyncRead`, encrypts each chunk, and writes it to an `AsyncWrite`.
/// This implementation is non-blocking.
///
/// 中文: `AsyncStreamingEncryptor` 异步地处理加密数据流的过程。
/// 它从一个 `AsyncRead` 中以块的形式读取数据，加密每个块，然后将其写入一个 `AsyncWrite`。
/// 这个实现是非阻塞的。
pub struct AsyncStreamingEncryptor<'a, C, R, W>
where
    C: SymmetricCryptographicSystem,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    SymmetricError: From<<C as SymmetricCryptographicSystem>::Error>,
{
    reader: R,
    writer: W,
    key: &'a C::Key,
    config: StreamingConfig,
    additional_data: Option<&'a [u8]>,
    chunk_index: u64,
    _phantom: PhantomData<C>,
}

impl<'a, C, R, W> AsyncStreamingEncryptor<'a, C, R, W>
where
    C: SymmetricCryptographicSystem,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    SymmetricError: From<<C as SymmetricCryptographicSystem>::Error>,
{
    /// Creates a new `AsyncStreamingEncryptor`.
    ///
    /// 中文: 创建一个新的 `AsyncStreamingEncryptor`。
    pub fn new(
        reader: R,
        writer: W,
        key: &'a C::Key,
        config: StreamingConfig,
        additional_data: Option<&'a [u8]>,
    ) -> Self {
        Self {
            reader,
            writer,
            key,
            config,
            additional_data,
            chunk_index: 0,
            _phantom: PhantomData,
        }
    }

    /// Processes the entire input stream asynchronously, encrypting it chunk by chunk.
    ///
    /// Similar to its synchronous counterpart, it constructs a unique AAD for each chunk
    /// by combining the global AAD with the chunk index. This prevents reordering and replay attacks
    /// in a streaming context. All I/O operations are `await`ed.
    ///
    /// 中文: 异步地逐块处理整个输入流并进行加密。
    ///
    /// 与其同步版本类似，它通过将全局 AAD 与块索引相结合，为每个块构造一个唯一的 AAD。
    /// 这可以防止在流式传输上下文中的重排序和重放攻击。所有的 I/O 操作都是 `await` 的。
    pub async fn process(mut self) -> Result<(StreamingResult, W), SymmetricError> {
        let mut buffer = vec![0u8; self.config.buffer_size];
        let mut total_written = 0;
        let mut bytes_processed = 0;

        while let Ok(read_bytes) = self.reader.read(&mut buffer).await {
            if read_bytes == 0 {
                break;
            }
            bytes_processed += read_bytes as u64;

            let plaintext = &buffer[..read_bytes];

            // Construct AAD with chunk index to prevent reordering attacks.
            // 中文: 构造包含块索引的 AAD 以防止重排序攻击。
            let mut aad = self.additional_data.map_or_else(Vec::new, |d| d.to_vec());
            aad.extend_from_slice(&self.chunk_index.to_le_bytes());

            let ciphertext = C::encrypt(self.key, plaintext, Some(&aad))?;
            let ciphertext_bytes = ciphertext.as_ref();

            // The ciphertext from C::encrypt already contains the length prefix.
            // We just need to write it directly to the stream.
            // 中文: C::encrypt 返回的密文已经包含了长度前缀，
            // 我们只需要直接将其写入流中即可。
            self.writer
                .write_all(ciphertext_bytes)
                .await
                .map_err(SymmetricError::Io)?;

            total_written += read_bytes as u64;
            self.chunk_index += 1;

            if let Some(cb) = &self.config.progress_callback {
                cb(bytes_processed, self.config.total_bytes);
            }
        }
        self.writer.flush().await.map_err(SymmetricError::Io)?;
        Ok((
            StreamingResult {
                bytes_processed: total_written,
                buffer: None,
            },
            self.writer,
        ))
    }
}

/// `AsyncStreamingDecryptor` handles the process of decrypting a stream of data asynchronously.
/// It reads encrypted chunks from an `AsyncRead`, decrypts them, and writes the plaintext to an `AsyncWrite`.
///
/// 中文: `AsyncStreamingDecryptor` 异步地处理解密数据流的过程。
/// 它从一个 `AsyncRead` 中读取加密的块，解密它们，然后将明文写入一个 `AsyncWrite`。
pub struct AsyncStreamingDecryptor<'a, C, R, W>
where
    C: SymmetricCryptographicSystem,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    SymmetricError: From<<C as SymmetricCryptographicSystem>::Error>,
{
    reader: R,
    writer: W,
    key: &'a C::Key,
    config: StreamingConfig,
    additional_data: Option<&'a [u8]>,
    chunk_index: u64,
    _phantom: PhantomData<C>,
}

impl<'a, C, R, W> AsyncStreamingDecryptor<'a, C, R, W>
where
    C: SymmetricCryptographicSystem,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    SymmetricError: From<<C as SymmetricCryptographicSystem>::Error>,
{
    /// Creates a new `AsyncStreamingDecryptor`.
    ///
    /// 中文: 创建一个新的 `AsyncStreamingDecryptor`。
    pub fn new(
        reader: R,
        writer: W,
        key: &'a C::Key,
        config: StreamingConfig,
        additional_data: Option<&'a [u8]>,
    ) -> Self {
        Self {
            reader,
            writer,
            key,
            config,
            additional_data,
            chunk_index: 0,
            _phantom: PhantomData,
        }
    }

    /// Processes the entire encrypted stream asynchronously, decrypting it chunk by chunk.
    ///
    /// It reads length-prefixed chunks and reconstructs the same AAD (global AAD + chunk index)
    /// used during encryption to verify the integrity and authenticity of each chunk.
    /// All I/O operations are non-blocking and `await`ed.
    ///
    /// 中文: 异步地逐块处理整个加密流并进行解密。
    ///
    /// 它读取带有长度前缀的块，并重建加密时使用的相同 AAD（全局 AAD + 块索引），
    /// 以验证每个块的完整性和真实性。所有 I/O 操作都是非阻塞的并 `await` 的。
    pub async fn process(mut self) -> Result<(StreamingResult, W), SymmetricError> {
        let mut total_written = 0;
        let mut bytes_processed = 0;
        let mut len_buf = [0u8; 4];

        while self.reader.read_exact(&mut len_buf).await.is_ok() {
            let block_size = u32::from_le_bytes(len_buf) as usize;
            let mut ciphertext_buffer = vec![0u8; block_size];
            self.reader
                .read_exact(&mut ciphertext_buffer)
                .await
                .map_err(SymmetricError::Io)?;
            bytes_processed += (4 + block_size) as u64;

            // Reconstruct the exact same AAD as used in encryption.
            // 中文: 重构与加密时完全相同的 AAD。
            let mut aad = self.additional_data.map_or_else(Vec::new, |d| d.to_vec());
            aad.extend_from_slice(&self.chunk_index.to_le_bytes());

            // C::decrypt needs a complete block with length prefix.
            // 中文: C::decrypt 需要一个带有长度前缀的完整块。
            let mut block_with_len = len_buf.to_vec();
            block_with_len.extend_from_slice(&ciphertext_buffer);

            let plaintext = C::decrypt(self.key, &block_with_len, Some(&aad))?;
            self.chunk_index += 1;

            self.writer
                .write_all(&plaintext)
                .await
                .map_err(SymmetricError::Io)?;
            total_written += plaintext.len() as u64;

            if let Some(cb) = &self.config.progress_callback {
                cb(bytes_processed, self.config.total_bytes);
            }
        }
        self.writer.flush().await.map_err(SymmetricError::Io)?;
        Ok((
            StreamingResult {
                bytes_processed: total_written,
                buffer: None,
            },
            self.writer,
        ))
    }
}

/// Provides a default implementation of `SymmetricAsyncStreamingSystem` for any type
/// that implements `SymmetricCryptographicSystem`. This blanket implementation allows any
/// core symmetric algorithm to be used for asynchronous streaming out-of-the-box,
/// provided the `async-engine` feature is enabled.
///
/// 中文: 为任何实现了 `SymmetricCryptographicSystem` 的类型提供 `SymmetricAsyncStreamingSystem` 的默认实现。
/// 这个毯式实现允许任何核心对称算法在启用 `async-engine` 功能的情况下，
/// 开箱即用地用于异步流式处理。
#[async_trait::async_trait]
impl<T> SymmetricAsyncStreamingSystem for T
where
    T: SymmetricCryptographicSystem + Send + Sync,
    T::Key: Send + Sync,
    T::Error: Send,
    SymmetricError: From<<T as SymmetricCryptographicSystem>::Error>,
{
    async fn encrypt_stream_async<R, W>(
        key: &Self::Key,
        reader: R,
        writer: W,
        config: &StreamingConfig,
        additional_data: Option<&[u8]>,
    ) -> Result<(StreamingResult, W), SymmetricError>
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send,
    {
        AsyncStreamingEncryptor::<Self, R, W>::new(
            reader,
            writer,
            key,
            config.clone(),
            additional_data,
        )
        .process()
        .await
    }

    async fn decrypt_stream_async<R, W>(
        key: &Self::Key,
        reader: R,
        writer: W,
        config: &StreamingConfig,
        additional_data: Option<&[u8]>,
    ) -> Result<(StreamingResult, W), SymmetricError>
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send,
    {
        AsyncStreamingDecryptor::<Self, R, W>::new(
            reader,
            writer,
            key,
            config.clone(),
            additional_data,
        )
        .process()
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::config::CryptoConfig;
    use crate::symmetric::systems::aes_gcm::AesGcmSystem;
    use std::io::Cursor;
    use tokio::io::BufReader;

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
        let (_, encrypted_dest) =
            AesGcmSystem::encrypt_stream_async(&key, source, &mut encrypted_dest, &config, None)
                .await
                .unwrap();

        // Decrypt
        let encrypted_source = BufReader::new(Cursor::new(encrypted_dest));
        let mut decrypted_dest = Vec::new();
        let (_, decrypted_dest) = AesGcmSystem::decrypt_stream_async(
            &key,
            encrypted_source,
            &mut decrypted_dest,
            &config,
            None,
        )
        .await
        .unwrap();

        assert_eq!(original_data, *decrypted_dest);
    }

    #[tokio::test]
    async fn test_async_streaming_with_aad() {
        let (key, config) = get_test_key_and_config();
        let original_data = b"Async streaming with AAD.".to_vec();
        let aad = b"my_aad";

        // Encrypt
        let source = BufReader::new(Cursor::new(original_data.clone()));
        let mut encrypted_dest = Vec::new();
        let (_, encrypted_dest) = AesGcmSystem::encrypt_stream_async(
            &key,
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
        let (_, decrypted_dest) = AesGcmSystem::decrypt_stream_async(
            &key,
            encrypted_source,
            &mut decrypted_dest,
            &config,
            Some(aad),
        )
        .await
        .unwrap();

        assert_eq!(original_data, *decrypted_dest);
    }

    #[tokio::test]
    async fn test_async_streaming_tampered_fails() {
        let (key, config) = get_test_key_and_config();
        let original_data = b"This data will be tampered.".to_vec();

        // Encrypt
        let source = BufReader::new(Cursor::new(original_data.clone()));
        let mut encrypted_dest = Vec::new();
        let (_, _) =
            AesGcmSystem::encrypt_stream_async(&key, source, &mut encrypted_dest, &config, None)
                .await
                .unwrap();

        // Tamper
        let len = encrypted_dest.len();
        if len > 0 {
            encrypted_dest[len / 2] ^= 0xff;
        }

        // Decrypt should fail
        let encrypted_source = BufReader::new(Cursor::new(encrypted_dest));
        let mut decrypted_dest = Vec::new();
        let result = AesGcmSystem::decrypt_stream_async(
            &key,
            encrypted_source,
            &mut decrypted_dest,
            &config,
            None,
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_async_streaming_empty_input() {
        let (key, config) = get_test_key_and_config();
        let original_data = b"".to_vec();

        let source = BufReader::new(Cursor::new(original_data.clone()));
        let mut encrypted_dest = Vec::new();
        let (_, encrypted_dest) =
            AesGcmSystem::encrypt_stream_async(&key, source, &mut encrypted_dest, &config, None)
                .await
                .unwrap();

        let encrypted_source = BufReader::new(Cursor::new(encrypted_dest));
        let mut decrypted_dest = Vec::new();
        let (_, decrypted_dest) = AesGcmSystem::decrypt_stream_async(
            &key,
            encrypted_source,
            &mut decrypted_dest,
            &config,
            None,
        )
        .await
        .unwrap();

        assert_eq!(original_data, *decrypted_dest);
    }

    #[tokio::test]
    async fn test_async_streaming_multiple_buffer_sizes() {
        let (key, mut config) = get_test_key_and_config();
        config.buffer_size = 64;

        let data_cases = vec![vec![1u8; 32], vec![2u8; 64], vec![3u8; 150]];

        for original_data in data_cases {
            let source = BufReader::new(Cursor::new(original_data.clone()));
            let mut encrypted_dest = Vec::new();
            let (_, encrypted_dest) = AesGcmSystem::encrypt_stream_async(
                &key,
                source,
                &mut encrypted_dest,
                &config,
                None,
            )
            .await
            .unwrap();

            let encrypted_source = BufReader::new(Cursor::new(encrypted_dest));
            let mut decrypted_dest = Vec::new();
            let (_, decrypted_dest) = AesGcmSystem::decrypt_stream_async(
                &key,
                encrypted_source,
                &mut decrypted_dest,
                &config,
                None,
            )
            .await
            .unwrap();

            assert_eq!(original_data, *decrypted_dest);
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
            progress_calls_clone
                .lock()
                .unwrap()
                .push((processed, total));
        }));

        let source = BufReader::new(Cursor::new(original_data));
        let mut encrypted_dest = Vec::new();
        let (_, _) =
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
        let result = AesGcmSystem::decrypt_stream_async(
            &key,
            encrypted_source,
            &mut decrypted_dest,
            &config,
            None,
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_async_streaming_reordered_chunks_fail() {
        let (key, mut config) = get_test_key_and_config();
        config.buffer_size = 32; // Use small chunks
        let original_data =
            b"chunk one. chunk two. chunk three. chunk four. chunk five. chunk six. ".to_vec();

        // Encrypt
        let source = BufReader::new(Cursor::new(original_data.clone()));
        let mut encrypted_dest = Vec::new();
        AesGcmSystem::encrypt_stream_async(&key, source, &mut encrypted_dest, &config, None)
            .await
            .unwrap();

        // Manually parse and reorder chunks
        let encrypted_bytes = encrypted_dest;
        let mut chunks = Vec::new();
        let mut sync_reader = Cursor::new(&encrypted_bytes);

        let mut len_buf = [0u8; 4];
        while std::io::Read::read_exact(&mut sync_reader, &mut len_buf).is_ok() {
            let len = u32::from_le_bytes(len_buf) as usize;
            let mut chunk_data = vec![0u8; len];
            std::io::Read::read_exact(&mut sync_reader, &mut chunk_data).unwrap();
            chunks.push(chunk_data);
        }

        if chunks.len() >= 2 {
            chunks.swap(0, 1);

            let mut reordered_bytes = Vec::new();
            for chunk_data in &chunks {
                reordered_bytes.extend_from_slice(&(chunk_data.len() as u32).to_le_bytes());
                reordered_bytes.extend_from_slice(chunk_data);
            }

            // Decryption should fail
            let encrypted_source = BufReader::new(Cursor::new(reordered_bytes));
            let mut decrypted_dest = Vec::new();
            let result = AesGcmSystem::decrypt_stream_async(
                &key,
                encrypted_source,
                &mut decrypted_dest,
                &config,
                None,
            )
            .await;
            assert!(
                result.is_err(),
                "Decryption of reordered async stream should fail"
            );
        }
    }

    #[tokio::test]
    async fn test_async_streaming_wrong_aad_fails() {
        let (key, config) = get_test_key_and_config();
        let original_data = b"some secret data".to_vec();
        let correct_aad = b"this is correct";
        let wrong_aad = b"this is wrong";

        // Encrypt
        let source = BufReader::new(Cursor::new(original_data.clone()));
        let mut encrypted_dest = Vec::new();
        let (_, encrypted_dest) = AesGcmSystem::encrypt_stream_async(
            &key,
            source,
            &mut encrypted_dest,
            &config,
            Some(correct_aad),
        )
        .await
        .unwrap();

        // Decrypt should fail
        let encrypted_source = BufReader::new(Cursor::new(encrypted_dest));
        let mut decrypted_dest = Vec::new();
        let result = AesGcmSystem::decrypt_stream_async(
            &key,
            encrypted_source,
            &mut decrypted_dest,
            &config,
            Some(wrong_aad),
        )
        .await;

        assert!(result.is_err());
    }
}
