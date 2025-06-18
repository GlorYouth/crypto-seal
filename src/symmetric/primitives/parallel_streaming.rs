#![cfg(feature = "parallel")]

//! 对称加密的并行同步流式处理实现。
//!
//! 该模块基于生产者-消费者模型，利用 `rayon` 实现并行化。
//! - **生产者 (Reader Thread)**: 从输入流中读取数据块。
//! - **处理器 (Rayon Pool)**: 并行地对数据块进行加解密。
//! - **消费者 (Writer Thread)**: 接收处理后的数据块，进行重新排序，然后写入输出流。
//!
//! 这种设计允许I/O操作和CPU密集型的加密操作同时进行，最大化吞吐量。

use crate::common::errors::Error;
use crate::common::streaming::{StreamingConfig, StreamingResult};
use crate::symmetric::traits::{SymmetricCryptographicSystem, SymmetricParallelStreamingSystem};
use rayon::prelude::*;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::mpsc;
use std::thread;

// 定义工作项和结果项的类型别名
type WorkItem = (u64, Vec<u8>); // (块索引, 数据)
type EncryptResultItem = (u64, usize, Result<Vec<u8>, Error>); // (块索引, 原始大小, 加密结果)
type DecryptResultItem = (u64, Result<Vec<u8>, Error>); // (块索引, 解密结果)

/// 并行流式加密器
pub struct ParallelStreamingEncryptor<'a, C, R, W>
where
    C: SymmetricCryptographicSystem,
    R: Read,
    W: Write,
{
    reader: R,
    writer: W,
    key: &'a C::Key,
    config: &'a StreamingConfig,
    additional_data: Option<&'a [u8]>,
    _phantom: std::marker::PhantomData<C>,
}

impl<'a, C, R, W> ParallelStreamingEncryptor<'a, C, R, W>
where
    C: SymmetricCryptographicSystem + Send + Sync,
    C::Key: Clone + Send + Sync,
    C::Error: Send,
    Error: From<C::Error> + Send,
    R: Read + Send + 'a,
    W: Write + Send + 'a,
{
    pub fn new(
        reader: R,
        writer: W,
        key: &'a C::Key,
        config: &'a StreamingConfig,
        additional_data: Option<&'a [u8]>,
    ) -> Self {
        Self {
            reader,
            writer,
            key,
            config,
            additional_data,
            _phantom: std::marker::PhantomData,
        }
    }

    pub fn process(self) -> Result<StreamingResult, Error> {
        let Self {
            mut reader,
            mut writer,
            key,
            config,
            additional_data,
            ..
        } = self;

        let additional_data = additional_data.map(|d| d.to_vec());
        let channel_bound = config.parallelism; // 0 for unbounded in practice, though now a concrete value

        let (work_tx, work_rx) = mpsc::sync_channel::<WorkItem>(channel_bound);
        let (result_tx, result_rx) = mpsc::sync_channel::<EncryptResultItem>(channel_bound);

        thread::scope(|s| {
            // --- 1. 写入线程 ---
            // 负责从结果通道接收加密块，重新排序后写入输出流
            let writer_handle = s.spawn(move || -> Result<StreamingResult, Error> {
                let mut reorder_buffer = HashMap::new();
                let mut next_chunk_to_write: u64 = 0;
                let mut total_bytes_processed: u64 = 0;

                for (index, original_size, result) in result_rx {
                    let ciphertext = result?;
                    reorder_buffer.insert(index, (original_size, ciphertext));

                    while let Some((size, data)) = reorder_buffer.remove(&next_chunk_to_write) {
                        let len = data.len() as u32;
                        writer.write_all(&len.to_le_bytes())?;
                        writer.write_all(&data)?;
                        total_bytes_processed += size as u64;
                        next_chunk_to_write += 1;
                    }
                }
                writer.flush()?;
                Ok(StreamingResult {
                    bytes_processed: total_bytes_processed,
                    buffer: None,
                })
            });

            // --- 2. 读取线程 ---
            // 负责从输入流读取数据，分块后送入工作通道
            let reader_handle = s.spawn(move || -> Result<(), Error> {
                let mut chunk_index: u64 = 0;
                loop {
                    let mut buffer = vec![0u8; config.buffer_size];
                    let read_bytes = reader.read(&mut buffer)?;
                    if read_bytes == 0 {
                        break;
                    }
                    buffer.truncate(read_bytes);

                    if work_tx.send((chunk_index, buffer)).is_err() {
                        return Err(Error::Operation(
                            "Parallel stream failed: work channel closed prematurely".to_string(),
                        ));
                    }
                    chunk_index += 1;
                }
                Ok(())
            });

            // --- 3. 处理线程 (主线程/Rayon) ---
            // 从工作通道接收数据，并行加密后送入结果通道
            work_rx
                .into_iter()
                .par_bridge()
                .for_each(|(index, plaintext)| {
                    let mut aad = additional_data.clone().unwrap_or_default();
                    aad.extend_from_slice(&index.to_le_bytes());

                    let result = C::encrypt(key, &plaintext, Some(&aad));

                    let original_size = plaintext.len();
                    if result_tx
                        .send((index, original_size, result.map_err(Error::from)))
                        .is_err()
                    {
                        // 如果结果通道关闭，说明写入线程已终止，我们无需继续处理
                    }
                });

            // 等待读取完成
            reader_handle.join().unwrap()?;

            // 关闭结果通道，通知写入线程所有工作已完成
            drop(result_tx);

            // 等待写入完成并返回结果
            writer_handle.join().unwrap()
        })
    }
}

/// 并行流式解密器
pub struct ParallelStreamingDecryptor<'a, C, R, W>
where
    C: SymmetricCryptographicSystem,
    R: Read,
    W: Write,
{
    reader: R,
    writer: W,
    key: &'a C::Key,
    additional_data: Option<&'a [u8]>,
    _phantom: std::marker::PhantomData<C>,
}

impl<'a, C, R, W> ParallelStreamingDecryptor<'a, C, R, W>
where
    C: SymmetricCryptographicSystem + Send + Sync,
    C::Key: Clone + Send + Sync,
    C::Error: Send,
    Error: From<C::Error> + Send,
    R: Read + Send + 'a,
    W: Write + Send + 'a,
{
    pub fn new(
        reader: R,
        writer: W,
        key: &'a C::Key,
        _config: &'a StreamingConfig,
        additional_data: Option<&'a [u8]>,
    ) -> Self {
        Self {
            reader,
            writer,
            key,
            additional_data,
            _phantom: std::marker::PhantomData,
        }
    }

    pub fn process(self) -> Result<StreamingResult, Error> {
        let Self {
            mut reader,
            mut writer,
            key,
            additional_data,
            ..
        } = self;

        let additional_data = additional_data.map(|d| d.to_vec());
        let channel_bound = 128; // Arbitrary bound for backpressure

        let (work_tx, work_rx) = mpsc::sync_channel::<WorkItem>(channel_bound);
        let (result_tx, result_rx) = mpsc::sync_channel::<DecryptResultItem>(channel_bound);

        thread::scope(|s| {
            // --- 1. 写入线程 ---
            let writer_handle = s.spawn(move || -> Result<StreamingResult, Error> {
                let mut reorder_buffer = HashMap::new();
                let mut next_chunk_to_write: u64 = 0;
                let mut total_bytes_processed: u64 = 0;

                for (index, result) in result_rx {
                    let plaintext = result?;
                    reorder_buffer.insert(index, plaintext);

                    while let Some(data) = reorder_buffer.remove(&next_chunk_to_write) {
                        total_bytes_processed += data.len() as u64;
                        writer.write_all(&data)?;
                        next_chunk_to_write += 1;
                    }
                }
                writer.flush()?;
                Ok(StreamingResult {
                    bytes_processed: total_bytes_processed,
                    buffer: None,
                })
            });

            // --- 2. 读取线程 ---
            let reader_handle = s.spawn(move || -> Result<(), Error> {
                let mut chunk_index: u64 = 0;
                let mut len_buf = [0u8; 4];
                while reader.read_exact(&mut len_buf).is_ok() {
                    let block_size = u32::from_le_bytes(len_buf) as usize;
                    let mut ciphertext_buffer = vec![0u8; block_size];
                    reader.read_exact(&mut ciphertext_buffer)?;

                    if work_tx.send((chunk_index, ciphertext_buffer)).is_err() {
                        return Err(Error::Operation(
                            "Parallel stream failed: work channel closed prematurely".to_string(),
                        ));
                    }
                    chunk_index += 1;
                }
                Ok(())
            });

            // --- 3. 处理线程 (主线程/Rayon) ---
            work_rx
                .into_iter()
                .par_bridge()
                .for_each(|(index, ciphertext)| {
                    let mut aad = additional_data.clone().unwrap_or_default();
                    aad.extend_from_slice(&index.to_le_bytes());
                    let result = C::decrypt(key, &ciphertext, Some(&aad));
                    if result_tx
                        .send((index, result.map_err(Error::from)))
                        .is_err()
                    {
                        // Writer thread terminated, stop processing
                    }
                });

            reader_handle.join().unwrap()?;
            drop(result_tx);
            writer_handle.join().unwrap()
        })
    }
}

/// 为所有实现了 `SymmetricCryptographicSystem` 的类型提供 `SymmetricParallelStreamingSystem` 的默认实现。
impl<T> SymmetricParallelStreamingSystem for T
where
    T: SymmetricCryptographicSystem + Send + Sync,
    T::Key: Clone + Send + Sync,
    T::Error: Send,
    Error: From<T::Error> + Send,
{
    fn par_encrypt_stream<R: Read + Send, W: Write + Send>(
        key: &Self::Key,
        reader: R,
        writer: W,
        config: &StreamingConfig,
        additional_data: Option<&[u8]>,
    ) -> Result<StreamingResult, Error> {
        ParallelStreamingEncryptor::<Self, R, W>::new(reader, writer, key, config, additional_data)
            .process()
    }

    fn par_decrypt_stream<R: Read + Send, W: Write + Send>(
        key: &Self::Key,
        reader: R,
        writer: W,
        config: &StreamingConfig,
        additional_data: Option<&[u8]>,
    ) -> Result<StreamingResult, Error> {
        ParallelStreamingDecryptor::<Self, R, W>::new(reader, writer, key, config, additional_data)
            .process()
    }
}

#[cfg(all(feature = "parallel", feature = "async-engine"))]
mod async_impl {
    use super::*;
    use crate::symmetric::traits::SymmetricAsyncParallelStreamingSystem;
    use tokio::io::{AsyncRead, AsyncWrite};
    use tokio_util::io::SyncIoBridge;

    #[async_trait::async_trait]
    impl<T> SymmetricAsyncParallelStreamingSystem for T
    where
        T: SymmetricParallelStreamingSystem + Send + Sync,
        T::Key: Clone + Send + Sync + 'static,
        T::Error: Send,
        Error: From<T::Error> + Send,
    {
        async fn par_encrypt_stream_async<R, W>(
            key: &Self::Key,
            reader: R,
            writer: W,
            config: &StreamingConfig,
            additional_data: Option<&[u8]>,
        ) -> Result<(StreamingResult, W), Error>
        where
            R: AsyncRead + Unpin + Send + 'static,
            W: AsyncWrite + Unpin + Send + 'static,
        {
            let key = key.clone();
            let config = config.clone();
            let additional_data = additional_data.map(|d| d.to_vec());

            tokio::task::spawn_blocking(move || {
                let mut sync_reader = SyncIoBridge::new(reader);
                let mut sync_writer = SyncIoBridge::new(writer);
                let additional_data_slice = additional_data.as_deref();

                // Call the SYNC parallel streaming implementation
                T::par_encrypt_stream(
                    &key,
                    &mut sync_reader,
                    &mut sync_writer,
                    &config,
                    additional_data_slice,
                )
                .map(|r| (r, sync_writer.into_inner()))
            })
            .await
            .map_err(|e| Error::Operation(format!("Parallel async task failed: {}", e)))?
        }

        async fn par_decrypt_stream_async<R, W>(
            key: &Self::Key,
            reader: R,
            writer: W,
            config: &StreamingConfig,
            additional_data: Option<&[u8]>,
        ) -> Result<(StreamingResult, W), Error>
        where
            R: AsyncRead + Unpin + Send + 'static,
            W: AsyncWrite + Unpin + Send + 'static,
        {
            let key = key.clone();
            let config = config.clone();
            let additional_data = additional_data.map(|d| d.to_vec());

            tokio::task::spawn_blocking(move || {
                let mut sync_reader = SyncIoBridge::new(reader);
                let mut sync_writer = SyncIoBridge::new(writer);
                let additional_data_slice = additional_data.as_deref();

                // Call the SYNC parallel streaming implementation
                T::par_decrypt_stream(
                    &key,
                    &mut sync_reader,
                    &mut sync_writer,
                    &config,
                    additional_data_slice,
                )
                .map(|r| (r, sync_writer.into_inner()))
            })
            .await
            .map_err(|e| Error::Operation(format!("Parallel async task failed: {}", e)))?
        }
    }
}

#[cfg(all(test, feature = "aes-gcm-feature"))]
mod tests {
    use super::*;
    use crate::common::utils::CryptoConfig;
    use crate::symmetric::systems::aes_gcm::AesGcmSystem;
    use std::io::Cursor;

    fn get_test_key_and_config() -> (
        <AesGcmSystem as SymmetricCryptographicSystem>::Key,
        StreamingConfig,
    ) {
        let key = AesGcmSystem::generate_key(&CryptoConfig::default()).unwrap();
        let config = StreamingConfig {
            buffer_size: 1024, // 1KB buffer for testing
            ..Default::default()
        };
        (key, config)
    }

    #[test]
    fn test_parallel_streaming_roundtrip() {
        let (key, config) = get_test_key_and_config();
        // Use data larger than the buffer to ensure chunking
        let original_data = vec![0x42; config.buffer_size * 5 + 123];

        // Encrypt in parallel
        let mut source = Cursor::new(original_data.clone());
        let mut encrypted_dest = Cursor::new(Vec::new());
        let enc_result =
            AesGcmSystem::par_encrypt_stream(&key, &mut source, &mut encrypted_dest, &config, None)
                .unwrap();

        assert_eq!(enc_result.bytes_processed, original_data.len() as u64);

        // Decrypt in parallel
        let mut encrypted_source = Cursor::new(encrypted_dest.into_inner());
        let mut decrypted_dest = Cursor::new(Vec::new());
        let dec_result = AesGcmSystem::par_decrypt_stream(
            &key,
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

    #[test]
    fn test_parallel_streaming_with_aad() {
        let (key, config) = get_test_key_and_config();
        let original_data = b"Some data to be encrypted with AAD.";
        let aad = b"additional authenticated data";

        // Encrypt
        let mut source = Cursor::new(original_data.as_ref());
        let mut encrypted_dest = Cursor::new(Vec::new());
        AesGcmSystem::par_encrypt_stream(
            &key,
            &mut source,
            &mut encrypted_dest,
            &config,
            Some(aad),
        )
        .unwrap();

        // Decrypt with correct AAD
        let mut encrypted_source = Cursor::new(encrypted_dest.into_inner());
        let mut decrypted_dest = Cursor::new(Vec::new());
        AesGcmSystem::par_decrypt_stream(
            &key,
            &mut encrypted_source,
            &mut decrypted_dest,
            &config,
            Some(aad),
        )
        .unwrap();

        assert_eq!(decrypted_dest.into_inner(), original_data);
    }

    #[test]
    fn test_parallel_streaming_tampered_data_fails() {
        let (key, config) = get_test_key_and_config();
        let original_data = vec![0xAB; config.buffer_size * 2];

        // Encrypt
        let mut source = Cursor::new(original_data);
        let mut encrypted_dest = Cursor::new(Vec::new());
        AesGcmSystem::par_encrypt_stream(&key, &mut source, &mut encrypted_dest, &config, None)
            .unwrap();

        let mut tampered_data = encrypted_dest.into_inner();
        // Tamper with the last byte of the ciphertext
        let len = tampered_data.len();
        if len > 0 {
            tampered_data[len - 1] ^= 0xff;
        }

        // Decrypting tampered data should fail
        let mut encrypted_source = Cursor::new(tampered_data);
        let mut decrypted_dest = Cursor::new(Vec::new());
        let result = AesGcmSystem::par_decrypt_stream(
            &key,
            &mut encrypted_source,
            &mut decrypted_dest,
            &config,
            None,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_parallel_streaming_wrong_aad_fails() {
        let (key, config) = get_test_key_and_config();
        let original_data = b"some secret data";
        let aad = b"correct aad";
        let wrong_aad = b"wrong aad";

        // Encrypt
        let mut source = Cursor::new(original_data.as_ref());
        let mut encrypted_dest = Cursor::new(Vec::new());
        AesGcmSystem::par_encrypt_stream(
            &key,
            &mut source,
            &mut encrypted_dest,
            &config,
            Some(aad),
        )
        .unwrap();

        // Decrypt with wrong AAD should fail
        let mut encrypted_source = Cursor::new(encrypted_dest.into_inner());
        let mut decrypted_dest = Cursor::new(Vec::new());
        let result = AesGcmSystem::par_decrypt_stream(
            &key,
            &mut encrypted_source,
            &mut decrypted_dest,
            &config,
            Some(wrong_aad),
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_parallel_streaming_empty_input() {
        let (key, config) = get_test_key_and_config();
        let original_data = b"";

        // Encrypt
        let mut source = Cursor::new(original_data);
        let mut encrypted_dest = Cursor::new(Vec::new());
        let enc_result =
            AesGcmSystem::par_encrypt_stream(&key, &mut source, &mut encrypted_dest, &config, None)
                .unwrap();

        assert_eq!(enc_result.bytes_processed, 0);

        // Decrypt
        let mut encrypted_source = Cursor::new(encrypted_dest.into_inner());
        let mut decrypted_dest = Cursor::new(Vec::new());
        let dec_result = AesGcmSystem::par_decrypt_stream(
            &key,
            &mut encrypted_source,
            &mut decrypted_dest,
            &config,
            None,
        )
        .unwrap();

        assert_eq!(dec_result.bytes_processed, 0);
        assert_eq!(decrypted_dest.into_inner(), original_data);
    }
}
