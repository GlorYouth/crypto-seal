#![cfg(feature = "parallel")]

//! Implements parallel synchronous streaming for symmetric encryption.
//!
//! This module utilizes a producer-consumer model with `rayon` for parallelization.
//! - **Producer (Reader Thread)**: Reads data chunks from the input stream.
//! - **Processor (Rayon Pool)**: Encrypts/decrypts data chunks in parallel.
//! - **Consumer (Writer Thread)**: Receives processed chunks, reorders them, and writes to the output stream.
//!
//! This design allows I/O operations and CPU-intensive cryptographic operations to run concurrently, maximizing throughput.
//
// 中文: //! 对称加密的并行同步流式处理实现。
// //!
// //! 该模块基于生产者-消费者模型，利用 `rayon` 实现并行化。
// //! - **生产者 (Reader Thread)**: 从输入流中读取数据块。
// //! - **处理器 (Rayon Pool)**: 并行地对数据块进行加解密。
// //! - **消费者 (Writer Thread)**: 接收处理后的数据块，进行重新排序，然后写入输出流。
// //!
// //! 这种设计允许I/O操作和CPU密集型的加密操作同时进行，最大化吞吐量。

use crate::common::config::{ParallelismConfig, StreamingConfig};
use crate::common::streaming::StreamingResult;
use crate::symmetric::errors::{ParallelOperationError, SymmetricError};
use crate::symmetric::traits::{SymmetricCryptographicSystem, SymmetricParallelStreamingSystem};
use rayon::prelude::*;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::mpsc;
use std::thread;

// Type aliases for work and result items passed through channels.
// 中文: 定义在通道中传递的工作项和结果项的类型别名。
type WorkItem = (u64, Vec<u8>); // (chunk_index, data)
type EncryptResultItem = (u64, usize, Result<Vec<u8>, SymmetricError>); // (chunk_index, original_size, encrypted_result)
type DecryptResultItem = (u64, Result<Vec<u8>, SymmetricError>); // (chunk_index, decrypted_result)

/// `ParallelStreamingEncryptor` orchestrates the parallel encryption of a stream.
///
/// It sets up three main components running in separate threads/contexts:
/// 1. A reader thread to read from the source.
/// 2. A `rayon` parallel bridge to consume and encrypt chunks.
/// 3. A writer thread to reorder and write chunks to the destination.
///
/// 中文: `ParallelStreamingEncryptor` 协调数据流的并行加密。
///
/// 它设置了三个在独立线程/上下文中运行的主要组件：
/// 1. 一个读取线程，用于从源读取数据。
/// 2. 一个 `rayon` 并行桥，用于消费和加密数据块。
/// 3. 一个写入线程，用于对数据块进行重排序并写入目的地。
struct ParallelStreamingEncryptor<'a, C, R, W>
where
    C: SymmetricCryptographicSystem,
    R: Read,
    W: Write,
{
    reader: R,
    writer: W,
    key: &'a C::Key,
    streaming_config: &'a StreamingConfig,
    parallelism_config: &'a ParallelismConfig,
    additional_data: Option<&'a [u8]>,
    _phantom: std::marker::PhantomData<C>,
}

impl<'a, C, R, W> ParallelStreamingEncryptor<'a, C, R, W>
where
    C: SymmetricCryptographicSystem + Send + Sync,
    C::Key: Clone + Send + Sync,
    C::Error: Send,
    R: Read + Send + 'a,
    W: Write + Send + 'a,
    SymmetricError: From<<C as SymmetricCryptographicSystem>::Error>,
{
    fn new(
        reader: R,
        writer: W,
        key: &'a C::Key,
        streaming_config: &'a StreamingConfig,
        parallelism_config: &'a ParallelismConfig,
        additional_data: Option<&'a [u8]>,
    ) -> Self {
        Self {
            reader,
            writer,
            key,
            streaming_config,
            parallelism_config,
            additional_data,
            _phantom: std::marker::PhantomData,
        }
    }

    fn process(self) -> Result<StreamingResult, SymmetricError> {
        let Self {
            mut reader,
            mut writer,
            key,
            streaming_config,
            parallelism_config,
            additional_data,
            ..
        } = self;

        let additional_data = additional_data.map(|d| d.to_vec());
        let channel_bound = parallelism_config.parallelism * 2;

        let (work_tx, work_rx) = mpsc::sync_channel::<WorkItem>(channel_bound);
        let (result_tx, result_rx) = mpsc::sync_channel::<EncryptResultItem>(channel_bound);

        thread::scope(|s| {
            // --- 1. Writer Thread ---
            // This thread receives encrypted chunks, which may arrive out of order.
            // It uses a HashMap as a reordering buffer to ensure chunks are written sequentially.
            // 中文: --- 1. 写入线程 ---
            // 该线程接收可能乱序到达的加密块。
            // 它使用 HashMap 作为重排序缓冲区，以确保存储块按顺序写入。
            let writer_handle = s.spawn(move || -> Result<StreamingResult, SymmetricError> {
                let mut reorder_buffer = HashMap::new();
                let mut next_chunk_to_write: u64 = 0;
                let mut total_bytes_processed: u64 = 0;

                for (index, original_size, result) in result_rx {
                    let ciphertext = result?;
                    reorder_buffer.insert(index, (original_size, ciphertext));

                    // Write all contiguous chunks from the buffer.
                    // 中文: 从缓冲区写入所有连续的块。
                    while let Some((size, data)) = reorder_buffer.remove(&next_chunk_to_write) {
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

            // --- 2. Reader Thread ---
            // This thread reads from the source in a loop, sending chunks
            // along with their sequential index to the processing pipeline.
            // 中文: --- 2. 读取线程 ---
            // 该线程循环从源读取数据，将数据块及其顺序索引发送到处理管道。
            let reader_handle = s.spawn(move || -> Result<(), SymmetricError> {
                let mut chunk_index: u64 = 0;
                loop {
                    let mut buffer = vec![0u8; streaming_config.buffer_size];
                    let read_bytes = reader.read(&mut buffer)?;
                    if read_bytes == 0 {
                        break;
                    }
                    buffer.truncate(read_bytes);

                    if work_tx.send((chunk_index, buffer)).is_err() {
                        return Err(SymmetricError::ParallelOperation(
                            ParallelOperationError::ChannelClosed,
                        ));
                    }
                    chunk_index += 1;
                }
                Ok(())
            });

            // --- 3. Processing Pipeline (Main Thread using Rayon) ---
            // `par_bridge` converts the MPSC iterator into a parallel iterator.
            // Rayon's thread pool then processes the chunks in parallel.
            // A unique AAD is constructed for each chunk to ensure security.
            // 中文: --- 3. 处理管道 (主线程使用 Rayon) ---
            // `par_bridge` 将 MPSC 迭代器转换为并行迭代器。
            // Rayon 的线程池随后并行处理这些块。
            // 为每个块构造唯一的 AAD 以确保安全。
            work_rx
                .into_iter()
                .par_bridge()
                .for_each(|(index, plaintext)| {
                    let mut aad = additional_data.clone().unwrap_or_default();
                    aad.extend_from_slice(&index.to_le_bytes());

                    let result = C::encrypt(key, &plaintext, Some(&aad));
                    let mapped_result = result.map(|d| d.as_ref().to_vec());

                    let original_size = plaintext.len();
                    if result_tx
                        .send((
                            index,
                            original_size,
                            mapped_result.map_err(SymmetricError::from),
                        ))
                        .is_err()
                    {
                        // Writer thread has terminated, no more processing needed.
                        // 中文: 写入线程已终止，无需更多处理。
                    }
                });

            // Wait for reader to finish, then close the result channel,
            // and finally wait for the writer to finish.
            // 中文: 等待读取线程完成，然后关闭结果通道，最后等待写入线程完成。
            reader_handle.join().unwrap()?;
            drop(result_tx);
            writer_handle.join().unwrap()
        })
    }
}

/// `ParallelStreamingDecryptor` orchestrates the parallel decryption of a stream.
///
/// It follows the same producer-consumer model as the encryptor. The reader thread
/// is responsible for parsing the length-prefixed encrypted chunks from the input stream.
///
/// 中文: `ParallelStreamingDecryptor` 协调数据流的并行解密。
///
/// 它遵循与加密器相同的生产者-消费者模型。读取线程负责从输入流中
/// 解析带有长度前缀的加密块。
struct ParallelStreamingDecryptor<'a, C, R, W>
where
    C: SymmetricCryptographicSystem,
    R: Read,
    W: Write,
{
    reader: R,
    writer: W,
    key: &'a C::Key,
    parallelism_config: &'a ParallelismConfig,
    additional_data: Option<&'a [u8]>,
    _phantom: std::marker::PhantomData<C>,
}

impl<'a, C, R, W> ParallelStreamingDecryptor<'a, C, R, W>
where
    C: SymmetricCryptographicSystem + Send + Sync,
    C::Key: Clone + Send + Sync,
    C::Error: Send,
    SymmetricError: From<<C as SymmetricCryptographicSystem>::Error>,
    R: Read + Send + 'a,
    W: Write + Send + 'a,
{
    fn new(
        reader: R,
        writer: W,
        key: &'a C::Key,
        parallelism_config: &'a ParallelismConfig,
        additional_data: Option<&'a [u8]>,
    ) -> Self {
        Self {
            reader,
            writer,
            key,
            parallelism_config,
            additional_data,
            _phantom: std::marker::PhantomData,
        }
    }

    fn process(self) -> Result<StreamingResult, SymmetricError> {
        let Self {
            mut reader,
            mut writer,
            key,
            parallelism_config,
            additional_data,
            ..
        } = self;

        let additional_data = additional_data.map(|d| d.to_vec());
        let channel_bound = parallelism_config.parallelism * 2;

        let (work_tx, work_rx) = mpsc::sync_channel::<WorkItem>(channel_bound);
        let (result_tx, result_rx) = mpsc::sync_channel::<DecryptResultItem>(channel_bound);

        thread::scope(|s| {
            // --- 1. Writer Thread ---
            // Same logic as encryptor: receives decrypted chunks, reorders, and writes.
            // 中文: --- 1. 写入线程 ---
            // 与加密器逻辑相同：接收解密的块，重排序，然后写入。
            let writer_handle = s.spawn(move || -> Result<StreamingResult, SymmetricError> {
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

            // --- 2. Reader Thread ---
            // This thread reads the custom-formatted encrypted stream. It reads a 4-byte
            // length prefix, then the ciphertext block, and sends the complete block for decryption.
            // 中文: --- 2. 读取线程 ---
            // 该线程读取自定义格式的加密流。它读取一个4字节的长度前缀，
            // 然后是密文块，并将完整的块发送以进行解密。
            let reader_handle = s.spawn(move || -> Result<(), SymmetricError> {
                let mut chunk_index: u64 = 0;
                let mut len_buf = [0u8; 4];
                while reader.read_exact(&mut len_buf).is_ok() {
                    let block_size = u32::from_le_bytes(len_buf) as usize;
                    let mut ciphertext_buffer = vec![0u8; block_size];
                    reader.read_exact(&mut ciphertext_buffer)?;

                    let mut block_with_len = len_buf.to_vec();
                    block_with_len.extend_from_slice(&ciphertext_buffer);

                    if work_tx.send((chunk_index, block_with_len)).is_err() {
                        return Err(SymmetricError::ParallelOperation(
                            ParallelOperationError::ChannelClosed,
                        ));
                    }
                    chunk_index += 1;
                }
                Ok(())
            });

            // --- 3. Processing Pipeline (Main Thread using Rayon) ---
            // Decrypts chunks in parallel. The AAD must be reconstructed exactly
            // as it was during encryption to ensure integrity.
            // 中文: --- 3. 处理管道 (主线程使用 Rayon) ---
            // 并行解密块。必须精确地重构加密期间的 AAD，以确保完整性。
            work_rx
                .into_iter()
                .par_bridge()
                .for_each(|(index, ciphertext)| {
                    let mut aad = additional_data.clone().unwrap_or_default();
                    aad.extend_from_slice(&index.to_le_bytes());

                    let result = C::decrypt(key, &ciphertext, Some(&aad));
                    if result_tx
                        .send((index, result.map_err(SymmetricError::from)))
                        .is_err()
                    {
                        // Writer thread has terminated.
                        // 中文: 写入线程已终止。
                    }
                });

            reader_handle.join().unwrap()?;
            drop(result_tx);
            writer_handle.join().unwrap()
        })
    }
}

/// Provides a default implementation of `SymmetricParallelStreamingSystem` for any type
/// that implements `SymmetricCryptographicSystem`.
///
/// 中文: 为任何实现了 `SymmetricCryptographicSystem` 的类型提供 `SymmetricParallelStreamingSystem` 的默认实现。
impl<T> SymmetricParallelStreamingSystem for T
where
    T: SymmetricCryptographicSystem + Send + Sync,
    T::Key: Clone + Send + Sync,
    SymmetricError: From<<T as SymmetricCryptographicSystem>::Error>,
{
    fn par_encrypt_stream<R: Read + Send, W: Write + Send>(
        key: &Self::Key,
        reader: R,
        writer: W,
        stream_config: &StreamingConfig,
        parallel_config: &ParallelismConfig,
        additional_data: Option<&[u8]>,
    ) -> Result<StreamingResult, SymmetricError> {
        ParallelStreamingEncryptor::<Self, R, W>::new(
            reader,
            writer,
            key,
            stream_config,
            parallel_config,
            additional_data,
        )
        .process()
    }

    fn par_decrypt_stream<R: Read + Send, W: Write + Send>(
        key: &Self::Key,
        reader: R,
        writer: W,
        _stream_config: &StreamingConfig,
        parallel_config: &ParallelismConfig,
        additional_data: Option<&[u8]>,
    ) -> Result<StreamingResult, SymmetricError> {
        ParallelStreamingDecryptor::<Self, R, W>::new(
            reader,
            writer,
            key,
            parallel_config,
            additional_data,
        )
        .process()
    }
}

#[cfg(all(feature = "parallel", feature = "async-engine"))]
mod async_impl {
    use super::*;
    use crate::symmetric::traits::SymmetricAsyncParallelStreamingSystem;
    use std::sync::mpsc as std_mpsc;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::sync::mpsc;
    use tokio::task::JoinHandle;

    #[async_trait::async_trait]
    impl<T> SymmetricAsyncParallelStreamingSystem for T
    where
        T: SymmetricCryptographicSystem + Send + Sync,
        T::Key: Clone + Send + Sync + 'static,
        T::Error: Send + Sync,
        SymmetricError: From<<T as SymmetricCryptographicSystem>::Error>,
    {
        async fn par_encrypt_stream_async<R, W>(
            key: &Self::Key,
            mut reader: R,
            mut writer: W,
            stream_config: &StreamingConfig,
            parallel_config: &ParallelismConfig,
            additional_data: Option<&[u8]>,
        ) -> Result<(StreamingResult, W), SymmetricError>
        where
            R: AsyncRead + Unpin + Send + 'static,
            W: AsyncWrite + Unpin + Send + 'static,
        {
            let (work_tx, mut work_rx) = mpsc::channel::<WorkItem>(parallel_config.parallelism);
            let (result_tx, mut result_rx) =
                mpsc::channel::<EncryptResultItem>(parallel_config.parallelism);

            let additional_data = additional_data.map(|d| d.to_vec());
            let stream_config = stream_config.clone();

            // --- 1. Reader Task (Tokio) ---
            // Asynchronously reads chunks and sends them to the processing pipeline.
            // 中文: --- 1. 读取任务 (Tokio) ---
            // 异步读取块并将其发送到处理管道。
            let reader_handle = tokio::spawn(async move {
                let mut chunk_index: u64 = 0;
                loop {
                    let mut buffer = vec![0u8; stream_config.buffer_size];
                    let read_bytes = match reader.read(&mut buffer).await {
                        Ok(0) => break,
                        Ok(n) => n,
                        Err(e) => return Err(SymmetricError::Io(e)),
                    };
                    buffer.truncate(read_bytes);

                    if work_tx.send((chunk_index, buffer)).await.is_err() {
                        break;
                    }
                    chunk_index += 1;
                }
                Ok(())
            });

            // --- 2. Processing Task (Rayon via spawn_blocking) ---
            // This is the bridge between Tokio's async world and Rayon's sync, parallel world.
            // A standard MPSC channel is used to feed work to Rayon.
            // `spawn_blocking` runs the Rayon loop on a dedicated thread pool for blocking tasks.
            //
            // 中文: --- 2. 处理任务 (通过 spawn_blocking 使用 Rayon) ---
            // 这是 Tokio 的异步世界和 Rayon 的同步、并行世界之间的桥梁。
            // 使用一个标准的 MPSC 通道将工作送入 Rayon。
            // `spawn_blocking` 在专用于阻塞任务的线程池上运行 Rayon 循环。
            let (rayon_tx, rayon_rx) = std_mpsc::sync_channel(parallel_config.parallelism);
            let key_clone = key.clone();
            let additional_data_clone = additional_data.clone();

            tokio::task::spawn_blocking(move || {
                rayon_rx
                    .into_iter()
                    .par_bridge()
                    .for_each(|(index, plaintext): WorkItem| {
                        let mut aad = additional_data_clone.clone().unwrap_or_default();
                        aad.extend_from_slice(&index.to_le_bytes());

                        let result = T::encrypt(&key_clone, &plaintext, Some(&aad));
                        let mapped_result = result
                            .map(|d| d.as_ref().to_vec())
                            .map_err(SymmetricError::from);

                        let original_size = plaintext.len();
                        let _ = result_tx.blocking_send((index, original_size, mapped_result));
                    });
            });

            // This task pulls work from the Tokio MPSC and sends it to the Rayon MPSC.
            // 中文: 这个任务从 Tokio MPSC 中拉取工作并发送到 Rayon MPSC。
            tokio::spawn(async move {
                while let Some(item) = work_rx.recv().await {
                    if rayon_tx.send(item).is_err() {
                        break;
                    }
                }
            });

            // --- 3. Writer Task (Tokio) ---
            // Asynchronously receives results, reorders them, and writes to the destination.
            // 中文: --- 3. 写入任务 (Tokio) ---
            // 异步接收结果，对其进行重排序，并写入目的地。
            let writer_handle: JoinHandle<Result<(u64, W), SymmetricError>> =
                tokio::spawn(async move {
                    let mut reorder_buffer = HashMap::new();
                    let mut next_chunk_to_write: u64 = 0;
                    let mut total_bytes_processed: u64 = 0;

                    while let Some((index, original_size, result)) = result_rx.recv().await {
                        let ciphertext = result?;
                        reorder_buffer.insert(index, (original_size, ciphertext));

                        while let Some((size, data)) = reorder_buffer.remove(&next_chunk_to_write) {
                            writer
                                .write_all(&data)
                                .await
                                .map_err(|e| SymmetricError::Io(e))?;
                            total_bytes_processed += size as u64;
                            next_chunk_to_write += 1;
                        }
                    }
                    writer.flush().await.map_err(SymmetricError::Io)?;
                    Ok((total_bytes_processed, writer))
                });

            reader_handle.await??;
            let (total_bytes, writer) = writer_handle.await??;

            Ok((
                StreamingResult {
                    bytes_processed: total_bytes,
                    buffer: None,
                },
                writer,
            ))
        }

        async fn par_decrypt_stream_async<R, W>(
            key: &Self::Key,
            mut reader: R,
            mut writer: W,
            _stream_config: &StreamingConfig,
            parallel_config: &ParallelismConfig,
            additional_data: Option<&[u8]>,
        ) -> Result<(StreamingResult, W), SymmetricError>
        where
            R: AsyncRead + Unpin + Send + 'static,
            W: AsyncWrite + Unpin + Send + 'static,
        {
            type DecryptWorkItem = (u64, Result<Vec<u8>, SymmetricError>);

            let (work_tx, mut work_rx) =
                mpsc::channel::<DecryptWorkItem>(parallel_config.parallelism);
            let (result_tx, mut result_rx) =
                mpsc::channel::<DecryptResultItem>(parallel_config.parallelism);

            let additional_data = additional_data.map(|d| d.to_vec());

            // --- 1. Reader Task (Tokio) ---
            // Asynchronously reads length-prefixed chunks.
            // 中文: --- 1. 读取任务 (Tokio) ---
            // 异步读取带长度前缀的块。
            let reader_handle = tokio::spawn(async move {
                let mut chunk_index: u64 = 0;
                loop {
                    let mut len_buf = [0u8; 4];
                    if reader.read_exact(&mut len_buf).await.is_err() {
                        break; // Clean EOF
                    }

                    let block_size = u32::from_le_bytes(len_buf) as usize;
                    let mut ciphertext_buffer = vec![0u8; block_size];

                    let work_item = match reader.read_exact(&mut ciphertext_buffer).await {
                        Ok(_) => {
                            let mut block_with_len = len_buf.to_vec();
                            block_with_len.extend_from_slice(&ciphertext_buffer);
                            Ok(block_with_len)
                        }
                        Err(e) => Err(SymmetricError::Io(e)),
                    };

                    if work_tx.send((chunk_index, work_item)).await.is_err() {
                        break;
                    }
                    chunk_index += 1;
                }
                Ok(())
            });

            // --- 2. Processing Task (Rayon via spawn_blocking) ---
            // Bridges async input to parallel, synchronous decryption.
            // 中文: --- 2. 处理任务 (通过 spawn_blocking 使用 Rayon) ---
            // 将异步输入桥接到并行的同步解密。
            let (rayon_tx, rayon_rx) = std_mpsc::sync_channel(parallel_config.parallelism);
            let key_clone = key.clone();
            let additional_data_clone = additional_data.clone();

            tokio::task::spawn_blocking(move || {
                rayon_rx.into_iter().par_bridge().for_each(
                    |(index, ciphertext_res): DecryptWorkItem| {
                        let result = match ciphertext_res {
                            Ok(ciphertext) => {
                                let mut aad = additional_data_clone.clone().unwrap_or_default();
                                aad.extend_from_slice(&index.to_le_bytes());
                                T::decrypt(&key_clone, &ciphertext, Some(&aad))
                                    .map_err(SymmetricError::from)
                            }
                            Err(e) => Err(e),
                        };
                        let _ = result_tx.blocking_send((index, result));
                    },
                );
            });

            tokio::spawn(async move {
                while let Some(item) = work_rx.recv().await {
                    if rayon_tx.send(item).is_err() {
                        break;
                    }
                }
            });

            // --- 3. Writer Task (Tokio) ---
            // Asynchronously reorders and writes decrypted plaintext.
            // 中文: --- 3. 写入任务 (Tokio) ---
            // 异步地重排序并写入解密后的明文。
            let writer_handle: JoinHandle<Result<(u64, W), SymmetricError>> =
                tokio::spawn(async move {
                    let mut reorder_buffer = HashMap::new();
                    let mut next_chunk_to_write: u64 = 0;
                    let mut total_bytes_processed: u64 = 0;

                    while let Some((index, result)) = result_rx.recv().await {
                        let plaintext = result?;
                        reorder_buffer.insert(index, plaintext);

                        while let Some(data) = reorder_buffer.remove(&next_chunk_to_write) {
                            total_bytes_processed += data.len() as u64;
                            writer.write_all(&data).await.map_err(SymmetricError::Io)?;
                            next_chunk_to_write += 1;
                        }
                    }
                    writer.flush().await.map_err(SymmetricError::Io)?;
                    Ok((total_bytes_processed, writer))
                });

            reader_handle.await??;
            let (total_bytes, writer) = writer_handle.await??;

            Ok((
                StreamingResult {
                    bytes_processed: total_bytes,
                    buffer: None,
                },
                writer,
            ))
        }
    }
}

#[cfg(all(test, feature = "aes-gcm-feature"))]
mod tests {
    use super::*;
    use crate::common::config::CryptoConfig;
    use crate::symmetric::systems::aes_gcm::AesGcmSystem;
    use std::io::Cursor;

    fn get_test_key_and_config() -> (
        <AesGcmSystem as SymmetricCryptographicSystem>::Key,
        StreamingConfig,
        ParallelismConfig,
    ) {
        let key = AesGcmSystem::generate_key(&CryptoConfig::default()).unwrap();
        let stream_config = StreamingConfig {
            buffer_size: 1024, // 1KB buffer for testing
            ..Default::default()
        };
        let parallel_config = ParallelismConfig::default();
        (key, stream_config, parallel_config)
    }

    #[test]
    fn test_parallel_streaming_roundtrip() {
        let (key, stream_config, parallel_config) = get_test_key_and_config();
        let original_data = vec![0x42; stream_config.buffer_size * 5 + 123];

        // Encrypt
        let mut source = Cursor::new(original_data.clone());
        let mut encrypted_dest = Cursor::new(Vec::new());
        let enc_result = AesGcmSystem::par_encrypt_stream(
            &key,
            &mut source,
            &mut encrypted_dest,
            &stream_config,
            &parallel_config,
            None,
        )
        .unwrap();

        assert_eq!(enc_result.bytes_processed, original_data.len() as u64);

        // Decrypt
        let mut encrypted_source = Cursor::new(encrypted_dest.into_inner());
        let mut decrypted_dest = Cursor::new(Vec::new());
        let dec_result = AesGcmSystem::par_decrypt_stream(
            &key,
            &mut encrypted_source,
            &mut decrypted_dest,
            &stream_config,
            &parallel_config,
            None,
        )
        .unwrap();

        let decrypted_data = decrypted_dest.into_inner();

        assert_eq!(dec_result.bytes_processed, original_data.len() as u64);
        assert_eq!(decrypted_data, original_data);
    }

    #[test]
    fn test_parallel_streaming_with_aad() {
        let (key, stream_config, parallel_config) = get_test_key_and_config();
        let original_data = b"Some data to be encrypted with AAD.";
        let aad = b"additional authenticated data";

        // Encrypt
        let mut source = Cursor::new(original_data.as_ref());
        let mut encrypted_dest = Cursor::new(Vec::new());
        AesGcmSystem::par_encrypt_stream(
            &key,
            &mut source,
            &mut encrypted_dest,
            &stream_config,
            &parallel_config,
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
            &stream_config,
            &parallel_config,
            Some(aad),
        )
        .unwrap();

        assert_eq!(decrypted_dest.into_inner(), original_data);
    }

    #[test]
    fn test_parallel_streaming_wrong_aad_fails() {
        let (key, stream_config, parallel_config) = get_test_key_and_config();
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
            &stream_config,
            &parallel_config,
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
            &stream_config,
            &parallel_config,
            Some(wrong_aad),
        );

        assert!(result.is_err());
    }
}
