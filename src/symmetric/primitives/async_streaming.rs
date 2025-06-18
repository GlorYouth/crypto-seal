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
            let ciphertext_bytes = utils::to_base64(ciphertext_obj.as_ref()).into_bytes();
            
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