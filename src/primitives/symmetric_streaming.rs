//! 对称加密的同步流式处理实现
use std::io::{Read, Write};
use std::marker::PhantomData;

use crate::errors::Error;
use crate::primitives::streaming::{StreamingConfig, StreamingResult};
use crate::traits::{SymmetricCryptographicSystem, SymmetricSyncStreamingSystem};

/// 对称流式加密器
pub struct SymmetricStreamingEncryptor<'a, C: SymmetricCryptographicSystem, R: Read, W: Write>
where
    Error: From<C::Error>,
{
    reader: R,
    writer: W,
    key: &'a C::Key,
    config: &'a StreamingConfig,
    additional_data: Option<&'a [u8]>,
    bytes_processed: u64,
    _phantom: PhantomData<C>,
}

impl<'a, C: SymmetricCryptographicSystem, R: Read, W: Write> SymmetricStreamingEncryptor<'a, C, R, W>
where
    Error: From<C::Error>,
{
    /// 创建新的对称流式加密器
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
            bytes_processed: 0,
            _phantom: PhantomData,
        }
    }

    /// 执行流式加密
    pub fn process(mut self) -> Result<StreamingResult, Error> {
        let mut buffer = vec![0u8; self.config.buffer_size];
        let mut total_written = 0;
        let mut mem_buffer = if self.config.keep_in_memory { Some(Vec::new()) } else { None };

        loop {
            let read_bytes = self.reader.read(&mut buffer)?;
            if read_bytes == 0 {
                break;
            }
            self.bytes_processed += read_bytes as u64;

            let plaintext = &buffer[..read_bytes];
            let ciphertext_obj = C::encrypt(self.key, plaintext, self.additional_data)?;
            let ciphertext_bytes = ciphertext_obj.as_ref();
            
            // 写入长度前缀和密文
            let len = ciphertext_bytes.len() as u32;
            self.writer.write_all(&len.to_le_bytes())?;
            self.writer.write_all(ciphertext_bytes)?;

            total_written += read_bytes as u64; // We track original bytes processed

            if let Some(ref mut buf) = mem_buffer {
                buf.extend_from_slice(ciphertext_bytes);
            }

            if let Some(cb) = &self.config.progress_callback {
                cb(self.bytes_processed, self.config.total_bytes);
            }
        }

        self.writer.flush()?;
        Ok(StreamingResult {
            bytes_processed: total_written,
            buffer: mem_buffer,
        })
    }
}

/// 对称流式解密器
pub struct SymmetricStreamingDecryptor<'a, C: SymmetricCryptographicSystem, R: Read, W: Write>
where
    Error: From<C::Error>,
{
    reader: R,
    writer: W,
    key: &'a C::Key,
    config: &'a StreamingConfig,
    additional_data: Option<&'a [u8]>,
    bytes_processed: u64,
    _phantom: PhantomData<C>,
}

impl<'a, C: SymmetricCryptographicSystem, R: Read, W: Write> SymmetricStreamingDecryptor<'a, C, R, W>
where
    Error: From<C::Error>,
{
    /// 创建新的对称流式解密器
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
            bytes_processed: 0,
            _phantom: PhantomData,
        }
    }

    /// 执行流式解密
    pub fn process(mut self) -> Result<StreamingResult, Error> {
        let mut total_written = 0;
        let mut mem_buffer = if self.config.keep_in_memory { Some(Vec::new()) } else { None };
        let mut len_buf = [0u8; 4];

        loop {
            match self.reader.read_exact(&mut len_buf) {
                Ok(_) => (),
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e.into()),
            }

            let block_size = u32::from_le_bytes(len_buf) as usize;
            let mut ciphertext_buffer = vec![0u8; block_size];
            self.reader.read_exact(&mut ciphertext_buffer)?;
            self.bytes_processed += (4 + block_size) as u64;

            let ciphertext_str = String::from_utf8(ciphertext_buffer)
                .map_err(|e| Error::Format(format!("无效的UTF-8密文: {}", e)))?;

            let plaintext = C::decrypt(self.key, &ciphertext_str, self.additional_data)?;
            
            self.writer.write_all(&plaintext)?;
            total_written += plaintext.len() as u64;

            if let Some(ref mut buf) = mem_buffer {
                buf.extend_from_slice(&plaintext);
            }

            if let Some(cb) = &self.config.progress_callback {
                // For decryption, progress is based on bytes read from source
                cb(self.bytes_processed, self.config.total_bytes);
            }
        }

        self.writer.flush()?;
        Ok(StreamingResult {
            bytes_processed: total_written,
            buffer: mem_buffer,
        })
    }
}

/// 为所有实现 `SymmetricCryptographicSystem` 的类型提供 `SymmetricSyncStreamingSystem` 的默认实现
impl<T> SymmetricSyncStreamingSystem for T
where
    T: SymmetricCryptographicSystem,
    Error: From<T::Error>,
{
    fn encrypt_stream<R: Read, W: Write>(
        key: &Self::Key,
        reader: R,
        writer: W,
        config: &StreamingConfig,
        additional_data: Option<&[u8]>,
    ) -> Result<StreamingResult, Error> {
        SymmetricStreamingEncryptor::<Self, R, W>::new(reader, writer, key, config, additional_data).process()
    }

    fn decrypt_stream<R: Read, W: Write>(
        key: &Self::Key,
        reader: R,
        writer: W,
        config: &StreamingConfig,
        additional_data: Option<&[u8]>,
    ) -> Result<StreamingResult, Error> {
        SymmetricStreamingDecryptor::<Self, R, W>::new(reader, writer, key, config, additional_data).process()
    }
} 