#![cfg(feature = "async-engine")]

use crate::errors::Error;
use crate::primitives::StreamingResult;
use crate::traits::CryptographicSystem;
use std::marker::PhantomData;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// 异步流式加密配置
pub struct AsyncStreamingConfig {
    /// 缓冲区大小
    pub buffer_size: usize,
    /// 是否在处理过程中显示进度
    pub show_progress: bool,
    /// 是否在内存中保留完整密文/明文
    pub keep_in_memory: bool,
    /// 可选的异步进度回调
    pub progress_callback: Option<Arc<dyn Fn(u64, Option<u64>) + Send + Sync>>,
    /// 可选的总字节数，用于进度计算
    pub total_bytes: Option<u64>,
}

impl Default for AsyncStreamingConfig {
    fn default() -> Self {
        Self {
            buffer_size: 65536, // 64KB
            show_progress: false,
            keep_in_memory: false,
            progress_callback: None,
            total_bytes: None,
        }
    }
}

impl AsyncStreamingConfig {
    pub fn with_total_bytes(mut self, total: u64) -> Self {
        self.total_bytes = Some(total);
        self
    }
    pub fn with_buffer_size(mut self, size: usize) -> Self {
        self.buffer_size = size;
        self
    }
    pub fn with_show_progress(mut self, show: bool) -> Self {
        self.show_progress = show;
        self
    }
    pub fn with_keep_in_memory(mut self, keep: bool) -> Self {
        self.keep_in_memory = keep;
        self
    }
    pub fn with_progress_callback(
        mut self,
        callback: Arc<dyn Fn(u64, Option<u64>) + Send + Sync>,
    ) -> Self {
        self.progress_callback = Some(callback);
        self
    }
}

/// 异步流式加密器
pub struct AsyncStreamingEncryptor<'a, C, R, W>
where
    C: CryptographicSystem,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    Error: From<C::Error>,
{
    reader: R,
    writer: W,
    public_key: &'a C::PublicKey,
    config: AsyncStreamingConfig,
    additional_data: Option<Vec<u8>>,
    _phantom: PhantomData<C>,
}

impl<'a, C, R, W> AsyncStreamingEncryptor<'a, C, R, W>
where
    C: CryptographicSystem,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    Error: From<C::Error>,
{
    pub fn new(
        reader: R,
        writer: W,
        public_key: &'a C::PublicKey,
        config: AsyncStreamingConfig,
    ) -> Self {
        Self {
            reader,
            writer,
            public_key,
            config,
            additional_data: None,
            _phantom: PhantomData,
        }
    }

    pub fn with_additional_data(mut self, data: &[u8]) -> Self {
        self.additional_data = Some(data.to_vec());
        self
    }

    pub async fn process(mut self) -> Result<StreamingResult, Error> {
        let mut buffer = vec![0u8; self.config.buffer_size];
        let mut bytes_processed = 0;
        let mut output_buffer = if self.config.keep_in_memory {
            Some(Vec::new())
        } else {
            None
        };

        loop {
            let read_bytes = self.reader.read(&mut buffer).await.map_err(Error::Io)?;
            if read_bytes == 0 {
                break;
            }

            let plaintext = &buffer[..read_bytes];
            let ciphertext =
                C::encrypt(self.public_key, plaintext, self.additional_data.as_deref())?;

            let ciphertext_bytes = ciphertext.to_string();
            let ciphertext_slice = ciphertext_bytes.as_bytes();
            let length = ciphertext_slice.len() as u32;

            self.writer
                .write_all(&length.to_le_bytes())
                .await
                .map_err(Error::Io)?;
            self.writer
                .write_all(ciphertext_slice)
                .await
                .map_err(Error::Io)?;
            
            if let Some(buf) = output_buffer.as_mut() {
                buf.extend_from_slice(ciphertext_slice);
            }

            bytes_processed += read_bytes as u64;

            if let Some(cb) = &self.config.progress_callback {
                cb(bytes_processed, self.config.total_bytes);
            }
            if self.config.show_progress {
                if let Some(total) = self.config.total_bytes {
                    println!("Encrypted {}/{} bytes", bytes_processed, total);
                } else {
                    println!("Encrypted {} bytes", bytes_processed);
                }
            }
        }

        self.writer.flush().await.map_err(Error::Io)?;

        Ok(StreamingResult {
            bytes_processed,
            buffer: output_buffer,
        })
    }
}

/// 异步流式解密器
pub struct AsyncStreamingDecryptor<'a, C, R, W>
where
    C: CryptographicSystem,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    Error: From<C::Error>,
{
    reader: R,
    writer: W,
    private_key: &'a C::PrivateKey,
    config: AsyncStreamingConfig,
    additional_data: Option<Vec<u8>>,
    _phantom: PhantomData<C>,
}

impl<'a, C, R, W> AsyncStreamingDecryptor<'a, C, R, W>
where
    C: CryptographicSystem,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    Error: From<C::Error>,
{
    pub fn new(
        reader: R,
        writer: W,
        private_key: &'a C::PrivateKey,
        config: AsyncStreamingConfig,
    ) -> Self {
        Self {
            reader,
            writer,
            private_key,
            config,
            additional_data: None,
            _phantom: PhantomData,
        }
    }

    pub fn with_additional_data(mut self, data: &[u8]) -> Self {
        self.additional_data = Some(data.to_vec());
        self
    }

    pub async fn process(mut self) -> Result<StreamingResult, Error> {
        let mut length_buffer = [0u8; 4];
        let mut bytes_processed = 0;
        let mut output_buffer = if self.config.keep_in_memory {
            Some(Vec::new())
        } else {
            None
        };

        while self.reader.read_exact(&mut length_buffer).await.is_ok() {
            let length = u32::from_le_bytes(length_buffer) as usize;
            let mut ciphertext_buffer = vec![0u8; length];
            self.reader
                .read_exact(&mut ciphertext_buffer)
                .await
                .map_err(Error::Io)?;

            let ciphertext_str = String::from_utf8(ciphertext_buffer)
                .map_err(|e| Error::Format(format!("Invalid UTF-8 ciphertext: {}", e)))?;
                
            let plaintext =
                C::decrypt(self.private_key, &ciphertext_str, self.additional_data.as_deref())?;
            
            self.writer.write_all(&plaintext).await.map_err(Error::Io)?;

            if let Some(buf) = output_buffer.as_mut() {
                buf.extend_from_slice(&plaintext);
            }
            
            bytes_processed += length as u64;

            if let Some(cb) = &self.config.progress_callback {
                cb(bytes_processed, self.config.total_bytes);
            }
            if self.config.show_progress {
                 if let Some(total) = self.config.total_bytes {
                    println!("Decrypted chunk. Total processed approx {}/{} bytes", bytes_processed, total);
                } else {
                    println!("Decrypted chunk. Total processed approx {} bytes", bytes_processed);
                }
            }
        }

        self.writer.flush().await.map_err(Error::Io)?;

        Ok(StreamingResult {
            bytes_processed,
            buffer: output_buffer,
        })
    }
} 