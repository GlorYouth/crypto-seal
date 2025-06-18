#![cfg(feature = "async-engine")]

use crate::common::errors::Error;
use crate::common::streaming::{StreamingConfig, StreamingResult};
use crate::asymmetric::traits::AsymmetricCryptographicSystem;
use std::marker::PhantomData;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// 异步流式加密器
pub struct AsyncStreamingEncryptor<'a, C, R, W>
where
    C: AsymmetricCryptographicSystem,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    Error: From<C::Error>,
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
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    Error: From<C::Error>,
{
    pub fn new(
        reader: R,
        writer: W,
        public_key: &'a C::PublicKey,
        config: StreamingConfig,
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
    C: AsymmetricCryptographicSystem,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    Error: From<C::Error>,
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
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    Error: From<C::Error>,
{
    pub fn new(
        reader: R,
        writer: W,
        private_key: &'a C::PrivateKey,
        config: StreamingConfig,
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

            let ciphertext = String::from_utf8(ciphertext_buffer)
                .map_err(|e| Error::Format(format!("Invalid UTF-8 ciphertext: {}", e)))?;
                
            let plaintext =
                C::decrypt(self.private_key, &ciphertext, self.additional_data.as_deref())?;
            
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