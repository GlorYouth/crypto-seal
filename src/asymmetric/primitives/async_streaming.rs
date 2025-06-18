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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asymmetric::systems::hybrid::rsa_kyber::RsaKyberCryptoSystem;
    use crate::asymmetric::traits::{AsymmetricCryptographicSystem, AsyncStreamingSystem};
    use crate::common::utils::CryptoConfig;
    use tokio::io::BufReader;
    use std::io::Cursor;

    // Helper function to get keys and config
    fn get_test_keys_and_config() -> (
        <RsaKyberCryptoSystem as AsymmetricCryptographicSystem>::PublicKey,
        <RsaKyberCryptoSystem as AsymmetricCryptographicSystem>::PrivateKey,
        StreamingConfig,
    ) {
        let (pk, sk) = RsaKyberCryptoSystem::generate_keypair(&CryptoConfig::default()).unwrap();
        let config = StreamingConfig {
            buffer_size: 128,
            ..Default::default()
        };
        (pk, sk, config)
    }

    #[tokio::test]
    async fn test_async_streaming_roundtrip() {
        let (pk, sk, config) = get_test_keys_and_config();
        let original_data = b"Test async streaming roundtrip.".to_vec();

        // Encrypt
        let source = BufReader::new(Cursor::new(original_data.clone()));
        let mut encrypted_dest = Vec::new();
        RsaKyberCryptoSystem::encrypt_stream_async(&pk, source, &mut encrypted_dest, &config, None)
            .await
            .unwrap();

        // Decrypt
        let encrypted_source = BufReader::new(Cursor::new(encrypted_dest));
        let mut decrypted_dest = Vec::new();
        RsaKyberCryptoSystem::decrypt_stream_async(&sk, encrypted_source, &mut decrypted_dest, &config, None)
            .await
            .unwrap();

        assert_eq!(original_data, decrypted_dest);
    }

    #[tokio::test]
    async fn test_async_streaming_with_aad() {
        let (pk, sk, config) = get_test_keys_and_config();
        let original_data = b"Async streaming with AAD.".to_vec();
        let aad = b"additional_data";

        // Encrypt
        let source = BufReader::new(Cursor::new(original_data.clone()));
        let mut encrypted_dest = Vec::new();
        RsaKyberCryptoSystem::encrypt_stream_async(&pk, source, &mut encrypted_dest, &config, Some(aad))
            .await
            .unwrap();

        // Decrypt
        let encrypted_source = BufReader::new(Cursor::new(encrypted_dest));
        let mut decrypted_dest = Vec::new();
        RsaKyberCryptoSystem::decrypt_stream_async(&sk, encrypted_source, &mut decrypted_dest, &config, Some(aad))
            .await
            .unwrap();

        assert_eq!(original_data, decrypted_dest);
    }

    #[tokio::test]
    async fn test_async_streaming_tampered_data_fails() {
        let (pk, sk, config) = get_test_keys_and_config();
        let original_data = b"This data will be tampered.".to_vec();
        let aad = b"aad_for_tamper_test";

        // Encrypt
        let source = BufReader::new(Cursor::new(original_data.clone()));
        let mut encrypted_dest = Vec::new();
        RsaKyberCryptoSystem::encrypt_stream_async(&pk, source, &mut encrypted_dest, &config, Some(aad))
            .await
            .unwrap();

        // Tamper with data
        if !encrypted_dest.is_empty() {
            let len = encrypted_dest.len();
            encrypted_dest[len / 2] ^= 0xff;
        }

        // Decrypt
        let encrypted_source = BufReader::new(Cursor::new(encrypted_dest));
        let mut decrypted_dest = Vec::new();
        let result = RsaKyberCryptoSystem::decrypt_stream_async(
            &sk,
            encrypted_source,
            &mut decrypted_dest,
            &config,
            Some(aad),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_async_streaming_wrong_aad_fails() {
        let (pk, sk, config) = get_test_keys_and_config();
        let original_data = b"Test wrong AAD.".to_vec();
        let correct_aad = b"correct_aad";
        let wrong_aad = b"wrong_aad";

        // Encrypt
        let source = BufReader::new(Cursor::new(original_data.clone()));
        let mut encrypted_dest = Vec::new();
        RsaKyberCryptoSystem::encrypt_stream_async(&pk, source, &mut encrypted_dest, &config, Some(correct_aad))
            .await
            .unwrap();

        // Decrypt with wrong AAD
        let encrypted_source = BufReader::new(Cursor::new(encrypted_dest));
        let mut decrypted_dest = Vec::new();
        let result = RsaKyberCryptoSystem::decrypt_stream_async(
            &sk,
            encrypted_source,
            &mut decrypted_dest,
            &config,
            Some(wrong_aad),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_async_streaming_empty_input() {
        let (pk, sk, config) = get_test_keys_and_config();
        let original_data = b"".to_vec();

        // Encrypt
        let source = BufReader::new(Cursor::new(original_data.clone()));
        let mut encrypted_dest = Vec::new();
        let enc_result = RsaKyberCryptoSystem::encrypt_stream_async(&pk, source, &mut encrypted_dest, &config, None)
            .await
            .unwrap();
        assert_eq!(enc_result.bytes_processed, 0);
        
        // Decrypt
        let encrypted_source = BufReader::new(Cursor::new(encrypted_dest));
        let mut decrypted_dest = Vec::new();
        let dec_result = RsaKyberCryptoSystem::decrypt_stream_async(&sk, encrypted_source, &mut decrypted_dest, &config, None)
            .await
            .unwrap();

        assert_eq!(dec_result.bytes_processed, 0);
        assert!(decrypted_dest.is_empty());
    }
} 