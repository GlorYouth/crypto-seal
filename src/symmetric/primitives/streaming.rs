//! 对称加密的同步流式处理实现
use crate::common::config::StreamingConfig;
use crate::common::streaming::StreamingResult;
use crate::symmetric::errors::SymmetricError;
use crate::symmetric::traits::{SymmetricCryptographicSystem, SymmetricSyncStreamingSystem};
use std::io::{Read, Write};
use std::marker::PhantomData;

/// 对称流式加密器
pub struct SymmetricStreamingEncryptor<'a, C: SymmetricCryptographicSystem, R: Read, W: Write> {
    reader: R,
    writer: W,
    key: &'a C::Key,
    config: &'a StreamingConfig,
    additional_data: Option<&'a [u8]>,
    bytes_processed: u64,
    chunk_index: u64,
    _phantom: PhantomData<C>,
}

impl<'a, C: SymmetricCryptographicSystem, R: Read, W: Write>
    SymmetricStreamingEncryptor<'a, C, R, W>
where
    SymmetricError: From<<C as SymmetricCryptographicSystem>::Error>,
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
            chunk_index: 0,
            _phantom: PhantomData,
        }
    }

    /// 执行流式加密
    pub fn process(mut self) -> Result<StreamingResult, SymmetricError> {
        let mut buffer = vec![0u8; self.config.buffer_size];
        let mut total_written = 0;
        let mut mem_buffer = if self.config.keep_in_memory {
            Some(Vec::new())
        } else {
            None
        };

        loop {
            let read_bytes = self.reader.read(&mut buffer)?;
            if read_bytes == 0 {
                break;
            }
            self.bytes_processed += read_bytes as u64;

            let plaintext = &buffer[..read_bytes];

            let mut aad = self.additional_data.map_or_else(Vec::new, |d| d.to_vec());
            aad.extend_from_slice(&self.chunk_index.to_le_bytes());

            let ciphertext = C::encrypt(self.key, plaintext, Some(&aad))?;
            let ciphertext_bytes = ciphertext.as_ref();

            self.writer.write_all(ciphertext_bytes)?;

            total_written += read_bytes as u64;
            self.chunk_index += 1;

            if let Some(ref mut buf) = mem_buffer {
                if ciphertext_bytes.len() >= 4 {
                    buf.extend_from_slice(&ciphertext_bytes[4..]);
                }
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
pub struct SymmetricStreamingDecryptor<'a, C: SymmetricCryptographicSystem, R: Read, W: Write> {
    reader: R,
    writer: W,
    key: &'a C::Key,
    config: &'a StreamingConfig,
    additional_data: Option<&'a [u8]>,
    bytes_processed: u64,
    chunk_index: u64,
    _phantom: PhantomData<C>,
}

impl<'a, C: SymmetricCryptographicSystem, R: Read, W: Write>
    SymmetricStreamingDecryptor<'a, C, R, W>
where
    SymmetricError: From<<C as SymmetricCryptographicSystem>::Error>,
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
            chunk_index: 0,
            _phantom: PhantomData,
        }
    }

    /// 执行流式解密
    pub fn process(mut self) -> Result<StreamingResult, SymmetricError> {
        let mut total_written = 0;
        let mut mem_buffer = if self.config.keep_in_memory {
            Some(Vec::new())
        } else {
            None
        };
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

            let mut aad = self.additional_data.map_or_else(Vec::new, |d| d.to_vec());
            aad.extend_from_slice(&self.chunk_index.to_le_bytes());

            let mut block_with_len = len_buf.to_vec();
            block_with_len.extend_from_slice(&ciphertext_buffer);

            let plaintext = C::decrypt(self.key, &block_with_len, Some(&aad))?;
            self.chunk_index += 1;

            self.writer.write_all(&plaintext)?;
            total_written += plaintext.len() as u64;

            if let Some(ref mut buf) = mem_buffer {
                buf.extend_from_slice(&plaintext);
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

/// 为所有实现 `SymmetricCryptographicSystem` 的类型提供 `SymmetricSyncStreamingSystem` 的默认实现
impl<T> SymmetricSyncStreamingSystem for T
where
    T: SymmetricCryptographicSystem,
    SymmetricError: From<<T as SymmetricCryptographicSystem>::Error>,
{
    fn encrypt_stream<R: Read, W: Write>(
        key: &Self::Key,
        reader: R,
        writer: W,
        config: &StreamingConfig,
        additional_data: Option<&[u8]>,
    ) -> Result<StreamingResult, SymmetricError> {
        SymmetricStreamingEncryptor::<Self, R, W>::new(reader, writer, key, config, additional_data)
            .process()
    }

    fn decrypt_stream<R: Read, W: Write>(
        key: &Self::Key,
        reader: R,
        writer: W,
        config: &StreamingConfig,
        additional_data: Option<&[u8]>,
    ) -> Result<StreamingResult, SymmetricError> {
        SymmetricStreamingDecryptor::<Self, R, W>::new(reader, writer, key, config, additional_data)
            .process()
    }
}

#[cfg(all(test, feature = "aes-gcm-feature"))]
mod tests {
    use super::*;
    use crate::common::config::CryptoConfig;
    use crate::symmetric::systems::aes_gcm::AesGcmSystem;
    use std::io::Cursor;
    use std::sync::Arc;
    use std::sync::Mutex;

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

    #[test]
    fn test_streaming_encrypt_decrypt_roundtrip() {
        let (key, config) = get_test_key_and_config();
        let original_data =
            b"This is a moderately long test string for streaming encryption and decryption.";

        // Encrypt
        let mut source = Cursor::new(original_data);
        let mut encrypted_dest = Cursor::new(Vec::new());
        AesGcmSystem::encrypt_stream(&key, &mut source, &mut encrypted_dest, &config, None)
            .unwrap();

        // Decrypt
        let mut encrypted_source = Cursor::new(encrypted_dest.into_inner());
        let mut decrypted_dest = Cursor::new(Vec::new());
        AesGcmSystem::decrypt_stream(
            &key,
            &mut encrypted_source,
            &mut decrypted_dest,
            &config,
            None,
        )
        .unwrap();

        assert_eq!(
            original_data.as_ref(),
            decrypted_dest.into_inner().as_slice()
        );
    }

    #[test]
    fn test_streaming_with_aad() {
        let (key, config) = get_test_key_and_config();
        let original_data = b"Some data to be protected by streaming with AAD.";
        let aad = b"additional authenticated data";

        // Encrypt
        let mut source = Cursor::new(original_data);
        let mut encrypted_dest = Cursor::new(Vec::new());
        AesGcmSystem::encrypt_stream(&key, &mut source, &mut encrypted_dest, &config, Some(aad))
            .unwrap();

        // Decrypt
        let mut encrypted_source = Cursor::new(encrypted_dest.into_inner());
        let mut decrypted_dest = Cursor::new(Vec::new());
        AesGcmSystem::decrypt_stream(
            &key,
            &mut encrypted_source,
            &mut decrypted_dest,
            &config,
            Some(aad),
        )
        .unwrap();

        assert_eq!(
            original_data.as_ref(),
            decrypted_dest.into_inner().as_slice()
        );
    }

    #[test]
    fn test_streaming_tampered_data_fails() {
        let (key, config) = get_test_key_and_config();
        let original_data = b"Some data that should not be tampered with.";

        // Encrypt
        let mut source = Cursor::new(original_data);
        let mut encrypted_dest = Cursor::new(Vec::new());
        AesGcmSystem::encrypt_stream(&key, &mut source, &mut encrypted_dest, &config, None)
            .unwrap();

        // Tamper with the encrypted data
        let mut tampered_data = encrypted_dest.into_inner();
        tampered_data[10] ^= 0xff; // Flip a bit in the ciphertext

        // Decrypt should fail
        let mut tampered_source = Cursor::new(tampered_data);
        let mut decrypted_dest = Cursor::new(Vec::new());
        let result = AesGcmSystem::decrypt_stream(
            &key,
            &mut tampered_source,
            &mut decrypted_dest,
            &config,
            None,
        );

        assert!(result.is_err(), "Decryption of tampered stream should fail");
    }

    #[test]
    fn test_streaming_reordered_chunks_fail() {
        let (key, mut config) = get_test_key_and_config();
        config.buffer_size = 16; // Use small chunks to test reordering
        let original_data = b"chunk one two three four five six seven eight"; // Must be multiple of 16

        // Encrypt to get a stream of chunks
        let mut source = Cursor::new(original_data);
        let mut encrypted_dest = Cursor::new(Vec::new());
        AesGcmSystem::encrypt_stream(&key, &mut source, &mut encrypted_dest, &config, None)
            .unwrap();

        let encrypted_bytes = encrypted_dest.into_inner();

        // Manually parse and reorder chunks
        let mut reader = Cursor::new(&encrypted_bytes);
        let mut chunks = Vec::new();
        let mut len_buf = [0u8; 4];
        while reader.read_exact(&mut len_buf).is_ok() {
            let len = u32::from_le_bytes(len_buf) as usize;
            let mut chunk_data = vec![0u8; len];
            reader.read_exact(&mut chunk_data).unwrap();
            chunks.push((len_buf, chunk_data));
        }

        if chunks.len() >= 2 {
            // Swap first two chunks
            chunks.swap(0, 1);

            // Reconstruct the tampered stream
            let mut reordered_bytes = Vec::new();
            for (len_buf, chunk_data) in chunks {
                reordered_bytes.extend_from_slice(&len_buf);
                reordered_bytes.extend_from_slice(&chunk_data);
            }

            // Decryption should fail because chunk indices in AAD won't match
            let mut tampered_source = Cursor::new(reordered_bytes);
            let mut decrypted_dest = Cursor::new(Vec::new());
            let result = AesGcmSystem::decrypt_stream(
                &key,
                &mut tampered_source,
                &mut decrypted_dest,
                &config,
                None,
            );

            assert!(
                result.is_err(),
                "Decryption of reordered chunks should fail"
            );
        }
    }

    #[test]
    fn test_streaming_wrong_aad_fails() {
        let (key, config) = get_test_key_and_config();
        let original_data = b"Some data to be protected by streaming with AAD.";
        let aad1 = b"additional authenticated data";
        let aad2 = b"wrong additional authenticated data";

        // Encrypt with aad1
        let mut source = Cursor::new(original_data);
        let mut encrypted_dest = Cursor::new(Vec::new());
        AesGcmSystem::encrypt_stream(&key, &mut source, &mut encrypted_dest, &config, Some(aad1))
            .unwrap();

        // Decrypt with aad2 should fail
        let mut encrypted_source = Cursor::new(encrypted_dest.into_inner());
        let mut decrypted_dest = Cursor::new(Vec::new());
        let result = AesGcmSystem::decrypt_stream(
            &key,
            &mut encrypted_source,
            &mut decrypted_dest,
            &config,
            Some(aad2),
        );

        assert!(result.is_err(), "Decryption with wrong AAD should fail");
    }

    #[test]
    fn test_streaming_empty_input() {
        let (key, config) = get_test_key_and_config();
        let original_data = b"";

        let mut source = Cursor::new(original_data);
        let mut encrypted_dest = Cursor::new(Vec::new());
        AesGcmSystem::encrypt_stream(&key, &mut source, &mut encrypted_dest, &config, None)
            .unwrap();

        let mut encrypted_source = Cursor::new(encrypted_dest.into_inner());
        let mut decrypted_dest = Cursor::new(Vec::new());
        AesGcmSystem::decrypt_stream(
            &key,
            &mut encrypted_source,
            &mut decrypted_dest,
            &config,
            None,
        )
        .unwrap();

        assert_eq!(
            original_data.as_ref(),
            decrypted_dest.into_inner().as_slice()
        );
    }

    #[test]
    fn test_streaming_multiple_buffer_sizes() {
        let (key, mut config) = get_test_key_and_config();
        config.buffer_size = 64; // smaller buffer size

        let data_cases = vec![
            vec![1u8; 32],  // Less than one buffer
            vec![2u8; 64],  // Exactly one buffer
            vec![3u8; 150], // More than one buffer
        ];

        for original_data in data_cases {
            // Encrypt
            let mut source = Cursor::new(&original_data);
            let mut encrypted_dest = Cursor::new(Vec::new());
            AesGcmSystem::encrypt_stream(&key, &mut source, &mut encrypted_dest, &config, None)
                .unwrap();

            // Decrypt
            let mut encrypted_source = Cursor::new(encrypted_dest.into_inner());
            let mut decrypted_dest = Cursor::new(Vec::new());
            AesGcmSystem::decrypt_stream(
                &key,
                &mut encrypted_source,
                &mut decrypted_dest,
                &config,
                None,
            )
            .unwrap();

            assert_eq!(original_data, decrypted_dest.into_inner());
        }
    }

    #[test]
    fn test_streaming_progress_callback() {
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

        let mut source = Cursor::new(&original_data);
        let mut encrypted_dest = Cursor::new(Vec::new());
        AesGcmSystem::encrypt_stream(&key, &mut source, &mut encrypted_dest, &config, None)
            .unwrap();

        let calls = progress_calls.lock().unwrap();
        assert_eq!(calls.len(), 4); // 1024 / 256 = 4
        assert_eq!(calls[0], (256, Some(1024)));
        assert_eq!(calls[1], (512, Some(1024)));
        assert_eq!(calls[2], (768, Some(1024)));
        assert_eq!(calls[3], (1024, Some(1024)));
    }

    #[test]
    fn test_streaming_incomplete_data_fails() {
        let (key, config) = get_test_key_and_config();

        // Case 1: Only length prefix, no data
        let mut encrypted_data = (100u32).to_le_bytes().to_vec();
        let mut encrypted_source = Cursor::new(encrypted_data);
        let mut decrypted_dest = Cursor::new(Vec::new());
        let result = AesGcmSystem::decrypt_stream(
            &key,
            &mut encrypted_source,
            &mut decrypted_dest,
            &config,
            None,
        );
        assert!(result.is_err());

        // Case 2: Length prefix says 100, but only 50 bytes of data follow
        encrypted_data = (100u32).to_le_bytes().to_vec();
        encrypted_data.extend_from_slice(&[0u8; 50]);
        encrypted_source = Cursor::new(encrypted_data);
        decrypted_dest = Cursor::new(Vec::new());
        let result = AesGcmSystem::decrypt_stream(
            &key,
            &mut encrypted_source,
            &mut decrypted_dest,
            &config,
            None,
        );
        assert!(result.is_err());
    }
}
