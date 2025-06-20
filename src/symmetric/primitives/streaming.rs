//! Implements synchronous streaming for symmetric encryption.
// English: Implements synchronous streaming for symmetric encryption.

use crate::common::config::StreamingConfig;
use crate::common::streaming::StreamingResult;
use crate::symmetric::errors::SymmetricError;
use crate::symmetric::traits::{SymmetricCryptographicSystem, SymmetricSyncStreamingSystem};
use std::io::{Read, Write};
use std::marker::PhantomData;

/// `SymmetricStreamingEncryptor` handles the process of encrypting a stream of data.
/// It reads data in chunks, encrypts each chunk, and writes it to an output stream.
///
/// 中文: `SymmetricStreamingEncryptor` 负责处理加密数据流的过程。
/// 它以块的形式读取数据，加密每个块，然后将其写入输出流。
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
    /// Creates a new `SymmetricStreamingEncryptor`.
    ///
    /// 中文: 创建一个新的 `SymmetricStreamingEncryptor`。
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

    /// Processes the entire input stream, encrypting it chunk by chunk.
    ///
    /// For each chunk, a unique Additional Authenticated Data (AAD) is constructed by combining
    /// the global AAD (if any) with the little-endian representation of the chunk index.
    /// This ensures that each chunk is authenticated with its position in the stream,
    /// preventing reordering or replay attacks.
    ///
    /// 中文: 逐块处理整个输入流，对其进行加密。
    ///
    /// 对于每个块，通过将全局 AAD（如果有）与块索引的小端表示形式相结合，
    /// 来构造一个唯一的附加认证数据 (AAD)。这确保了每个数据块都与其在流中的位置一起被认证，
    /// 从而防止重排序或重放攻击。
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

            // Construct AAD with chunk index to prevent reordering attacks.
            // 中文: 构造包含块索引的 AAD 以防止重排序攻击。
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

/// `SymmetricStreamingDecryptor` handles the process of decrypting a stream of data.
/// It reads encrypted chunks, decrypts them, and writes the plaintext to an output stream.
///
/// 中文: `SymmetricStreamingDecryptor` 负责处理解密数据流的过程。
/// 它读取加密的块，解密它们，然后将明文写入输出流。
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
    /// Creates a new `SymmetricStreamingDecryptor`.
    ///
    /// 中文: 创建一个新的 `SymmetricStreamingDecryptor`。
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

    /// Processes the entire encrypted stream, decrypting it chunk by chunk.
    ///
    /// It reads the length-prefixed chunks from the input stream. For each chunk, it reconstructs
    /// the exact same AAD used during encryption (global AAD + chunk index) to ensure
    /// data integrity and authenticity. If the AAD doesn't match or the data is tampered with,
    /// decryption for that chunk will fail.
    ///
    /// 中文: 逐块处理整个加密流，对其进行解密。
    ///
    /// 它从输入流中读取带有长度前缀的块。对于每个块，它会重建加密期间使用的
    /// 完全相同的 AAD（全局 AAD + 块索引），以确保数据的完整性和真实性。
    /// 如果 AAD 不匹配或数据被篡改，该块的解密将失败。
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

            // Reconstruct the exact same AAD as used in encryption.
            // 中文: 重构与加密时完全相同的 AAD。
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

/// Provides a default implementation of `SymmetricSyncStreamingSystem` for any type
/// that implements `SymmetricCryptographicSystem`. This allows any core symmetric
/// algorithm to be used for streaming out-of-the-box.
///
/// 中文: 为任何实现了 `SymmetricCryptographicSystem` 的类型提供 `SymmetricSyncStreamingSystem` 的默认实现。
/// 这使得任何核心对称算法都可以开箱即用地用于流式处理。
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
