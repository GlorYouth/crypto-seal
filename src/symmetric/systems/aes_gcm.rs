//! # AES-GCM Symmetric Encryption Implementation
//!
//! This module provides a symmetric encryption system based on AES-256-GCM (Galois/Counter Mode).
//! AES-GCM is an authenticated encryption with associated data (AEAD) cipher, which means it provides
//! confidentiality, integrity, and authenticity.
//!
//! ## Features
//! - **Strong Security**: Uses AES with a 256-bit key.
//! - **Authenticated Encryption**: Protects against tampering of the ciphertext and associated data.
//! - **Nonce Management**: Automatically generates a unique 96-bit (12-byte) nonce for each encryption
//!   operation to ensure security.
//! - **Standard Compliance**: Implements the `SymmetricCryptographicSystem` trait.
//! - **Parallelism**: Implements the `SymmetricParallelSystem` trait (when the "parallel" feature is enabled)
//!   to accelerate the encryption and decryption of large data payloads by processing chunks in parallel.
//!
//! ## Ciphertext Format
//! The output of a single encryption operation has the following structure to bundle the necessary components:
//! `[4-byte length prefix][12-byte nonce][16-byte tag][encrypted data]`
//!
//! ---
//!
//! # AES-GCM 对称加密实现
//!
//! 本模块提供了基于 AES-256-GCM (伽罗瓦/计数器模式) 的对称加密系统。
//! AES-GCM 是一种带有关联数据的认证加密 (AEAD) 密码，这意味着它同时提供
//! 机密性、完整性和真实性。
//!
//! ## 特性
//! - **强安全性**: 使用256位密钥的AES。
//! - **认证加密**: 防止密文和关联数据被篡改。
//! - **Nonce管理**: 为每次加密操作自动生成一个唯一的96位 (12字节) Nonce，以确保安全。
//! - **标准符合性**: 实现了 `SymmetricCryptographicSystem` 特征。
//! - **并行处理**: (当 "parallel" 特性启用时) 实现了 `SymmetricParallelSystem` 特征，
//!   通过并行处理数据块来加速大载荷数据的加解密。
//!
//! ## 密文格式
//! 单次加密操作的输出具有以下结构，以捆绑所有必要组件：
//! `[4字节长度前缀][12字节nonce][16字节tag][加密数据]`

use crate::common::config::{CryptoConfig, ParallelismConfig};
use crate::symmetric::traits::{SymmetricCryptographicSystem, SymmetricParallelSystem};
use aes_gcm::aead::{AeadInPlace, Error as AeadError, KeyInit};
use aes_gcm::{AeadCore, Aes256Gcm, Nonce, Tag};
use base64::{Engine, engine::general_purpose};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::io::{Cursor, Read};

use thiserror::Error;

// --- Constants ---
const KEY_SIZE: usize = 32; // 256 bits
const NONCE_SIZE: usize = 12; // 96 bits, standard for AES-GCM
const TAG_SIZE: usize = 16; // 128 bits, standard for AES-GCM
const PARALLEL_CHUNK_SIZE: usize = 1024 * 1024; // 1 MiB for parallel processing

/// Dedicated error types for the AES-GCM system.
///
/// ---
///
/// AES-GCM 系统的专用错误类型。
#[derive(Error, Debug)]
pub enum AesGcmSystemError {
    /// Error during cryptographic key generation.
    /// ---
    /// 加密密钥生成期间出错。
    #[error("Key generation failed: {0}")]
    KeyGeneration(Box<rand_core::OsError>),

    /// The provided key has an incorrect size.
    /// ---
    /// 提供的密钥大小不正确。
    #[error("Invalid key size: expected {expected}, got {actual}")]
    InvalidKeySize { expected: usize, actual: usize },

    /// Encryption operation failed at the AEAD level.
    /// ---
    /// 加密操作在AEAD层失败。
    #[error("Encryption failed: {0}")]
    EncryptionFailed(Box<AeadError>),

    /// Decryption failed, typically due to an incorrect key, tampered ciphertext, or invalid tag.
    /// ---
    /// 解密失败，通常因为密钥不正确、密文被篡改或标签无效。
    #[error("Decryption failed")]
    DecryptionFailed,

    /// The ciphertext is malformed, truncated, or does not follow the expected format.
    /// ---
    /// 密文格式错误、被截断或不符合预期格式。
    #[error("Ciphertext is malformed or truncated: {0}")]
    MalformedCiphertext(String),

    /// Failed to decode a key from a Base64 string.
    /// ---
    /// 从 Base64 字符串解码密钥失败。
    #[error("Base64 decoding failed: {0}")]
    Base64Decode(#[from] base64::DecodeError),

    /// An I/O error occurred, typically during streaming operations.
    /// ---
    /// 发生 I/O 错误，通常在流式操作期间。
    #[error("I/O error: {0}")]
    Io(Box<std::io::Error>),

    /// Failed to set up the thread pool for parallel execution.
    /// ---
    /// 为并行执行设置线程池失败。
    #[error("Parallel execution setup failed: {0}")]
    ParallelSetup(String),
}

/// A struct representing the AES-GCM symmetric cryptographic system.
///
/// ---
///
/// 代表 AES-GCM 对称加密系统的结构体。
#[derive(Debug)]
pub struct AesGcmSystem;

/// A wrapper for an AES-GCM key to support serialization and debugging.
///
/// ---
///
/// AES-GCM 密钥的包装器，以支持序列化和调试。
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct AesGcmKey(pub Vec<u8>);

impl SymmetricCryptographicSystem for AesGcmSystem {
    const KEY_SIZE: usize = KEY_SIZE;
    type CiphertextOutput = Vec<u8>;
    type Key = AesGcmKey;
    type Error = AesGcmSystemError;

    /// Generates a new 256-bit (32-byte) random key for AES-GCM.
    ///
    /// ---
    ///
    /// 为 AES-GCM 生成一个新的256位（32字节）随机密钥。
    fn generate_key(_config: &CryptoConfig) -> Result<Self::Key, Self::Error> {
        let mut key_bytes = vec![0u8; Self::KEY_SIZE];
        use rand_core::{OsRng, TryRngCore};
        OsRng
            .try_fill_bytes(&mut key_bytes)
            .map_err(|e| AesGcmSystemError::KeyGeneration(Box::new(e)))?;
        Ok(AesGcmKey(key_bytes))
    }

    /// Encrypts plaintext using AES-256-GCM.
    /// A unique nonce is generated for each call. The resulting ciphertext includes the
    /// nonce, authentication tag, and the encrypted data, prefixed by its total length.
    ///
    /// ---
    ///
    /// 使用 AES-256-GCM 加密明文。
    /// 每次调用都会生成一个唯一的 nonce。生成的密文包含 nonce、认证标签和加密后的数据，
    /// 并在最前面加上其总长度。
    fn encrypt(
        key: &Self::Key,
        plaintext: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, Self::Error> {
        // Create a new AES-256-GCM cipher instance from the key.
        // ---
        // 从密钥创建一个新的 AES-256-GCM 密码实例。
        let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key.0);
        let cipher = Aes256Gcm::new(key);
        use aes_gcm::aead::OsRng;
        // Generate a cryptographically secure random 96-bit nonce.
        // It is essential that the nonce is unique for every encryption with the same key.
        // ---
        // 生成一个加密安全的随机96位 nonce。
        // 对于使用相同密钥的每次加密，nonce 必须是唯一的，这一点至关重要。
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        // The `encrypt_in_place_detached` method encrypts the buffer and returns the authentication tag separately.
        // ---
        // `encrypt_in_place_detached` 方法会就地加密缓冲区，并分别返回认证标签。
        let mut buffer = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(&nonce, additional_data.unwrap_or(&[]), &mut buffer)
            .map_err(|e| AesGcmSystemError::EncryptionFailed(Box::new(e)))?;

        // Assemble the final ciphertext payload: nonce || tag || encrypted_data
        // ---
        // 组装最终的密文载荷: nonce || tag || encrypted_data
        let mut raw_ciphertext = Vec::with_capacity(NONCE_SIZE + TAG_SIZE + buffer.len());
        raw_ciphertext.extend_from_slice(nonce.as_slice());
        raw_ciphertext.extend_from_slice(&tag);
        raw_ciphertext.extend_from_slice(&buffer);

        // Prepend the length of the raw ciphertext as a 4-byte little-endian integer.
        // This helps in parsing the data, especially in streaming or parallel contexts.
        // ---
        // 将原始密文的长度作为一个4字节的小端整数前缀。
        // 这有助于解析数据，尤其是在流式或并行上下文中。
        let mut final_output = Vec::with_capacity(4 + raw_ciphertext.len());
        final_output.extend_from_slice(&(raw_ciphertext.len() as u32).to_le_bytes());
        final_output.extend_from_slice(&raw_ciphertext);

        Ok(final_output)
    }

    /// Decrypts ciphertext using AES-256-GCM.
    /// It parses the input to extract the nonce, tag, and encrypted data, then performs
    /// authenticated decryption.
    ///
    /// ---
    ///
    /// 使用 AES-256-GCM 解密密文。
    /// 它会解析输入以提取 nonce、标签和加密数据，然后执行认证解密。
    fn decrypt(
        key: &Self::Key,
        ciphertext: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, Self::Error> {
        // First, parse the 4-byte length prefix to determine the actual ciphertext length.
        // ---
        // 首先，解析4字节的长度前缀以确定实际的密文长度。
        if ciphertext.len() < 4 {
            return Err(AesGcmSystemError::MalformedCiphertext(
                "Ciphertext is too short to contain length prefix".to_string(),
            ));
        }
        let (len_slice, raw_ciphertext) = ciphertext.split_at(4);
        let len = u32::from_le_bytes(len_slice.try_into().unwrap()) as usize;

        if raw_ciphertext.len() != len {
            return Err(AesGcmSystemError::MalformedCiphertext(
                "Ciphertext length does not match length prefix".to_string(),
            ));
        }

        // Ensure the ciphertext is long enough to contain both the nonce and the tag.
        // ---
        // 确保密文足够长，能够同时包含 nonce 和 tag。
        if raw_ciphertext.len() < NONCE_SIZE + TAG_SIZE {
            return Err(AesGcmSystemError::MalformedCiphertext(
                "Ciphertext is too short".to_string(),
            ));
        }
        let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key.0);
        let cipher = Aes256Gcm::new(key);

        // Deconstruct the raw ciphertext back into its components: nonce, tag, and the encrypted data.
        // ---
        // 将原始密文分解回其组成部分：nonce、tag 和加密数据。
        let (nonce_slice, rest) = raw_ciphertext.split_at(NONCE_SIZE);
        let (tag_slice, ct_slice) = rest.split_at(TAG_SIZE);
        let nonce = Nonce::from_slice(nonce_slice);
        let tag = Tag::from_slice(tag_slice);

        // The `decrypt_in_place_detached` method verifies the tag against the nonce, AAD, and ciphertext.
        // If verification succeeds, it decrypts the buffer in place. Otherwise, it returns an error.
        // ---
        // `decrypt_in_place_detached` 方法会根据 nonce、AAD 和密文来验证标签。
        // 如果验证成功，它会就地解密缓冲区。否则，返回错误。
        let mut buffer = ct_slice.to_vec();
        cipher
            .decrypt_in_place_detached(nonce, additional_data.unwrap_or(&[]), &mut buffer, tag)
            .map_err(|_| AesGcmSystemError::DecryptionFailed)?;

        Ok(buffer)
    }

    /// Exports the key to a Base64 encoded string.
    ///
    /// ---
    ///
    /// 将密钥导出为 Base64 编码的字符串。
    fn export_key(key: &Self::Key) -> Result<String, Self::Error> {
        Ok(general_purpose::STANDARD.encode(&key.0))
    }

    /// Imports a key from a Base64 encoded string, validating its size.
    ///
    /// ---
    ///
    /// 从 Base64 编码的字符串导入密钥，并验证其大小。
    fn import_key(encoded_key: &str) -> Result<Self::Key, Self::Error> {
        let key_bytes = general_purpose::STANDARD.decode(encoded_key)?;
        if key_bytes.len() != KEY_SIZE {
            return Err(AesGcmSystemError::InvalidKeySize {
                expected: KEY_SIZE,
                actual: key_bytes.len(),
            });
        }
        Ok(AesGcmKey(key_bytes))
    }
}

#[cfg(feature = "parallel")]
impl SymmetricParallelSystem for AesGcmSystem {
    /// Encrypts a large plaintext payload in parallel.
    /// The plaintext is split into chunks, and each chunk is encrypted concurrently.
    /// To ensure each chunk's AAD is unique, the chunk index is appended to the user-provided AAD.
    ///
    /// ---
    ///
    /// 并行加密一个大的明文载荷。
    /// 明文被分割成块，每个块被并发加密。
    /// 为确保每个块的AAD是唯一的，块索引会被附加到用户提供的AAD之后。
    fn par_encrypt(
        key: &Self::Key,
        plaintext: &[u8],
        additional_data: Option<&[u8]>,
        parallelism_config: &ParallelismConfig,
    ) -> Result<Vec<u8>, Self::Error> {
        if plaintext.is_empty() {
            return Ok(Vec::new());
        }

        // Set up a Rayon thread pool with the specified number of threads.
        // ---
        // 设置一个具有指定线程数的 Rayon 线程池。
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(parallelism_config.parallelism)
            .build()
            .map_err(|e| AesGcmSystemError::ParallelSetup(e.to_string()))?;

        let additional_data = additional_data.map(|d| d.to_vec());

        // Process chunks of the plaintext in parallel.
        // ---
        // 并行处理明文块。
        let encrypted_chunks: Vec<Result<Vec<u8>, Self::Error>> = pool.install(|| {
            plaintext
                .par_chunks(PARALLEL_CHUNK_SIZE)
                .enumerate() // Get chunk index / 获取块索引
                .map(|(i, chunk)| {
                    // To maintain security in AEAD, the AAD for each chunk must be unique.
                    // We achieve this by appending the chunk's index to the original AAD.
                    // This ensures that reordering chunks will cause decryption to fail.
                    // ---
                    // 为了在AEAD中保持安全性，每个块的AAD必须是唯一的。
                    // 我们通过将块的索引附加到原始AAD上来实现这一点。
                    // 这确保了重新排序的块将导致解密失败。
                    let mut aad_chunk = additional_data.clone().unwrap_or_default();
                    aad_chunk.extend_from_slice(&(i as u64).to_le_bytes()); // Add index to AAD / 添加索引作为 AAD 的一部分
                    // Each chunk is encrypted as a self-contained block using the standard `encrypt` method.
                    // ---
                    // 每个块都使用标准的 `encrypt` 方法作为一个独立的块进行加密。
                    Self::encrypt(key, chunk, Some(&aad_chunk))
                })
                .collect()
        });

        // Concatenate the encrypted chunks to form the final ciphertext.
        // Since each chunk is already in the `[length][data]` format, they can be simply joined together.
        // ---
        // 连接加密后的块以形成最终的密文。
        // 由于每个块已经是 `[length][data]` 格式，它们可以被简单地连接在一起。
        let mut final_result = Vec::new();
        for result in encrypted_chunks {
            final_result.extend_from_slice(&result?);
        }

        Ok(final_result)
    }

    /// Decrypts a large ciphertext payload in parallel.
    /// The ciphertext is first parsed into chunks based on the length prefixes.
    /// Then, each chunk is decrypted concurrently. The chunk index is appended to the
    /// user-provided AAD to match the AAD used during encryption.
    ///
    /// ---
    ///
    /// 并行解密一个大的密文载荷。
    /// 密文首先根据长度前缀被解析成块。
    /// 然后，每个块被并发解密。块索引会被附加到用户提供的AAD之后，以匹配加密时使用的AAD。
    fn par_decrypt(
        key: &Self::Key,
        ciphertext: &[u8],
        additional_data: Option<&[u8]>,
        parallelism_config: &ParallelismConfig,
    ) -> Result<Vec<u8>, Self::Error> {
        if ciphertext.is_empty() {
            return Ok(Vec::new());
        }

        let mut reader = Cursor::new(ciphertext);
        let mut chunks_to_decrypt: Vec<Vec<u8>> = Vec::new();
        let mut len_buf = [0u8; 4];

        // First, parse the concatenated ciphertext stream into individual chunks.
        // This is done by repeatedly reading a 4-byte length prefix, then reading the chunk of that length.
        // ---
        // 首先，将连接的密文流解析为单个块。
        // 这是通过重复读取4字节的长度前缀，然后读取该长度的块来完成的。
        while reader.read_exact(&mut len_buf).is_ok() {
            let len = u32::from_le_bytes(len_buf) as usize;
            if (reader.position() as usize + len) > ciphertext.len() {
                return Err(AesGcmSystemError::MalformedCiphertext(
                    "Ciphertext is truncated or malformed.".to_string(),
                ));
            }
            let mut chunk_buf = vec![0u8; len];
            reader
                .read_exact(&mut chunk_buf)
                .map_err(|e| AesGcmSystemError::Io(Box::new(e)))?;

            // The `decrypt` function expects the full `[length][data]` block, so we reconstruct it.
            // ---
            // `decrypt` 函数期望完整的 `[length][data]` 块，所以我们重新构建它。
            let mut final_chunk = len_buf.to_vec();
            final_chunk.extend_from_slice(&chunk_buf);
            chunks_to_decrypt.push(final_chunk);
        }

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(parallelism_config.parallelism)
            .build()
            .map_err(|e| AesGcmSystemError::ParallelSetup(e.to_string()))?;

        let additional_data = additional_data.map(|d| d.to_vec());

        // Process the chunks in parallel.
        // ---
        // 并行处理这些块。
        let decrypted_chunks: Vec<Result<Vec<u8>, Self::Error>> = pool.install(|| {
            chunks_to_decrypt
                .par_iter()
                .enumerate()
                .map(|(i, chunk)| {
                    // Re-create the same unique AAD for each chunk by appending the index,
                    // mirroring the logic used in `par_encrypt`.
                    // ---
                    // 通过附加索引为每个块重新创建相同的唯一AAD，
                    // 这与 `par_encrypt` 中使用的逻辑相呼应。
                    let mut aad_chunk = additional_data.clone().unwrap_or_default();
                    aad_chunk.extend_from_slice(&(i as u64).to_le_bytes());
                    // Each chunk is decrypted independently using the standard `decrypt` method.
                    // ---
                    // 每个块都使用标准的 `decrypt` 方法独立解密。
                    Self::decrypt(key, chunk, Some(&aad_chunk))
                })
                .collect()
        });

        // Concatenate the decrypted chunks to reconstruct the original plaintext.
        // ---
        // 连接解密后的块以重构原始明文。
        let mut final_result = Vec::new();
        for result in decrypted_chunks {
            final_result.extend_from_slice(&result?);
        }

        Ok(final_result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::config::CryptoConfig;

    #[cfg(feature = "parallel")]
    use crate::common::config::ParallelismConfig;

    #[test]
    fn test_generate_key() {
        let config = CryptoConfig::default();
        let key = AesGcmSystem::generate_key(&config).unwrap();
        assert_eq!(key.0.len(), KEY_SIZE);
    }

    #[test]
    fn test_encrypt_decrypt_success() {
        let config = CryptoConfig::default();
        let key = AesGcmSystem::generate_key(&config).unwrap();
        let plaintext = b"this is a secret message";

        let ciphertext = AesGcmSystem::encrypt(&key, plaintext, None).unwrap();
        let decrypted_plaintext = AesGcmSystem::decrypt(&key, &ciphertext, None).unwrap();

        assert_eq!(plaintext, decrypted_plaintext.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_with_aad_success() {
        let config = CryptoConfig::default();
        let key = AesGcmSystem::generate_key(&config).unwrap();
        let plaintext = b"this is a secret message with aad";
        let aad = b"additional authenticated data";

        let ciphertext = AesGcmSystem::encrypt(&key, plaintext, Some(aad)).unwrap();
        let decrypted_plaintext = AesGcmSystem::decrypt(&key, &ciphertext, Some(aad)).unwrap();

        assert_eq!(plaintext, decrypted_plaintext.as_slice());
    }

    #[test]
    fn test_decrypt_wrong_key() {
        let config = CryptoConfig::default();
        let key1 = AesGcmSystem::generate_key(&config).unwrap();
        let key2 = AesGcmSystem::generate_key(&config).unwrap();
        let plaintext = b"this is another secret";

        let ciphertext = AesGcmSystem::encrypt(&key1, plaintext, None).unwrap();
        let result = AesGcmSystem::decrypt(&key2, &ciphertext, None);

        assert!(matches!(result, Err(AesGcmSystemError::DecryptionFailed)));
    }

    #[test]
    fn test_decrypt_tampered_ciphertext() {
        let config = CryptoConfig::default();
        let key = AesGcmSystem::generate_key(&config).unwrap();
        let plaintext = b"secret message, do not tamper";

        let mut ciphertext = AesGcmSystem::encrypt(&key, plaintext, None).unwrap();

        // 篡改密文部分
        let len = ciphertext.len();
        if len > 0 {
            ciphertext[len - 1] ^= 0xff; // 翻转最后一个字节
        }

        // 解密应该失败
        let result = AesGcmSystem::decrypt(&key, &ciphertext, None);

        assert!(matches!(result, Err(AesGcmSystemError::DecryptionFailed)));
    }

    #[test]
    fn test_decrypt_tampered_aad() {
        let config = CryptoConfig::default();
        let key = AesGcmSystem::generate_key(&config).unwrap();
        let plaintext = b"secret message";
        let aad = b"authentic data";
        let tampered_aad = b"tampered authentic data";

        let ciphertext = AesGcmSystem::encrypt(&key, plaintext, Some(aad)).unwrap();
        let result = AesGcmSystem::decrypt(&key, &ciphertext, Some(tampered_aad));

        assert!(matches!(result, Err(AesGcmSystemError::DecryptionFailed)));
    }

    #[test]
    fn test_export_import_key() {
        let config = CryptoConfig::default();
        let key = AesGcmSystem::generate_key(&config).unwrap();
        let plaintext = b"message for exported/imported key";

        let exported_key = AesGcmSystem::export_key(&key).unwrap();
        let imported_key = AesGcmSystem::import_key(&exported_key).unwrap();

        assert_eq!(key.0, imported_key.0);

        let ciphertext = AesGcmSystem::encrypt(&imported_key, plaintext, None).unwrap();
        let decrypted_plaintext = AesGcmSystem::decrypt(&key, &ciphertext, None).unwrap();

        assert_eq!(plaintext, decrypted_plaintext.as_slice());
    }

    #[test]
    fn test_import_invalid_key() {
        let invalid_encoded_key = "not-a-base64-key";
        let result = AesGcmSystem::import_key(invalid_encoded_key);
        assert!(matches!(result, Err(AesGcmSystemError::Base64Decode(_))));

        let short_key_bytes = vec![0u8; 16];
        let short_encoded_key = general_purpose::STANDARD.encode(&short_key_bytes);
        let result_short = AesGcmSystem::import_key(&short_encoded_key);
        assert!(matches!(
            result_short,
            Err(AesGcmSystemError::InvalidKeySize { .. })
        ));
    }

    #[test]
    fn test_decrypt_invalid_ciphertext() {
        let config = CryptoConfig::default();
        let key = AesGcmSystem::generate_key(&config).unwrap();
        let plaintext = b"some data";

        let mut ciphertext = AesGcmSystem::encrypt(&key, plaintext, None).unwrap();

        // 篡改长度前缀，使其与实际长度不符
        let original_len = u32::from_le_bytes(ciphertext[0..4].try_into().unwrap());
        let tampered_len = (original_len - 1).to_le_bytes(); // Make it smaller
        ciphertext[0..4].copy_from_slice(&tampered_len);

        let result = AesGcmSystem::decrypt(&key, &ciphertext, None);
        assert!(
            matches!(result, Err(AesGcmSystemError::MalformedCiphertext(e)) if e.contains("length does not match length prefix"))
        );

        // 测试过短的密文 (无法包含长度前缀)
        let short_ciphertext = vec![0, 1, 2];
        let result_short = AesGcmSystem::decrypt(&key, &short_ciphertext, None);
        assert!(
            matches!(result_short, Err(AesGcmSystemError::MalformedCiphertext(e)) if e.contains("too short to contain length prefix"))
        );

        // 测试过短的密文 (包含长度前缀但数据不足)
        let mut another_short_ciphertext = vec![0u8; NONCE_SIZE + TAG_SIZE - 1];
        let len_bytes = (another_short_ciphertext.len() as u32).to_le_bytes();
        let mut final_ciphertext = len_bytes.to_vec();
        final_ciphertext.append(&mut another_short_ciphertext);
        let result_another_short = AesGcmSystem::decrypt(&key, &final_ciphertext, None);
        assert!(
            matches!(result_another_short, Err(AesGcmSystemError::MalformedCiphertext(e)) if e.contains("too short"))
        );
    }

    #[test]
    fn test_empty_plaintext_roundtrip() {
        let config = CryptoConfig::default();
        let key = AesGcmSystem::generate_key(&config).unwrap();
        let plaintext = b"";

        let ciphertext = AesGcmSystem::encrypt(&key, plaintext, None).unwrap();
        let decrypted_plaintext = AesGcmSystem::decrypt(&key, &ciphertext, None).unwrap();

        assert_eq!(plaintext, decrypted_plaintext.as_slice());
    }

    #[test]
    fn test_encrypt_with_aad_decrypt_without_fails() {
        let config = CryptoConfig::default();
        let key = AesGcmSystem::generate_key(&config).unwrap();
        let plaintext = b"some data";
        let aad = b"some aad";

        let ciphertext = AesGcmSystem::encrypt(&key, plaintext, Some(aad)).unwrap();
        let result = AesGcmSystem::decrypt(&key, &ciphertext, None);

        assert!(matches!(result, Err(AesGcmSystemError::DecryptionFailed)));
    }

    #[test]
    fn test_ciphertext_uniqueness() {
        let config = CryptoConfig::default();
        let key = AesGcmSystem::generate_key(&config).unwrap();
        let plaintext = b"this is the same message";

        let ciphertext1 = AesGcmSystem::encrypt(&key, plaintext, None).unwrap();
        let ciphertext2 = AesGcmSystem::encrypt(&key, plaintext, None).unwrap();

        assert_ne!(ciphertext1, ciphertext2);
    }

    #[test]
    fn test_empty_aad_roundtrip() {
        let config = CryptoConfig::default();
        let key = AesGcmSystem::generate_key(&config).unwrap();
        let plaintext = b"plaintext";
        let aad = b"";

        let ciphertext = AesGcmSystem::encrypt(&key, plaintext, Some(aad)).unwrap();
        let decrypted_plaintext = AesGcmSystem::decrypt(&key, &ciphertext, Some(aad)).unwrap();

        assert_eq!(plaintext, decrypted_plaintext.as_slice());
    }

    #[test]
    fn test_decrypt_tampered_tag() {
        let config = CryptoConfig::default();
        let key = AesGcmSystem::generate_key(&config).unwrap();
        let plaintext = b"some data";
        let mut ciphertext = AesGcmSystem::encrypt(&key, plaintext, None).unwrap();

        // Tamper the tag (located after the nonce)
        // The length prefix is 4 bytes long. The nonce is 12 bytes.
        if ciphertext.len() >= 4 + NONCE_SIZE + TAG_SIZE {
            ciphertext[4 + NONCE_SIZE] ^= 0xff;
        }

        let result = AesGcmSystem::decrypt(&key, &ciphertext, None);
        assert!(matches!(result, Err(AesGcmSystemError::DecryptionFailed)));
    }

    #[test]
    fn test_decrypt_tampered_nonce() {
        let config = CryptoConfig::default();
        let key = AesGcmSystem::generate_key(&config).unwrap();
        let plaintext = b"some data";
        let mut ciphertext = AesGcmSystem::encrypt(&key, plaintext, None).unwrap();

        // Tamper the nonce (after the 4-byte length prefix)
        if ciphertext.len() > 4 {
            ciphertext[4] ^= 0xff;
        }

        let result = AesGcmSystem::decrypt(&key, &ciphertext, None);
        assert!(matches!(result, Err(AesGcmSystemError::DecryptionFailed)));
    }

    #[test]
    fn test_encrypt_without_aad_decrypt_with_fails() {
        let config = CryptoConfig::default();
        let key = AesGcmSystem::generate_key(&config).unwrap();
        let plaintext = b"some data";
        let aad = b"some aad";

        let ciphertext = AesGcmSystem::encrypt(&key, plaintext, None).unwrap();
        let result = AesGcmSystem::decrypt(&key, &ciphertext, Some(aad));
        assert!(matches!(result, Err(AesGcmSystemError::DecryptionFailed)));
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn test_par_encrypt_decrypt_roundtrip() {
        let config = CryptoConfig::default();
        let key = AesGcmSystem::generate_key(&config).unwrap();
        let plaintext = b"This is a test for parallel encryption.";
        let parallelism_config = ParallelismConfig::default();

        let ciphertext =
            AesGcmSystem::par_encrypt(&key, plaintext, None, &parallelism_config).unwrap();
        let decrypted =
            AesGcmSystem::par_decrypt(&key, &ciphertext, None, &parallelism_config).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn test_par_encrypt_decrypt_with_aad_roundtrip() {
        let config = CryptoConfig::default();
        let key = AesGcmSystem::generate_key(&config).unwrap();
        let plaintext = b"This is a test for parallel encryption with AAD.";
        let aad = b"parallel aad";
        let parallelism_config = ParallelismConfig::default();

        let ciphertext =
            AesGcmSystem::par_encrypt(&key, plaintext, Some(aad), &parallelism_config).unwrap();
        let decrypted =
            AesGcmSystem::par_decrypt(&key, &ciphertext, Some(aad), &parallelism_config).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn test_par_encrypt_decrypt_large_payload() {
        let config = CryptoConfig::default();
        let key = AesGcmSystem::generate_key(&config).unwrap();
        let parallelism_config = ParallelismConfig::default();

        // 创建一个大于 PARALLEL_CHUNK_SIZE 的载荷，以强制多块处理
        let large_plaintext = vec![65u8; PARALLEL_CHUNK_SIZE + PARALLEL_CHUNK_SIZE / 2]; // 1.5 MiB
        let aad = b"additional data for large payload";

        let ciphertext =
            AesGcmSystem::par_encrypt(&key, &large_plaintext, Some(aad), &parallelism_config)
                .unwrap();
        let decrypted =
            AesGcmSystem::par_decrypt(&key, &ciphertext, Some(aad), &parallelism_config).unwrap();

        assert_eq!(decrypted, large_plaintext);
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn test_par_encrypt_empty_payload() {
        let config = CryptoConfig::default();
        let key = AesGcmSystem::generate_key(&config).unwrap();
        let parallelism_config = ParallelismConfig::default();
        let plaintext = b"";

        let ciphertext =
            AesGcmSystem::par_encrypt(&key, plaintext, None, &parallelism_config).unwrap();
        assert!(ciphertext.is_empty());

        let decrypted =
            AesGcmSystem::par_decrypt(&key, &ciphertext, None, &parallelism_config).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn test_par_decrypt_wrong_aad() {
        let config = CryptoConfig::default();
        let key = AesGcmSystem::generate_key(&config).unwrap();
        let parallelism_config = ParallelismConfig::default();
        let plaintext = vec![66u8; PARALLEL_CHUNK_SIZE + 100]; // Ensure multiple chunks
        let aad = b"correct aad";
        let wrong_aad = b"wrong aad";

        let ciphertext =
            AesGcmSystem::par_encrypt(&key, &plaintext, Some(aad), &parallelism_config).unwrap();

        let result =
            AesGcmSystem::par_decrypt(&key, &ciphertext, Some(wrong_aad), &parallelism_config);
        assert!(matches!(result, Err(AesGcmSystemError::DecryptionFailed)));
    }
}
