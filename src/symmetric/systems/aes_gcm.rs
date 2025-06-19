//! AES-GCM 对称加密实现
use crate::common::config::{CryptoConfig, ParallelismConfig};
use crate::common::errors::Error;
use crate::symmetric::traits::{SymmetricCryptographicSystem, SymmetricParallelSystem};
use aes_gcm::aead::{AeadInPlace, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Nonce, Tag};
use base64::{Engine, engine::general_purpose};
use rayon::prelude::*;
use rsa::rand_core::RngCore;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::io::{Cursor, Read};
use typenum::U12;

const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16; // AES-GCM's tag is 16 bytes
const PARALLEL_CHUNK_SIZE: usize = 1024 * 1024; // 1 MiB

/// AES-GCM 对称加密系统
#[derive(Debug)]
pub struct AesGcmSystem;

/// AES-GCM 密钥的包装，以支持序列化和调试
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct AesGcmKey(pub Vec<u8>);

/// A helper struct to manage chunk-level encryption results.
/// 一个辅助结构，用于管理块级加密结果。
struct EncryptedChunk {
    nonce: Nonce<U12>,
    tag: Tag,
    ciphertext: Vec<u8>,
}

impl SymmetricCryptographicSystem for AesGcmSystem {
    const KEY_SIZE: usize = KEY_SIZE;
    type Key = AesGcmKey;
    type Error = Error;
    type CiphertextOutput = Vec<u8>;

    fn generate_key(_config: &CryptoConfig) -> Result<Self::Key, Self::Error> {
        let mut key_bytes = vec![0u8; Self::KEY_SIZE];
        OsRng
            .try_fill_bytes(&mut key_bytes)
            .map_err(|e| Error::Key(e.to_string()))?;
        Ok(AesGcmKey(key_bytes))
    }

    fn encrypt(
        key: &Self::Key,
        plaintext: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, Self::Error> {
        let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key.0);
        let cipher = Aes256Gcm::new(key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let mut buffer = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(&nonce, additional_data.unwrap_or(&[]), &mut buffer)
            .map_err(|e| Error::EncryptionFailed(e.to_string()))?;

        let mut raw_ciphertext = Vec::with_capacity(NONCE_SIZE + TAG_SIZE + buffer.len());
        raw_ciphertext.extend_from_slice(nonce.as_slice());
        raw_ciphertext.extend_from_slice(&tag);
        raw_ciphertext.extend_from_slice(&buffer);

        // 统一密文格式：[4字节长度][加密块]
        let mut final_output = Vec::with_capacity(4 + raw_ciphertext.len());
        final_output.extend_from_slice(&(raw_ciphertext.len() as u32).to_le_bytes());
        final_output.extend_from_slice(&raw_ciphertext);

        Ok(final_output)
    }

    fn decrypt(
        key: &Self::Key,
        ciphertext: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, Self::Error> {
        // 统一密文格式：[4字节长度][加密块]
        if ciphertext.len() < 4 {
            return Err(Error::DecryptionFailed(
                "Ciphertext is too short to contain length prefix".to_string(),
            ));
        }
        let (len_slice, raw_ciphertext) = ciphertext.split_at(4);
        let len = u32::from_le_bytes(len_slice.try_into().unwrap()) as usize;

        if raw_ciphertext.len() != len {
            return Err(Error::DecryptionFailed(
                "Ciphertext length does not match length prefix".to_string(),
            ));
        }

        if raw_ciphertext.len() < NONCE_SIZE + TAG_SIZE {
            return Err(Error::DecryptionFailed(
                "Ciphertext is too short".to_string(),
            ));
        }
        let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key.0);
        let cipher = Aes256Gcm::new(key);

        let (nonce_slice, rest) = raw_ciphertext.split_at(NONCE_SIZE);
        let (tag_slice, ct_slice) = rest.split_at(TAG_SIZE);
        let nonce = Nonce::from_slice(nonce_slice);
        let tag = Tag::from_slice(tag_slice);

        let mut buffer = ct_slice.to_vec();
        cipher
            .decrypt_in_place_detached(nonce, additional_data.unwrap_or(&[]), &mut buffer, tag)
            .map_err(|e| Error::DecryptionFailed(e.to_string()))?;

        Ok(buffer)
    }

    fn export_key(key: &Self::Key) -> Result<String, Self::Error> {
        Ok(general_purpose::STANDARD.encode(&key.0))
    }

    fn import_key(encoded_key: &str) -> Result<Self::Key, Self::Error> {
        let key_bytes = general_purpose::STANDARD
            .decode(encoded_key)
            .map_err(|e| Error::Key(format!("Base64 decoding failed: {}", e)))?;
        if key_bytes.len() != KEY_SIZE {
            return Err(Error::Key("Invalid key size after decoding".to_string()));
        }
        Ok(AesGcmKey(key_bytes))
    }
}

impl AesGcmSystem {
    /// Encrypts a single chunk of data, intended for parallel execution.
    /// 加密单个数据块，专为并行执行设计。
    fn encrypt_chunk_parallel(
        cipher: &Aes256Gcm,
        chunk: &[u8],
        aad: &[u8],
    ) -> Result<EncryptedChunk, Error> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let mut buffer = chunk.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(&nonce, aad, &mut buffer)
            .map_err(|e| Error::EncryptionFailed(e.to_string()))?;
        Ok(EncryptedChunk {
            nonce,
            tag,
            ciphertext: buffer,
        })
    }
}

#[cfg(feature = "parallel")]
impl SymmetricParallelSystem for AesGcmSystem {
    fn par_encrypt(
        key: &Self::Key,
        plaintext: &[u8],
        additional_data: Option<&[u8]>,
        parallelism_config: &ParallelismConfig,
    ) -> Result<Vec<u8>, Self::Error> {
        if plaintext.is_empty() {
            return Self::encrypt(key, plaintext, additional_data); // Use serial for empty
        }

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(parallelism_config.parallelism)
            .build()
            .map_err(|e| Error::Key(e.to_string()))?;

        let key_slice = aes_gcm::Key::<Aes256Gcm>::from_slice(&key.0);
        let cipher = Aes256Gcm::new(key_slice);
        let additional_data = additional_data.unwrap_or(&[]);

        let encrypted_chunks: Vec<Result<EncryptedChunk, Self::Error>> = pool.install(|| {
            plaintext
                .par_chunks(PARALLEL_CHUNK_SIZE)
                .enumerate()
                .map(|(i, chunk)| {
                    let mut aad_chunk = additional_data.to_vec();
                    aad_chunk.extend_from_slice(&(i as u64).to_le_bytes());
                    Self::encrypt_chunk_parallel(&cipher, chunk, &aad_chunk)
                })
                .collect()
        });

        // Serialize the chunks into the final format: [num_chunks: u32][chunk_1]...[chunk_n]
        // where chunk_i = [nonce][tag][ciphertext]
        let mut final_result = Vec::new();
        let num_chunks = encrypted_chunks.len() as u32;
        final_result.extend_from_slice(&num_chunks.to_le_bytes());

        for result in encrypted_chunks {
            let chunk = result?;
            final_result.extend_from_slice(chunk.nonce.as_slice());
            final_result.extend_from_slice(&chunk.tag);
            final_result.extend_from_slice(&chunk.ciphertext);
        }

        Ok(final_result)
    }

    fn par_decrypt(
        key: &Self::Key,
        ciphertext: &[u8],
        additional_data: Option<&[u8]>,
        parallelism_config: &ParallelismConfig,
    ) -> Result<Vec<u8>, Self::Error> {
        if ciphertext.is_empty() {
            return Ok(Vec::new());
        }

        // Deserialize the ciphertext format: [num_chunks: u32][chunk_1]...[chunk_n]
        if ciphertext.len() < 4 {
            return Err(Error::DecryptionFailed(
                "Ciphertext too short for chunk count".into(),
            ));
        }
        let (num_chunks_slice, mut data_area) = ciphertext.split_at(4);
        let num_chunks = u32::from_le_bytes(num_chunks_slice.try_into().unwrap());

        if num_chunks == 0 {
            return Ok(Vec::new());
        }

        let mut chunks_to_decrypt = Vec::with_capacity(num_chunks as usize);
        for i in 0..num_chunks {
            if data_area.len() < NONCE_SIZE + TAG_SIZE {
                return Err(Error::DecryptionFailed(format!(
                    "Ciphertext truncated, not enough data for nonce and tag in chunk {}",
                    i
                )));
            }
            let (nonce_slice, r1) = data_area.split_at(NONCE_SIZE);
            let (tag_slice, r2) = r1.split_at(TAG_SIZE);

            // The last chunk's size is whatever is left.
            // 最后一个块的大小就是剩余的所有数据。
            let chunk_ct_len = if i < num_chunks - 1 {
                PARALLEL_CHUNK_SIZE
            } else {
                r2.len()
            };

            if r2.len() < chunk_ct_len {
                return Err(Error::DecryptionFailed(format!(
                    "Ciphertext truncated, not enough data for ciphertext in chunk {}",
                    i
                )));
            }

            let (ct_slice, r3) = r2.split_at(chunk_ct_len);

            chunks_to_decrypt.push((
                Nonce::<U12>::clone_from_slice(nonce_slice),
                Tag::clone_from_slice(tag_slice),
                ct_slice.to_vec(),
            ));
            data_area = r3; // Update the slice to the remaining part
        }

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(parallelism_config.parallelism)
            .build()
            .map_err(|e| Error::Key(e.to_string()))?;

        let key_slice = aes_gcm::Key::<Aes256Gcm>::from_slice(&key.0);
        let cipher = Aes256Gcm::new(key_slice);
        let additional_data = additional_data.unwrap_or(&[]);

        let decrypted_chunks: Vec<Result<Vec<u8>, Self::Error>> = pool.install(|| {
            chunks_to_decrypt
                .par_iter()
                .enumerate()
                .map(|(i, (nonce, tag, chunk_ct))| {
                    let mut aad_chunk = additional_data.to_vec();
                    aad_chunk.extend_from_slice(&(i as u64).to_le_bytes());
                    let mut buffer = chunk_ct.clone();
                    cipher
                        .decrypt_in_place_detached(nonce, &aad_chunk, &mut buffer, tag)
                        .map_err(|e| Error::DecryptionFailed(e.to_string()))?;
                    Ok(buffer)
                })
                .collect()
        });

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

        assert!(result.is_err());
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

        assert!(result.is_err(), "对被篡改的密文进行解密应该失败");
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

        assert!(result.is_err());
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
        assert!(matches!(result, Err(Error::Key(_))));

        let short_key_bytes = vec![0u8; 16];
        let short_encoded_key = general_purpose::STANDARD.encode(&short_key_bytes);
        let result_short = AesGcmSystem::import_key(&short_encoded_key);
        assert!(matches!(result_short, Err(Error::Key(_))));
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
            matches!(result, Err(Error::DecryptionFailed(e)) if e.contains("length does not match length prefix"))
        );

        // 测试过短的密文 (无法包含长度前缀)
        let short_ciphertext = vec![0, 1, 2];
        let result_short = AesGcmSystem::decrypt(&key, &short_ciphertext, None);
        assert!(
            matches!(result_short, Err(Error::DecryptionFailed(e)) if e.contains("too short to contain length prefix"))
        );

        // 测试过短的密文 (包含长度前缀但数据不足)
        let mut another_short_ciphertext = vec![0u8; NONCE_SIZE + TAG_SIZE - 1];
        let len_bytes = (another_short_ciphertext.len() as u32).to_le_bytes();
        let mut final_ciphertext = len_bytes.to_vec();
        final_ciphertext.append(&mut another_short_ciphertext);
        let result_another_short = AesGcmSystem::decrypt(&key, &final_ciphertext, None);
        assert!(
            matches!(result_another_short, Err(Error::DecryptionFailed(e)) if e.contains("too short"))
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

        assert!(result.is_err());
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
        if ciphertext.len() >= NONCE_SIZE + TAG_SIZE {
            ciphertext[NONCE_SIZE] ^= 0xff;
        }

        let result = AesGcmSystem::decrypt(&key, &ciphertext, None);
        assert!(
            result.is_err(),
            "Decryption should fail with a tampered tag"
        );
    }

    #[test]
    fn test_decrypt_tampered_nonce() {
        let config = CryptoConfig::default();
        let key = AesGcmSystem::generate_key(&config).unwrap();
        let plaintext = b"some data";
        let mut ciphertext = AesGcmSystem::encrypt(&key, plaintext, None).unwrap();

        // Tamper the nonce
        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0xff;
        }

        let result = AesGcmSystem::decrypt(&key, &ciphertext, None);
        assert!(
            result.is_err(),
            "Decryption should fail with a tampered nonce"
        );
    }

    #[test]
    fn test_encrypt_without_aad_decrypt_with_fails() {
        let config = CryptoConfig::default();
        let key = AesGcmSystem::generate_key(&config).unwrap();
        let plaintext = b"some data";
        let aad = b"some aad";

        let ciphertext = AesGcmSystem::encrypt(&key, plaintext, None).unwrap();
        let result = AesGcmSystem::decrypt(&key, &ciphertext, Some(aad));
        assert!(
            result.is_err(),
            "Decryption should fail when AAD is unexpectedly provided"
        );
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
        assert!(matches!(result, Err(Error::DecryptionFailed(_))));
    }
}
