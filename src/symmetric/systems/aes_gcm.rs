//! AES-GCM 对称加密实现
use crate::common::errors::Error;
use crate::common::to_base64;
use crate::common::utils::CryptoConfig;
use crate::symmetric::traits::SymmetricCryptographicSystem;
use aes_gcm::aead::{Aead, Payload, rand_core::OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, KeyInit, Nonce};
use base64::{Engine as _, engine::general_purpose};
use rsa::rand_core::RngCore;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

#[cfg(feature = "parallel")]
use crate::symmetric::traits::SymmetricParallelSystem;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
#[cfg(feature = "parallel")]
use std::io::{Cursor, Read};

const KEY_SIZE: usize = 32; // AES-256 需要 32 字节的密钥
const NONCE_SIZE: usize = 12; // GCM 标准的 Nonce 大小是 12 字节

/// AES-GCM 对称加密系统
pub struct AesGcmSystem;

/// AES-GCM 密钥的包装，以支持序列化和调试
#[derive(Clone, Serialize, Deserialize)]
pub struct AesGcmKey(pub Vec<u8>);

impl Debug for AesGcmKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AesGcmKey").finish_non_exhaustive()
    }
}

impl SymmetricCryptographicSystem for AesGcmSystem {
    const KEY_SIZE: usize = KEY_SIZE;
    type Key = AesGcmKey;
    type Error = Error;

    /// 生成一个随机的 AES-256 密钥
    fn generate_key(_config: &CryptoConfig) -> Result<Self::Key, Self::Error> {
        let mut key_bytes = vec![0u8; KEY_SIZE];
        OsRng
            .try_fill_bytes(&mut key_bytes)
            .map_err(|e| Error::Operation(e.to_string()))?;
        Ok(AesGcmKey(key_bytes))
    }

    /// 使用 AES-256-GCM 加密数据
    /// Nonce 会被预置在密文前
    fn encrypt(
        key: &Self::Key,
        plaintext: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, Self::Error> {
        let cipher = Aes256Gcm::new_from_slice(&key.0).map_err(|e| Error::Key(e.to_string()))?;
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let aad = additional_data.unwrap_or(&[]);

        let payload = Payload {
            msg: plaintext,
            aad,
        };
        let ciphertext = cipher
            .encrypt(&nonce, payload)
            .map_err(|_| Error::EncryptionFailed("AEAD encryption failed".to_string()))?;

        let mut result = nonce.to_vec();
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// 解密 AES-256-GCM 加密的数据
    /// 输入是包含了 Nonce 和密文的字节切片
    fn decrypt(
        key: &Self::Key,
        ciphertext: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, Self::Error> {
        if ciphertext.len() < NONCE_SIZE {
            return Err(Error::DecryptionFailed(
                "Ciphertext is too short to contain a nonce.".to_string(),
            ));
        }

        let (nonce_bytes, ciphertext_bytes) = ciphertext.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);
        let cipher = Aes256Gcm::new_from_slice(&key.0).map_err(|e| Error::Key(e.to_string()))?;
        let aad = additional_data.unwrap_or(&[]);

        let payload = Payload {
            msg: ciphertext_bytes,
            aad,
        };
        cipher
            .decrypt(nonce, payload)
            .map_err(|_| Error::DecryptionFailed("AEAD authentication failed.".to_string()))
    }

    /// 将密钥导出为 Base64 字符串
    fn export_key(key: &Self::Key) -> Result<String, Self::Error> {
        Ok(to_base64(&key.0))
    }

    /// 从 Base64 字符串导入密钥
    fn import_key(encoded_key: &str) -> Result<Self::Key, Self::Error> {
        let key_bytes = general_purpose::STANDARD
            .decode(encoded_key)
            .map_err(|e| Error::KeyImportFailed(format!("Base64 decoding failed: {}", e)))?;
        if key_bytes.len() != KEY_SIZE {
            return Err(Error::KeyImportFailed(format!(
                "Invalid key size: expected {}, got {}",
                KEY_SIZE,
                key_bytes.len()
            )));
        }
        Ok(AesGcmKey(key_bytes))
    }
}

#[cfg(feature = "parallel")]
const PARALLEL_CHUNK_SIZE: usize = 1024 * 1024; // 1 MiB

#[cfg(feature = "parallel")]
impl SymmetricParallelSystem for AesGcmSystem {
    /// 使用分块策略并行加密数据。
    /// 每个块都被独立加密，并附带自己的Nonce和认证标签。
    /// 输出格式为：[块1长度][加密块1][块2长度][加密块2]...
    fn par_encrypt(
        key: &Self::Key,
        plaintext: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, Self::Error> {
        if plaintext.is_empty() {
            return Ok(Vec::new());
        }

        // 1. 将明文分块，并并行加密
        let encrypted_chunks: Vec<Result<Vec<u8>, Self::Error>> = plaintext
            .par_chunks(PARALLEL_CHUNK_SIZE)
            .map(|chunk| Self::encrypt(key, chunk, additional_data))
            .collect();

        // 2. 检查是否有任何块加密失败，并组装成最终的带长度前缀的格式
        let mut final_result = Vec::new();
        for result in encrypted_chunks {
            let chunk = result?;
            let len = chunk.len() as u32;
            final_result.extend_from_slice(&len.to_le_bytes());
            final_result.extend_from_slice(&chunk);
        }

        Ok(final_result)
    }

    /// 并行解密使用 `par_encrypt` 加密的数据。
    fn par_decrypt(
        key: &Self::Key,
        ciphertext: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, Self::Error> {
        if ciphertext.is_empty() {
            return Ok(Vec::new());
        }

        // 1. 从流式格式中解析出所有独立的加密块
        let mut reader = Cursor::new(ciphertext);
        let mut chunks_to_decrypt: Vec<Vec<u8>> = Vec::new();
        let mut len_buf = [0u8; 4];

        while reader.read_exact(&mut len_buf).is_ok() {
            let len = u32::from_le_bytes(len_buf) as usize;
            if reader.get_ref().len() < reader.position() as usize + len {
                return Err(Error::DecryptionFailed(
                    "Ciphertext is truncated or malformed.".to_string(),
                ));
            }
            let mut chunk_buf = vec![0u8; len];
            reader.read_exact(&mut chunk_buf)?;
            chunks_to_decrypt.push(chunk_buf);
        }

        // 2. 并行解密所有块
        let decrypted_chunks: Vec<Result<Vec<u8>, Self::Error>> = chunks_to_decrypt
            .par_iter()
            .map(|chunk| Self::decrypt(key, chunk, additional_data))
            .collect();

        // 3. 检查是否有任何块解密失败，并拼接成最终的明文
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
    use crate::common::utils::CryptoConfig;

    #[cfg(feature = "parallel")]
    #[test]
    fn test_parallel_encrypt_decrypt_roundtrip() {
        let config = CryptoConfig::default();
        let key = AesGcmSystem::generate_key(&config).unwrap();
        let plaintext = vec![0xCF; PARALLEL_CHUNK_SIZE * 2 + 1]; // Make sure it spans multiple chunks

        let ciphertext = AesGcmSystem::par_encrypt(&key, &plaintext, None).unwrap();
        let decrypted_plaintext = AesGcmSystem::par_decrypt(&key, &ciphertext, None).unwrap();

        assert_eq!(plaintext, decrypted_plaintext);
    }

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
        let invalid_key_b64 = "invalid-base64-key";
        let result = AesGcmSystem::import_key(invalid_key_b64);
        assert!(result.is_err());

        let short_key_bytes = vec![0; 16];
        let short_key_b64 = general_purpose::STANDARD.encode(&short_key_bytes);
        let result = AesGcmSystem::import_key(&short_key_b64);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_invalid_ciphertext() {
        let config = CryptoConfig::default();
        let key = AesGcmSystem::generate_key(&config).unwrap();

        let _invalid_ciphertext = "not-even-valid-bytes-so-no-need-to-test";
        // We can't create invalid &[u8] in the same way as &str, so we test behavior with invalid formats.

        // Ciphertext too short
        let short_ciphertext = vec![0; NONCE_SIZE - 1];
        let result = AesGcmSystem::decrypt(&key, &short_ciphertext, None);
        assert!(result.is_err());
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
}
