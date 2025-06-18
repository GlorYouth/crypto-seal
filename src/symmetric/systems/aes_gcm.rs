//! AES-GCM 对称加密实现
use rsa::rand_core::RngCore;
use aes_gcm::{AeadCore, Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::{Aead, rand_core::OsRng, Payload};
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use crate::symmetric::traits::SymmetricCryptographicSystem;
use std::fmt::Debug;
use crate::common::utils::{Base64String, CryptoConfig};
use crate::common::to_base64;
use crate::Error;

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
    const KEY_SIZE: usize = KEY_SIZE; // Use the module-level constant
    type Key = AesGcmKey;
    type CiphertextOutput = Base64String;
    type Error = Error;

    /// 生成一个随机的 AES-256 密钥
    fn generate_key(_config: &CryptoConfig) -> Result<Self::Key, Self::Error> {
        let mut key_bytes = vec![0u8; KEY_SIZE];
        OsRng.try_fill_bytes(&mut key_bytes)
            .map_err(|e| Error::Operation(e.to_string()))?;
        Ok(AesGcmKey(key_bytes))
    }

    /// 使用 AES-256-GCM 加密数据
    /// Nonce 会被预置在密文前，然后整体进行 Base64 编码
    fn encrypt(
        key: &Self::Key,
        plaintext: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<String, Self::Error> {
        let cipher = Aes256Gcm::new_from_slice(&key.0).map_err(|e| Error::Key(e.to_string()))?;
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let aad = additional_data.unwrap_or(&[]);

        let payload = Payload { msg: plaintext, aad };
        let ciphertext = cipher
            .encrypt(&nonce, payload)
            .map_err(|_| Error::EncryptionFailed("AEAD encryption failed".to_string()))?;

        let mut result = nonce.to_vec();
        result.extend_from_slice(&ciphertext);

        Ok(to_base64(&result))
    }

    /// 解密 AES-256-GCM 加密的数据
    /// 输入是 Base64 编码的字符串，其中包含了 Nonce 和密文
    fn decrypt(
        key: &Self::Key,
        ciphertext: &str,
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, Self::Error> {
        let decoded_data = general_purpose::STANDARD
            .decode(ciphertext)
            .map_err(|e| Error::Format(format!("Base64 decoding failed: {}", e)))?;

        if decoded_data.len() < NONCE_SIZE {
            return Err(Error::DecryptionFailed(
                "Ciphertext is too short to contain a nonce.".to_string(),
            ));
        }

        let (nonce_bytes, ciphertext_bytes) = decoded_data.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);
        let cipher = Aes256Gcm::new_from_slice(&key.0).map_err(|e| Error::Key(e.to_string()))?;
        let aad = additional_data.unwrap_or(&[]);

        let payload = Payload { msg: ciphertext_bytes, aad };
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::utils::CryptoConfig;

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
        let ciphertext_b64 = ciphertext.to_string();
        let decrypted_plaintext = AesGcmSystem::decrypt(&key, &ciphertext_b64, None).unwrap();

        assert_eq!(plaintext, decrypted_plaintext.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_with_aad_success() {
        let config = CryptoConfig::default();
        let key = AesGcmSystem::generate_key(&config).unwrap();
        let plaintext = b"this is a secret message with aad";
        let aad = b"additional authenticated data";

        let ciphertext = AesGcmSystem::encrypt(&key, plaintext, Some(aad)).unwrap();
        let ciphertext_b64 = ciphertext.to_string();
        let decrypted_plaintext = AesGcmSystem::decrypt(&key, &ciphertext_b64, Some(aad)).unwrap();

        assert_eq!(plaintext, decrypted_plaintext.as_slice());
    }

    #[test]
    fn test_decrypt_wrong_key() {
        let config = CryptoConfig::default();
        let key1 = AesGcmSystem::generate_key(&config).unwrap();
        let key2 = AesGcmSystem::generate_key(&config).unwrap();
        let plaintext = b"this is another secret";

        let ciphertext = AesGcmSystem::encrypt(&key1, plaintext, None).unwrap();
        let ciphertext_b64 = ciphertext.to_string();
        let result = AesGcmSystem::decrypt(&key2, &ciphertext_b64, None);

        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_tampered_ciphertext() {
        let config = CryptoConfig::default();
        let key = AesGcmSystem::generate_key(&config).unwrap();
        let plaintext = b"secret message, do not tamper";

        // 1. 加密并获得base64字符串
        let ciphertext_b64 = AesGcmSystem::encrypt(&key, plaintext, None).unwrap();

        // 2. 从base64解码为原始字节(nonce || 密文)
        let mut raw_data = general_purpose::STANDARD.decode(&ciphertext_b64).unwrap();

        // 3. 篡改密文部分
        let len = raw_data.len();
        if len > 0 {
            raw_data[len - 1] ^= 0xff; // 翻转最后一个字节
        }

        // 4. 将篡改后的数据重新编码为base64
        let tampered_ciphertext_b64 = general_purpose::STANDARD.encode(&raw_data);

        // 5. 解密应该失败
        let result = AesGcmSystem::decrypt(&key, &tampered_ciphertext_b64, None);

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
        let ciphertext_b64 = ciphertext.to_string();
        let result = AesGcmSystem::decrypt(&key, &ciphertext_b64, Some(tampered_aad));
        
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
        let ciphertext_b64 = ciphertext.to_string();
        let decrypted_plaintext = AesGcmSystem::decrypt(&key, &ciphertext_b64, None).unwrap();
        
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
        
        let invalid_ciphertext = "not-even-base64";
        let result = AesGcmSystem::decrypt(&key, invalid_ciphertext, None);
        assert!(result.is_err());

        // Ciphertext too short
        let short_ciphertext = general_purpose::STANDARD.encode(&[0; NONCE_SIZE - 1]);
        let result = AesGcmSystem::decrypt(&key, &short_ciphertext, None);
        assert!(result.is_err());
    }
} 