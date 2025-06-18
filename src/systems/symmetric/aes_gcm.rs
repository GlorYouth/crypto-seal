//! AES-GCM 对称加密实现
use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit};
use aes_gcm::aead::{Aead, Payload};
use base64::{Engine as _, engine::general_purpose};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Serialize, Deserialize};
use crate::errors::Error;
use crate::primitives::{CryptoConfig, Base64String};
use crate::traits::SymmetricCryptographicSystem;
use std::fmt::Debug;

const KEY_SIZE: usize = 32; // AES-256 需要 32 字节的密钥
const NONCE_SIZE: usize = 12; // GCM 标准的 Nonce 大小是 12 字节

/// AES-GCM 对称加密系统
pub struct AesGcmSystem;

/// AES-GCM 密钥的包装，以支持序列化和调试
#[derive(Clone, Serialize, Deserialize)]
pub struct AesGcmKey(Vec<u8>);

impl Debug for AesGcmKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AesGcmKey").finish_non_exhaustive()
    }
}

impl SymmetricCryptographicSystem for AesGcmSystem {
    type Key = AesGcmKey;
    type CiphertextOutput = Base64String;
    type Error = Error;

    /// 生成一个随机的 AES-256 密钥
    fn generate_key(_config: &CryptoConfig) -> Result<Self::Key, Self::Error> {
        let mut key_bytes = vec![0u8; KEY_SIZE];
        OsRng.fill_bytes(&mut key_bytes);
        Ok(AesGcmKey(key_bytes))
    }

    /// 使用 AES-256-GCM 加密数据
    /// Nonce 会被预置在密文前，然后整体进行 Base64 编码
    fn encrypt(
        key: &Self::Key,
        plaintext: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<Self::CiphertextOutput, Self::Error> {
        let key = Key::<Aes256Gcm>::from_slice(&key.0);
        let cipher = Aes256Gcm::new(key);

        let mut nonce_bytes = vec![0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let aad = additional_data.unwrap_or_default();

        let ciphertext = cipher.encrypt(nonce, Payload { msg: plaintext, aad })
            .map_err(|e| Error::EncryptionFailed(e.to_string()))?;

        let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(nonce.as_slice());
        result.extend_from_slice(&ciphertext);

        Ok(Base64String::from(result))
    }

    /// 解密 AES-256-GCM 加密的数据
    /// 输入是 Base64 编码的字符串，其中包含了 Nonce 和密文
    fn decrypt(
        key: &Self::Key,
        ciphertext_b64: &str,
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, Self::Error> {
        let key = Key::<Aes256Gcm>::from_slice(&key.0);
        let cipher = Aes256Gcm::new(key);
        
        let decoded_data = general_purpose::STANDARD.decode(ciphertext_b64)
            .map_err(|e| Error::DecryptionFailed(format!("Base64 decoding failed: {}", e)))?;

        if decoded_data.len() < NONCE_SIZE {
            return Err(Error::DecryptionFailed("Ciphertext is too short to contain a nonce".to_string()));
        }

        let (nonce_bytes, ciphertext) = decoded_data.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        let aad = additional_data.unwrap_or_default();

        cipher.decrypt(nonce, Payload { msg: ciphertext, aad })
            .map_err(|e| Error::DecryptionFailed(e.to_string()))
    }

    /// 将密钥导出为 Base64 字符串
    fn export_key(key: &Self::Key) -> Result<String, Self::Error> {
        Ok(general_purpose::STANDARD.encode(&key.0))
    }

    /// 从 Base64 字符串导入密钥
    fn import_key(key_data: &str) -> Result<Self::Key, Self::Error> {
        let key_bytes = general_purpose::STANDARD.decode(key_data)
            .map_err(|e| Error::KeyImportFailed(format!("Base64 decoding failed: {}", e)))?;
        
        if key_bytes.len() != KEY_SIZE {
            return Err(Error::KeyImportFailed(format!("Invalid key size: expected {}, got {}", KEY_SIZE, key_bytes.len())));
        }

        Ok(AesGcmKey(key_bytes))
    }
} 