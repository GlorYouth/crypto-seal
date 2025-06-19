#![cfg(feature = "secure-storage")]

use argon2::{
    Argon2, ParamsBuilder,
    password_hash::{PasswordHasher, SaltString},
};
use chrono::Utc;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::common::config::CryptoConfig;
use crate::common::errors::Error;
use crate::common::traits::SecureKeyStorage;
use crate::common::utils::{from_base64, to_base64};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use argon2::password_hash::rand_core::{OsRng, RngCore};

/// 加密的密钥容器，实现了SecureKeyStorage特征
/// 提供密码保护的密钥存储功能
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedKeyContainer {
    /// 加密的密钥数据
    encrypted_data: String,

    /// 用于AES-GCM的随机nonce
    nonce: String,

    /// Argon2密钥派生盐值
    salt: String,

    /// 算法标识符
    algorithm_id: String,

    /// 创建时间 (ISO 8601格式)
    created_at: String,

    /// Argon2内存成本参数（KB）
    #[serde(default = "default_memory_cost")]
    memory_cost: u32,

    /// Argon2时间成本参数（迭代次数）
    #[serde(default = "default_time_cost")]
    time_cost: u32,
}

fn default_memory_cost() -> u32 {
    19456 // 19MB
}

fn default_time_cost() -> u32 {
    2
}

impl EncryptedKeyContainer {
    /// 生成新的密钥容器
    pub fn new<K: AsRef<[u8]>>(
        password: &SecretString,
        key_data: K,
        algorithm_id: &str,
    ) -> Result<Self, Error> {
        Self::encrypt_key(password, key_data, algorithm_id)
    }

    /// 使用自定义配置生成新的密钥容器
    pub fn new_with_config<K: AsRef<[u8]>>(
        password: &SecretString,
        key_data: K,
        algorithm_id: &str,
        config: &CryptoConfig,
    ) -> Result<Self, Error> {
        Self::encrypt_key_with_config(password, key_data, algorithm_id, config)
    }

    /// 从密钥容器中提取密钥
    pub fn get_key(&self, password: &SecretString) -> Result<Vec<u8>, Error> {
        let secure_bytes = self.decrypt_key(password)?;
        Ok(secure_bytes.to_vec())
    }

    /// 使用自定义参数加密密钥
    pub fn encrypt_key_with_config<K: AsRef<[u8]>>(
        password: &SecretString,
        key_data: K,
        algorithm_id: &str,
        config: &CryptoConfig,
    ) -> Result<Self, Error> {
        // 生成随机盐值用于密钥派生
        let salt = SaltString::generate(&mut OsRng);

        // 使用配置的参数创建Argon2实例
        let mut params_builder = ParamsBuilder::new();
        params_builder
            .m_cost(config.argon2_memory_cost)
            .t_cost(config.argon2_time_cost)
            .p_cost(1) // 并行度参数
            .output_len(32); // 输出长度为32字节（256位）

        let params = params_builder
            .build()
            .map_err(|e| Error::KeyStorage(format!("Argon2参数无效: {}", e)))?;

        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

        // 使用Argon2派生加密密钥
        let password_bytes = password.expose_secret().as_bytes();
        let password_hash = argon2
            .hash_password(password_bytes, &salt)
            .map_err(|e| Error::KeyStorage(format!("密码哈希失败: {}", e)))?;

        // 安全地获取哈希值
        let hash = password_hash
            .hash
            .ok_or_else(|| Error::KeyStorage("无法生成密码哈希".to_string()))?;
        let derived_key = hash.as_bytes();

        // 创建AES-GCM加密器
        let cipher = Aes256Gcm::new_from_slice(derived_key)
            .map_err(|e| Error::KeyStorage(format!("创建加密器失败: {}", e)))?;

        // 生成随机nonce并加密数据
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);

        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, key_data.as_ref())
            .map_err(|e| Error::KeyStorage(format!("加密密钥失败: {}", e)))?;

        Ok(Self {
            encrypted_data: to_base64(&ciphertext),
            nonce: to_base64(&nonce_bytes),
            salt: salt.as_str().to_string(),
            algorithm_id: algorithm_id.to_string(),
            created_at: Utc::now().to_rfc3339(),
            memory_cost: config.argon2_memory_cost,
            time_cost: config.argon2_time_cost,
        })
    }
}

impl SecureKeyStorage for EncryptedKeyContainer {
    type Error = Error;

    fn encrypt_key<K: AsRef<[u8]>>(
        password: &SecretString,
        key_data: K,
        algorithm_id: &str,
    ) -> Result<Self, Self::Error> {
        // 使用默认配置
        Self::encrypt_key_with_config(password, key_data, algorithm_id, &CryptoConfig::default())
    }

    fn decrypt_key(&self, password: &SecretString) -> Result<Vec<u8>, Self::Error> {
        // 重建盐值和派生密钥
        let salt_str = &self.salt;
        let salt = SaltString::from_b64(salt_str)
            .map_err(|e| Error::KeyStorage(format!("无效的盐值: {}", e)))?;

        // 使用存储的参数重新创建Argon2实例
        let mut params_builder = ParamsBuilder::new();
        params_builder
            .m_cost(self.memory_cost)
            .t_cost(self.time_cost)
            .p_cost(1) // 并行度参数
            .output_len(32); // 输出长度为32字节（256位）

        let params = params_builder
            .build()
            .map_err(|e| Error::KeyStorage(format!("Argon2参数无效: {}", e)))?;

        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

        let password_bytes = password.expose_secret().as_bytes();
        let password_hash = argon2
            .hash_password(password_bytes, &salt)
            .map_err(|e| Error::KeyStorage(format!("密码哈希失败: {}", e)))?;

        // 安全地获取哈希值
        let hash = password_hash
            .hash
            .ok_or_else(|| Error::KeyStorage("无法生成密码哈希".to_string()))?;
        let derived_key = hash.as_bytes();

        // 创建AES-GCM解密器
        let cipher = Aes256Gcm::new_from_slice(derived_key)
            .map_err(|e| Error::KeyStorage(format!("创建解密器失败: {}", e)))?;

        // 解码nonce和密文
        let nonce_bytes = from_base64(&self.nonce)?;
        let ciphertext = from_base64(&self.encrypted_data)?;

        // 解密密钥数据
        let nonce = Nonce::from_slice(&nonce_bytes);
        let decrypted = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| Error::KeyStorage(format!("解密密钥失败，密码可能不正确: {}", e)))?;

        Ok(decrypted)
    }

    fn algorithm_id(&self) -> &str {
        &self.algorithm_id
    }

    fn created_at(&self) -> &str {
        &self.created_at
    }

    fn to_json(&self) -> Result<String, Self::Error> {
        serde_json::to_string(self)
            .map_err(|e| Error::Serialization(format!("序列化容器失败: {}", e)))
    }

    fn from_json(json: &str) -> Result<Self, Self::Error> {
        serde_json::from_str(json).map_err(|e| Error::Serialization(format!("解析容器失败: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_container_roundtrip() {
        let password = SecretString::new(Box::from("test-password"));
        let key_data = b"this-is-a-secret-key";
        let algorithm_id = "test-algorithm";

        // 加密密钥
        let container =
            EncryptedKeyContainer::encrypt_key(&password, key_data, algorithm_id).unwrap();

        // 解密密钥
        let decrypted = container.decrypt_key(&password).unwrap();
        assert_eq!(&decrypted, key_data);

        // 验证其他字段
        assert_eq!(container.algorithm_id(), algorithm_id);
        assert!(!container.created_at().is_empty());
    }

    #[test]
    fn json_serialization_roundtrip() {
        let password = SecretString::new(Box::from("test-password"));
        let key_data = b"this-is-a-secret-key";
        let algorithm_id = "test-algorithm";

        // 创建并序列化容器
        let container =
            EncryptedKeyContainer::encrypt_key(&password, key_data, algorithm_id).unwrap();
        let json = container.to_json().unwrap();

        // 反序列化和解密
        let restored = EncryptedKeyContainer::from_json(&json).unwrap();
        let decrypted = restored.decrypt_key(&password).unwrap();

        assert_eq!(decrypted, key_data);
        assert_eq!(restored.algorithm_id(), container.algorithm_id());
        assert_eq!(restored.created_at(), container.created_at());
    }

    #[test]
    fn wrong_password_fails() {
        let password = SecretString::new(Box::from("correct-password"));
        let wrong_password = SecretString::new(Box::from("wrong-password"));
        let key_data = b"this-is-a-secret-key";

        // 加密密钥
        let container = EncryptedKeyContainer::encrypt_key(&password, key_data, "test").unwrap();

        // 使用错误密码尝试解密
        let result = container.decrypt_key(&wrong_password);
        assert!(result.is_err());
    }

    #[test]
    fn custom_config_works() {
        let password = SecretString::new(Box::from("secure-password"));
        let key_data = b"this-is-a-secret-key";
        let algorithm_id = "test-algorithm";

        // 创建自定义配置
        let config = CryptoConfig {
            argon2_memory_cost: 32768, // 32MB
            argon2_time_cost: 3,       // 3次迭代
            ..CryptoConfig::default()
        };

        // 使用自定义配置加密
        let container =
            EncryptedKeyContainer::new_with_config(&password, key_data, algorithm_id, &config)
                .unwrap();

        // 验证配置参数已应用
        assert_eq!(container.memory_cost, config.argon2_memory_cost);
        assert_eq!(container.time_cost, config.argon2_time_cost);

        // 解密并验证
        let decrypted = container.decrypt_key(&password).unwrap();
        assert_eq!(&decrypted, key_data);
    }
}
