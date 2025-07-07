//! An encrypted container for password-protected key storage.
//!
//! 一个用于存储受密码保护的密钥的加密容器。

use seal_flow::secrecy::SecretBox;
use serde::{Deserialize, Serialize};
use chrono::Utc;
use base64::{Engine as _, engine::general_purpose};

use seal_flow::{
    seal::SymmetricSeal,
    algorithms::{
        kdf::passwd::Argon2,
        symmetric::Aes256Gcm,
    },
    prelude::*,
};
use crate::error::Error;

/// An encrypted container for storing a key, protected by a user-provided password.
/// It uses Argon2 for key derivation from the password, and AES-256-GCM to encrypt the key data.
///
/// 用于存储受用户密码保护的密钥的加密容器。
/// 它使用 Argon2 从密码派生密钥，并使用 AES-256-GCM 加密密钥数据。
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedKeyContainer {
    /// Base64-encoded encrypted data block, produced by `SymmetricSeal`.
    ///
    /// Base64 编码的加密数据块，由 `SymmetricSeal` 生成。
    encrypted_data: String,
    
    /// Base64-encoded salt used for Argon2 key derivation.
    ///
    /// 用于 Argon2 密钥派生的 Base64 编码盐值。
    salt: String,
    
    /// Algorithm identifier of the key being stored (for metadata purposes).
    ///
    /// 存储的密钥的算法标识符（用于元数据目的）。
    algorithm_id: String,
    
    /// Creation timestamp in ISO 8601 format.
    ///
    /// ISO 8601 格式的创建时间戳。
    created_at: String,
    
    /// Argon2 memory cost parameter (in KiB).
    ///
    /// Argon2 内存成本参数（以 KiB 为单位）。
    #[serde(default = "default_memory_cost")]
    memory_cost: u32,
    
    /// Argon2 time cost parameter (number of iterations).
    ///
    /// Argon2 时间成本参数（迭代次数）。
    #[serde(default = "default_time_cost")]
    time_cost: u32,
    
    /// Argon2 parallelism cost parameter.
    ///
    /// Argon2 并行成本参数。
    #[serde(default = "default_parallelism_cost")]
    parallelism_cost: u32,
}

fn default_memory_cost() -> u32 { 19456 } // 19 MiB
fn default_time_cost() -> u32 { 2 }
fn default_parallelism_cost() -> u32 { 1 }

impl EncryptedKeyContainer {
    /// Creates a new encrypted key container with default Argon2 parameters.
    ///
    /// 使用默认的 Argon2 参数创建一个新的加密密钥容器。
    pub fn new<K: AsRef<[u8]>>(
        password: &SecretBox<[u8]>,
        key_data: K,
        algorithm_id: &str,
    ) -> Result<Self, Error> {
        Self::encrypt_key(
            password,
            key_data,
            algorithm_id,
            default_memory_cost(),
            default_time_cost(),
            default_parallelism_cost(),
        )
    }
    
    /// Creates a new encrypted key container with custom Argon2 parameters.
    ///
    /// 使用自定义的 Argon2 参数创建一个新的加密密钥容器。
    pub fn new_with_params<K: AsRef<[u8]>>(
        password: &SecretBox<[u8]>,
        key_data: K,
        algorithm_id: &str,
        memory_cost: u32,
        time_cost: u32,
        parallelism_cost: u32,
    ) -> Result<Self, Error> {
        Self::encrypt_key(password, key_data, algorithm_id, memory_cost, time_cost, parallelism_cost)
    }

    /// Creates a new container by serializing and encrypting a given object.
    ///
    /// 通过序列化和加密给定对象来创建一个新容器。
    pub fn create_from_serializable<T: Serialize>(
        password: &SecretBox<[u8]>,
        item: &T,
        algorithm_id: &str,
    ) -> Result<Self, Error> {
        let serialized_data = bincode::serde::encode_to_vec(item, bincode::config::standard())
            .map_err(|e| Error::FormatError(format!("Failed to serialize key pair: {}", e).into()))?;
        Self::new(password, &serialized_data, algorithm_id)
    }
    
    /// Decrypts and returns the raw key bytes from the container.
    ///
    /// 从容器中解密并返回原始密钥字节。
    pub fn get_key(&self, password: &SecretBox<[u8]>) -> Result<Vec<u8>, Error> {
        self.decrypt_key(password)
    }

    /// Decrypts the container and deserializes the content into a specific type.
    ///
    /// 解密容器并将内容反序列化为特定类型。
    pub fn get_deserializable<T: for<'de> Deserialize<'de>>(&self, password: &SecretBox<[u8]>) -> Result<T, Error> {
        let decrypted_bytes = self.decrypt_key(password)?;
        let r = bincode::serde::decode_from_slice(&decrypted_bytes, bincode::config::standard())
            .map_err(|e| Error::FormatError(format!("Failed to deserialize key pair: {}", e).into()))?
            .0;
        Ok(r)
    }

    /// Serializes the container to a JSON string.
    ///
    /// 将容器序列化为 JSON 字符串。
    pub fn to_json(&self) -> Result<String, Error> {
        serde_json::to_string(self)
            .map_err(|e| Error::SerializeError(e))
    }

    /// Deserializes a container from a JSON string.
    ///
    /// 从 JSON 字符串反序列化容器。
    pub fn from_json(json: &str) -> Result<Self, Error> {
        serde_json::from_str(json)
            .map_err(|e| Error::DeserializeError(e))
    }
    
    /// The core encryption logic.
    ///
    /// 核心加密逻辑。
    fn encrypt_key<K: AsRef<[u8]>>(
        password: &SecretBox<[u8]>,
        key_data: K,
        algorithm_id: &str,
        memory_cost: u32,
        time_cost: u32,
        parallelism_cost: u32,
    ) -> Result<Self, Error> {
        // 1. Setup KDF for password derivation.
        // 1. 设置用于密码派生的 KDF。
        let argon2 = Argon2::new(memory_cost, time_cost, parallelism_cost);
        let salt = argon2.generate_salt()?;
        let output_len = <Aes256Gcm as SymmetricCipher>::KEY_SIZE;

        // 2. Derive a temporary "wrapping key" from the password.
        // 2. 从密码派生一个临时的“包装密钥”。
        let wrapping_key = SymmetricKey::derive_from_password(
            password,
            &argon2,
            &salt,
            output_len,
        )?;

        // 3. Use SymmetricSeal to encrypt the actual key_data with the wrapping key.
        // 3. 使用 SymmetricSeal 和包装密钥加密实际的 key_data。
        let ciphertext = SymmetricSeal::new()
            .encrypt(wrapping_key, "password-derived-key".to_string())
            .to_vec::<Aes256Gcm>(key_data.as_ref())?;
        
        Ok(Self {
            encrypted_data: general_purpose::STANDARD.encode(&ciphertext),
            salt: general_purpose::STANDARD.encode(salt),
            algorithm_id: algorithm_id.to_string(),
            created_at: Utc::now().to_rfc3339(),
            memory_cost,
            time_cost,
            parallelism_cost,
        })
    }

    /// The core decryption logic.
    ///
    /// 核心解密逻辑。
    fn decrypt_key(&self, password: &SecretBox<[u8]>) -> Result<Vec<u8>, Error> {
        // 1. Decode the salt from Base64.
        // 1. 从 Base64 解码盐值。
        let salt_bytes = general_purpose::STANDARD.decode(&self.salt)?;

        // 2. Re-derive the same "wrapping key" using the stored parameters.
        // 2. 使用存储的参数重新派生相同的“包装密钥”。
        let argon2 = Argon2::new(self.memory_cost, self.time_cost, self.parallelism_cost);
        let output_len = <Aes256Gcm as SymmetricCipher>::KEY_SIZE;
        
        let wrapping_key = SymmetricKey::derive_from_password(
            password,
            &argon2,
            &salt_bytes,
            output_len,
        )?;

        // 3. Decode the ciphertext and use SymmetricSeal to decrypt it.
        // 3. 解码密文并使用 SymmetricSeal 进行解密。
        let ciphertext = general_purpose::STANDARD.decode(&self.encrypted_data)?;
        
        let decrypted_bytes = SymmetricSeal::new()
            .decrypt()
            .slice(&ciphertext)?
            .with_key(wrapping_key)?;

        Ok(decrypted_bytes)
    }

    /// Returns the algorithm identifier of the key being stored.
    ///
    /// 返回存储的密钥的算法标识符。
    pub fn get_algorithm_id(&self) -> &str {
        &self.algorithm_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seal_flow::{keys::TypedAsymmetricKeyPair, secrecy::SecretBox};
    
    #[test]
    fn encrypted_container_roundtrip() -> Result<(), Error> {
        let password = SecretBox::new(Box::from(b"test-password".as_slice()));
        let key_data = b"this-is-a-secret-key";
        let algorithm_id = "test-algorithm";
        
        let container = EncryptedKeyContainer::new(&password, key_data, algorithm_id)?;
        let decrypted = container.get_key(&password)?;
        assert_eq!(&decrypted, key_data);
        
        assert_eq!(container.algorithm_id, algorithm_id);
        assert!(!container.created_at.is_empty());
        Ok(())
    }

    #[test]
    fn serializable_roundtrip() -> Result<(), Error> {
        let password = SecretBox::new(Box::from(b"test-password-for-serializable".as_slice()));
        let key_pair = TypedAsymmetricKeyPair::generate(AsymmetricAlgorithmEnum::Kyber512)?;

        let algorithm_id = "kyber512-pair";
        
        let container = EncryptedKeyContainer::create_from_serializable(&password, &key_pair, algorithm_id)?;
        
        let decrypted_pair: TypedAsymmetricKeyPair = container.get_deserializable(&password)?;

        // We can't directly compare the key pairs for equality as they don't derive `PartialEq`.
        // Instead, we compare their byte representations.
        assert_eq!(key_pair.private_key().as_bytes(), decrypted_pair.private_key().as_bytes());
        assert_eq!(key_pair.public_key().as_bytes(), decrypted_pair.public_key().as_bytes());

        assert_eq!(container.algorithm_id, algorithm_id);

        Ok(())
    }
    
    #[test]
    fn json_serialization_roundtrip() -> Result<(), Error> {
        let password = SecretBox::new(Box::from(b"test-password".as_slice()));
        let key_data = b"another-secret";
        
        let container = EncryptedKeyContainer::new(&password, key_data, "test-algo-2")?;
        let json = container.to_json()?;
        let container2 = EncryptedKeyContainer::from_json(&json)?;
        
        assert_eq!(container.encrypted_data, container2.encrypted_data);
        assert_eq!(container.salt, container2.salt);
        assert_eq!(container.algorithm_id, container2.algorithm_id);

        let decrypted = container2.get_key(&password)?;
        assert_eq!(&decrypted, key_data);
        Ok(())
    }
    
    #[test]
    fn wrong_password_fails() -> Result<(), Error> {
        let password = SecretBox::new(Box::from(b"correct-password".as_slice()));
        let wrong_password = SecretBox::new(Box::from(b"wrong-password".as_slice()));
        
        let container = EncryptedKeyContainer::new(&password, b"some key data", "id")?;
        let result = container.get_key(&wrong_password);
        
        assert!(result.is_err());
        Ok(())
    }
    
    #[test]
    fn custom_config_works() -> Result<(), Error> {
        let password = SecretBox::new(Box::from(b"a-password".as_slice()));
        let key_data = b"key with custom config";
        
        let container = EncryptedKeyContainer::new_with_params(
            &password, key_data, "custom-id", 4096, 3, 2
        )?;
        
        assert_eq!(container.memory_cost, 4096);
        assert_eq!(container.time_cost, 3);
        assert_eq!(container.parallelism_cost, 2);
        
        let decrypted = container.get_key(&password)?;
        assert_eq!(&decrypted, key_data);
        Ok(())
    }
} 