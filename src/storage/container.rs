//! An encrypted container for password-protected key storage.

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
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedKeyContainer {
    /// Base64-encoded encrypted data block, produced by `SymmetricSeal`.
    encrypted_data: String,
    
    /// Base64-encoded salt used for Argon2 key derivation.
    salt: String,
    
    /// Algorithm identifier of the key being stored (for metadata purposes).
    algorithm_id: String,
    
    /// Creation timestamp in ISO 8601 format.
    created_at: String,
    
    /// Argon2 memory cost parameter (in KiB).
    #[serde(default = "default_memory_cost")]
    memory_cost: u32,
    
    /// Argon2 time cost parameter (number of iterations).
    #[serde(default = "default_time_cost")]
    time_cost: u32,
    
    /// Argon2 parallelism cost parameter.
    #[serde(default = "default_parallelism_cost")]
    parallelism_cost: u32,
}

fn default_memory_cost() -> u32 { 19456 } // 19 MiB
fn default_time_cost() -> u32 { 2 }
fn default_parallelism_cost() -> u32 { 1 }

impl EncryptedKeyContainer {
    /// Creates a new encrypted key container with default Argon2 parameters.
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
    
    /// Decrypts and returns the raw key bytes from the container.
    pub fn get_key(&self, password: &SecretBox<[u8]>) -> Result<Vec<u8>, Error> {
        self.decrypt_key(password)
    }

    /// Serializes the container to a JSON string.
    pub fn to_json(&self) -> Result<String, Error> {
        serde_json::to_string(self)
            .map_err(|e| Error::SerializeError(e))
    }

    /// Deserializes a container from a JSON string.
    pub fn from_json(json: &str) -> Result<Self, Error> {
        serde_json::from_str(json)
            .map_err(|e| Error::DeserializeError(e))
    }
    
    /// The core encryption logic.
    fn encrypt_key<K: AsRef<[u8]>>(
        password: &SecretBox<[u8]>,
        key_data: K,
        algorithm_id: &str,
        memory_cost: u32,
        time_cost: u32,
        parallelism_cost: u32,
    ) -> Result<Self, Error> {
        // 1. Setup KDF for password derivation.
        let argon2 = Argon2::new(memory_cost, time_cost, parallelism_cost);
        let salt = argon2.generate_salt()?;
        let output_len = <Aes256Gcm as SymmetricCipher>::KEY_SIZE;

        // 2. Derive a temporary "wrapping key" from the password.
        let wrapping_key = SymmetricKey::derive_from_password(
            password,
            &argon2,
            &salt,
            output_len,
        )?;

        // 3. Use SymmetricSeal to encrypt the actual key_data with the wrapping key.
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
    fn decrypt_key(&self, password: &SecretBox<[u8]>) -> Result<Vec<u8>, Error> {
        // 1. Decode the salt from Base64.
        let salt_bytes = general_purpose::STANDARD.decode(&self.salt)?;

        // 2. Re-derive the same "wrapping key" using the stored parameters.
        let argon2 = Argon2::new(self.memory_cost, self.time_cost, self.parallelism_cost);
        let output_len = <Aes256Gcm as SymmetricCipher>::KEY_SIZE;
        
        let wrapping_key = SymmetricKey::derive_from_password(
            password,
            &argon2,
            &salt_bytes,
            output_len,
        )?;

        // 3. Decode the ciphertext and use SymmetricSeal to decrypt it.
        let ciphertext = general_purpose::STANDARD.decode(&self.encrypted_data)?;
        
        let decrypted_bytes = SymmetricSeal::new()
            .decrypt()
            .slice(&ciphertext)?
            .with_key(wrapping_key)?;

        Ok(decrypted_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
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