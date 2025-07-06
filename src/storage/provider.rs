//! Implements a `KeyProvider` that stores password-protected keys on the local filesystem.

use std::path::{Path, PathBuf};
use dashmap::DashMap;
use seal_flow::secrecy::SecretBox;

use crate::prelude::*;
use crate::storage::container::EncryptedKeyContainer;
use crate::error::Error;

/// A `KeyProvider` that manages keys stored as password-protected JSON files
/// in a specified directory.
///
/// Private and symmetric keys are encrypted using an `EncryptedKeyContainer`.
/// Public keys for signature verification are held in memory for fast access.
pub struct FileSystemKeyProvider {
    storage_dir: PathBuf,
    password: SecretBox<[u8]>,
    // Public keys are cached in memory as they are not secret and are read often.
    public_keys: DashMap<String, SignaturePublicKey>,
}

impl FileSystemKeyProvider {
    /// Creates a new `FileSystemKeyProvider`.
    ///
    /// # Arguments
    ///
    /// * `storage_dir`: The directory where encrypted key files will be stored.
    /// * `password`: The master password used to encrypt and decrypt all private/symmetric keys.
    pub fn new<P: AsRef<Path>>(storage_dir: P, password: SecretBox<[u8]>) -> Result<Self, Error> {
        let path = storage_dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&path)?;

        Ok(Self {
            storage_dir: path,
            password,
            public_keys: DashMap::new(),
        })
    }

    /// Adds a key to the provider, encrypting it and saving it to a file.
    pub fn add_key(&self, key_id: &str, key_bytes: &[u8], algorithm_id: &str) -> Result<(), Error> {
        let container = EncryptedKeyContainer::new(&self.password, key_bytes, algorithm_id)?;
        self.save_container(key_id, &container)
    }

    /// Adds a new symmetric key to the provider, encrypting it and saving it to a file.
    pub fn add_symmetric_key(&self, key_id: &str, key: &SymmetricKey) -> Result<(), Error> {
        self.add_key(key_id, key.as_bytes(), "symmetric")
    }

    /// Adds a new asymmetric private key to the provider, encrypting and saving it.
    pub fn add_asymmetric_private_key(&self, key_id: &str, key: &AsymmetricPrivateKey) -> Result<(), Error> {
        self.add_key(key_id, key.as_bytes(), "asymmetric")
    }

    /// Adds a signature public key to the in-memory cache.
    /// These are not persisted to disk by this provider.
    pub fn add_signature_public_key(&self, key_id: &str, key: SignaturePublicKey) {
        self.public_keys.insert(key_id.to_string(), key);
    }

    /// Lists all key IDs found in the storage directory.
    /// This is done by finding all files that end with the `.key.json` suffix.
    pub fn list_key_ids(&self) -> Result<Vec<String>, Error> {
        let mut key_ids = Vec::new();
        for entry in std::fs::read_dir(&self.storage_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                    if let Some(key_id) = file_name.strip_suffix(".key.json") {
                        key_ids.push(key_id.to_string());
                    }
                }
            }
        }
        Ok(key_ids)
    }

    /// Saves an `EncryptedKeyContainer` to a JSON file.
    fn save_container(&self, key_id: &str, container: &EncryptedKeyContainer) -> Result<(), Error> {
        let file_path = self.get_container_path(key_id);
        let json = container.to_json()?;
        std::fs::write(&file_path, json)?;
        Ok(())
    }

    /// Loads an `EncryptedKeyContainer` from a JSON file.
    fn load_container(&self, key_id: &str) -> Result<EncryptedKeyContainer, KeyProviderError> {
        let file_path = self.get_container_path(key_id);
        if !file_path.exists() {
            return Err(KeyProviderError::KeyNotFound(key_id.to_string()));
        }
        let json = std::fs::read_to_string(&file_path).map_err(|e| KeyProviderError::Other(Box::new(e)))?;
        EncryptedKeyContainer::from_json(&json).map_err(|e| KeyProviderError::FormatError(Box::new(e)))
    }

    /// Returns the full path for a given key ID's container file.
    fn get_container_path(&self, key_id: &str) -> PathBuf {
        self.storage_dir.join(format!("{}.key.json", key_id))
    }
}

impl KeyProvider for FileSystemKeyProvider {
    fn get_symmetric_key(&self, key_id: &str) -> Result<SymmetricKey, KeyProviderError> {
        let container = self.load_container(key_id)?;
        let key_bytes = container.get_key(&self.password).map_err(|e| KeyProviderError::Other(Box::new(e)))?;
        Ok(SymmetricKey::new(key_bytes))
    }

    fn get_asymmetric_private_key(&self, key_id: &str) -> Result<AsymmetricPrivateKey, KeyProviderError> {
        let container = self.load_container(key_id)?;
        let key_bytes = container.get_key(&self.password).map_err(|e| KeyProviderError::Other(Box::new(e)))?;
        Ok(AsymmetricPrivateKey::new(key_bytes))
    }

    fn get_signature_public_key(&self, key_id: &str) -> Result<SignaturePublicKey, KeyProviderError> {
        self.public_keys
            .get(key_id)
            .map(|k| k.clone())
            .ok_or_else(|| KeyProviderError::KeyNotFound(key_id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn file_system_key_provider_symmetric_roundtrip() -> Result<(), Error> {
        let dir = tempdir()?;
        let password = SecretBox::new(Box::from(b"my-secret-password".as_slice()));
        let provider = FileSystemKeyProvider::new(dir.path(), password)?;

        let key_id = "test-symm-key-1";
        let key = SymmetricKey::new(vec![42; 32]);

        // Add and retrieve key
        provider.add_symmetric_key(key_id, &key)?;
        let retrieved_key = provider.get_symmetric_key(key_id).map_err(|e| Error::KeyProvider(e))?;

        assert_eq!(key.as_bytes(), retrieved_key.as_bytes());

        // Test not found
        assert!(provider.get_symmetric_key("non-existent-key").is_err());

        Ok(())
    }

    #[test]
    fn file_system_key_provider_asymmetric_roundtrip() -> Result<(), Error> {
        let dir = tempdir()?;
        let password = SecretBox::new(Box::from(b"another-password".as_slice()));
        let provider = FileSystemKeyProvider::new(dir.path(), password)?;

        let key_id = "test-asymm-key-1";
        let key = AsymmetricPrivateKey::new(vec![1, 2, 3, 4]); // Dummy key data

        // Add and retrieve key
        provider.add_asymmetric_private_key(key_id, &key)?;
        let retrieved_key = provider.get_asymmetric_private_key(key_id).map_err(|e| Error::KeyProvider(e))?;

        assert_eq!(key.as_bytes(), retrieved_key.as_bytes());
        Ok(())
    }

    #[test]
    fn file_system_key_provider_public_key() -> Result<(), Error> {
        let dir = tempdir()?;
        let password = SecretBox::new(Box::from(b"public-key-pw".as_slice()));
        let provider = FileSystemKeyProvider::new(dir.path(), password)?;

        let key_id = "test-pub-key-1";
        let key = SignaturePublicKey::new(vec![10, 20, 30]);

        // Add and retrieve public key
        provider.add_signature_public_key(key_id, key.clone());
        let retrieved_key = provider.get_signature_public_key(key_id).map_err(|e| Error::KeyProvider(e))?;

        assert_eq!(key.as_bytes(), retrieved_key.as_bytes());

        // Test not found
        assert!(provider.get_signature_public_key("non-existent-pub-key").is_err());

        Ok(())
    }
} 