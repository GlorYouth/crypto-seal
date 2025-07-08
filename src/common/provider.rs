//! Implements a `KeyProvider` that stores password-protected keys on the local filesystem.
//!
//! 实现一个 `KeyProvider`，用于在本地文件系统上存储受密码保护的密钥。

use std::path::{Path, PathBuf};
use seal_flow::secrecy::SecretBox;

use crate::prelude::*;
use crate::common::storage::EncryptedKeyContainer;
use crate::error::Error;
use crate::common::managed::ManagedKey;
use seal_flow::keys::{TypedAsymmetricKeyPair, TypedSignatureKeyPair};
use std::sync::{Arc, Mutex};
use seal_flow::algorithms::traits::AsymmetricAlgorithm;
use chrono::Utc;
use base64::Engine;
use crate::contract::PublicKeyBundle;

/// A `KeyProvider` that manages keys stored as password-protected JSON files
/// in a specified directory.
///
/// Both asymmetric and signature key pairs are encrypted using an `EncryptedKeyContainer`.
///
/// 一个 `KeyProvider`，用于管理存储在指定目录中受密码保护的 JSON 文件中的密钥对。
///
/// 无论是用于加密的非对称密钥对还是用于签名的密钥对，都使用 `EncryptedKeyContainer` 进行加密。
pub struct FileSystemKeyProvider {
    /// The directory where encrypted key files are stored.
    ///
    /// 存储加密密钥文件的目录。
    storage_dir: PathBuf,
    /// The master password used to encrypt and decrypt all key pairs.
    ///
    /// 用于加密和解密所有密钥对的主密码。
    password: SecretBox<[u8]>,
}

impl FileSystemKeyProvider {
    /// Creates a new `FileSystemKeyProvider`.
    ///
    /// # Arguments
    ///
    /// * `storage_dir`: The directory where encrypted key files will be stored.
    /// * `password`: The master password used to encrypt and decrypt all key pairs.
    ///
    /// 创建一个新的 `FileSystemKeyProvider`。
    ///
    /// # 参数
    ///
    /// * `storage_dir`: 将存储加密密钥文件的目录。
    /// * `password`: 用于加密和解密所有密钥对的主密码。
    pub fn new<P: AsRef<Path>>(storage_dir: P, password: SecretBox<[u8]>) -> Result<Self, Error> {
        let path = storage_dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&path)?;

        Ok(Self {
            storage_dir: path,
            password,
        })
    }

    /// Saves a managed key to the provider, encrypting it and storing it as a JSON file.
    pub fn save_key(&self, key: &ManagedKey) -> Result<(), Error> {
        let container = EncryptedKeyContainer::create_from_serializable(
            &self.password,
            key,
            &key.metadata.algorithm,
        )?;
        self.save_container(&key.metadata.id, &container)
    }

    /// Loads and decrypts a managed key from the provider.
    pub fn load_key(&self, key_id: &str) -> Result<ManagedKey, Error> {
        let container = self
            .load_container(key_id)
            .map_err(|e| Error::KeyProvider(e))?;
        container
            .get_deserializable(&self.password)
            .map_err(Error::from)
    }

    /// Lists all key IDs found in the storage directory.
    /// This is done by finding all files that end with the `.key.json` suffix.
    ///
    /// 列出在存储目录中找到的所有密钥 ID。
    /// 这是通过查找所有以 `.key.json` 后缀结尾的文件来完成的。
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
    ///
    /// 将一个 `EncryptedKeyContainer` 保存到 JSON 文件。
    fn save_container(&self, key_id: &str, container: &EncryptedKeyContainer) -> Result<(), Error> {
        let file_path = self.get_container_path(key_id);
        let json = container.to_json()?;
        std::fs::write(&file_path, json)?;
        Ok(())
    }

    /// Loads an `EncryptedKeyContainer` from a JSON file.
    ///
    /// 从 JSON 文件加载一个 `EncryptedKeyContainer`。
    fn load_container(&self, key_id: &str) -> Result<EncryptedKeyContainer, KeyProviderError> {
        let file_path = self.get_container_path(key_id);
        if !file_path.exists() {
            return Err(KeyProviderError::KeyNotFound(key_id.to_string()));
        }
        let json = std::fs::read_to_string(&file_path).map_err(|e| KeyProviderError::Other(Box::new(e)))?;
        EncryptedKeyContainer::from_json(&json).map_err(|e| KeyProviderError::FormatError(Box::new(e)))
    }

    /// Returns the full path for a given key ID's container file.
    ///
    /// 返回给定密钥 ID 的容器文件的完整路径。
    fn get_container_path(&self, key_id: &str) -> PathBuf {
        self.storage_dir.join(format!("{}.key.json", key_id))
    }
}

impl KeyProvider for FileSystemKeyProvider {
    fn get_symmetric_key(&self, key_id: &str) -> Result<SymmetricKey, KeyProviderError> {
        let managed_key = self.load_key(key_id).map_err(|e| KeyProviderError::Other(Box::new(e)))?;
        
        // Here you could add checks based on metadata if needed, e.g.,
        // if !managed_key.metadata.algorithm.starts_with("Aes") { ... }

        Ok(SymmetricKey::new(managed_key.key_material))
    }

    fn get_asymmetric_private_key(&self, key_id: &str) -> Result<AsymmetricPrivateKey, KeyProviderError> {
        let managed_key = self.load_key(key_id).map_err(|e| KeyProviderError::Other(Box::new(e)))?;
        let (key_pair, _): (TypedAsymmetricKeyPair, usize) = bincode::serde::decode_from_slice(&managed_key.key_material, bincode::config::standard())
            .map_err(|e| KeyProviderError::FormatError(Box::new(e)))?;
        Ok(key_pair.private_key())
    }

    fn get_signature_public_key(&self, key_id: &str) -> Result<SignaturePublicKey, KeyProviderError> {
        let managed_key = self.load_key(key_id).map_err(|e| KeyProviderError::Other(Box::new(e)))?;
        let (key_pair, _): (TypedSignatureKeyPair, usize) = bincode::serde::decode_from_slice(&managed_key.key_material, bincode::config::standard())
            .map_err(|e| KeyProviderError::FormatError(Box::new(e)))?;
        Ok(key_pair.public_key())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use crate::common::managed::{KeyMetadata, KeyStatus};
    use chrono::Utc;
    use seal_flow::prelude::{AsymmetricAlgorithmEnum, SignatureAlgorithmEnum};
    use crate::algorithms::symmetric::Aes256Gcm;

    fn create_test_managed_key(
        id: &str,
        alias: &str,
        version: u32,
        algorithm: &str,
        key_material: Vec<u8>,
    ) -> ManagedKey {
        ManagedKey {
            metadata: KeyMetadata {
                id: id.to_string(),
                alias: alias.to_string(),
                version,
                created_at: Utc::now(),
                expires_at: Utc::now(),
                status: KeyStatus::Primary,
                algorithm: algorithm.to_string(),
            },
            key_material,
        }
    }

    #[test]
    fn symmetric_key_roundtrip() -> Result<(), Error> {
        let dir = tempdir()?;
        let password = SecretBox::new(Box::from(b"my-secret-password".as_slice()));
        let provider = FileSystemKeyProvider::new(dir.path(), password)?;

        let key_id = "test-symm-key-1";
        let key_material = SymmetricKey::generate(<Aes256Gcm as SymmetricCipher>::KEY_SIZE)?.into_bytes().to_vec();
        let managed_key = create_test_managed_key(
            key_id,
            "test-symm",
            1,
            "Aes256Gcm",
            key_material.clone(),
        );

        provider.save_key(&managed_key)?;
        let retrieved_key = provider.get_symmetric_key(key_id).map_err(Error::KeyProvider)?;

        assert_eq!(key_material, retrieved_key.as_bytes());
        Ok(())
    }

    #[test]
    fn asymmetric_key_roundtrip() -> Result<(), Error> {
        let dir = tempdir()?;
        let password = SecretBox::new(Box::from(b"another-password".as_slice()));
        let provider = FileSystemKeyProvider::new(dir.path(), password)?;

        let key_id = "test-asymm-key-1";
        let key_pair = TypedAsymmetricKeyPair::generate(AsymmetricAlgorithmEnum::Kyber512)?;
        let key_pair_bytes = bincode::serde::encode_to_vec(&key_pair, bincode::config::standard())
            .map_err(|e| Error::FormatError(format!("Failed to serialize key pair: {}", e)))?;

        let managed_key = create_test_managed_key(
            key_id,
            "test-asymm",
            1,
            "Kyber512",
            key_pair_bytes,
        );
        
        provider.save_key(&managed_key)?;
        let retrieved_key = provider.get_asymmetric_private_key(key_id).map_err(Error::KeyProvider)?;

        assert_eq!(key_pair.private_key().as_bytes(), retrieved_key.as_bytes());
        Ok(())
    }

    #[test]
    fn signature_key_roundtrip() -> Result<(), Error> {
        let dir = tempdir()?;
        let password = SecretBox::new(Box::from(b"sig-key-password".as_slice()));
        let provider = FileSystemKeyProvider::new(dir.path(), password)?;

        let key_id = "test-sig-key-1";
        let key_pair = TypedSignatureKeyPair::generate(SignatureAlgorithmEnum::Dilithium2)?;
        let key_pair_bytes = bincode::serde::encode_to_vec(&key_pair, bincode::config::standard())
            .map_err(|e| Error::FormatError(format!("Failed to serialize key pair: {}", e)))?;

        let managed_key = create_test_managed_key(
            key_id,
            "test-sig",
            1,
            "Dilithium2",
            key_pair_bytes,
        );

        provider.save_key(&managed_key)?;
        let retrieved_key = provider.get_signature_public_key(key_id).map_err(Error::KeyProvider)?;
        
        assert_eq!(key_pair.public_key().as_bytes(), retrieved_key.as_bytes());
        Ok(())
    }
}

/// A key provider that retrieves public keys from a remote server endpoint.
///
/// It caches the key locally to reduce network latency and handles fetching
/// a new key when the cached one expires. This component is designed for
/// client-side use and does not handle private keys.
pub struct RemoteKeyProvider {
    /// The remote server's base URL.
    server_url: String,
    /// The cached public key bundle. The Mutex is used for interior mutability.
    cache: Arc<Mutex<Option<PublicKeyBundle>>>,
}

impl RemoteKeyProvider {
    /// Creates a new `RemoteKeyProvider`.
    ///
    /// # Arguments
    ///
    /// * `server_url`: The base URL of the `seal-kit` server's public key endpoint.
    pub fn new(server_url: impl Into<String>) -> Self {
        Self {
            server_url: server_url.into(),
            cache: Arc::new(Mutex::new(None)),
        }
    }

    /// Retrieves a public key for the specified asymmetric algorithm.
    ///
    /// This method first checks for a valid (non-expired) cached key. If not found,
    /// it fetches a new `PublicKeyBundle` from the remote server and updates the cache.
    pub fn get_public_key<A: AsymmetricAlgorithm>(
        &self,
    ) -> Result<(String, AsymmetricPublicKey), Error> {
        let cache = self.cache.lock().unwrap();

        let bundle = match &*cache {
            Some(bundle) if bundle.expires_at > Utc::now() => {
                println!("Using cached key: {}", bundle.key_id);
                bundle.clone()
            }
            _ => {
                println!("Cache miss or expired, fetching new key...");
                drop(cache); // Drop the lock before the potentially slow network call
                let new_bundle = self.fetch_and_cache_key::<A>()?;
                new_bundle
            }
        };

        let key_bytes = base64::engine::general_purpose::STANDARD.decode(&bundle.public_key)?;
        let public_key = AsymmetricPublicKey::new(key_bytes);

        Ok((bundle.key_id, public_key))
    }

    /// Simulates fetching a new `PublicKeyBundle` from the server and caching it.
    ///
    /// In a real implementation, this would be an actual network request.
    fn fetch_and_cache_key<A: AsymmetricAlgorithm>(&self) -> Result<PublicKeyBundle, Error> {
        println!(
            "Simulating fetch from: {}/public_key/{}",
            self.server_url,
            A::name()
        );

        // Simulate generating a key on the server side.
        let (pk, _) = A::generate_keypair()?;

        let bundle = PublicKeyBundle {
            key_id: format!("{}-simulated-key-{}", A::name(), Utc::now().timestamp()),
            algorithm: A::name().to_string(),
            public_key: base64::engine::general_purpose::STANDARD.encode(pk.to_bytes()),
            issued_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
        };

        let mut cache = self.cache.lock().unwrap();
        *cache = Some(bundle.clone());

        Ok(bundle)
    }
}