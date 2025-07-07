//! Manages the lifecycle and rotation of cryptographic keys.

use crate::error::Error;
use crate::managed::{KeyMetadata, KeyStatus, ManagedKey};
use crate::prelude::*;
use crate::storage::provider::FileSystemKeyProvider;
use chrono::{Duration, Utc};
use dashmap::DashMap;
use seal_flow::algorithms::symmetric::Aes256Gcm;
use seal_flow::prelude::{
    AsymmetricPrivateKey, AsymmetricPublicKey, KeyProvider, KeyProviderError, SignaturePublicKey,
    SymmetricCipher,
};
use seal_flow::algorithms::traits::AsymmetricAlgorithm;
use seal_flow::keys::{TypedAsymmetricKeyPair};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// A policy defining when and how keys should be rotated.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RotationPolicy {
    /// The total validity period for a key, in days.
    pub validity_period_days: u32,
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self {
            validity_period_days: 90, // Default to 90 days
        }
    }
}

/// Manages the automatic rotation of a logical key.
///
/// This manager handles a set of key versions for a given `alias`,
/// ensuring that a `Primary` key is always available for encryption and that
/// `Secondary` keys are available for decryption.
pub struct RotatingKeyManager {
    provider: Arc<FileSystemKeyProvider>,
    alias: String,
    policy: RotationPolicy,
    // Caches the metadata of all known key versions for the alias.
    versions: DashMap<String, KeyMetadata>,
}

impl RotatingKeyManager {
    /// Creates a new `RotatingKeyManager` and initializes it by loading all
    /// existing key versions for the given alias from the provider.
    ///
    /// # Arguments
    ///
    /// * `provider`: The storage provider to load from and save to.
    /// * `alias`: The logical name of the key to manage.
    /// * `policy`: The rotation policy to apply.
    pub fn new(
        provider: Arc<FileSystemKeyProvider>,
        alias: &str,
        policy: RotationPolicy,
    ) -> Result<Self, Error> {
        let manager = Self {
            provider,
            alias: alias.to_string(),
            policy,
            versions: DashMap::new(),
        };
        manager.load_all_versions()?;
        Ok(manager)
    }

    /// Loads all key versions associated with this manager's alias from the
    /// storage provider and populates the in-memory `versions` cache.
    fn load_all_versions(&self) -> Result<(), Error> {
        let all_key_ids = self.provider.list_key_ids()?;

        self.versions.clear();

        for key_id in all_key_ids {
            // Key IDs are structured as "{alias}-v{version}".
            // We only want to load keys that match our alias prefix.
            if key_id.starts_with(&format!("{}-v", self.alias)) {
                match self.load_managed_key(&key_id) {
                    Ok(managed_key) => {
                        // As a safeguard, double-check the alias inside the metadata.
                        if managed_key.metadata.alias == self.alias {
                            self.versions.insert(key_id, managed_key.metadata);
                        }
                    }
                    Err(e) => {
                        // If a single key is corrupt or fails to load, we'll log
                        // the error but not fail the entire manager initialization.
                        eprintln!("Warning: Failed to load key '{}': {}", key_id, e);
                    }
                }
            }
        }

        Ok(())
    }

    /// Retrieves the current primary key for encryption.
    /// If no primary key exists or the current one needs rotation, this method
    /// will trigger the rotation process.
    pub fn get_encryption_key(
        &self,
        algorithm_name: &str,
    ) -> Result<(KeyMetadata, SymmetricKey), Error> {
        // First, perform a read-only check to find a valid primary key.
        // This is an optimistic check to avoid the more expensive rotation logic if possible.
        if let Some(primary_meta) = self
            .versions
            .iter()
            .find(|m| m.status == KeyStatus::Primary && m.alias == self.alias)
        {
            // Also check if the algorithm matches. If not, we need to rotate.
            if !self.needs_rotation(&primary_meta) && primary_meta.algorithm == algorithm_name {
                let managed_key = self.load_managed_key(&primary_meta.id)?;
                return Ok((
                    managed_key.metadata,
                    SymmetricKey::new(managed_key.key_material),
                ));
            }
        }

        // If the optimistic check fails (no primary, or it needs rotation, or algorithm mismatch),
        // proceed to the full rotation logic. This part handles the write operations.
        self.rotate_key(algorithm_name)
    }

    /// Retrieves the current primary public key for encryption.
    /// If no primary key exists or the current one needs rotation, this method
    /// will trigger the rotation process for an asymmetric key.
    pub fn get_encryption_public_key<K: AsymmetricAlgorithm>(
        &self,
    ) -> Result<(KeyMetadata, AsymmetricPublicKey), Error> {
        // First, perform a read-only check to find a valid primary key.
        if let Some(primary_meta) = self
            .versions
            .iter()
            .find(|m| m.status == KeyStatus::Primary && m.alias == self.alias)
        {
            if !self.needs_rotation(&primary_meta) {
                let managed_key = self.load_managed_key(&primary_meta.id)?;
                let (key_pair, _): (TypedAsymmetricKeyPair, _) =
                    bincode::serde::decode_from_slice(
                        &managed_key.key_material,
                        bincode::config::standard(),
                    )
                    .map_err(|e| {
                        Error::FormatError(format!(
                            "Failed to deserialize TypedAsymmetricKeyPair: {}",
                            e
                        ))
                    })?;
                return Ok((managed_key.metadata, key_pair.public_key()));
            }
        }

        // If the optimistic check fails, proceed to the full rotation logic.
        self.rotate_asymmetric_key::<K>()
    }

    /// Retrieves a specific key by its full ID for decryption.
    pub fn get_decryption_key(&self, key_id: &str) -> Result<SymmetricKey, Error> {
        let managed_key = self.load_managed_key(key_id)?;
        if managed_key.metadata.status == KeyStatus::Expired {
            return Err(Error::RotationError(format!(
                "Key {} has expired and cannot be used.",
                key_id
            )));
        }
        Ok(SymmetricKey::new(managed_key.key_material))
    }

    /// Checks if the current primary key is due for rotation.
    fn needs_rotation(&self, metadata: &KeyMetadata) -> bool {
        Utc::now() >= metadata.expires_at
    }

    /// The core key rotation logic.
    ///
    /// This function performs the following steps atomically:
    /// 1. Demotes the current `Primary` key to `Secondary`.
    /// 2. Creates a new `Primary` key with the specified algorithm.
    /// 3. Saves both updated keys to the provider.
    /// 4. Updates the in-memory cache.
    fn rotate_key(&self, algorithm_name: &str) -> Result<(KeyMetadata, SymmetricKey), Error> {
        // 1. Find and demote the old primary key, if it exists.
        if let Some(mut old_primary) = self
            .versions
            .iter_mut()
            .find(|m| m.status == KeyStatus::Primary)
        {
            old_primary.status = KeyStatus::Secondary;
            let mut managed_key = self.load_managed_key(old_primary.key())?;
            managed_key.metadata.status = KeyStatus::Secondary;
            self.save_managed_key(&managed_key)?;
        }

        // 2. Create a new primary key.
        let new_version = self
            .versions
            .iter()
            .filter(|m| m.alias == self.alias)
            .map(|m| m.version)
            .max()
            .unwrap_or(0)
            + 1;

        let now = Utc::now();
        let new_metadata = KeyMetadata {
            id: format!("{}-v{}", self.alias, new_version),
            alias: self.alias.clone(),
            version: new_version,
            created_at: now,
            expires_at: now + Duration::days(self.policy.validity_period_days as i64),
            status: KeyStatus::Primary,
            algorithm: algorithm_name.to_string(),
        };

        let key_size = match algorithm_name {
            "Aes256Gcm" => <Aes256Gcm as SymmetricCipher>::KEY_SIZE,
            _ => {
                return Err(Error::RotationError(format!(
                    "Unsupported symmetric algorithm for rotation: {}",
                    algorithm_name
                )))
            }
        };

        let new_key_material = SymmetricKey::generate(key_size)?;

        let new_managed_key = ManagedKey {
            metadata: new_metadata.clone(),
            key_material: new_key_material.as_bytes().to_vec(),
        };

        // 3. Save the new key first.
        self.save_managed_key(&new_managed_key)?;

        // 4. Update the in-memory cache.
        self.versions
            .insert(new_metadata.id.clone(), new_metadata.clone());

        Ok((new_metadata, new_key_material))
    }

    /// Rotates an asymmetric key pair.
    fn rotate_asymmetric_key<K: AsymmetricAlgorithm>(
        &self,
    ) -> Result<(KeyMetadata, AsymmetricPublicKey), Error> {
        // 1. Find and demote the old primary key, if it exists.
        if let Some(mut old_primary) = self
            .versions
            .iter_mut()
            .find(|m| m.status == KeyStatus::Primary)
        {
            old_primary.status = KeyStatus::Secondary;
            let mut managed_key = self.load_managed_key(old_primary.key())?;
            managed_key.metadata.status = KeyStatus::Secondary;
            self.save_managed_key(&managed_key)?;
        }

        // 2. Create a new primary key.
        let new_version = self
            .versions
            .iter()
            .filter(|m| m.alias == self.alias)
            .map(|m| m.version)
            .max()
            .unwrap_or(0)
            + 1;

        let now = Utc::now();
        let new_metadata = KeyMetadata {
            id: format!("{}-v{}", self.alias, new_version),
            alias: self.alias.clone(),
            version: new_version,
            created_at: now,
            expires_at: now + Duration::days(self.policy.validity_period_days as i64),
            status: KeyStatus::Primary,
            algorithm: K::name(),
        };

        let key_pair = TypedAsymmetricKeyPair::generate(K::ALGORITHM)?;
        let key_pair_bytes = bincode::serde::encode_to_vec(&key_pair, bincode::config::standard())
            .map_err(|e| {
                Error::FormatError(format!(
                    "Failed to serialize TypedAsymmetricKeyPair: {}",
                    e
                ))
            })?;

        let new_managed_key = ManagedKey {
            metadata: new_metadata.clone(),
            key_material: key_pair_bytes,
        };

        // 3. Save the new key.
        self.save_managed_key(&new_managed_key)?;

        // 4. Update in-memory cache.
        self.versions
            .insert(new_metadata.id.clone(), new_metadata.clone());

        Ok((new_metadata, key_pair.public_key()))
    }

    /// Helper to load and deserialize a `ManagedKey` from the provider.
    fn load_managed_key(&self, key_id: &str) -> Result<ManagedKey, Error> {
        self.provider.load_key(key_id)
    }

    /// Helper to serialize and save a `ManagedKey` to the provider.
    fn save_managed_key(&self, managed_key: &ManagedKey) -> Result<(), Error> {
        self.provider.save_key(managed_key)
    }
}

impl KeyProvider for RotatingKeyManager {
    fn get_symmetric_key(&self, key_id: &str) -> Result<SymmetricKey, KeyProviderError> {
        self.get_decryption_key(key_id)
            .map_err(|e| KeyProviderError::Other(Box::new(e)))
    }

    fn get_asymmetric_private_key(
        &self,
        key_id: &str,
    ) -> Result<AsymmetricPrivateKey, KeyProviderError> {
        let managed_key = self
            .load_managed_key(key_id)
            .map_err(|e| KeyProviderError::Other(Box::new(e)))?;
        if managed_key.metadata.status == KeyStatus::Expired {
            return Err(KeyProviderError::Other(Box::new(Error::RotationError(
                format!("Key {} has expired and cannot be used.", key_id),
            ))));
        }
        let (key_pair, _): (TypedAsymmetricKeyPair, _) =
            bincode::serde::decode_from_slice(
                &managed_key.key_material,
                bincode::config::standard(),
            )
            .map_err(|e| KeyProviderError::FormatError(Box::new(e)))?;
        Ok(key_pair.private_key())
    }

    fn get_signature_public_key(
        &self,
        key_id: &str,
    ) -> Result<SignaturePublicKey, KeyProviderError> {
        // This KeyProvider implementation is focused on encryption/decryption keys.
        // A separate manager could be implemented for signature keys if needed.
        // 这个 KeyProvider 实现专注于加密/解密密钥。
        // 如果需要，可以实现一个单独的签名密钥管理器。
        Err(KeyProviderError::KeyNotFound(key_id.to_string()))
    }
} 