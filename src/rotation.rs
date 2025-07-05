//! Manages the lifecycle and rotation of cryptographic keys.

use crate::error::Error;
use crate::prelude::*;
use crate::storage::provider::FileSystemKeyProvider;
use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use seal_flow::algorithms::symmetric::Aes256Gcm;
use seal_flow::prelude::{
    AsymmetricPrivateKey, KeyProvider, KeyProviderError, SignaturePublicKey, SymmetricCipher,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// The status of a cryptographic key within its lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum KeyStatus {
    /// The primary key, currently used for all new encryption operations.
    Primary,
    /// A previous primary key, now only used for decrypting old data.
    Secondary,
    /// An old key that is past its validity period and should no longer be used.
    Expired,
}

/// Metadata associated with a managed cryptographic key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// The full, unique identifier for this specific key version (e.g., "my-key-alias-v2").
    pub id: String,
    /// The logical name for the key, common across all its versions (e.g., "my-key-alias").
    pub alias: String,
    /// The version number of the key.
    pub version: u32,
    /// The timestamp when the key was created.
    pub created_at: DateTime<Utc>,
    /// The timestamp when the key is scheduled to expire.
    pub expires_at: DateTime<Utc>,
    /// The current status of the key in the rotation lifecycle.
    pub status: KeyStatus,
    /// The algorithm the key is intended for.
    pub algorithm: String,
}

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

/// A container that atomically stores a key's metadata alongside its raw key material.
/// This struct is what gets serialized and encrypted into a `EncryptedKeyContainer`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredKey {
    metadata: KeyMetadata,
    key_material: Vec<u8>,
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
                match self.load_stored_key(&key_id) {
                    Ok(stored_key) => {
                        // As a safeguard, double-check the alias inside the metadata.
                        if stored_key.metadata.alias == self.alias {
                            self.versions.insert(key_id, stored_key.metadata);
                        }
                    }
                    Err(e) => {
                        // If a single key is corrupt or fails to load, we'll log
                        // the error but not fail the entire manager initialization.
                        eprintln!("Warning: Failed to load and deserialize key '{}': {}", key_id, e);
                    }
                }
            }
        }

        Ok(())
    }

    /// Retrieves the current primary key for encryption.
    /// If no primary key exists or the current one needs rotation, this method
    /// will trigger the rotation process.
    pub fn get_encryption_key(&self) -> Result<(KeyMetadata, SymmetricKey), Error> {
        // First, perform a read-only check to find a valid primary key.
        // This is an optimistic check to avoid the more expensive rotation logic if possible.
        if let Some(primary_meta) = self
            .versions
            .iter()
            .find(|m| m.status == KeyStatus::Primary && m.alias == self.alias)
        {
            if !self.needs_rotation(&primary_meta) {
                let stored_key = self.load_stored_key(&primary_meta.id)?;
                return Ok((
                    stored_key.metadata,
                    SymmetricKey::new(stored_key.key_material),
                ));
            }
        }

        // If the optimistic check fails (no primary, or it needs rotation),
        // proceed to the full rotation logic. This part handles the write operations.
        self.rotate_key()
    }

    /// Retrieves a specific key by its full ID for decryption.
    pub fn get_decryption_key(&self, key_id: &str) -> Result<SymmetricKey, Error> {
        let stored_key = self.load_stored_key(key_id)?;
        if stored_key.metadata.status == KeyStatus::Expired {
            return Err(Error::RotationError(format!(
                "Key {} has expired and cannot be used.",
                key_id
            )));
        }
        Ok(SymmetricKey::new(stored_key.key_material))
    }

    /// Checks if the current primary key is due for rotation.
    fn needs_rotation(&self, metadata: &KeyMetadata) -> bool {
        Utc::now() >= metadata.expires_at
    }

    /// The core key rotation logic.
    ///
    /// This function performs the following steps atomically:
    /// 1. Demotes the current `Primary` key to `Secondary`.
    /// 2. Creates a new `Primary` key.
    /// 3. Saves both updated keys to the provider.
    /// 4. Updates the in-memory cache.
    fn rotate_key(&self) -> Result<(KeyMetadata, SymmetricKey), Error> {
        // 1. Find and demote the old primary key, if it exists.
        if let Some(mut old_primary) = self
            .versions
            .iter_mut()
            .find(|m| m.status == KeyStatus::Primary)
        {
            old_primary.status = KeyStatus::Secondary;
            // The change to `old_primary` is now "latched" within the iter_mut.
            // We now load the full key and re-save it with the updated status.
            let mut stored_key = self.load_stored_key(old_primary.key())?;
            stored_key.metadata.status = KeyStatus::Secondary;
            self.save_stored_key(&stored_key)?;
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
            algorithm: "Aes256Gcm".to_string(), // Assuming this for now
        };

        let new_key_material = SymmetricKey::generate(<Aes256Gcm as SymmetricCipher>::KEY_SIZE)?;

        let new_stored_key = StoredKey {
            metadata: new_metadata.clone(),
            key_material: new_key_material.as_bytes().to_vec(),
        };

        // 3. Save the new key.
        self.save_stored_key(&new_stored_key)?;

        // 4. Update in-memory cache with the new primary key.
        self.versions
            .insert(new_metadata.id.clone(), new_metadata.clone());

        Ok((new_metadata, new_key_material))
    }

    /// Helper to load and deserialize a `StoredKey` from the provider.
    fn load_stored_key(&self, key_id: &str) -> Result<StoredKey, Error> {
        let key_bundle = self.provider.get_symmetric_key(key_id)
            .map_err(|e| Error::KeyProvider(e))?;
        
        bincode::serde::decode_from_slice(key_bundle.as_bytes(), bincode::config::standard())
            .map(|(key, _)| key)
            .map_err(|e| Error::FormatError(format!("Failed to deserialize StoredKey: {}", e)))
    }

    /// Helper to serialize and save a `StoredKey` to the provider.
    fn save_stored_key(&self, stored_key: &StoredKey) -> Result<(), Error> {
        let serialized = bincode::serde::encode_to_vec(stored_key, bincode::config::standard())
            .map_err(|e| Error::FormatError(format!("Failed to serialize StoredKey: {}", e)))?;

        self.provider
            .add_symmetric_key(&stored_key.metadata.id, &SymmetricKey::new(serialized))
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
        Err(KeyProviderError::KeyNotFound(key_id.to_string()))
    }

    fn get_signature_public_key(
        &self,
        key_id: &str,
    ) -> Result<SignaturePublicKey, KeyProviderError> {
        Err(KeyProviderError::KeyNotFound(key_id.to_string()))
    }
} 