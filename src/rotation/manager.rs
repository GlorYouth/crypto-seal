//! Unified key rotation manager.
// English: Unified key rotation manager.

use crate::Error;
use crate::asymmetric::errors::AsymmetricError;
use crate::common::config::ConfigFile;
use crate::common::errors::KeyManagementError;
use crate::common::header::SealMode;
use crate::common::traits::{
    Algorithm, AsymmetricAlgorithm, KeyMetadata, KeyStatus, SecureKeyStorage,
};
use crate::rotation::RotationPolicy;
use crate::seal::Seal;
use crate::symmetric::errors::SymmetricError;
use crate::symmetric::traits::SymmetricCryptographicSystem;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use secrecy::{ExposeSecret, SecretBox, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use uuid::Uuid;

/// `KeyManager` is the unified interface in `seal-kit` for managing all cryptographic keys (both symmetric and asymmetric).
///
/// It internally selects the appropriate key storage and management strategy based on the `SealMode`
/// and handles the entire lifecycle of keys, including generation, storage, rotation, and on-demand retrieval.
/// It is instantiated by `Seal` and used by `SealEngine`.
///
/// 中文: `KeyManager` 是 seal-kit 中用于管理所有加密密钥（对称和非对称）的统一接口。
///
/// 它根据 `SealMode` 在内部选择合适的密钥存储和管理策略，
/// 并处理密钥的整个生命周期，包括生成、存储、轮换和按需检索。
/// 它由 `Seal` 实例化并由 `SealEngine` 使用。
#[derive(Clone)]
pub struct KeyManager {
    mode: SealMode,
    // A reference to the master `Seal` instance, providing access to the vault's payload and configuration.
    // 中文: 对主 `Seal` 实例的引用，提供对保险库载荷和配置的访问。
    seal: Arc<Seal>,
    // The rotation policy that determines when keys should be rotated.
    // 中文: 决定何时应轮换密钥的轮换策略。
    rotation_policy: RotationPolicy,
    // A prefix to namespace keys within the vault, allowing multiple independent managers.
    // 中文: 用于在保险库中为密钥提供命名空间的前缀，允许多个独立的管理器。
    key_prefix: String,

    // The currently active key for encryption.
    // 中文: 当前用于加密的活动主密钥。
    primary_key_metadata: Option<KeyMetadata>,
    // A list of older keys kept for decryption purposes.
    // 中文: 为解密目的而保留的旧密钥列表。
    secondary_keys_metadata: Vec<KeyMetadata>,
}

impl KeyManager {
    /// Creates a new unified key manager.
    ///
    /// # Arguments
    /// * `seal` - An Arc reference to the `Seal` instance.
    /// * `key_prefix` - A string to prefix key IDs, namespacing them for this manager.
    /// * `mode` - The operational mode (`Symmetric` or `Hybrid`).
    ///
    /// 中文: 创建一个新的统一密钥管理器。
    /// # 参数
    /// * `seal` - 对 `Seal` 实例的 Arc 引用。
    /// * `key_prefix` - 用于为该管理器的密钥 ID 添加前缀的字符串，以实现命名空间。
    /// * `mode` - 操作模式（`Symmetric` 或 `Hybrid`）。
    pub fn new(seal: Arc<Seal>, key_prefix: &str, mode: SealMode) -> Self {
        let rotation_policy = seal.config().rotation.clone();
        Self {
            mode,
            seal,
            rotation_policy,
            key_prefix: key_prefix.to_string(),
            primary_key_metadata: None,
            secondary_keys_metadata: Vec::new(),
        }
    }

    /// Initializes the manager by loading key metadata for a specific mode from the Seal vault.
    /// It filters keys by `key_prefix`, identifies the latest active key as primary,
    /// and collects the rest as secondary keys.
    ///
    /// 中文: 初始化管理器，从 Seal 保险库加载特定模式的密钥元数据。
    /// 它通过 `key_prefix` 筛选密钥，将最新的活动密钥识别为主密钥，
    /// 并将其余密钥收集为次要密钥。
    pub fn initialize(&mut self) {
        let payload = self.seal.payload();
        let mut relevant_keys = BTreeMap::new();

        // Filter relevant keys based on the key_prefix.
        // 中文: 根据 key_prefix 筛选出相关的密钥。
        for (key_id, metadata) in &payload.key_registry {
            if key_id.starts_with(&self.key_prefix) {
                relevant_keys.insert(metadata.version, metadata.clone());
            }
        }

        // The latest version is the primary key.
        // 中文: 最新版本的为 Primary Key。
        if let Some((_, primary_metadata)) = relevant_keys.pop_last() {
            if primary_metadata.status == KeyStatus::Active {
                self.primary_key_metadata = Some(primary_metadata.clone());
            }
        }

        self.secondary_keys_metadata = relevant_keys.into_values().collect();
    }

    /// Returns the configuration from the `seal` instance.
    ///
    /// 中文: 返回 `seal` 实例的配置。
    pub fn config(&self) -> ConfigFile {
        self.seal.config()
    }

    /// Checks if the primary key needs rotation based on the configured policy.
    /// Rotation is needed if the key is expired, nearing expiry, has exceeded its usage count,
    /// or if no primary key exists.
    ///
    /// 中文: 检查主密钥是否根据策略需要轮换。
    /// 如果密钥已过期、临近过期、已超过其使用次数，或者不存在主密钥，则需要轮换。
    pub fn needs_rotation(&self) -> bool {
        if let Some(metadata) = &self.primary_key_metadata {
            // Check expiry time.
            // 中文: 检查过期时间。
            if let Some(expires_at) = &metadata.expires_at {
                if let Ok(expiry_time) = DateTime::parse_from_rfc3339(expires_at) {
                    let now = Utc::now();
                    let warning_period =
                        Duration::days(self.rotation_policy.rotation_start_days as i64);
                    if (now + warning_period) >= expiry_time {
                        return true;
                    }
                }
            }
            // Check usage count.
            // 中文: 检查使用次数。
            if let Some(max_count) = self.rotation_policy.max_usage_count {
                if metadata.usage_count >= max_count {
                    return true;
                }
            }
            false
        } else {
            // No primary key, so "rotation" is needed to create the first one.
            // 中文: 没有主密钥，就需要"轮换"（即创建第一个）。
            true
        }
    }

    /// Increments the usage count of the primary key.
    /// This is an atomic operation that commits the change to the vault.
    ///
    /// 中文: 增加主密钥的使用计数。
    /// 这是一个原子操作，会将更改提交到保险库。
    pub fn increment_usage_count(&mut self, password: &SecretString) -> Result<(), Error> {
        if let Some(meta) = &mut self.primary_key_metadata {
            let key_id = meta.id.clone();
            let new_count = meta.usage_count + 1;

            self.seal.commit_payload(password, |payload| {
                if let Some(m) = payload.key_registry.get_mut(&key_id) {
                    m.usage_count = new_count;
                }
            })?;

            // Update in-memory state.
            // 中文: 更新内存状态。
            meta.usage_count = new_count;
        }
        Ok(())
    }

    /// Starts the key rotation process.
    ///
    /// Depending on the manager's mode, this method will:
    /// - **Symmetric**: Create new key metadata and set it to active. The key material itself is derived on demand.
    /// - **Hybrid**: Generate a new asymmetric key pair (KEK), store its public key, encrypt the private key,
    ///   and then set the metadata as active.
    ///
    /// 中文: 开始密钥轮换过程。
    ///
    /// 根据管理器的模式，此方法将：
    /// - **Symmetric**: 创建新的密钥元数据，并将其设为活动状态。密钥材料本身是按需派生的。
    /// - **Hybrid**: 生成一个新的非对称密钥对 (KEK)，将其公钥存储并加密私钥，然后将元数据设为活动状态。
    pub fn start_rotation(&mut self, password: &SecretString) -> Result<(), Error> {
        // Branch to handle key generation and storage logic for different modes.
        // 中文: 分支处理不同模式下的密钥生成和存储逻辑。
        match self.mode {
            SealMode::Symmetric => self.start_symmetric_rotation(password),
            SealMode::Hybrid => self.start_hybrid_rotation(password),
        }
    }

    // --- Private helpers for rotation ---

    fn start_symmetric_rotation(&mut self, password: &SecretString) -> Result<(), Error> {
        let new_version = self.get_next_version();
        let new_id = format!("{}-{}", self.key_prefix, Uuid::new_v4());
        let now = Utc::now();
        let expires_at = now + Duration::days(self.rotation_policy.validity_period_days as i64);
        let crypto_config = self.seal.config().crypto;

        // In symmetric mode, we only create metadata. The key is derived on demand, not stored.
        // 中文: 对称模式下，我们只创建元数据。密钥是按需派生的，不存储。
        let new_metadata = KeyMetadata {
            id: new_id.clone(),
            created_at: now.to_rfc3339(),
            expires_at: Some(expires_at.to_rfc3339()),
            usage_count: 0,
            status: KeyStatus::Active,
            version: new_version,
            algorithm: Algorithm::Symmetric(crypto_config.primary_symmetric_algorithm),
            public_key: None,
            encrypted_private_key: None,
        };

        self.commit_and_update_metadata(password, new_metadata)
    }

    fn start_hybrid_rotation(&mut self, password: &SecretString) -> Result<(), Error> {
        use crate::asymmetric::traits::AsymmetricCryptographicSystem;
        use base64::{Engine, engine::general_purpose::STANDARD as BASE64};

        let crypto_config = self.seal.config().crypto;

        let (public_key_b64, private_key_b64, algorithm) = match crypto_config
            .primary_asymmetric_algorithm
        {
            AsymmetricAlgorithm::Rsa2048 => {
                use crate::asymmetric::systems::traditional::rsa::RsaCryptoSystem;
                let (pk, sk) = RsaCryptoSystem::generate_keypair(&crypto_config)
                    .map_err(AsymmetricError::from)?;
                (
                    RsaCryptoSystem::export_public_key(&pk).map_err(AsymmetricError::from)?,
                    RsaCryptoSystem::export_private_key(&sk).map_err(AsymmetricError::from)?,
                    Algorithm::Asymmetric(AsymmetricAlgorithm::Rsa2048),
                )
            }
            AsymmetricAlgorithm::Kyber768 => {
                use crate::asymmetric::systems::post_quantum::kyber::KyberCryptoSystem;
                let (pk, sk) = KyberCryptoSystem::generate_keypair(&crypto_config)
                    .map_err(AsymmetricError::from)?;
                (
                    KyberCryptoSystem::export_public_key(&pk).map_err(AsymmetricError::from)?,
                    KyberCryptoSystem::export_private_key(&sk).map_err(AsymmetricError::from)?,
                    Algorithm::Asymmetric(AsymmetricAlgorithm::Kyber768),
                )
            }
            AsymmetricAlgorithm::RsaKyber768 => {
                use crate::asymmetric::systems::hybrid::rsa_kyber::RsaKyberCryptoSystem;
                let (pk, sk) = RsaKyberCryptoSystem::generate_keypair(&crypto_config)
                    .map_err(AsymmetricError::from)?;
                (
                    RsaKyberCryptoSystem::export_public_key(&pk).map_err(AsymmetricError::from)?,
                    RsaKyberCryptoSystem::export_private_key(&sk).map_err(AsymmetricError::from)?,
                    Algorithm::Asymmetric(AsymmetricAlgorithm::RsaKyber768),
                )
            }
        };

        // Encrypt the private key for secure storage.
        // A dedicated key for this purpose is derived from the master seed.
        // 中文: 加密私钥以便安全存储。
        // 从主种子派生一个专用于此目的的密钥。
        let encrypted_private_key = {
            let payload = self.seal.payload();
            let key_derivation_key =
                self.seal
                    .derive_key(&payload.master_seed, b"private-key-encryption", 32)?;
            let container = crate::storage::EncryptedKeyContainer::encrypt_key(
                &SecretString::new(BASE64.encode(&key_derivation_key).into_boxed_str()),
                private_key_b64.as_bytes(),
                "asymmetric-private-key",
                &crypto_config,
            )?;
            SecretBox::new(Box::new(crate::common::traits::SecString(
                container.to_json()?,
            )))
        };

        let new_version = self.get_next_version();
        let new_id = format!("{}-{}", self.key_prefix, Uuid::new_v4());
        let now = Utc::now();
        let expires_at = now + Duration::days(self.rotation_policy.validity_period_days as i64);

        let new_metadata = KeyMetadata {
            id: new_id.clone(),
            created_at: now.to_rfc3339(),
            expires_at: Some(expires_at.to_rfc3339()),
            usage_count: 0,
            status: KeyStatus::Active,
            version: new_version,
            algorithm,
            public_key: Some(public_key_b64),
            encrypted_private_key: Some(encrypted_private_key),
        };

        self.commit_and_update_metadata(password, new_metadata)
    }

    /// Commits new metadata to the Seal vault and updates the manager's in-memory state.
    ///
    /// This is an atomic operation. It first updates the status of the old primary key (if any) to `Rotating`,
    /// then inserts the new primary key metadata. Finally, it updates the in-memory state of the manager.
    ///
    /// 中文: 提交新的元数据到 Seal 并更新管理器在内存中的状态。
    ///
    /// 这是一个原子操作。它首先将旧的主密钥（如果存在）状态更新为 `Rotating`，
    /// 然后插入新的主密钥元数据。最后，它更新管理器在内存中的状态。
    fn commit_and_update_metadata(
        &mut self,
        password: &SecretString,
        new_metadata: KeyMetadata,
    ) -> Result<(), Error> {
        let old_primary_metadata = self.primary_key_metadata.clone();

        self.seal.commit_payload(password, |payload| {
            // 1. Update the status of the old primary key (if it exists) to Rotating.
            // 中文: 1. 将旧的主密钥（如果存在）状态更新为 Rotating。
            if let Some(mut old_meta) = old_primary_metadata {
                old_meta.status = KeyStatus::Rotating;
                payload.key_registry.insert(old_meta.id.clone(), old_meta);
            }
            // 2. Insert the new primary key metadata.
            // 中文: 2. 插入新的主密钥元数据。
            payload
                .key_registry
                .insert(new_metadata.id.clone(), new_metadata.clone());
        })?;

        // 3. Update the in-memory state.
        // 中文: 3. 更新内存状态。
        if let Some(old_meta) = self.primary_key_metadata.take() {
            let mut rotating_meta = old_meta.clone();
            rotating_meta.status = KeyStatus::Rotating;
            self.secondary_keys_metadata.push(rotating_meta);
        }
        self.primary_key_metadata = Some(new_metadata);

        Ok(())
    }

    // --- Public methods for key retrieval ---

    /// Derives a symmetric key by its ID. Only valid in symmetric mode.
    /// The key material is derived from the master seed using the key ID as context/salt.
    ///
    /// 中文: 根据ID派生对称密钥。仅在对称模式下有效。
    /// 密钥材料是使用密钥ID作为上下文/盐，从主种子派生出来的。
    pub fn derive_symmetric_key<T: SymmetricCryptographicSystem>(
        &self,
        key_id: &str,
    ) -> Result<Option<T::Key>, Error>
    where
        SymmetricError: From<<T as SymmetricCryptographicSystem>::Error>,
    {
        if self.mode != SealMode::Symmetric {
            return Err(Error::KeyManagement(KeyManagementError::ModeMismatch(
                "Cannot derive symmetric key in hybrid mode.".to_string(),
            )));
        }

        if let Some(metadata) = self.find_key_metadata_by_id(key_id) {
            let key_bytes = self.seal.derive_key(
                &self.seal.payload().master_seed,
                metadata.id.as_bytes(),
                T::KEY_SIZE,
            )?;
            let key_b64 = base64::engine::general_purpose::STANDARD.encode(key_bytes);
            Ok(Some(T::import_key(&key_b64).map_err(SymmetricError::from)?))
        } else {
            Ok(None)
        }
    }

    /// Retrieves an asymmetric key pair by its ID. Only valid in hybrid mode.
    /// The public key is stored in plaintext, while the private key is decrypted on-demand
    /// using a key derived from the master seed.
    ///
    /// 中文: 根据ID获取非对称密钥对。仅在混合模式下有效。
    /// 公钥以明文形式存储，而私钥则使用从主种子派生的密钥按需解密。
    pub fn get_asymmetric_keypair<T: crate::asymmetric::traits::AsymmetricCryptographicSystem>(
        &self,
        key_id: &str,
    ) -> Result<Option<(T::PublicKey, T::PrivateKey)>, Error>
    where
        AsymmetricError:
            From<<T as crate::asymmetric::traits::AsymmetricCryptographicSystem>::Error>,
    {
        if self.mode != SealMode::Hybrid {
            return Err(Error::KeyManagement(KeyManagementError::ModeMismatch(
                "Cannot get asymmetric keypair in symmetric mode.".to_string(),
            )));
        }

        if let Some(metadata) = self.find_key_metadata_by_id(key_id) {
            let public_key_b64 = metadata.public_key.as_ref().ok_or_else(|| {
                Error::KeyNotFound("Public key not found in metadata for hybrid mode.".to_string())
            })?;
            let public_key = T::import_public_key(public_key_b64).map_err(AsymmetricError::from)?;

            let encrypted_private_key_container =
                metadata.encrypted_private_key.as_ref().ok_or_else(|| {
                    Error::KeyNotFound(
                        "Encrypted private key not found in metadata for hybrid mode.".to_string(),
                    )
                })?;

            let container_json = encrypted_private_key_container.expose_secret().0.clone();
            let container = crate::storage::EncryptedKeyContainer::from_json(&container_json)?;

            let key_derivation_key = self.seal.derive_key(
                &self.seal.payload().master_seed,
                b"private-key-encryption",
                32,
            )?;

            let private_key_bytes = container.decrypt_key(&SecretString::new(
                base64::engine::general_purpose::STANDARD
                    .encode(&key_derivation_key)
                    .into_boxed_str(),
            ))?;

            let private_key_b64 = String::from_utf8(private_key_bytes.to_vec())
                .map_err(|e| Error::Format(format!("Failed to decode private key: {}", e)))?;
            let private_key =
                T::import_private_key(&private_key_b64).map_err(AsymmetricError::from)?;

            Ok(Some((public_key, private_key)))
        } else {
            Ok(None)
        }
    }

    /// Gets the metadata for the primary key.
    ///
    /// 中文: 获取主密钥的元数据。
    pub fn get_primary_key_metadata(&self) -> Option<&KeyMetadata> {
        self.primary_key_metadata.as_ref()
    }

    /// Finds key metadata by ID across all known keys (primary and secondary).
    ///
    /// 中文: 在所有已知密钥中（主密钥和次要密钥）按ID查找元数据。
    fn find_key_metadata_by_id(&self, key_id: &str) -> Option<&KeyMetadata> {
        if let Some(meta) = &self.primary_key_metadata {
            if meta.id == key_id {
                return Some(meta);
            }
        }
        self.secondary_keys_metadata
            .iter()
            .find(|&meta| meta.id == key_id)
    }

    /// Gets the next available key version number.
    ///
    /// 中文: 获取下一个可用的密钥版本号。
    fn get_next_version(&self) -> u32 {
        let max_version = self
            .primary_key_metadata
            .iter()
            .chain(self.secondary_keys_metadata.iter())
            .map(|m| m.version)
            .max()
            .unwrap_or(0);
        max_version + 1
    }

    /// Returns the current operational mode of the manager.
    ///
    /// 中文: 返回管理器的当前操作模式。
    pub fn mode(&self) -> SealMode {
        self.mode
    }
}
