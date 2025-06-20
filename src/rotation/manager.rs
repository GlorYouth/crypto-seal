//! 统一的密钥轮换管理器
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

/// `KeyManager` 是 seal-kit 中用于管理所有加密密钥（对称和非对称）的统一接口。
///
/// 它根据 `SealMode` 在内部选择合适的密钥存储和管理策略，
/// 并处理密钥的整个生命周期，包括生成、存储、轮换和按需检索。
#[derive(Clone)]
pub struct KeyManager {
    mode: SealMode,
    // 未来这里会持有一个具体的 KeyStore 实现
    // store: Box<dyn KeyStore>,
    seal: Arc<Seal>,
    rotation_policy: RotationPolicy,
    key_prefix: String,

    primary_key_metadata: Option<KeyMetadata>,
    secondary_keys_metadata: Vec<KeyMetadata>,
}

impl KeyManager {
    /// 创建一个新的统一密钥管理器。
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

    /// 初始化管理器，从 Seal 保险库加载特定模式的密钥元数据。
    pub fn initialize(&mut self) {
        let payload = self.seal.payload();
        let mut relevant_keys = BTreeMap::new();

        // 根据 key_prefix 筛选出相关的密钥
        for (key_id, metadata) in &payload.key_registry {
            if key_id.starts_with(&self.key_prefix) {
                relevant_keys.insert(metadata.version, metadata.clone());
            }
        }

        // 最新版本的为 Primary Key
        if let Some((_, primary_metadata)) = relevant_keys.pop_last() {
            if primary_metadata.status == KeyStatus::Active {
                self.primary_key_metadata = Some(primary_metadata.clone());
            }
        }

        self.secondary_keys_metadata = relevant_keys.into_values().collect();
    }

    /// 返回 `seal` 实例的配置。
    pub fn config(&self) -> ConfigFile {
        self.seal.config()
    }

    /// 检查主密钥是否根据策略需要轮换。
    pub fn needs_rotation(&self) -> bool {
        if let Some(metadata) = &self.primary_key_metadata {
            // 检查过期时间
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
            // 检查使用次数
            if let Some(max_count) = self.rotation_policy.max_usage_count {
                if metadata.usage_count >= max_count {
                    return true;
                }
            }
            false
        } else {
            // 没有主密钥，就需要"轮换"（即创建第一个）
            true
        }
    }

    /// 增加主密钥的使用计数。
    pub fn increment_usage_count(&mut self, password: &SecretString) -> Result<(), Error> {
        if let Some(meta) = &mut self.primary_key_metadata {
            let key_id = meta.id.clone();
            let new_count = meta.usage_count + 1;

            self.seal.commit_payload(password, |payload| {
                if let Some(m) = payload.key_registry.get_mut(&key_id) {
                    m.usage_count = new_count;
                }
            })?;

            // 更新内存状态
            meta.usage_count = new_count;
        }
        Ok(())
    }

    /// 开始密钥轮换过程。
    ///
    /// 根据管理器的模式，此方法将：
    /// - **Symmetric**: 创建新的密钥元数据，并将其设为活动状态。密钥材料本身是按需派生的。
    /// - **Hybrid**: 生成一个新的非对称密钥对 (KEK)，将其公钥存储并加密私钥，然后将元数据设为活动状态。
    pub fn start_rotation(&mut self, password: &SecretString) -> Result<(), Error> {
        // 分支处理不同模式下的密钥生成和存储逻辑
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

        // 对称模式下，我们只创建元数据。密钥是按需派生的，不存储。
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

        // 加密私钥以便安全存储
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

    /// 提交新的元数据到 Seal 并更新管理器在内存中的状态
    fn commit_and_update_metadata(
        &mut self,
        password: &SecretString,
        new_metadata: KeyMetadata,
    ) -> Result<(), Error> {
        let old_primary_metadata = self.primary_key_metadata.clone();

        self.seal.commit_payload(password, |payload| {
            // 1. 将旧的主密钥（如果存在）状态更新为 Rotating。
            if let Some(mut old_meta) = old_primary_metadata {
                old_meta.status = KeyStatus::Rotating;
                payload.key_registry.insert(old_meta.id.clone(), old_meta);
            }
            // 2. 插入新的主密钥元数据。
            payload
                .key_registry
                .insert(new_metadata.id.clone(), new_metadata.clone());
        })?;

        // 3. 更新内存状态。
        if let Some(old_meta) = self.primary_key_metadata.take() {
            let mut rotating_meta = old_meta.clone();
            rotating_meta.status = KeyStatus::Rotating;
            self.secondary_keys_metadata.push(rotating_meta);
        }
        self.primary_key_metadata = Some(new_metadata);

        Ok(())
    }

    // --- Public methods for key retrieval ---

    /// 根据ID派生对称密钥。仅在对称模式下有效。
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

    /// 根据ID获取非对称密钥对。仅在混合模式下有效。
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

    /// 获取主密钥的元数据
    pub fn get_primary_key_metadata(&self) -> Option<&KeyMetadata> {
        self.primary_key_metadata.as_ref()
    }

    /// 在所有已知密钥中（主密钥和次要密钥）按ID查找元数据。
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

    /// 获取下一个可用的密钥版本号。
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

    pub fn mode(&self) -> SealMode {
        self.mode
    }
}
