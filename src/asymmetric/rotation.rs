use crate::asymmetric::traits::AsymmetricCryptographicSystem;
use crate::common::config::ConfigFile;
use crate::common::errors::Error;
use crate::common::to_base64;
use crate::common::traits::SecString;
use crate::common::traits::{KeyMetadata, KeyStatus, SecureKeyStorage};
use crate::rotation::RotationPolicy;
use crate::seal::Seal;
use chrono::{DateTime, Duration, Utc};
use secrecy::{ExposeSecret, SecretBox, SecretString};
use std::collections::BTreeMap;
use std::sync::Arc;
use uuid::Uuid;

/// 非对称密钥轮换管理器。
///
/// 管理存储在 `Seal` 保险库中的非对称密钥元数据。
/// 私钥被 `Seal` 的主种子加密存储，公钥则明文存储。
pub struct AsymmetricKeyRotationManager {
    primary_key_metadata: Option<KeyMetadata>,
    secondary_keys_metadata: Vec<KeyMetadata>,
    seal: Arc<Seal>,
    rotation_policy: RotationPolicy,
    key_prefix: String,
}

impl AsymmetricKeyRotationManager {
    /// 创建新的非对称密钥轮换管理器。
    pub fn new(seal: Arc<Seal>, key_prefix: &str) -> Self {
        let rotation_policy = seal.config().rotation.clone();
        Self {
            primary_key_metadata: None,
            secondary_keys_metadata: Vec::new(),
            seal,
            rotation_policy,
            key_prefix: key_prefix.to_string(),
        }
    }

    /// 返回 `seal` 实例的配置。
    pub fn config(&self) -> ConfigFile {
        self.seal.config()
    }

    /// 初始化管理器，从 Seal 保险库加载密钥元数据。
    pub fn initialize(&mut self) -> Result<(), Error> {
        let payload = self.seal.payload();
        let mut relevant_keys = BTreeMap::new();

        for (key_id, metadata) in &payload.key_registry {
            if key_id.starts_with(&self.key_prefix) {
                relevant_keys.insert(metadata.version, metadata.clone());
            }
        }

        if let Some((_, primary_metadata)) = relevant_keys.pop_last() {
            if primary_metadata.status == KeyStatus::Active {
                self.primary_key_metadata = Some(primary_metadata.clone());
            }
        }

        self.secondary_keys_metadata = relevant_keys.into_values().collect();
        Ok(())
    }

    /// 检查主密钥是否根据策略需要轮换。
    pub fn needs_rotation(&self) -> bool {
        if let Some(metadata) = &self.primary_key_metadata {
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
            if let Some(max_count) = self.rotation_policy.max_usage_count {
                if metadata.usage_count >= max_count {
                    return true;
                }
            }
            false
        } else {
            true // 没有主密钥，就需要创建第一个。
        }
    }

    /// 开始密钥轮换：创建一个新的主密钥，并将旧的降级。
    pub fn start_rotation<T>(&mut self, password: &SecretString) -> Result<(), Error>
    where
        T: AsymmetricCryptographicSystem,
        Error: From<T::Error>,
    {
        let crypto_config = self.seal.config().crypto;
        let (public_key, private_key) = T::generate_keypair(&crypto_config)?;

        let public_key_b64 = T::export_public_key(&public_key)?;
        let private_key_b64 = T::export_private_key(&private_key)?;

        let encrypted_private_key = {
            let payload = self.seal.payload();
            let key_derivation_key =
                self.seal
                    .derive_key(&payload.master_seed, b"private-key-encryption", 32)?;
            let container = crate::storage::EncryptedKeyContainer::encrypt_key(
                &SecretString::new(to_base64(&key_derivation_key).into_boxed_str()),
                private_key_b64.as_bytes(),
                "asymmetric-private-key",
            )?;
            SecretBox::new(Box::new(SecString(container.to_json()?)))
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
            algorithm: std::any::type_name::<T>().to_string(),
            public_key: Some(public_key_b64),
            encrypted_private_key: Some(encrypted_private_key),
        };

        let old_primary_metadata = self.primary_key_metadata.clone();

        self.seal.commit_payload(password, |payload| {
            if let Some(mut old_meta) = old_primary_metadata {
                old_meta.status = KeyStatus::Rotating;
                payload.key_registry.insert(old_meta.id.clone(), old_meta);
            }
            payload.key_registry.insert(new_id, new_metadata.clone());
        })?;

        if let Some(old_meta) = self.primary_key_metadata.take() {
            let mut rotating_meta = old_meta;
            rotating_meta.status = KeyStatus::Rotating;
            self.secondary_keys_metadata.push(rotating_meta);
        }
        self.primary_key_metadata = Some(new_metadata);

        Ok(())
    }

    /// (Async) 开始密钥轮换
    pub async fn start_rotation_async<T>(&mut self, password: &SecretString) -> Result<(), Error>
    where
        T: AsymmetricCryptographicSystem,
        Error: From<T::Error>,
    {
        let crypto_config = self.seal.config().crypto;
        let (public_key, private_key) = T::generate_keypair(&crypto_config)?;

        let public_key_b64 = T::export_public_key(&public_key)?;
        let private_key_b64 = T::export_private_key(&private_key)?;

        let encrypted_private_key = {
            let payload = self.seal.payload();
            let key_derivation_key =
                self.seal
                    .derive_key(&payload.master_seed, b"private-key-encryption", 32)?;
            let container = crate::storage::EncryptedKeyContainer::encrypt_key(
                &SecretString::new(to_base64(&key_derivation_key).into_boxed_str()),
                private_key_b64.as_bytes(),
                "asymmetric-private-key",
            )?;
            SecretBox::new(Box::new(SecString(container.to_json()?)))
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
            algorithm: std::any::type_name::<T>().to_string(),
            public_key: Some(public_key_b64),
            encrypted_private_key: Some(encrypted_private_key),
        };

        let old_primary_metadata = self.primary_key_metadata.clone();

        self.seal
            .commit_payload_async(password, |payload| {
                if let Some(mut old_meta) = old_primary_metadata {
                    old_meta.status = KeyStatus::Rotating;
                    payload.key_registry.insert(old_meta.id.clone(), old_meta);
                }
                payload.key_registry.insert(new_id, new_metadata.clone());
            })
            .await?;

        if let Some(old_meta) = self.primary_key_metadata.take() {
            let mut rotating_meta = old_meta;
            rotating_meta.status = KeyStatus::Rotating;
            self.secondary_keys_metadata.push(rotating_meta);
        }
        self.primary_key_metadata = Some(new_metadata);

        Ok(())
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
            meta.usage_count = new_count;
        }
        Ok(())
    }

    /// (Async) 增加主密钥的使用计数。
    pub async fn increment_usage_count_async(
        &mut self,
        password: &SecretString,
    ) -> Result<(), Error> {
        if let Some(meta) = &mut self.primary_key_metadata {
            let key_id = meta.id.clone();
            let new_count = meta.usage_count + 1;

            self.seal
                .commit_payload_async(password, |payload| {
                    if let Some(m) = payload.key_registry.get_mut(&key_id) {
                        m.usage_count = new_count;
                    }
                })
                .await?;
            meta.usage_count = new_count;
        }
        Ok(())
    }

    /// 获取主密钥的元数据。
    pub fn get_primary_key_metadata(&self) -> Option<&KeyMetadata> {
        self.primary_key_metadata.as_ref()
    }

    /// 根据给定的密钥 ID 获取公钥。
    pub fn get_public_key_by_id<T>(&self, key_id: &str) -> Result<Option<T::PublicKey>, Error>
    where
        T: AsymmetricCryptographicSystem,
        Error: From<T::Error>,
    {
        let payload = self.seal.payload();
        if let Some(metadata) = payload.key_registry.get(key_id) {
            if let Some(pk_b64) = &metadata.public_key {
                let pk = T::import_public_key(pk_b64)?;
                return Ok(Some(pk));
            }
        }
        Ok(None)
    }

    /// 按需解密并返回给定ID的密钥对。
    pub fn get_keypair_by_id<T>(
        &self,
        key_id: &str,
    ) -> Result<Option<(T::PublicKey, T::PrivateKey)>, Error>
    where
        T: AsymmetricCryptographicSystem,
        Error: From<T::Error>,
    {
        let payload = self.seal.payload();
        if let Some(metadata) = payload.key_registry.get(key_id) {
            let public_key_b64 = metadata.public_key.as_ref().ok_or_else(|| {
                Error::KeyManagement("Public key not found in metadata".to_string())
            })?;

            let encrypted_private_key =
                metadata.encrypted_private_key.as_ref().ok_or_else(|| {
                    Error::KeyManagement("Encrypted private key not found in metadata".to_string())
                })?;

            let key_derivation_key =
                self.seal
                    .derive_key(&payload.master_seed, b"private-key-encryption", 32)?;

            let container = crate::storage::EncryptedKeyContainer::from_json(
                encrypted_private_key.expose_secret().0.as_str(),
            )?;
            let private_key_b64_bytes = container.decrypt_key(&SecretString::new(
                to_base64(&key_derivation_key).into_boxed_str(),
            ))?;
            let private_key_b64 = String::from_utf8(private_key_b64_bytes).map_err(|_| {
                Error::Format("Decrypted private key is not valid UTF-8".to_string())
            })?;

            let pk = T::import_public_key(public_key_b64)?;
            let sk = T::import_private_key(&private_key_b64)?;

            return Ok(Some((pk, sk)));
        }
        Ok(None)
    }

    /// 获取下一个可用的密钥版本号。
    fn get_next_version(&self) -> u32 {
        let primary_version = self
            .primary_key_metadata
            .as_ref()
            .map(|m| m.version)
            .unwrap_or(0);
        let max_secondary_version = self
            .secondary_keys_metadata
            .iter()
            .map(|m| m.version)
            .max()
            .unwrap_or(0);
        std::cmp::max(primary_version, max_secondary_version) + 1
    }
}
