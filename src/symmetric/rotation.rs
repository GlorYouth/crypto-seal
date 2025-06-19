use crate::common::config::ConfigFile;
use crate::common::errors::Error;
use crate::common::traits::{KeyMetadata, KeyStatus};
use crate::rotation::RotationPolicy;
use crate::seal::Seal;
use crate::symmetric::traits::SymmetricCryptographicSystem;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::{DateTime, Duration, Utc};
use secrecy::SecretString;
use std::collections::BTreeMap;
use std::sync::Arc;
use uuid::Uuid;

/// 对称密钥轮换管理器。
///
/// 这个管理器不再直接持有密钥材料，而是管理存储在 `Seal` 保险库中的密钥元数据。
/// 密钥材料在需要时通过 `Seal` 按需派生。
pub struct SymmetricKeyRotationManager {
    /// 主密钥（当前活跃密钥的元数据）。
    primary_key_metadata: Option<KeyMetadata>,
    /// 次要密钥（用于解密旧数据或即将启用的新密钥的元数据）。
    secondary_keys_metadata: Vec<KeyMetadata>,
    /// 对 Seal 保险库的引用，用于持久化和密钥派生。
    seal: Arc<Seal>,
    /// 轮换策略。
    rotation_policy: RotationPolicy,
    /// 此管理器负责的密钥的前缀，用于在共享的 `key_registry` 中区分密钥。
    key_prefix: String,
}

impl SymmetricKeyRotationManager {
    /// 创建新的对称密钥轮换管理器。
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

        // 1. 筛选出与此前缀相关的密钥。
        for (key_id, metadata) in &payload.key_registry {
            if key_id.starts_with(&self.key_prefix) {
                relevant_keys.insert(metadata.version, metadata.clone());
            }
        }

        // 2. 找到版本最高的密钥作为主密钥。
        if let Some((_, primary_metadata)) = relevant_keys.pop_last() {
            if primary_metadata.status == KeyStatus::Active {
                self.primary_key_metadata = Some(primary_metadata.clone());
            }
        }

        // 3. 其余的作为次要密钥。
        self.secondary_keys_metadata = relevant_keys.into_values().collect();

        // 4. 如果没有找到活跃的主密钥，就创建一个。
        if self.primary_key_metadata.is_none() {
            // 这个逻辑需要由调用者处理，通常是在创建引擎时检查并触发第一次轮换。
        }

        Ok(())
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

    /// 开始密钥轮换过程：创建一个新的主密钥，并将旧的降级。
    pub fn start_rotation(
        &mut self,
        password: &SecretString,
        algorithm_name: &str,
    ) -> Result<(), Error> {
        let new_version = self.get_next_version();
        let new_id = format!("{}-{}", self.key_prefix, Uuid::new_v4());

        let now = Utc::now();
        let created_at = now.to_rfc3339();
        let expires_at = now + Duration::days(self.rotation_policy.validity_period_days as i64);

        let new_metadata = KeyMetadata {
            id: new_id.clone(),
            created_at,
            expires_at: Some(expires_at.to_rfc3339()),
            usage_count: 0,
            status: KeyStatus::Active,
            version: new_version,
            algorithm: algorithm_name.to_string(),
            public_key: None,
            encrypted_private_key: None,
        };

        let old_primary_metadata = self.primary_key_metadata.clone();

        self.seal.commit_payload(password, |payload| {
            // 1. 将旧的主密钥（如果存在）状态更新为 Rotating。
            if let Some(mut old_meta) = old_primary_metadata {
                old_meta.status = KeyStatus::Rotating;
                payload.key_registry.insert(old_meta.id.clone(), old_meta);
            }
            // 2. 插入新的主密钥元数据。
            payload.key_registry.insert(new_id, new_metadata.clone());
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

    /// (Async) 开始密钥轮换过程。
    pub async fn start_rotation_async(
        &mut self,
        password: &SecretString,
        algorithm_name: &str,
    ) -> Result<(), Error> {
        let new_version = self.get_next_version();
        let new_id = format!("{}-{}", self.key_prefix, Uuid::new_v4());

        let now = Utc::now();
        let created_at = now.to_rfc3339();
        let expires_at = now + Duration::days(self.rotation_policy.validity_period_days as i64);

        let new_metadata = KeyMetadata {
            id: new_id.clone(),
            created_at,
            expires_at: Some(expires_at.to_rfc3339()),
            usage_count: 0,
            status: KeyStatus::Active,
            version: new_version,
            algorithm: algorithm_name.to_string(),
            public_key: None,
            encrypted_private_key: None,
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
            let mut rotating_meta = old_meta.clone();
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

            // 更新内存状态
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

            // 更新内存状态
            meta.usage_count = new_count;
        }
        Ok(())
    }

    /// 按需派生并返回主密钥。
    pub fn get_primary_key<T>(&self) -> Result<Option<T::Key>, Error>
    where
        T: SymmetricCryptographicSystem,
        Error: From<T::Error>,
    {
        if let Some(metadata) = &self.primary_key_metadata {
            let key = self.derive_key::<T>(metadata)?;
            Ok(Some(key))
        } else {
            Ok(None)
        }
    }

    /// 获取主密钥的元数据。
    pub fn get_primary_key_metadata(&self) -> Option<&KeyMetadata> {
        self.primary_key_metadata.as_ref()
    }

    /// 根据给定的密钥 ID 派生密钥。
    pub fn derive_key_by_id<T>(&self, key_id: &str) -> Result<Option<T::Key>, Error>
    where
        T: SymmetricCryptographicSystem,
        Error: From<T::Error>,
    {
        let payload = self.seal.payload();
        if let Some(metadata) = payload.key_registry.get(key_id) {
            let key = self.derive_key::<T>(metadata)?;
            Ok(Some(key))
        } else {
            Ok(None)
        }
    }

    /// 辅助函数：根据元数据派生一个特定类型的密钥。
    fn derive_key<T>(&self, metadata: &KeyMetadata) -> Result<T::Key, Error>
    where
        T: SymmetricCryptographicSystem,
        Error: From<T::Error>,
    {
        let salt = metadata.id.as_bytes();
        let derived_material = self
            .seal
            .derive_key(&self.seal.payload().master_seed, salt, 32)?;
        T::import_key(&BASE64.encode(&derived_material)).map_err(Error::from)
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
