use std::sync::Arc;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use crate::Error;
use crate::common::utils::CryptoConfig;
use crate::rotation::{KeyMetadata, KeyStatus, KeyStorage, RotationPolicy};
use crate::symmetric::traits::SymmetricCryptographicSystem;

/// 对称密钥轮换管理器
pub struct SymmetricKeyRotationManager<T: SymmetricCryptographicSystem> {
    /// 主密钥（当前活跃密钥）
    primary_key: Option<(T::Key, KeyMetadata)>,
    /// 次要密钥（用于解密旧数据，或即将启用的新密钥）
    secondary_keys: Vec<(T::Key, KeyMetadata)>,
    /// 密钥存储
    key_storage: Arc<dyn KeyStorage>,
    /// 轮换策略
    rotation_policy: RotationPolicy,
    /// 密钥名称前缀
    key_prefix: String,
}

impl<T: SymmetricCryptographicSystem> SymmetricKeyRotationManager<T> 
where
    T::Error: std::error::Error + 'static,
{
    /// 创建新的对称密钥轮换管理器
    pub fn new(
        key_storage: Arc<dyn KeyStorage>,
        rotation_policy: RotationPolicy,
        key_prefix: &str,
    ) -> Self {
        Self {
            primary_key: None,
            secondary_keys: Vec::new(),
            key_storage,
            rotation_policy,
            key_prefix: key_prefix.to_string(),
        }
    }

    /// 初始化管理器，加载现有密钥或创建新密钥
    pub fn initialize(&mut self, config: &CryptoConfig) -> Result<(), Error> {
        let keys = self.key_storage.list_keys()?;
        
        let mut primary_key_name = None;
        let mut secondary_key_names = Vec::new();
        
        for key_name in &keys {
            if key_name.starts_with(&self.key_prefix) {
                let (metadata, _) = self.key_storage.load_key(key_name)?;
                match metadata.status {
                    KeyStatus::Active => {
                        primary_key_name = Some(key_name.clone());
                    },
                    KeyStatus::Rotating => {
                        secondary_key_names.push(key_name.clone());
                    },
                    KeyStatus::Expired => {
                        let _ = self.key_storage.delete_key(key_name);
                    }
                }
            }
        }
        
        if let Some(name) = primary_key_name {
            self.load_primary_key(&name)?;
        } else {
            self.create_new_primary_key(config)?;
        }
        
        for name in secondary_key_names {
            self.load_secondary_key(&name)?;
        }
        
        Ok(())
    }

    /// 检查密钥是否需要轮换
    pub fn needs_rotation(&self) -> bool {
        if let Some((_, metadata)) = &self.primary_key {
            if let Some(expires_at) = &metadata.expires_at {
                if let Ok(expiry_time) = DateTime::parse_from_rfc3339(expires_at) {
                    let now = Utc::now();
                    let warning_period = chrono::Duration::days(self.rotation_policy.rotation_start_days as i64);
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
        } else {
            return true;
        }
        
        false
    }

    /// 开始密钥轮换过程
    pub fn start_rotation(&mut self, config: &CryptoConfig) -> Result<(), Error> {
        if self.primary_key.is_none() {
            return self.create_new_primary_key(config);
        }
        
        let new_key = T::generate_key(config)
            .map_err(|e| Error::Operation(format!("生成密钥失败: {}", e)))?;
        
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let created_at = now.to_rfc3339();
        let expires_at = now + chrono::Duration::days(self.rotation_policy.validity_period_days as i64);
        let expires_at_str = expires_at.to_rfc3339();
        
        let metadata = KeyMetadata {
            id,
            created_at,
            expires_at: Some(expires_at_str),
            usage_count: 0,
            status: KeyStatus::Active,
            version: self.get_next_version(),
            algorithm: format!("{}", std::any::type_name::<T>()),
        };
        
        if let Some((old_key, mut old_metadata)) = self.primary_key.take() {
            old_metadata.status = KeyStatus::Rotating;
            
            let key_name = format!("{}-{}", self.key_prefix, old_metadata.id);
            let key_data = self.serialize_key(&old_key)?;
            self.key_storage.save_key(&key_name, &old_metadata, &key_data)?;
            
            self.secondary_keys.push((old_key, old_metadata));
        }
        
        let key_name = format!("{}-{}", self.key_prefix, metadata.id);
        let key_data = self.serialize_key(&new_key)?;
        self.key_storage.save_key(&key_name, &metadata, &key_data)?;
        
        self.primary_key = Some((new_key, metadata));
        
        Ok(())
    }

    /// 完成密钥轮换过程
    pub fn complete_rotation(&mut self) -> Result<(), Error> {
        let mut rotating_index = None;
        for (i, (_, metadata)) in self.secondary_keys.iter().enumerate() {
            if metadata.status == KeyStatus::Rotating {
                rotating_index = Some(i);
                break;
            }
        }
        
        if let Some(index) = rotating_index {
            let (_, metadata) = self.secondary_keys.remove(index);
            let key_name = format!("{}-{}", self.key_prefix, metadata.id);
            let _ = self.key_storage.delete_key(&key_name);
        }
        
        Ok(())
    }

    /// 增加主密钥的使用计数
    pub fn increment_usage_count(&mut self) -> Result<(), Error> {
        if let Some((key, mut metadata)) = self.primary_key.take() {
            metadata.usage_count += 1;
            let key_name = format!("{}-{}", self.key_prefix, metadata.id);
            let key_data = self.serialize_key(&key)?;

            if let Err(e) = self.key_storage.save_key(&key_name, &metadata, &key_data) {
                metadata.usage_count -= 1;
                self.primary_key = Some((key, metadata));
                return Err(e);
            }
            self.primary_key = Some((key, metadata));
        }
        Ok(())
    }

    /// 获取主密钥
    pub fn get_primary_key(&self) -> Option<&T::Key> {
        self.primary_key.as_ref().map(|(key, _)| key)
    }

    /// 获取主密钥元数据
    pub fn get_primary_key_metadata(&self) -> Option<&KeyMetadata> {
        self.primary_key.as_ref().map(|(_, metadata)| metadata)
    }

    #[cfg(test)]
    pub(crate) fn set_usage_count(&mut self, count: u64) {
        if let Some((_, metadata)) = &mut self.primary_key {
            metadata.usage_count = count;
        }
    }

    /// 获取所有密钥（主密钥和次要密钥）
    pub fn get_all_keys(&self) -> Vec<&T::Key> {
        let mut keys = Vec::new();
        if let Some((key, _)) = &self.primary_key {
            keys.push(key);
        }
        for (key, _) in &self.secondary_keys {
            keys.push(key);
        }
        keys
    }

    /// 序列化单个密钥
    fn serialize_key(&self, key: &T::Key) -> Result<Vec<u8>, Error> {
        let key_str = T::export_key(key).map_err(|e| Error::Operation(e.to_string()))?;
        Ok(key_str.into_bytes())
    }

    /// 反序列化单个密钥
    fn deserialize_key(&self, data: &[u8]) -> Result<T::Key, Error> {
        let key_str = String::from_utf8(data.to_vec())
            .map_err(|e| Error::Serialization(e.to_string()))?;
        T::import_key(&key_str).map_err(|e| Error::Operation(e.to_string()))
    }
    
    /// 创建新的主密钥
    fn create_new_primary_key(&mut self, config: &CryptoConfig) -> Result<(), Error> {
        let key = T::generate_key(config)
            .map_err(|e| Error::Operation(format!("生成密钥失败: {}", e)))?;
        
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let created_at = now.to_rfc3339();
        let expires_at = now + chrono::Duration::days(self.rotation_policy.validity_period_days as i64);
        let expires_at_str = expires_at.to_rfc3339();
        
        let metadata = KeyMetadata {
            id,
            created_at,
            expires_at: Some(expires_at_str),
            usage_count: 0,
            status: KeyStatus::Active,
            version: self.get_next_version(),
            algorithm: format!("{}", std::any::type_name::<T>()),
        };
        
        let key_name = format!("{}-{}", self.key_prefix, metadata.id);
        let key_data = self.serialize_key(&key)?;
        self.key_storage.save_key(&key_name, &metadata, &key_data)?;
        
        self.primary_key = Some((key, metadata));
        
        Ok(())
    }
    
    /// 加载主密钥
    fn load_primary_key(&mut self, name: &str) -> Result<(), Error> {
        let (metadata, key_data) = self.key_storage.load_key(name)?;
        let key = self.deserialize_key(&key_data)?;
        self.primary_key = Some((key, metadata));
        Ok(())
    }

    /// 加载次要密钥
    fn load_secondary_key(&mut self, name: &str) -> Result<(), Error> {
        let (metadata, key_data) = self.key_storage.load_key(name)?;
        let key = self.deserialize_key(&key_data)?;
        self.secondary_keys.push((key, metadata));
        Ok(())
    }

    fn get_next_version(&self) -> u32 {
        let primary_version = self.primary_key.as_ref().map(|(_, m)| m.version).unwrap_or(0);
        let max_secondary_version = self.secondary_keys.iter().map(|(_, m)| m.version).max().unwrap_or(0);
        std::cmp::max(primary_version, max_secondary_version) + 1
    }
}