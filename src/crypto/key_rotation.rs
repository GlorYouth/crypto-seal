use std::sync::Arc;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use serde::{Serialize, Deserialize};

pub(crate) use crate::crypto::traits::{CryptographicSystem, KeyMetadata, KeyStatus};
use crate::crypto::errors::Error;
use crate::crypto::common::CryptoConfig;

/// 密钥轮换策略
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationPolicy {
    /// 密钥有效期（天）
    pub validity_period_days: u32,
    /// 最大使用次数
    pub max_usage_count: Option<u64>,
    /// 提前轮换天数（到期前多少天开始轮换过程）
    pub rotation_start_days: u32,
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self {
            validity_period_days: 90, // 默认90天
            max_usage_count: Some(10_000_000), // 默认1千万次
            rotation_start_days: 7,   // 默认提前7天开始轮换
        }
    }
}

/// 密钥存储接口
pub trait KeyStorage: Send + Sync {
    /// 保存密钥
    fn save_key(&self, name: &str, metadata: &KeyMetadata, key_data: &[u8]) -> Result<(), Error>;
    
    /// 加载密钥
    fn load_key(&self, name: &str) -> Result<(KeyMetadata, Vec<u8>), Error>;
    
    /// 检查密钥是否存在
    fn key_exists(&self, name: &str) -> bool;
    
    /// 列出所有密钥
    fn list_keys(&self) -> Result<Vec<String>, Error>;
    
    /// 删除密钥
    fn delete_key(&self, name: &str) -> Result<(), Error>;
}

/// 密钥轮换管理器
pub struct KeyRotationManager<T: CryptographicSystem> {
    /// 主密钥（当前活跃密钥）
    primary_key: Option<(T::PublicKey, T::PrivateKey, KeyMetadata)>,
    /// 次要密钥（用于解密旧数据，或即将启用的新密钥）
    secondary_keys: Vec<(T::PublicKey, T::PrivateKey, KeyMetadata)>,
    /// 密钥存储
    key_storage: Arc<dyn KeyStorage>,
    /// 轮换策略
    rotation_policy: RotationPolicy,
    /// 密钥名称前缀
    key_prefix: String,
}

impl<T: CryptographicSystem> KeyRotationManager<T> 
where
    T::Error: std::error::Error + 'static,
{
    /// 创建新的密钥轮换管理器
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
        
        // 查找以指定前缀开头的密钥
        let mut primary_key_name = None;
        let mut secondary_key_names = Vec::new();
        
        for key_name in &keys {
            if key_name.starts_with(&self.key_prefix) {
                // 加载密钥元数据
                let (metadata, _) = self.key_storage.load_key(key_name)?;
                
                // 根据状态分类
                match metadata.status {
                    KeyStatus::Active => {
                        primary_key_name = Some(key_name.clone());
                    },
                    KeyStatus::Rotating => {
                        secondary_key_names.push(key_name.clone());
                    },
                    KeyStatus::Expired => {
                        // 删除过期密钥
                        let _ = self.key_storage.delete_key(key_name);
                    }
                }
            }
        }
        
        // 加载主密钥
        if let Some(name) = primary_key_name {
            self.load_primary_key(&name)?;
        } else {
            // 没有找到主密钥，创建新密钥
            self.create_new_primary_key(config)?;
        }
        
        // 加载次要密钥
        for name in secondary_key_names {
            self.load_secondary_key(&name)?;
        }
        
        Ok(())
    }
    
    /// 检查密钥是否需要轮换
    pub fn needs_rotation(&self) -> bool {
        if let Some((_, _, metadata)) = &self.primary_key {
            // 检查基于时间的轮换需求
            if let Some(expires_at) = &metadata.expires_at {
                if let Ok(expiry_time) = DateTime::parse_from_rfc3339(expires_at) {
                    let now = Utc::now();
                    let warning_period = chrono::Duration::days(self.rotation_policy.rotation_start_days as i64);
                    
                    // 如果当前时间加上警告期超过过期时间，则需要轮换
                    if (now + warning_period) >= expiry_time {
                        return true;
                    }
                }
            }
            
            // 检查基于使用次数的轮换需求
            if let Some(max_count) = self.rotation_policy.max_usage_count {
                if metadata.usage_count >= max_count {
                    return true;
                }
            }
        } else {
            // 如果没有主密钥，则需要创建
            return true;
        }
        
        false
    }
    
    /// 开始密钥轮换过程
    pub fn start_rotation(&mut self, config: &CryptoConfig) -> Result<(), Error> {
        if self.primary_key.is_none() {
            return self.create_new_primary_key(config);
        }
        
        // 生成新密钥
        let (new_public_key, new_private_key) = T::generate_keypair(config)
            .map_err(|e| Error::Operation(format!("生成密钥对失败: {}", e)))?;
        
        // 生成唯一ID
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let created_at = now.to_rfc3339();
        
        // 计算过期时间
        let expires_at = now + chrono::Duration::days(self.rotation_policy.validity_period_days as i64);
        let expires_at_str = expires_at.to_rfc3339();
        
        // 创建元数据
        let metadata = KeyMetadata {
            id,
            created_at,
            expires_at: Some(expires_at_str),
            usage_count: 0,
            status: KeyStatus::Active,
            version: self.get_next_version(),
            algorithm: format!("{}", std::any::type_name::<T>()),
        };
        
        // 更新现有主密钥状态为轮换中
        if let Some((pub_key, priv_key, mut old_metadata)) = self.primary_key.take() {
            old_metadata.status = KeyStatus::Rotating;
            
            // 保存更新后的旧密钥
            let key_name = format!("{}-{}", self.key_prefix, old_metadata.id);
            let key_data = self.serialize_key_pair(&pub_key, &priv_key)?;
            self.key_storage.save_key(&key_name, &old_metadata, &key_data)?;
            
            // 将旧密钥移到次要密钥
            self.secondary_keys.push((pub_key, priv_key, old_metadata));
        }
        
        // 保存新密钥
        let key_name = format!("{}-{}", self.key_prefix, metadata.id);
        let key_data = self.serialize_key_pair(&new_public_key, &new_private_key)?;
        self.key_storage.save_key(&key_name, &metadata, &key_data)?;
        
        // 设置新主密钥
        self.primary_key = Some((new_public_key, new_private_key, metadata));
        
        Ok(())
    }
    
    /// 完成密钥轮换过程
    pub fn complete_rotation(&mut self) -> Result<(), Error> {
        // 查找状态为Rotating的次要密钥
        let mut rotating_index = None;
        for (i, (_, _, metadata)) in self.secondary_keys.iter().enumerate() {
            if metadata.status == KeyStatus::Rotating {
                rotating_index = Some(i);
                break;
            }
        }
        
        // 如果找到处于轮换中的密钥，将其状态更新为过期
        if let Some(index) = rotating_index {
            // 移除轮换中的密钥并删除存储
            let (_pub_key, _priv_key, metadata) = self.secondary_keys.remove(index);
            let key_name = format!("{}-{}", self.key_prefix, metadata.id);
            // 删除已过期密钥文件
            let _ = self.key_storage.delete_key(&key_name);
        }
        
        Ok(())
    }
    
    /// 增加主密钥的使用计数
    pub fn increment_usage_count(&mut self) -> Result<(), Error> {
        if let Some((pub_key, priv_key, mut metadata)) = self.primary_key.take() {
            // 更新使用计数
            metadata.usage_count += 1;
            // 序列化并保存更新后的密钥元数据
            let key_name = format!("{}-{}", self.key_prefix, metadata.id);
            let key_data = self.serialize_key_pair(&pub_key, &priv_key)?;
            if let Err(e) = self.key_storage.save_key(&key_name, &metadata, &key_data) {
                // 保存失败，回滚并恢复原主密钥
                metadata.usage_count -= 1;
                self.primary_key = Some((pub_key, priv_key, metadata));
                return Err(e);
            }
            // 保存成功，恢复主密钥
            self.primary_key = Some((pub_key, priv_key, metadata));
        }
        Ok(())
    }
    
    /// 获取主密钥
    pub fn get_primary_key(&self) -> Option<(&T::PublicKey, &T::PrivateKey)> {
        self.primary_key.as_ref().map(|(pub_key, priv_key, _)| (pub_key, priv_key))
    }
    
    /// 获取主密钥引用
    pub fn get_primary_key_metadata(&self) -> Option<&KeyMetadata> {
        self.primary_key.as_ref().map(|(_, _, metadata)| metadata)
    }
    
    /// 获取所有次要密钥
    pub fn get_secondary_keys(&self) -> Vec<(&T::PublicKey, &T::PrivateKey, &KeyMetadata)> {
        self.secondary_keys.iter().map(|(pub_key, priv_key, metadata)| (pub_key, priv_key, metadata)).collect()
    }
    
    // 私有方法
    
    /// 创建新的主密钥
    fn create_new_primary_key(&mut self, config: &CryptoConfig) -> Result<(), Error> {
        // 生成密钥对
        let (public_key, private_key) = T::generate_keypair(config)
            .map_err(|e| Error::Operation(format!("生成密钥对失败: {}", e)))?;
        
        // 生成唯一ID
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let created_at = now.to_rfc3339();
        
        // 计算过期时间
        let expires_at = now + chrono::Duration::days(self.rotation_policy.validity_period_days as i64);
        let expires_at_str = expires_at.to_rfc3339();
        
        // 创建元数据
        let metadata = KeyMetadata {
            id: id.clone(),
            created_at,
            expires_at: Some(expires_at_str),
            usage_count: 0,
            status: KeyStatus::Active,
            version: 1,
            algorithm: format!("{}", std::any::type_name::<T>()),
        };
        
        // 保存密钥
        let key_name = format!("{}-{}", self.key_prefix, id);
        let key_data = self.serialize_key_pair(&public_key, &private_key)?;
        self.key_storage.save_key(&key_name, &metadata, &key_data)?;
        
        // 设置为主密钥
        self.primary_key = Some((public_key, private_key, metadata));
        
        Ok(())
    }
    
    /// 加载主密钥
    fn load_primary_key(&mut self, name: &str) -> Result<(), Error> {
        let (metadata, key_data) = self.key_storage.load_key(name)?;
        let (public_key, private_key) = self.deserialize_key_pair(&key_data)?;
        self.primary_key = Some((public_key, private_key, metadata));
        Ok(())
    }
    
    /// 加载次要密钥
    fn load_secondary_key(&mut self, name: &str) -> Result<(), Error> {
        let (metadata, key_data) = self.key_storage.load_key(name)?;
        let (public_key, private_key) = self.deserialize_key_pair(&key_data)?;
        self.secondary_keys.push((public_key, private_key, metadata));
        Ok(())
    }
    
    /// 获取下一个版本号
    fn get_next_version(&self) -> u32 {
        let mut max_version = 0;
        
        if let Some((_, _, metadata)) = &self.primary_key {
            max_version = metadata.version;
        }
        
        for (_, _, metadata) in &self.secondary_keys {
            if metadata.version > max_version {
                max_version = metadata.version;
            }
        }
        
        max_version + 1
    }
    
    /// 序列化密钥对
    fn serialize_key_pair(&self, public_key: &T::PublicKey, private_key: &T::PrivateKey) -> Result<Vec<u8>, Error> {
        let pub_key = T::export_public_key(public_key)
            .map_err(|e| Error::Operation(format!("导出公钥失败: {}", e)))?;
        let priv_key = T::export_private_key(private_key)
            .map_err(|e| Error::Operation(format!("导出私钥失败: {}", e)))?;
        
        let key_pair = KeyPairData {
            public_key: pub_key,
            private_key: priv_key,
        };
        
        serde_json::to_vec(&key_pair)
            .map_err(|e| Error::Serialization(format!("序列化密钥对失败: {}", e)))
    }
    
    /// 反序列化密钥对
    fn deserialize_key_pair(&self, data: &[u8]) -> Result<(T::PublicKey, T::PrivateKey), Error> {
        let key_pair: KeyPairData = serde_json::from_slice(data)
            .map_err(|e| Error::Serialization(format!("反序列化密钥对失败: {}", e)))?;
            
        let public_key = T::import_public_key(&key_pair.public_key)
            .map_err(|e| Error::Operation(format!("导入公钥失败: {}", e)))?;
        let private_key = T::import_private_key(&key_pair.private_key)
            .map_err(|e| Error::Operation(format!("导入私钥失败: {}", e)))?;
        
        Ok((public_key, private_key))
    }
}

/// 密钥对序列化数据
#[derive(Serialize, Deserialize)]
struct KeyPairData {
    public_key: String,
    private_key: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::collections::HashMap;
    use crate::crypto::common::{CryptoConfig, Base64String};
    use crate::crypto::traits::{CryptographicSystem, KeyStatus, KeyMetadata};
    use crate::crypto::errors::Error;

    /// 内存存储用于测试
    struct InMemoryStorage {
        map: Mutex<HashMap<String, (KeyMetadata, Vec<u8>)>>,
    }

    impl InMemoryStorage {
        fn new() -> Self {
            Self { map: Mutex::new(HashMap::new()) }
        }
    }

    impl KeyStorage for InMemoryStorage {
        fn save_key(&self, name: &str, metadata: &KeyMetadata, key_data: &[u8]) -> Result<(), Error> {
            let mut m = self.map.lock().unwrap();
            m.insert(name.to_string(), (metadata.clone(), key_data.to_vec()));
            Ok(())
        }
        fn load_key(&self, name: &str) -> Result<(KeyMetadata, Vec<u8>), Error> {
            let m = self.map.lock().unwrap();
            m.get(name)
                .map(|(meta, data)| (meta.clone(), data.clone()))
                .ok_or_else(|| Error::Operation(format!("Key {} not found", name)))
        }
        fn key_exists(&self, name: &str) -> bool {
            let m = self.map.lock().unwrap();
            m.contains_key(name)
        }
        fn list_keys(&self) -> Result<Vec<String>, Error> {
            let m = self.map.lock().unwrap();
            Ok(m.keys().cloned().collect())
        }
        fn delete_key(&self, name: &str) -> Result<(), Error> {
            let mut m = self.map.lock().unwrap();
            m.remove(name);
            Ok(())
        }
    }

    /// 简单的 DummySystem，用于测试密钥轮换逻辑
    #[derive(Clone)]
    struct DummySystem;
    impl CryptographicSystem for DummySystem {
        type PublicKey = String;
        type PrivateKey = String;
        type CiphertextOutput = Base64String;
        type Error = Error;

        fn generate_keypair(_config: &CryptoConfig) -> Result<(Self::PublicKey, Self::PrivateKey), Self::Error> {
            Ok(("PUB".to_string(), "PRIV".to_string()))
        }
        fn encrypt(_public_key: &Self::PublicKey, _plaintext: &[u8], _additional_data: Option<&[u8]>) -> Result<Self::CiphertextOutput, Self::Error> {
            Ok(Base64String::from(vec![]))
        }
        fn decrypt(_private_key: &Self::PrivateKey, _ciphertext: &str, _additional_data: Option<&[u8]>) -> Result<Vec<u8>, Self::Error> {
            Ok(vec![])
        }
        fn export_public_key(pk: &Self::PublicKey) -> Result<String, Self::Error> { Ok(pk.clone()) }
        fn export_private_key(sk: &Self::PrivateKey) -> Result<String, Self::Error> { Ok(sk.clone()) }
        fn import_public_key(pk: &str) -> Result<Self::PublicKey, Self::Error> { Ok(pk.to_string()) }
        fn import_private_key(sk: &str) -> Result<Self::PrivateKey, Self::Error> { Ok(sk.to_string()) }
    }

    #[test]
    fn test_initialize_and_delete_expired() {
        let storage = Arc::new(InMemoryStorage::new());
        // 插入已过期的密钥
        let expired_meta = KeyMetadata {
            id: "expired".to_string(),
            created_at: "".to_string(),
            expires_at: None,
            usage_count: 0,
            status: KeyStatus::Expired,
            version: 1,
            algorithm: "".to_string(),
        };
        storage.save_key("test-expired", &expired_meta, &[]).unwrap();
        // 使用短轮换策略
        let policy = RotationPolicy { validity_period_days: 1, rotation_start_days: 1, max_usage_count: Some(1) };
        let mut mgr = KeyRotationManager::<DummySystem>::new(storage.clone(), policy, "test");
        // initialize 应该删除已过期的，且创建新的主密钥
        mgr.initialize(&CryptoConfig::default()).unwrap();
        let keys = storage.list_keys().unwrap();
        assert_eq!(keys.len(), 1);
        assert!(!storage.key_exists("test-expired"));
        // 只有新主密钥，前缀正确
        assert!(keys[0].starts_with("test-"));
    }

    #[test]
    fn test_rotation_flow() {
        let storage = Arc::new(InMemoryStorage::new());
        let policy = RotationPolicy { validity_period_days: 1, rotation_start_days: 1, max_usage_count: Some(1) };
        let mut mgr = KeyRotationManager::<DummySystem>::new(storage.clone(), policy.clone(), "prefix");
        mgr.initialize(&CryptoConfig::default()).unwrap();
        // 触发基于时间的轮换
        assert!(mgr.needs_rotation());
        // 启动轮换
        mgr.start_rotation(&CryptoConfig::default()).unwrap();
        // 次要密钥列表应包含一个
        assert_eq!(mgr.get_secondary_keys().len(), 1);
        // 存储应有两个文件：旧主密钥(Rotating)和新主密钥
        assert_eq!(storage.list_keys().unwrap().len(), 2);
        // 完成轮换，移除旧密钥
        mgr.complete_rotation().unwrap();
        assert_eq!(mgr.get_secondary_keys().len(), 0);
        assert_eq!(storage.list_keys().unwrap().len(), 1);
        // 新主密钥版本应加1
        let meta = mgr.get_primary_key_metadata().unwrap();
        assert_eq!(meta.version, 2);
    }

    #[test]
    fn test_increment_usage_count() {
        let storage = Arc::new(InMemoryStorage::new());
        let policy = RotationPolicy { validity_period_days: 10, rotation_start_days: 5, max_usage_count: Some(5) };
        let mut mgr = KeyRotationManager::<DummySystem>::new(storage.clone(), policy, "inc");
        mgr.initialize(&CryptoConfig::default()).unwrap();
        let keys = storage.list_keys().unwrap();
        assert_eq!(keys.len(), 1);
        let name = &keys[0];
        // 初始计数为 0
        let (meta1, _) = storage.load_key(name).unwrap();
        assert_eq!(meta1.usage_count, 0);
        // 调用 increment
        mgr.increment_usage_count().unwrap();
        let (meta2, _) = storage.load_key(name).unwrap();
        assert_eq!(meta2.usage_count, 1);
    }
} 