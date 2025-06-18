use serde::{Deserialize, Serialize};
pub(crate) use crate::common::traits::{KeyMetadata, KeyStatus};
use crate::common::errors::Error;


/// 密钥轮换策略
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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

/// 密钥对序列化数据
#[derive(Serialize, Deserialize)]
pub(crate) struct KeyPairData {
    pub(crate) public_key: String,
    pub(crate) private_key: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::collections::HashMap;
    use crate::asymmetric::rotation::KeyRotationManager;
    use crate::asymmetric::traits::AsymmetricCryptographicSystem;
    use crate::common::traits::{KeyMetadata, KeyStatus};
    use crate::common::errors::Error;
    use crate::common::utils::Base64String;
    use crate::common::utils::CryptoConfig;

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
    impl AsymmetricCryptographicSystem for DummySystem {
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