use serde::{Deserialize, Serialize};
pub(crate) use crate::common::traits::KeyMetadata;
use crate::common::errors::Error;

/// 密钥轮换策略，定义了密钥的生命周期和使用限制。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RotationPolicy {
    /// 密钥的有效天数。
    pub validity_period_days: u32,
    /// 密钥在被轮换前的最大允许使用次数。
    pub max_usage_count: Option<u64>,
    /// 在密钥过期前多少天，系统就应该开始准备或触发下一次轮换。
    pub rotation_start_days: u32,
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self {
            validity_period_days: 90,
            max_usage_count: Some(10_000_000),
            rotation_start_days: 7,
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