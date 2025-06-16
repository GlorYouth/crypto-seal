//! Q-Seal核心引擎，提供统一的高级API
//!
//! 该模块封装了密钥管理、轮换、加解密等复杂性，为用户提供一个简洁的入口。

use std::sync::{Arc, Mutex};
use std::path::Path;

use crate::crypto::traits::CryptographicSystem;
use crate::crypto::errors::Error;
use crate::crypto::config::ConfigManager;
use crate::crypto::key_rotation::KeyRotationManager;
use crate::crypto::storage::KeyFileStorage;

/// Q-Seal核心引擎
///
/// 这是一个高级API，它封装了所有底层组件，提供了一个简单、统一的接口。
/// `C` 是一个实现了 `CryptographicSystem` 特征的加密系统类型。
pub struct QSealEngine<C: CryptographicSystem>
where
    // 确保引擎内可以处理其使用的加密系统的错误
    Error: From<<C as CryptographicSystem>::Error>
{
    /// 配置管理器
    config: Arc<ConfigManager>,
    /// 密钥轮换管理器
    key_manager: Mutex<KeyRotationManager<C>>,
}

impl<C: CryptographicSystem> QSealEngine<C>
where
    Error: From<<C as CryptographicSystem>::Error>,
    <C as CryptographicSystem>::Error: std::error::Error + 'static,
{
    /// 使用指定的配置管理器创建一个新的引擎实例
    ///
    /// # 参数
    ///
    /// * `config_manager` - 一个 `Arc<ConfigManager>`，包含了所有配置信息。
    /// * `key_prefix` - 用于此引擎实例的密钥名称前缀，例如 "user_keys" 或 "document_keys"。
    pub fn new(config_manager: Arc<ConfigManager>, key_prefix: &str) -> Result<Self, Error> {
        // 从配置中获取存储配置
        let storage_config = config_manager.get_storage_config();
        
        // 创建密钥文件存储实例
        let key_storage = Arc::new(KeyFileStorage::new(&storage_config.key_storage_dir)?);
        
        // 从配置中获取轮换策略
        let rotation_policy = config_manager.get_rotation_policy();
        
        // 创建并初始化密钥轮换管理器
        let mut key_manager = KeyRotationManager::<C>::new(
            key_storage,
            rotation_policy,
            key_prefix
        );
        key_manager.initialize(&config_manager.get_crypto_config())?;
        
        Ok(Self {
            config: config_manager,
            key_manager: Mutex::new(key_manager),
        })
    }
    
    /// 从配置文件路径创建一个新的引擎实例
    ///
    /// # 参数
    ///
    /// * `path` - 配置文件的路径。
    /// * `key_prefix` - 用于此引擎实例的密钥名称前缀。
    pub fn from_file<P: AsRef<Path>>(path: P, key_prefix: &str) -> Result<Self, Error> {
        let config_manager = Arc::new(ConfigManager::from_file(path)?);
        Self::new(config_manager, key_prefix)
    }

    /// 使用默认配置创建一个新的引擎实例
    ///
    /// # 参数
    ///
    /// * `key_prefix` - 用于此引擎实例的密钥名称前缀。
    pub fn with_defaults(key_prefix: &str) -> Result<Self, Error> {
        let config_manager = Arc::new(ConfigManager::new());
        Self::new(config_manager, key_prefix)
    }
    
    /// 加密数据
    ///
    /// 自动处理密钥选择、使用计数更新和必要的密钥轮换。
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<String, Error> {
        let mut manager = self.key_manager.lock()
            .map_err(|_| Error::Operation("无法锁定密钥管理器".to_string()))?;
        
        // 检查是否需要轮换
        if manager.needs_rotation(&self.config.get_crypto_config()) {
            manager.start_rotation(&self.config.get_crypto_config())?;
        }
        
        // 获取主密钥的克隆，从而立即释放对manager的不可变借用
        let public_key = manager.get_primary_key()
            .map(|(pk, _)| pk.clone())
            .ok_or_else(|| Error::Key("没有可用的主加密密钥".to_string()))?;
            
        // 现在可以安全地对manager进行可变借用
        manager.increment_usage_count()?;
        
        // 使用克隆的密钥执行加密
        let ciphertext = C::encrypt(&public_key, plaintext, None)?;
        
        Ok(ciphertext.to_string())
    }
    
    /// 解密数据
    ///
    /// 自动尝试使用主密钥和所有次要密钥进行解密，直到成功为止。
    pub fn decrypt(&self, ciphertext: &str) -> Result<Vec<u8>, Error> {
        let manager = self.key_manager.lock()
            .map_err(|_| Error::Operation("无法锁定密钥管理器".to_string()))?;
            
        // 首先尝试使用主密钥解密
        if let Some((_, private_key)) = manager.get_primary_key() {
            if let Ok(plaintext) = C::decrypt(private_key, ciphertext, None) {
                return Ok(plaintext);
            }
        }
        
        // 如果主密钥失败，遍历次要密钥尝试解密
        for (_, private_key, _) in manager.get_secondary_keys() {
            if let Ok(plaintext) = C::decrypt(private_key, ciphertext, None) {
                return Ok(plaintext);
            }
        }
        
        Err(Error::Operation("解密失败：所有可用密钥都无法解密该密文".to_string()))
    }
    
    /// 获取当前的配置管理器
    pub fn config(&self) -> Arc<ConfigManager> {
        Arc::clone(&self.config)
    }
} 