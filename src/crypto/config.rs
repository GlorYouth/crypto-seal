use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, RwLock};
use std::collections::HashMap;

use serde::{Serialize, Deserialize};

use crate::crypto::errors::Error;
use crate::crypto::common::CryptoConfig;
use crate::crypto::key_rotation::RotationPolicy;

/// 配置来源
#[derive(Debug, Clone, PartialEq)]
pub enum ConfigSource {
    /// 内存默认值
    Default,
    /// 文件
    File,
    /// 环境变量
    Environment,
}

/// 存储配置
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorageConfig {
    /// 密钥存储目录
    pub key_storage_dir: String,
    /// 是否启用元数据缓存
    pub use_metadata_cache: bool,
    /// 是否使用安全删除（擦除）
    pub secure_delete: bool,
    /// 持久化文件权限（Unix文件模式，如0o600）
    #[serde(default = "default_file_permissions")]
    pub file_permissions: u32,
}

fn default_file_permissions() -> u32 {
    0o600
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            key_storage_dir: "./keys".to_string(),
            use_metadata_cache: true,
            secure_delete: true,
            file_permissions: 0o600,
        }
    }
}

/// 完整配置文件
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfigFile {
    /// 加密配置
    pub crypto: CryptoConfig,
    /// 轮换配置
    pub rotation: RotationPolicy,
    /// 存储配置
    pub storage: StorageConfig,
}

/// 配置管理器事件类型
#[derive(Clone)]
pub enum ConfigEvent {
    /// 加密配置变更
    CryptoConfigChanged,
    /// 轮换配置变更
    RotationConfigChanged,
    /// 存储配置变更
    StorageConfigChanged,
}

/// 配置监听器
pub type ConfigListener = Box<dyn Fn(&ConfigManager, ConfigEvent) + Send + Sync>;

/// 全局配置管理器
pub struct ConfigManager {
    /// 加密配置
    crypto_config: RwLock<CryptoConfig>,
    /// 密钥轮换配置
    rotation_config: RwLock<RotationPolicy>,
    /// 存储配置
    storage_config: RwLock<StorageConfig>,
    /// 配置源
    config_source: ConfigSource,
    /// 配置文件路径
    config_path: Option<PathBuf>,
    /// 监听器列表
    listeners: Mutex<Vec<ConfigListener>>,
    /// 自定义配置
    custom_configs: RwLock<HashMap<String, String>>,
}

impl ConfigManager {
    /// 创建默认配置管理器
    pub fn new() -> Self {
        Self {
            crypto_config: RwLock::new(CryptoConfig::default()),
            rotation_config: RwLock::new(RotationPolicy::default()),
            storage_config: RwLock::new(StorageConfig::default()),
            config_source: ConfigSource::Default,
            config_path: None,
            listeners: Mutex::new(Vec::new()),
            custom_configs: RwLock::new(HashMap::new()),
        }
    }
    
    /// 从文件加载配置
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let path = path.as_ref();
        let contents = fs::read_to_string(path)
            .map_err(|e| Error::Io(e))?;
            
        let config: ConfigFile = serde_json::from_str(&contents)
            .map_err(|e| Error::Serialization(format!("解析配置文件失败: {}", e)))?;
            
        // 转换为ConfigManager
        let mut manager = Self::new();
        {
            let mut crypto = manager.crypto_config.write().unwrap();
            *crypto = config.crypto;
        }
        {
            let mut rotation = manager.rotation_config.write().unwrap();
            *rotation = config.rotation;
        }
        {
            let mut storage = manager.storage_config.write().unwrap();
            *storage = config.storage;
        }
        
        manager.config_source = ConfigSource::File;
        manager.config_path = Some(path.to_path_buf());
        
        Ok(manager)
    }
    
    /// 从环境变量加载配置
    pub fn from_env() -> Self {
        let mut config = Self::new();
        config.config_source = ConfigSource::Environment;
        
        // 加密配置环境变量
        if let Ok(value) = std::env::var("Q_SEAL_USE_PQ") {
            let mut crypto = config.crypto_config.write().unwrap();
            crypto.use_post_quantum = value.to_lowercase() == "true";
        }
        
        if let Ok(value) = std::env::var("Q_SEAL_USE_TRADITIONAL") {
            let mut crypto = config.crypto_config.write().unwrap();
            crypto.use_traditional = value.to_lowercase() == "true";
        }
        
        if let Ok(value) = std::env::var("Q_SEAL_RSA_BITS") {
            if let Ok(bits) = value.parse::<usize>() {
                let mut crypto = config.crypto_config.write().unwrap();
                crypto.rsa_key_bits = bits;
            }
        }
        
        // 后量子参数环境变量
        if let Ok(value) = std::env::var("Q_SEAL_KYBER_PARAMETER_K") {
            if let Ok(k) = value.parse::<usize>() {
                let mut crypto = config.crypto_config.write().unwrap();
                crypto.kyber_parameter_k = k;
            }
        }
        
        // 认证加密配置
        if let Ok(value) = std::env::var("Q_SEAL_USE_AUTHENTICATED_ENCRYPTION") {
            let mut crypto = config.crypto_config.write().unwrap();
            crypto.use_authenticated_encryption = value.to_lowercase() == "true";
        }
        
        // 自动验证签名
        if let Ok(value) = std::env::var("Q_SEAL_AUTO_VERIFY_SIGNATURES") {
            let mut crypto = config.crypto_config.write().unwrap();
            crypto.auto_verify_signatures = value.to_lowercase() == "true";
        }
        
        // 轮换配置环境变量
        if let Ok(value) = std::env::var("Q_SEAL_KEY_VALIDITY_DAYS") {
            if let Ok(days) = value.parse::<u32>() {
                let mut rotation = config.rotation_config.write().unwrap();
                rotation.validity_period_days = days;
            }
        }
        
        if let Ok(value) = std::env::var("Q_SEAL_MAX_KEY_USES") {
            if let Ok(uses) = value.parse::<u64>() {
                let mut rotation = config.rotation_config.write().unwrap();
                rotation.max_usage_count = Some(uses);
            }
        }
        
        // 提前轮换天数
        if let Ok(value) = std::env::var("Q_SEAL_ROTATION_START_DAYS") {
            if let Ok(days) = value.parse::<u32>() {
                let mut rotation = config.rotation_config.write().unwrap();
                rotation.rotation_start_days = days;
            }
        }
        
        // 存储配置环境变量
        if let Ok(value) = std::env::var("Q_SEAL_KEY_STORAGE_DIR") {
            let mut storage = config.storage_config.write().unwrap();
            storage.key_storage_dir = value;
        }
        
        if let Ok(value) = std::env::var("Q_SEAL_USE_METADATA_CACHE") {
            let mut storage = config.storage_config.write().unwrap();
            storage.use_metadata_cache = value.to_lowercase() == "true";
        }
        
        if let Ok(value) = std::env::var("Q_SEAL_SECURE_DELETE") {
            let mut storage = config.storage_config.write().unwrap();
            storage.secure_delete = value.to_lowercase() == "true";
        }
        
        if let Ok(value) = std::env::var("Q_SEAL_FILE_PERMISSIONS") {
            if let Ok(mode) = value.parse::<u32>() {
                let mut storage = config.storage_config.write().unwrap();
                storage.file_permissions = mode;
            }
        }
        
        // 新增环境变量：默认签名算法
        if let Ok(value) = std::env::var("Q_SEAL_DEFAULT_SIGNATURE_ALGORITHM") {
            let mut crypto = config.crypto_config.write().unwrap();
            crypto.default_signature_algorithm = value;
        }
        
        // 新增环境变量：Argon2 内存成本
        if let Ok(value) = std::env::var("Q_SEAL_ARGON2_MEMORY_COST") {
            if let Ok(mem) = value.parse::<u32>() {
                let mut crypto = config.crypto_config.write().unwrap();
                crypto.argon2_memory_cost = mem;
            }
        }
        
        // 新增环境变量：Argon2 时间成本
        if let Ok(value) = std::env::var("Q_SEAL_ARGON2_TIME_COST") {
            if let Ok(tc) = value.parse::<u32>() {
                let mut crypto = config.crypto_config.write().unwrap();
                crypto.argon2_time_cost = tc;
            }
        }
        
        config
    }
    
    /// 保存配置到文件
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), Error> {
        let crypto = self.crypto_config.read().unwrap();
        let rotation = self.rotation_config.read().unwrap();
        let storage = self.storage_config.read().unwrap();
        
        let config = ConfigFile {
            crypto: crypto.clone(),
            rotation: rotation.clone(),
            storage: storage.clone(),
        };
        
        let json = serde_json::to_string_pretty(&config)
            .map_err(|e| Error::Serialization(format!("序列化配置失败: {}", e)))?;
            
        fs::write(path, json)
            .map_err(|e| Error::Io(e))?;
            
        Ok(())
    }
    
    /// 添加配置变更监听器
    pub fn add_listener<F>(&self, listener: F)
    where
        F: Fn(&ConfigManager, ConfigEvent) + Send + Sync + 'static,
    {
        let mut listeners = self.listeners.lock().unwrap();
        listeners.push(Box::new(listener));
    }
    
    /// 通知所有监听器配置已更新
    fn notify_listeners(&self, event: ConfigEvent) {
        let listeners = self.listeners.lock().unwrap();
        for listener in listeners.iter() {
            listener(self, event.clone());
        }
    }
    
    /// 获取加密配置
    pub fn get_crypto_config(&self) -> CryptoConfig {
        self.crypto_config.read().unwrap().clone()
    }
    
    /// 获取轮换配置
    pub fn get_rotation_policy(&self) -> RotationPolicy {
        self.rotation_config.read().unwrap().clone()
    }
    
    /// 获取存储配置
    pub fn get_storage_config(&self) -> StorageConfig {
        self.storage_config.read().unwrap().clone()
    }
    
    /// 更新加密配置
    pub fn update_crypto_config(&self, config: CryptoConfig) -> Result<(), Error> {
        {
            let mut crypto = self.crypto_config.write().unwrap();
            *crypto = config;
        }
        
        self.notify_listeners(ConfigEvent::CryptoConfigChanged);
        
        // 如果配置来源是文件，则自动保存
        if self.config_source == ConfigSource::File {
            if let Some(path) = &self.config_path {
                self.save_to_file(path)?;
            }
        }
        
        Ok(())
    }
    
    /// 更新轮换配置
    pub fn update_rotation_policy(&self, policy: RotationPolicy) -> Result<(), Error> {
        {
            let mut rotation = self.rotation_config.write().unwrap();
            *rotation = policy;
        }
        
        self.notify_listeners(ConfigEvent::RotationConfigChanged);
        
        // 如果配置来源是文件，则自动保存
        if self.config_source == ConfigSource::File {
            if let Some(path) = &self.config_path {
                self.save_to_file(path)?;
            }
        }
        
        Ok(())
    }
    
    /// 更新存储配置
    pub fn update_storage_config(&self, config: StorageConfig) -> Result<(), Error> {
        {
            let mut storage = self.storage_config.write().unwrap();
            *storage = config;
        }
        
        self.notify_listeners(ConfigEvent::StorageConfigChanged);
        
        // 如果配置来源是文件，则自动保存
        if self.config_source == ConfigSource::File {
            if let Some(path) = &self.config_path {
                self.save_to_file(path)?;
            }
        }
        
        Ok(())
    }
    
    /// 设置自定义配置项
    pub fn set_custom_config(&self, key: &str, value: &str) -> Result<(), Error> {
        let mut configs = self.custom_configs.write().unwrap();
        configs.insert(key.to_string(), value.to_string());
        
        // 如果配置来源是文件，则自动保存
        if self.config_source == ConfigSource::File {
            if let Some(path) = &self.config_path {
                self.save_to_file(path)?;
            }
        }
        
        Ok(())
    }
    
    /// 获取自定义配置项
    pub fn get_custom_config(&self, key: &str) -> Option<String> {
        let configs = self.custom_configs.read().unwrap();
        configs.get(key).cloned()
    }
}

impl Default for ConfigManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use tempfile::tempdir;
    
    #[test]
    fn config_manager_initialization() {
        let config = ConfigManager::new();
        
        // 默认值检查
        let crypto = config.get_crypto_config();
        let rotation = config.get_rotation_policy();
        let storage = config.get_storage_config();
        
        assert!(crypto.use_post_quantum);
        assert!(crypto.use_traditional);
        assert_eq!(storage.key_storage_dir, "./keys");
        assert_eq!(rotation.validity_period_days, 90);
    }
    
    #[test]
    fn config_file_roundtrip() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("config.json");
        
        // 创建自定义配置
        let config = ConfigManager::new();
        
        // 修改默认值
        {
            let mut crypto = config.crypto_config.write().unwrap();
            crypto.use_post_quantum = false;
            crypto.rsa_key_bits = 4096;
        }
        
        // 保存到文件
        config.save_to_file(&config_path).unwrap();
        
        // 从文件加载
        let loaded_config = ConfigManager::from_file(&config_path).unwrap();
        
        // 验证值
        let crypto = loaded_config.get_crypto_config();
        assert!(!crypto.use_post_quantum);
        assert_eq!(crypto.rsa_key_bits, 4096);
    }
    
    #[test]
    fn config_listener_notification() {
        let config = ConfigManager::new();
        let notification_received = Arc::new(AtomicBool::new(false));
        
        // 添加监听器
        {
            let notification_clone = Arc::clone(&notification_received);
            config.add_listener(move |_, event| {
                if let ConfigEvent::CryptoConfigChanged = event {
                    notification_clone.store(true, Ordering::SeqCst);
                }
            });
        }
        
        // 更新配置
        let mut crypto_config = config.get_crypto_config();
        crypto_config.use_post_quantum = false;
        config.update_crypto_config(crypto_config).unwrap();
        
        // 检查是否收到通知
        assert!(notification_received.load(Ordering::SeqCst));
    }
    
    #[test]
    fn custom_config_values() {
        let config = ConfigManager::new();
        
        // 设置自定义值
        config.set_custom_config("app_name", "Q-Seal Test").unwrap();
        config.set_custom_config("log_level", "debug").unwrap();
        
        // 获取并验证
        assert_eq!(config.get_custom_config("app_name"), Some("Q-Seal Test".to_string()));
        assert_eq!(config.get_custom_config("log_level"), Some("debug".to_string()));
        assert_eq!(config.get_custom_config("unknown"), None);
    }

    #[test]
    fn test_config_from_file_and_save_roundtrip() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().join("cfg.json");
        let manager = ConfigManager::new();
        {
            let mut crypto = manager.crypto_config.write().unwrap();
            crypto.use_post_quantum = false;
            crypto.rsa_key_bits = 4321;
        }
        {
            let mut rotation = manager.rotation_config.write().unwrap();
            rotation.validity_period_days = 15;
        }
        {
            let mut storage = manager.storage_config.write().unwrap();
            storage.key_storage_dir = "path_cfg".to_string();
        }
        manager.save_to_file(&path).unwrap();
        let loaded = ConfigManager::from_file(&path).unwrap();
        // 验证各部分配置
        let crypto = loaded.get_crypto_config();
        assert!(!crypto.use_post_quantum);
        assert_eq!(crypto.rsa_key_bits, 4321);
        assert_eq!(loaded.get_rotation_policy().validity_period_days, 15);
        assert_eq!(loaded.get_storage_config().key_storage_dir, "path_cfg");
    }

    #[test]
    fn test_config_from_env_overrides() {
        unsafe { std::env::set_var("Q_SEAL_USE_PQ", "false"); }
        unsafe { std::env::set_var("Q_SEAL_RSA_BITS", "1234"); }
        unsafe { std::env::set_var("Q_SEAL_KEY_STORAGE_DIR", "env_keys"); }
        unsafe { std::env::set_var("Q_SEAL_FILE_PERMISSIONS", "420"); }
        unsafe { std::env::set_var("Q_SEAL_DEFAULT_SIGNATURE_ALGORITHM", "EnvAlgo"); }
        unsafe { std::env::set_var("Q_SEAL_ARGON2_MEMORY_COST", "9999"); }
        let mgr = ConfigManager::from_env();
        let crypto = mgr.get_crypto_config();
        assert!(!crypto.use_post_quantum);
        assert_eq!(crypto.rsa_key_bits, 1234);
        assert_eq!(crypto.default_signature_algorithm, "EnvAlgo");
        assert_eq!(crypto.argon2_memory_cost, 9999);
        let storage = mgr.get_storage_config();
        assert_eq!(storage.key_storage_dir, "env_keys");
        assert_eq!(storage.file_permissions, 420);
        // cleanup 环境变量
        unsafe { std::env::remove_var("Q_SEAL_USE_PQ"); }
        unsafe { std::env::remove_var("Q_SEAL_RSA_BITS"); }
        unsafe { std::env::remove_var("Q_SEAL_KEY_STORAGE_DIR"); }
        unsafe { std::env::remove_var("Q_SEAL_FILE_PERMISSIONS"); }
        unsafe { std::env::remove_var("Q_SEAL_DEFAULT_SIGNATURE_ALGORITHM"); }
        unsafe { std::env::remove_var("Q_SEAL_ARGON2_MEMORY_COST"); }
    }

    #[test]
    fn test_update_auto_save_and_notify_listener() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().join("cfg.json");
        // 初始保存以设置文件来源
        let manager = ConfigManager::new();
        manager.save_to_file(&path).unwrap();
        let manager = ConfigManager::from_file(&path).unwrap();
        let notified = Arc::new(AtomicBool::new(false));
        {
            let notified_clone = Arc::clone(&notified);
            manager.add_listener(move |_, event| {
                if let ConfigEvent::StorageConfigChanged = event {
                    notified_clone.store(true, Ordering::SeqCst);
                }
            });
        }
        // 更新存储配置，应触发通知并自动保存
        let new_storage = StorageConfig {
            key_storage_dir: "new_dir".to_string(),
            use_metadata_cache: false,
            secure_delete: false,
            file_permissions: 0o600,
        };
        manager.update_storage_config(new_storage.clone()).unwrap();
        assert!(notified.load(Ordering::SeqCst));
        let reloaded = ConfigManager::from_file(&path).unwrap();
        let storage2 = reloaded.get_storage_config();
        assert_eq!(storage2.key_storage_dir, new_storage.key_storage_dir);
        assert_eq!(storage2.use_metadata_cache, new_storage.use_metadata_cache);
        assert_eq!(storage2.secure_delete, new_storage.secure_delete);
        assert_eq!(storage2.file_permissions, new_storage.file_permissions);
    }
} 