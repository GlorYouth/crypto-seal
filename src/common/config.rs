//!
//! # 通用配置模块
//!
//! 负责管理整个应用程序的配置，包括加密参数、旋转策略等。
//! 它支持从文件加载配置、环境变量覆盖以及动态更新通知。
//!
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use arc_swap::ArcSwap;
use std::collections::HashMap;

#[cfg(feature = "async")]
use notify::{Watcher, RecommendedWatcher, RecursiveMode, Event as NotifyEvent};
#[cfg(feature = "async")]
use tokio::sync::mpsc;
use serde::{Serialize, Deserialize};

use crate::common::errors::Error;
use crate::rotation::RotationPolicy;
use crate::common::utils::CryptoConfig;

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
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
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
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
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
pub type ConfigListener = Arc<dyn Fn(&ConfigManager, ConfigEvent) + Send + Sync + 'static>;

/// Internal snapshot of all dynamic configuration
#[derive(Clone)]
struct ConfigState {
    crypto: CryptoConfig,
    rotation: RotationPolicy,
    storage: StorageConfig,
    custom: std::collections::HashMap<String, String>,
}

/// 全局配置管理器（无锁化）
pub struct ConfigManager {
    /// 原子快照存储所有动态配置
    state: ArcSwap<ConfigState>,
    /// 配置源
    config_source: ConfigSource,
    /// 配置文件路径
    config_path: Option<PathBuf>,
    /// 监听器列表（无锁并发）
    listeners: ArcSwap<Vec<ConfigListener>>,
}

impl ConfigManager {
    /// 创建默认配置管理器
    pub fn new() -> Self {
        Self {
            state: ArcSwap::new(Arc::new(ConfigState {
                crypto: CryptoConfig::default(),
                rotation: RotationPolicy::default(),
                storage: StorageConfig::default(),
                custom: HashMap::new(),
            })),
            config_source: ConfigSource::Default,
            config_path: None,
            listeners: ArcSwap::new(Arc::new(Vec::new())),
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
        // 更新初始快照
        {
            // 获取当前快照并克隆状态
            let arc = manager.state.load_full();
            let mut new_state = (*arc).clone();
            new_state.crypto = config.crypto;
            new_state.rotation = config.rotation;
            new_state.storage = config.storage;
            manager.state.store(Arc::new(new_state));
        }
        
        manager.config_source = ConfigSource::File;
        manager.config_path = Some(path.to_path_buf());
        
        Ok(manager)
    }
    
    
    /// 从内存中的 `ConfigFile` 结构创建配置管理器
    pub fn from_config_file(config: ConfigFile) -> Self {
        let manager = Self::new();
        let arc = manager.state.load_full();
        let mut new_state = (*arc).clone();
        new_state.crypto = config.crypto;
        new_state.rotation = config.rotation;
        new_state.storage = config.storage;
        manager.state.store(Arc::new(new_state));
        manager
    }
    
    /// 启用热加载
    ///
    /// 此方法会启动一个新线程来监控配置文件。
    /// 当文件发生变化时，会自动重新加载配置并通知所有监听器。
    ///
    /// # Arguments
    /// * `self` - An `Arc<Self>` to allow the `ConfigManager` to be shared with the background task.
    #[cfg(feature = "async")]
    pub fn enable_hot_reload(self: Arc<Self>) {
        if self.config_source != ConfigSource::File || self.config_path.is_none() {
            return;
        }

        let manager = self.clone();

        tokio::spawn(async move {
            if let Err(e) = manager.watch_config_file().await {
                // Log the error, e.g., using a logging framework
                eprintln!("Failed to start config file watcher: {}", e);
            }
        });
    }

    #[cfg(feature = "async")]
    async fn watch_config_file(self: Arc<Self>) -> notify::Result<()> {
        let path = self.config_path.as_ref().unwrap().clone();
        let (tx, mut rx) = mpsc::channel(1);

        let mut watcher = RecommendedWatcher::new(move |res| {
            tx.blocking_send(res).unwrap();
        }, notify::Config::default())?;

        watcher.watch(&path, RecursiveMode::NonRecursive)?;

        while let Some(res) = rx.recv().await {
            match res {
                Ok(NotifyEvent { kind, .. }) => {
                    if kind.is_modify() || kind.is_create() {
                        println!("Config file changed, reloading...");
                        if let Err(e) = self.reload_from_file() {
                            eprintln!("Failed to reload config file: {}", e);
                        }
                    }
                },
                Err(e) => eprintln!("watch error: {:?}", e),
            }
        }

        Ok(())
    }

    #[cfg(feature = "async")]
    fn reload_from_file(&self) -> Result<(), Error> {
        let path = self.config_path.as_ref().ok_or_else(|| Error::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "Config path not set")))?;
        let contents = fs::read_to_string(path)?;
        let new_config_file: ConfigFile = serde_json::from_str(&contents)?;

        let mut new_state = (*self.state.load_full()).clone();
        let mut changed = false;
        if new_state.crypto != new_config_file.crypto {
            new_state.crypto = new_config_file.crypto;
            changed = true;
            self.notify_listeners(ConfigEvent::CryptoConfigChanged);
        }
        if new_state.rotation != new_config_file.rotation {
            new_state.rotation = new_config_file.rotation;
            changed = true;
            self.notify_listeners(ConfigEvent::RotationConfigChanged);
        }
        if new_state.storage != new_config_file.storage {
            new_state.storage = new_config_file.storage;
            changed = true;
            self.notify_listeners(ConfigEvent::StorageConfigChanged);
        }

        if changed {
            self.state.store(Arc::new(new_state));
        }
        
        Ok(())
    }
    
    /// 从环境变量加载配置
    pub fn from_env() -> Self {
        let mut manager = Self::new();
        manager.config_source = ConfigSource::Environment;
        // 从默认快照复制并应用环境变量覆盖
        let arc0 = manager.state.load_full();
        let mut new_state = (*arc0).clone();
        if let Ok(v) = std::env::var("Q_SEAL_USE_PQ") {
            new_state.crypto.use_post_quantum = v.to_lowercase() == "true";
        }
        if let Ok(v) = std::env::var("Q_SEAL_USE_TRADITIONAL") {
            new_state.crypto.use_traditional = v.to_lowercase() == "true";
        }
        if let Ok(v) = std::env::var("Q_SEAL_RSA_BITS") {
            if let Ok(bits) = v.parse() { new_state.crypto.rsa_key_bits = bits; }
        }
        if let Ok(v) = std::env::var("Q_SEAL_KYBER_PARAMETER_K") {
            if let Ok(k) = v.parse() { new_state.crypto.kyber_parameter_k = k; }
        }
        if let Ok(v) = std::env::var("Q_SEAL_USE_AUTHENTICATED_ENCRYPTION") {
            new_state.crypto.use_authenticated_encryption = v.to_lowercase() == "true";
        }
        if let Ok(v) = std::env::var("Q_SEAL_AUTO_VERIFY_SIGNATURES") {
            new_state.crypto.auto_verify_signatures = v.to_lowercase() == "true";
        }
        if let Ok(v) = std::env::var("Q_SEAL_KEY_VALIDITY_DAYS") {
            if let Ok(d) = v.parse() { new_state.rotation.validity_period_days = d; }
        }
        if let Ok(v) = std::env::var("Q_SEAL_MAX_KEY_USES") {
            if let Ok(u) = v.parse() { new_state.rotation.max_usage_count = Some(u); }
        }
        if let Ok(v) = std::env::var("Q_SEAL_ROTATION_START_DAYS") {
            if let Ok(d) = v.parse() { new_state.rotation.rotation_start_days = d; }
        }
        if let Ok(v) = std::env::var("Q_SEAL_KEY_STORAGE_DIR") {
            new_state.storage.key_storage_dir = v;
        }
        if let Ok(v) = std::env::var("Q_SEAL_USE_METADATA_CACHE") {
            new_state.storage.use_metadata_cache = v.to_lowercase() == "true";
        }
        if let Ok(v) = std::env::var("Q_SEAL_SECURE_DELETE") {
            new_state.storage.secure_delete = v.to_lowercase() == "true";
        }
        if let Ok(v) = std::env::var("Q_SEAL_FILE_PERMISSIONS") {
            if let Ok(m) = v.parse() { new_state.storage.file_permissions = m; }
        }
        if let Ok(v) = std::env::var("Q_SEAL_DEFAULT_SIGNATURE_ALGORITHM") {
            new_state.crypto.default_signature_algorithm = v;
        }
        if let Ok(v) = std::env::var("Q_SEAL_ARGON2_MEMORY_COST") {
            if let Ok(m) = v.parse() { new_state.crypto.argon2_memory_cost = m; }
        }
        if let Ok(v) = std::env::var("Q_SEAL_ARGON2_TIME_COST") {
            if let Ok(t) = v.parse() { new_state.crypto.argon2_time_cost = t; }
        }
        manager.state.store(Arc::new(new_state));
        manager
    }
    
    /// 保存配置到文件
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), Error> {
        let state = self.state.load_full();
        
        let config = ConfigFile {
            crypto: state.crypto.clone(),
            rotation: state.rotation.clone(),
            storage: state.storage.clone(),
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
        // 原子替换监听器列表
        let arc = self.listeners.load_full();
        let mut vec = (*arc).clone();
        let arc_listener: ConfigListener = Arc::new(listener);
        vec.push(arc_listener);
        self.listeners.store(Arc::new(vec));
    }
    
    /// 通知所有监听器配置已更新
    fn notify_listeners(&self, event: ConfigEvent) {
        let listeners = self.listeners.load_full();
        for listener in listeners.iter() {
            listener(self, event.clone());
        }
    }
    
    /// 获取加密配置
    pub fn get_crypto_config(&self) -> CryptoConfig {
        self.state.load_full().crypto.clone()
    }
    
    /// 获取轮换配置
    pub fn get_rotation_policy(&self) -> RotationPolicy {
        self.state.load_full().rotation.clone()
    }
    
    /// 获取存储配置
    pub fn get_storage_config(&self) -> StorageConfig {
        self.state.load_full().storage.clone()
    }
    
    /// 更新加密配置
    pub fn update_crypto_config(&self, config: CryptoConfig) -> Result<(), Error> {
        // 原子更新快照
        let arc = self.state.load_full();
        let mut new_state = (*arc).clone();
        new_state.crypto = config.clone();
        self.state.store(Arc::new(new_state));
        
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
        let arc = self.state.load_full();
        let mut new_state = (*arc).clone();
        new_state.rotation = policy.clone();
        self.state.store(Arc::new(new_state));
        
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
        let arc = self.state.load_full();
        let mut new_state = (*arc).clone();
        new_state.storage = config.clone();
        self.state.store(Arc::new(new_state));
        
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
        let arc = self.state.load_full();
        let mut new_state = (*arc).clone();
        new_state.custom.insert(key.to_string(), value.to_string());
        self.state.store(Arc::new(new_state));
        
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
        let state = self.state.load_full();
        state.custom.get(key).cloned()
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
        // 修改默认值并更新
        let mut crypto_cfg = config.get_crypto_config();
        crypto_cfg.use_post_quantum = false;
        crypto_cfg.rsa_key_bits = 4096;
        config.update_crypto_config(crypto_cfg).unwrap();
        
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
        // 更新各部分配置
        let mut crypto_cfg = manager.get_crypto_config();
        crypto_cfg.use_post_quantum = false;
        crypto_cfg.rsa_key_bits = 4321;
        manager.update_crypto_config(crypto_cfg).unwrap();
        let mut rotation = manager.get_rotation_policy();
        rotation.validity_period_days = 15;
        manager.update_rotation_policy(rotation).unwrap();
        let mut storage = manager.get_storage_config();
        storage.key_storage_dir = "path_cfg".to_string();
        manager.update_storage_config(storage).unwrap();
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
        unsafe { std::env::set_var("Q_SEAL_USE_TRADITIONAL", "false"); }
        unsafe { std::env::set_var("Q_SEAL_RSA_BITS", "1234"); }
        unsafe { std::env::set_var("Q_SEAL_KEY_STORAGE_DIR", "env_keys"); }
        unsafe { std::env::set_var("Q_SEAL_FILE_PERMISSIONS", "420"); }
        unsafe { std::env::set_var("Q_SEAL_DEFAULT_SIGNATURE_ALGORITHM", "EnvAlgo"); }
        unsafe { std::env::set_var("Q_SEAL_ARGON2_MEMORY_COST", "9999"); }
        unsafe { std::env::set_var("Q_SEAL_USE_METADATA_CACHE", "false"); }
        unsafe { std::env::set_var("Q_SEAL_SECURE_DELETE", "false"); }
        unsafe { std::env::set_var("Q_SEAL_KEY_VALIDITY_DAYS", "7"); }
        unsafe { std::env::set_var("Q_SEAL_MAX_KEY_USES", "5000"); }
        unsafe { std::env::set_var("Q_SEAL_ROTATION_START_DAYS", "3"); }
        let mgr = ConfigManager::from_env();
        let crypto = mgr.get_crypto_config();
        assert!(!crypto.use_post_quantum);
        assert!(!crypto.use_traditional);
        assert_eq!(crypto.rsa_key_bits, 1234);
        assert_eq!(crypto.default_signature_algorithm, "EnvAlgo");
        assert_eq!(crypto.argon2_memory_cost, 9999);
        let rotation = mgr.get_rotation_policy();
        assert_eq!(rotation.validity_period_days, 7);
        assert_eq!(rotation.max_usage_count, Some(5000));
        assert_eq!(rotation.rotation_start_days, 3);
        let storage = mgr.get_storage_config();
        assert_eq!(storage.key_storage_dir, "env_keys");
        assert_eq!(storage.file_permissions, 420);
        assert_eq!(storage.use_metadata_cache, false);
        assert_eq!(storage.secure_delete, false);
        // cleanup 环境变量
        unsafe { std::env::remove_var("Q_SEAL_USE_PQ"); }
        unsafe { std::env::remove_var("Q_SEAL_USE_TRADITIONAL"); }
        unsafe { std::env::remove_var("Q_SEAL_RSA_BITS"); }
        unsafe { std::env::remove_var("Q_SEAL_KEY_STORAGE_DIR"); }
        unsafe { std::env::remove_var("Q_SEAL_FILE_PERMISSIONS"); }
        unsafe { std::env::remove_var("Q_SEAL_DEFAULT_SIGNATURE_ALGORITHM"); }
        unsafe { std::env::remove_var("Q_SEAL_ARGON2_MEMORY_COST"); }
        unsafe { std::env::remove_var("Q_SEAL_USE_METADATA_CACHE"); }
        unsafe { std::env::remove_var("Q_SEAL_SECURE_DELETE"); }
        unsafe { std::env::remove_var("Q_SEAL_KEY_VALIDITY_DAYS"); }
        unsafe { std::env::remove_var("Q_SEAL_MAX_KEY_USES"); }
        unsafe { std::env::remove_var("Q_SEAL_ROTATION_START_DAYS"); }
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