//!
//! # 通用配置模块
//!
//! 包含 Seal 保险库所使用的核心配置结构。
//! 这些结构定义了加密参数、存储行为和密钥轮换策略。
//!
use crate::common::utils::CryptoConfig;
use crate::rotation::RotationPolicy;
use std::env;
use serde::{Deserialize, Serialize};

// 注意：ConfigManager 相关的定义（如 ConfigListener, ConfigEvent, ConfigManager 本身）
// 已被移除，因为它们的功能已被 Seal 的原子化状态管理所取代。

/// 存储配置
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct StorageConfig {
    /// 密钥存储目录（此字段可能已废弃，因为 Seal 使用单一文件）
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
    0o600 // 等同于 -rw-------
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

/// 完整配置文件，代表了 Seal 内部存储的所有可配置项。
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct ConfigFile {
    /// 加密配置
    #[serde(default)]
    pub crypto: CryptoConfig,
    /// 轮换配置
    #[serde(default)]
    pub rotation: RotationPolicy,
    /// 存储配置
    #[serde(default)]
    pub storage: StorageConfig,
}

/// 配置管理器，负责从多个源加载配置。
pub struct ConfigManager;

impl ConfigManager {
    /// 创建一个新的配置构建器，并从多个源加载配置。
    ///
    /// 加载顺序 (后续的会覆盖之前的):
    /// 1. `ConfigFile` 的默认值。
    /// 2. `config.json` 文件 (如果存在)。
    /// 3. 手动解析的环境变量。
    pub fn new() -> Result<ConfigFile, config::ConfigError> {
        let builder = config::Config::builder()
            // 1. 从默认结构开始
            .add_source(config::Config::try_from(&ConfigFile::default())?)
            // 2. 添加配置文件（可选）
            .add_source(config::File::with_name("config.json").required(false));

        let mut config: ConfigFile = builder.build()?.try_deserialize()?;

        // 3. 手动从环境变量加载，覆盖现有配置
        // 这种方法更明确，且不依赖于 config 库的环境变量特性
        if let Ok(val) = env::var("Q_SEAL_CRYPTO__RSA_KEY_BITS") {
            if let Ok(parsed) = val.parse::<usize>() {
                config.crypto.rsa_key_bits = parsed;
            }
        }
        if let Ok(val) = env::var("Q_SEAL_ROTATION__VALIDITY_PERIOD_DAYS") {
            if let Ok(parsed) = val.parse::<u32>() {
                config.rotation.validity_period_days = parsed;
            }
        }
        if let Ok(val) = env::var("Q_SEAL_STORAGE__SECURE_DELETE") {
            if let Ok(parsed) = val.parse::<bool>() {
                config.storage.secure_delete = parsed;
            }
        }
        // ... 在这里可以为其他需要支持的环境变量添加类似逻辑 ...

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use std::sync::Mutex;
    use tempfile::tempdir;

    // 使用全局互斥锁来序列化所有修改全局状态（环境变量、当前目录）的测试，
    // 以避免并行执行时产生数据竞争和状态污染。
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    /// 测试能否成功加载默认配置
    #[test]
    fn test_load_defaults() {
        let _lock = TEST_LOCK.lock().unwrap();

        let dir = tempdir().unwrap();
        let original_dir = env::current_dir().unwrap();
        env::set_current_dir(dir.path()).unwrap();

        let config = ConfigManager::new().unwrap();
        assert_eq!(config, ConfigFile::default());

        env::set_current_dir(original_dir).unwrap();
    }

    /// 测试能否从 JSON 文件加载配置并覆盖默认值
    #[test]
    fn test_load_from_json_file() {
        let _lock = TEST_LOCK.lock().unwrap();
        let dir = tempdir().unwrap();
        let original_dir = env::current_dir().unwrap();
        env::set_current_dir(dir.path()).unwrap();

        let config_path = dir.path().join("config.json");
        let mut file = File::create(&config_path).unwrap();
        writeln!(file, r#"{{"crypto": {{"rsa_key_bits": 4096}} }}"#).unwrap();

        let config = ConfigManager::new().unwrap();

        assert_eq!(config.crypto.rsa_key_bits, 4096);
        assert_eq!(config.crypto.kyber_parameter_k, 768);
        assert_eq!(config.storage.secure_delete, true);

        env::set_current_dir(original_dir).unwrap();
    }

    /// 测试能否从环境变量加载配置，并验证其优先级高于 JSON 文件
    #[test]
    fn test_load_from_env_overrides_json() {
        let _lock = TEST_LOCK.lock().unwrap();
        let dir = tempdir().unwrap();
        let original_dir = env::current_dir().unwrap();
        env::set_current_dir(dir.path()).unwrap();

        let config_path = dir.path().join("config.json");
        let mut file = File::create(&config_path).unwrap();
        writeln!(
            file,
            r#"{{"crypto": {{"rsa_key_bits": 4096}}, "storage": {{"secure_delete": false}} }}"#
        )
        .unwrap();

        unsafe {
            env::set_var("Q_SEAL_CRYPTO__RSA_KEY_BITS", "2048");
            env::set_var("Q_SEAL_ROTATION__VALIDITY_PERIOD_DAYS", "180");
        }

        let config = ConfigManager::new().unwrap();

        assert_eq!(config.crypto.rsa_key_bits, 2048);
        assert_eq!(config.storage.secure_delete, false);
        assert_eq!(config.rotation.validity_period_days, 180);
        assert_eq!(config.crypto.use_traditional, true);

        unsafe {
            env::remove_var("Q_SEAL_CRYPTO__RSA_KEY_BITS");
            env::remove_var("Q_SEAL_ROTATION__VALIDITY_PERIOD_DAYS");
        }
        env::set_current_dir(original_dir).unwrap();
    }

    /// 测试当环境变量类型不匹配时，该变量会被静默忽略。
    #[test]
    fn test_env_type_mismatch_is_ignored() {
        let _lock = TEST_LOCK.lock().unwrap();
        let dir = tempdir().unwrap();
        let original_dir = env::current_dir().unwrap();
        env::set_current_dir(dir.path()).unwrap();

        // 为一个布尔字段设置一个无法解析的值
        unsafe {
            env::set_var("Q_SEAL_CRYPTO__USE_TRADITIONAL", "not-a-boolean");
        }

        // 我们的新实现会静默忽略无法解析的值
        let config = ConfigManager::new().unwrap();

        // 验证该字段的值仍然是其默认值，证明无效的环境变量已被忽略。
        assert_eq!(
            config.crypto.use_traditional,
            ConfigFile::default().crypto.use_traditional
        );

        unsafe {
            env::remove_var("Q_SEAL_CRYPTO__USE_TRADITIONAL");
        }
        env::set_current_dir(original_dir).unwrap();
    }
}
