//!
//! # 通用配置模块
//!
//! 包含 Seal 保险库所使用的核心配置结构。
//! 这些结构定义了加密参数、存储行为和密钥轮换策略。
//!
use crate::rotation::RotationPolicy;
use num_cpus;
use serde::{Deserialize, Serialize};
use std::env;
use std::sync::Arc;
// 注意：ConfigManager 相关的定义（如 ConfigListener, ConfigEvent, ConfigManager 本身）
// 已被移除，因为它们的功能已被 Seal 的原子化状态管理所取代。

/// 默认的并行度，通常等于CPU核心数
fn default_parallelism() -> usize {
    num_cpus::get()
}

/// 并行计算配置
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ParallelismConfig {
    /// 并行处理的并行度
    #[serde(default = "default_parallelism")]
    pub parallelism: usize,
}

impl Default for ParallelismConfig {
    fn default() -> Self {
        Self {
            parallelism: default_parallelism(),
        }
    }
}

/// 加密系统配置
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CryptoConfig {
    /// 是否使用传统密码学（如RSA）
    pub use_traditional: bool,
    /// 是否使用后量子密码学
    pub use_post_quantum: bool,
    /// RSA密钥位数
    pub rsa_key_bits: usize,
    /// Kyber安全级别 (512/768/1024)
    pub kyber_parameter_k: usize,
    /// 是否使用认证加密
    pub use_authenticated_encryption: bool,
    /// 是否自动验证签名
    pub auto_verify_signatures: bool,
    /// 默认签名算法
    pub default_signature_algorithm: String,
    /// Argon2内存成本（默认19456 KB）
    pub argon2_memory_cost: u32,
    /// Argon2时间成本（默认2）
    pub argon2_time_cost: u32,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            use_traditional: true,
            use_post_quantum: true,
            rsa_key_bits: 3072,     // NIST建议的安全位数
            kyber_parameter_k: 768, // NIST竞赛中的推荐级别
            use_authenticated_encryption: true,
            auto_verify_signatures: true,
            default_signature_algorithm: "RSA-PSS-SHA256".to_string(),
            argon2_memory_cost: 19456, // 19MB
            argon2_time_cost: 2,
        }
    }
}

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
    /// 并行配置
    #[serde(default)]
    pub parallelism: ParallelismConfig,
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


/// 流式处理配置
#[derive(Clone, Serialize, Deserialize)]
pub struct StreamingConfig {
    /// 用于流式处理的缓冲区大小
    pub buffer_size: usize,
    /// 是否显示进度回调
    pub show_progress: bool,
    /// 是否在内存中保留处理后的数据
    pub keep_in_memory: bool,
    /// 进度回调函数
    #[serde(skip)]
    pub progress_callback: Option<Arc<dyn Fn(u64, Option<u64>) + Send + Sync>>,
    /// 待处理的总字节数，用于进度计算
    pub total_bytes: Option<u64>,
}

impl Default for StreamingConfig {
    fn default() -> Self {
        Self {
            buffer_size: 65536, // 64KB
            show_progress: false,
            keep_in_memory: false,
            progress_callback: None,
            total_bytes: None,
        }
    }
}

/// 为 StreamingConfig 添加 builder 方法：设置总字节数
impl StreamingConfig {
    /// 设置总字节大小（用于进度回调）
    pub fn with_total_bytes(mut self, total: u64) -> Self {
        self.total_bytes = Some(total);
        self
    }
    /// 设置缓冲区大小
    pub fn with_buffer_size(mut self, size: usize) -> Self {
        self.buffer_size = size;
        self
    }
    /// 设置是否在控制台显示进度
    pub fn with_show_progress(mut self, show: bool) -> Self {
        self.show_progress = show;
        self
    }
    /// 设置是否在内存保留完整数据
    pub fn with_keep_in_memory(mut self, keep: bool) -> Self {
        self.keep_in_memory = keep;
        self
    }
    /// 设置进度回调
    pub fn with_progress_callback(
        mut self,
        callback: Arc<dyn Fn(u64, Option<u64>) + Send + Sync>,
    ) -> Self {
        self.progress_callback = Some(callback);
        self
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