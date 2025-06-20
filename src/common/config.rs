//!
//! # 通用配置模块
//!
//! 包含 Seal 保险库所使用的核心配置结构。
//! 这些结构定义了加密参数、存储行为和密钥轮换策略。
//!
use crate::common::traits::{AsymmetricAlgorithm, SymmetricAlgorithm};
use crate::rotation::RotationPolicy;
use num_cpus;
use serde::{Deserialize, Serialize};
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
    /// 默认使用的非对称算法
    pub primary_asymmetric_algorithm: AsymmetricAlgorithm,
    /// 默认使用的对称算法
    pub primary_symmetric_algorithm: SymmetricAlgorithm,
    /// RSA密钥位数
    pub rsa_key_bits: usize,
    /// Kyber安全级别 (512/768/1024)
    pub kyber_parameter_k: usize,
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
            primary_asymmetric_algorithm: AsymmetricAlgorithm::Rsa2048,
            primary_symmetric_algorithm: SymmetricAlgorithm::Aes256Gcm,
            rsa_key_bits: 3072,        // NIST建议的安全位数
            kyber_parameter_k: 768,    // NIST竞赛中的推荐级别
            argon2_memory_cost: 19456, // 19MB
            argon2_time_cost: 2,
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
    /// 流式处理配置
    #[serde(default)]
    pub streaming: StreamingConfig,
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
    /// 3. 环境变量 (前缀 `Q_SEAL`，分隔符 `__`)。
    pub fn new(config_dir: Option<&std::path::Path>) -> Result<ConfigFile, config::ConfigError> {
        let builder = config::Config::builder()
            // 1. 从默认结构开始
            .add_source(config::Config::try_from(&ConfigFile::default())?);

        // 2. 添加配置文件（可选）
        let builder = if let Some(dir) = config_dir {
            // 如果提供了目录，则从该目录加载
            builder.add_source(config::File::from(dir.join("config.json")).required(false))
        } else {
            // 否则，从当前工作目录加载
            builder.add_source(config::File::with_name("config.json").required(false))
        };

        // 3. 从环境变量加载
        let builder = builder.add_source(
            config::Environment::with_prefix("Q_SEAL")
                .prefix_separator("_")
                .separator("__"),
        );

        builder.build()?.try_deserialize()
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

use std::fmt;

impl fmt::Debug for StreamingConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamingConfig")
            .field("buffer_size", &self.buffer_size)
            .field("show_progress", &self.show_progress)
            .field("keep_in_memory", &self.keep_in_memory)
            .field(
                "progress_callback",
                &if self.progress_callback.is_some() {
                    "Some(<function>)"
                } else {
                    "None"
                },
            )
            .field("total_bytes", &self.total_bytes)
            .finish()
    }
}

impl PartialEq for StreamingConfig {
    fn eq(&self, other: &Self) -> bool {
        self.buffer_size == other.buffer_size
            && self.show_progress == other.show_progress
            && self.keep_in_memory == other.keep_in_memory
            && self.total_bytes == other.total_bytes
    }
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

    // 我们仍然需要锁来序列化修改全局环境变量的测试，
    // 以避免并行执行时产生数据竞争。
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    /// 测试能否成功加载默认配置
    #[test]
    fn test_load_defaults() {
        // 此测试对环境变量敏感，因此我们使用锁来隔离它。
        let _lock = TEST_LOCK.lock().unwrap();

        // 我们在一个空的临时目录中进行测试，以确保没有 config.json 文件被加载。
        let dir = tempdir().unwrap();
        let config = ConfigManager::new(Some(dir.path())).unwrap();

        // 在没有文件和环境变量（由于锁的存在）的情况下，结果应为默认配置。
        assert_eq!(config, ConfigFile::default());
    }

    /// 测试能否从 JSON 文件加载配置并覆盖默认值
    #[test]
    fn test_load_from_json_file() {
        // 此测试也对环境变量敏感，所以我们也需要使用锁。
        let _lock = TEST_LOCK.lock().unwrap();
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("config.json");
        let mut file = File::create(&config_path).unwrap();
        writeln!(file, r#"{{"crypto": {{"rsa_key_bits": 4096}} }}"#).unwrap();

        // 将临时目录的路径传递给配置管理器
        let config = ConfigManager::new(Some(dir.path())).unwrap();

        assert_eq!(config.crypto.rsa_key_bits, 4096);
        assert_eq!(config.crypto.kyber_parameter_k, 768); // 检查默认值是否保留
    }

    /// 测试能否从环境变量加载配置，并验证其优先级高于 JSON 文件
    #[test]
    fn test_load_from_env_overrides_json() {
        // 此测试修改全局环境变量，必须使用锁进行序列化
        let _lock = TEST_LOCK.lock().unwrap();
        let dir = tempdir().unwrap();

        let config_path = dir.path().join("config.json");
        let mut file = File::create(&config_path).unwrap();
        writeln!(file, r#"{{"crypto": {{"rsa_key_bits": 4096}} }}"#).unwrap();

        // 使用 RAII guard 确保环境变量在测试结束时被清理
        struct EnvGuard(&'static str);
        impl Drop for EnvGuard {
            fn drop(&mut self) {
                unsafe {
                    std::env::remove_var(self.0);
                }
            }
        }

        let _guard1 = EnvGuard("Q_SEAL_CRYPTO__RSA_KEY_BITS");
        unsafe {
            std::env::set_var("Q_SEAL_CRYPTO__RSA_KEY_BITS", "2048");
        }
        let _guard2 = EnvGuard("Q_SEAL_ROTATION__VALIDITY_PERIOD_DAYS");
        unsafe {
            std::env::set_var("Q_SEAL_ROTATION__VALIDITY_PERIOD_DAYS", "180");
        }
        let _guard3 = EnvGuard("Q_SEAL_STREAMING__BUFFER_SIZE");
        unsafe {
            std::env::set_var("Q_SEAL_STREAMING__BUFFER_SIZE", "8192");
        }

        let config = ConfigManager::new(Some(dir.path())).unwrap();

        assert_eq!(config.crypto.rsa_key_bits, 2048); // 被环境变量覆盖
        assert_eq!(config.rotation.validity_period_days, 180); // 来自环境变量
        assert_eq!(config.streaming.buffer_size, 8192); // 新增：测试深层结构
        assert_eq!(config.crypto.use_traditional, true); // 来自默认值
    }

    /// 测试当环境变量类型不匹配时，该变量会被静默忽略。
    #[test]
    fn test_env_type_mismatch_is_ignored() {
        // 此测试修改全局环境变量，必须使用锁进行序列化
        let _lock = TEST_LOCK.lock().unwrap();

        struct EnvGuard(&'static str);
        impl Drop for EnvGuard {
            fn drop(&mut self) {
                unsafe {
                    std::env::remove_var(self.0);
                }
            }
        }
        let _guard = EnvGuard("Q_SEAL_CRYPTO__RSA_KEY_BITS");
        // 为一个 usize 字段设置一个无法解析的值
        unsafe {
            std::env::set_var("Q_SEAL_CRYPTO__RSA_KEY_BITS", "not-a-number");
        }

        // config-rs 在遇到无法解析的值时会返回错误
        let config_result = ConfigManager::new(None);
        assert!(config_result.is_err());
    }
}
