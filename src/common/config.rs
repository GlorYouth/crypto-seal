//!
//! # 通用配置模块
//!
//! 包含 Seal 保险库所使用的核心配置结构。
//! 这些结构定义了加密参数、存储行为和密钥轮换策略。
//!
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use crate::rotation::RotationPolicy;
use crate::common::utils::CryptoConfig;

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