//! Defines the data structures for managed, rotatable keys.
//! 
//! 定义管理、可轮换的密钥的数据结构。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The status of a cryptographic key within its lifecycle.
///
/// 一个加密密钥在其生命周期中的状态。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum KeyStatus {
    /// The primary key, currently used for all new encryption operations.
    ///
    /// 主密钥，当前用于所有新的加密操作。
    Primary,
    /// A previous primary key, now only used for decrypting old data.
    ///
    /// 以前的主密钥，现在只用于解密旧数据。
    Secondary,
    /// An old key that is past its validity period and should no longer be used.
    ///
    /// 一个过期的密钥，其有效期已过，不应再使用。
    Expired,
}

/// Metadata associated with a managed cryptographic key.
///
/// 与管理加密密钥相关的元数据。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// The full, unique identifier for this specific key version (e.g., "my-key-alias-v2").
    ///
    /// 此特定密钥版本的完整、唯一标识符（例如，"my-key-alias-v2"）。
    pub id: String,
    /// The logical name for the key, common across all its versions (e.g., "my-key-alias").
    ///
    /// 密钥的逻辑名称，在所有版本中都相同（例如，"my-key-alias"）。
    pub alias: String,
    /// The version number of the key.
    ///
    /// 密钥的版本号。
    pub version: u32,
    /// The timestamp when the key was created.
    ///
    /// 密钥创建的时间戳。
    pub created_at: DateTime<Utc>,
    /// The timestamp when the key is scheduled to expire.
    ///
    /// 密钥计划过期的时间戳。
    pub expires_at: DateTime<Utc>,
    /// The current status of the key in the rotation lifecycle.
    ///
    /// 密钥在旋转生命周期中的当前状态。
    pub status: KeyStatus,
    /// The algorithm the key is intended for.
    ///
    /// 密钥 intended for.
    pub algorithm: String,
}

/// A container that atomically stores a key's metadata alongside its raw key material.
/// This struct is the standard unit for storage and management by the `FileSystemKeyProvider`.
///
/// 一个容器，用于原子性地存储密钥的元数据以及其原始密钥材料。
/// 这个结构体是 `FileSystemKeyProvider` 的标准存储和管理的单位。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedKey {
    /// The metadata describing the key's properties and lifecycle status.
    ///
    /// 描述密钥的属性和生命周期状态的元数据。
    pub metadata: KeyMetadata,
    /// The raw cryptographic key material, which could be a symmetric key
    /// or a serialized asymmetric key pair.
    ///
    /// 原始加密密钥材料，可以是对称密钥或序列化的非对称密钥对。
    pub key_material: Vec<u8>,
} 