//! Plaintext storage implementation for `VaultPersistence`.
// 中文: `VaultPersistence` 的明文存储实现。

use super::traits::VaultPersistence;
use crate::common::errors::{Error, VaultError};
use crate::vault::VaultPayload;
use secrecy::SecretString;
use std::fs;
use std::path::Path;

/// A persistence strategy that saves and loads the vault as a plaintext JSON file.
///
/// This implementation is suitable for environments where the underlying storage medium
/// is already encrypted, or for local tools where at-rest encryption is not a requirement.
/// It completely ignores the password parameter during `load` and `save` operations,
/// as no encryption or decryption is performed on the vault file itself.
///
/// 中文: 一个将保险库保存和加载为明文 JSON 文件的持久化策略。
///
/// 此实现适用于底层存储介质已加密的环境，或静态加密非必需的本地工具。
/// 它在 `load` 和 `save` 操作期间完全忽略密码参数，因为保险库文件本身不执行任何加密或解密。
#[derive(Default)]
pub struct PlaintextVaultStore;

impl PlaintextVaultStore {
    /// Creates a new instance of `PlaintextVaultStore`.
    /// 中文: 创建一个新的 `PlaintextVaultStore` 实例。
    pub fn new() -> Self {
        Self
    }
}

impl VaultPersistence for PlaintextVaultStore {
    /// Loads the vault payload from a plaintext JSON file.
    ///
    /// This method reads the file content, deserializes it from JSON into a `VaultPayload`,
    /// and returns it. The `password` parameter is explicitly ignored.
    ///
    /// 中文: 从明文 JSON 文件加载保险库载荷。
    ///
    /// 此方法读取文件内容，将其从 JSON 反序列化为 `VaultPayload` 并返回。
    /// `password` 参数被明确忽略。
    fn load(&self, path: &Path, _password: Option<&SecretString>) -> Result<VaultPayload, Error> {
        let payload_json = fs::read_to_string(path)?;
        let payload: VaultPayload = serde_json::from_str(&payload_json)?;
        Ok(payload)
    }

    /// Saves the vault payload as a human-readable (pretty-printed) JSON file.
    ///
    /// This method serializes the `VaultPayload` into a JSON string and writes it to the specified path.
    /// The `password` parameter is explicitly ignored. An atomic write is performed using a temporary file
    /// to prevent data corruption.
    ///
    /// 中文: 将保险库载荷保存为人类可读的（格式化）JSON 文件。
    ///
    /// 此方法将 `VaultPayload` 序列化为 JSON 字符串，并将其写入指定路径。
    /// `password` 参数被明确忽略。它使用临时文件执行原子写入，以防止数据损坏。
    fn save(
        &self,
        path: &Path,
        payload: &VaultPayload,
        _password: Option<&SecretString>,
    ) -> Result<(), Error> {
        let payload_json = serde_json::to_string_pretty(payload)?;

        // Atomic write to prevent data corruption if the write is interrupted.
        // 中文: 原子写入，防止在写入中断时数据损坏。
        let temp_path = path.with_extension("tmp");
        fs::write(&temp_path, payload_json)?;
        fs::rename(&temp_path, path)?;

        Ok(())
    }

    /// Returns `false` as this strategy does not use encryption.
    /// 中文: 返回 `false`，因为此策略不使用加密。
    fn is_encrypted(&self) -> bool {
        false
    }
} 