//! Encrypted storage implementation for `VaultPersistence`.
// 中文: `VaultPersistence` 的加密存储实现。

#![cfg(feature = "secure-storage")]

use super::{container::EncryptedKeyContainer, traits::VaultPersistence};
use crate::{
    common::{
        errors::{Error, VaultError},
        traits::SecureKeyStorage,
    },
    vault::VaultPayload,
    SEAL_ALGORITHM_ID,
};
use secrecy::SecretString;
use std::{fs, path::Path};

/// A persistence strategy that encrypts the entire vault using a user-provided password.
///
/// This is the default and recommended secure implementation. It leverages `EncryptedKeyContainer`
/// to derive an encryption key from the password (using Argon2id) and then encrypts the
/// serialized `VaultPayload` (using AES-256-GCM).
/// This implementation is only available when the `secure-storage` feature is enabled.
///
/// 中文: 一个使用用户提供的密码来加密整个保险库的持久化策略。
///
/// 这是默认且推荐的安全实现。它利用 `EncryptedKeyContainer` 从密码派生加密密钥（使用 Argon2id），
/// 然后加密序列化后的 `VaultPayload`（使用 AES-256-GCM）。
/// 此实现仅在 `secure-storage` 特性启用时可用。
#[derive(Default)]
pub struct EncryptedVaultStore;

impl EncryptedVaultStore {
    /// Creates a new instance of `EncryptedVaultStore`.
    /// 中文: 创建一个新的 `EncryptedVaultStore` 实例。
    pub fn new() -> Self {
        Self
    }
}

impl VaultPersistence for EncryptedVaultStore {
    /// Loads an encrypted vault file, decrypts it, and returns the `VaultPayload`.
    ///
    /// A valid password is required for this operation. The method first reads the
    /// `EncryptedKeyContainer` from the file, then uses the password to decrypt its content,
    /// and finally deserializes the plaintext bytes into a `VaultPayload`.
    ///
    /// # Errors
    /// Returns `VaultError::PasswordRequired` if the password is `None`.
    ///
    /// 中文: 加载一个加密的保险库文件，将其解密，并返回 `VaultPayload`。
    ///
    /// 此操作必须提供有效的密码。该方法首先从文件中读取 `EncryptedKeyContainer`，
    /// 然后使用密码解密其内容，最后将明文字节反序列化为 `VaultPayload`。
    ///
    /// # 错误
    /// 如果密码是 `None`，则返回 `VaultError::PasswordRequired`。
    fn load(&self, path: &Path, password: Option<&SecretString>) -> Result<VaultPayload, Error> {
        let password = password.ok_or(VaultError::PasswordRequired)?;

        let container_json = fs::read_to_string(path)?;
        let container = EncryptedKeyContainer::from_json(&container_json)
            .map_err(VaultError::Container)?;

        let decrypted_bytes = container
            .decrypt_key(password)
            .map_err(VaultError::Container)?;
        let payload: VaultPayload = serde_json::from_slice(&decrypted_bytes)?;
        Ok(payload)
    }

    /// Encrypts the `VaultPayload` with a password and saves it to a file.
    ///
    /// A password is required for this operation. The `VaultPayload` is first serialized to JSON bytes,
    /// then encrypted and wrapped in an `EncryptedKeyContainer`, which is finally written to disk.
    /// An atomic write is performed to prevent data corruption.
    ///
    /// # Errors
    /// Returns `VaultError::PasswordRequired` if the password is `None`.
    ///
    /// 中文: 使用密码加密 `VaultPayload` 并将其保存到文件。
    ///
    /// 此操作必须提供密码。`VaultPayload` 首先被序列化为 JSON 字节，然后被加密并包装在
    /// `EncryptedKeyContainer` 中，最终写入磁盘。
    /// 执行原子写入以防止数据损坏。
    ///
    /// # 错误
    /// 如果密码是 `None`，则返回 `VaultError::PasswordRequired`。
    fn save(
        &self,
        path: &Path,
        payload: &VaultPayload,
        password: Option<&SecretString>,
    ) -> Result<(), Error> {
        let password = password.ok_or(VaultError::PasswordRequired)?;
        let payload_json = serde_json::to_string(payload)?;

        let container = EncryptedKeyContainer::encrypt_key(
            password,
            payload_json.as_bytes(),
            SEAL_ALGORITHM_ID,
            &payload.config.crypto,
        )
        .map_err(VaultError::Container)?;

        let container_json = container.to_json().map_err(VaultError::Container)?;

        // Atomic write to prevent data corruption.
        // 中文: 原子写入以防止数据损坏。
        let temp_path = path.with_extension("tmp");
        fs::write(&temp_path, container_json)?;
        fs::rename(&temp_path, path)?;

        Ok(())
    }

    /// Returns `true` as this strategy uses encryption.
    /// 中文: 返回 `true`，因为此策略使用加密。
    fn is_encrypted(&self) -> bool {
        true
    }
} 