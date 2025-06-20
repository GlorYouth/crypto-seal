//! Traits for abstracting storage operations.
// 中文: 用于抽象存储操作的 Trait。

use crate::common::errors::Error;
use crate::vault::VaultPayload;
use secrecy::SecretString;
use std::path::Path;

/// Defines the universal interface for vault persistence behavior.
///
/// This trait abstracts the loading (`load`) and saving (`save`) of the `VaultPayload`.
/// It decouples the main `Seal` struct from the specifics of any storage backend,
/// such as whether the vault is an encrypted container or a plaintext JSON file.
/// This allows for flexible and interchangeable storage strategies.
///
/// 中文: 定义了保险库持久化行为的通用接口。
///
/// 这个 Trait 抽象了 `VaultPayload` 的加载 (`load`) 和保存 (`save`) 操作。
/// 它将主 `Seal` 结构与任何特定存储后端的具体实现（例如加密容器或明文 JSON 文件）解耦。
/// 这使得存储策略可以灵活地互换。
pub trait VaultPersistence: Send + Sync + 'static {
    /// Loads a `VaultPayload` from the specified path.
    ///
    /// The implementation determines how to interpret the file at the path
    /// and whether a password is required for decryption.
    ///
    /// # Arguments
    /// * `path` - The path to the vault file.
    /// * `password` - An optional password, which may be required for decryption by some implementations.
    ///
    /// 中文: 从指定路径加载 `VaultPayload`。
    ///
    /// 具体实现决定了如何解析路径指向的文件以及是否需要密码来解密。
    ///
    /// # 参数
    /// * `path` - 保险库文件的路径。
    /// * `password` - 一个可选的密码，某些实现可能需要用它来解密。
    fn load(&self, path: &Path, password: Option<&SecretString>) -> Result<VaultPayload, Error>;

    /// Saves a `VaultPayload` to the specified path.
    ///
    /// The implementation determines how to serialize and write the payload
    /// and whether a password is required for encryption.
    ///
    /// # Arguments
    /// * `path` - The path where the vault file will be saved.
    /// * `payload` - The `VaultPayload` to be persisted.
    /// * `password` - An optional password, which may be required for encryption by some implementations.
    ///
    /// 中文: 将 `VaultPayload` 保存到指定路径。
    ///
    /// 具体实现决定了如何序列化和写入载荷，以及是否需要密码来进行加密。
    ///
    /// # 参数
    /// * `path` - 保存保险库文件的路径。
    /// * `payload` - 需要被持久化的 `VaultPayload`。
    /// * `password` - 一个可选的密码，某些实现可能需要用它来加密。
    fn save(
        &self,
        path: &Path,
        payload: &VaultPayload,
        password: Option<&SecretString>,
    ) -> Result<(), Error>;

    /// Returns `true` if the persistence strategy uses encryption.
    ///
    /// This allows components like `Seal` to know whether password-related operations are relevant.
    ///
    /// 中文: 如果持久化策略使用加密，则返回 `true`。
    ///
    /// 这允许像 `Seal` 这样的组件了解与密码相关的操作是否适用。
    fn is_encrypted(&self) -> bool;
} 