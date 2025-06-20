use crate::asymmetric::errors::AsymmetricError;
use crate::storage::container::ContainerError;
use crate::symmetric::errors::SymmetricError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum BincodeError {
    #[error("Encode error: {0}")]
    Enc(#[source] Box<bincode::error::EncodeError>),
    #[error("Decode error: {0}")]
    Dec(#[source] Box<bincode::error::DecodeError>),
}

impl From<bincode::error::EncodeError> for BincodeError {
    fn from(err: bincode::error::EncodeError) -> Self {
        BincodeError::Enc(Box::from(err))
    }
}

impl From<bincode::error::DecodeError> for BincodeError {
    fn from(err: bincode::error::DecodeError) -> Self {
        BincodeError::Dec(Box::from(err))
    }
}

/// The primary error type for the `seal-kit` library.
/// This enum consolidates all possible failure modes into a single, unified error type,
/// simplifying error handling for the library's consumers.
/// 中文: `seal-kit` 库的主错误类型。
/// 该枚举将所有可能的失败模式整合为单一、统一的错误类型，从而简化库使用者的错误处理。
#[derive(Error, Debug)]
pub enum Error {
    /// Errors related to cryptographic operations.
    /// 中文: 与加密操作相关的错误。
    #[error("Cryptography error: {0}")]
    Cryptography(#[from] CryptographyError),

    /// Errors related to key management, such as rotation or derivation.
    /// 中文: 与密钥管理相关的错误，如轮换或派生。
    #[error("Key management error: {0}")]
    KeyManagement(#[from] KeyManagementError),

    /// Errors originating from the underlying storage or vault operations.
    /// 中文: 源于底层存储或保险库操作的错误。
    #[error("Vault error: {0}")]
    Vault(#[from] VaultError),

    /// Errors related to I/O operations, like reading or writing files.
    /// 中文: 与I/O操作相关的错误，如读写文件。
    #[error("I/O error")]
    Io(#[from] std::io::Error),

    /// Errors related to serialization or deserialization (e.g., JSON).
    /// 中文: 与序列化或反序列化相关的错误（例如JSON）。
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Errors related to converting a string from UTF-8 bytes.
    /// 中文: 与从UTF-8字节转换字符串相关的错误。
    #[error("Invalid data format: {0}")]
    Format(String),

    /// Errors related to serialization (Bincode).
    #[error("Serialization error (Bincode)")]
    Bincode(#[from] BincodeError),

    /// Errors related to configuration.
    #[error("Configuration error: {0}")]
    Config(String),

    /// Errors related to password hashing.
    #[error("Password hashing failed")]
    PasswordHash(#[from] argon2::password_hash::Error),

    /// Errors related to asymmetric cryptographic operations.
    #[error("Asymmetric cryptographic error")]
    Asymmetric(#[from] AsymmetricError),

    /// Errors related to symmetric cryptographic operations.
    #[error("Symmetric cryptographic error")]
    Symmetric(#[from] SymmetricError),

    /// Errors related to the storage container.
    /// Indicates that a key with a specific ID could not be found in the key registry.
    /// This can happen during decryption if the key used for encryption has been removed or was never present.
    /// 中文: 表示在密钥注册表中找不到具有特定ID的密钥。
    /// 这可能在解密过程中发生，如果用于加密的密钥已被移除或从未存在。
    #[error("Secure storage container error")]
    Storage(#[from] ContainerError),

    /// Errors related to the key not found with a given id.
    #[error("Key not found with id: {0}")]
    KeyNotFound(String),
}

/// Errors specific to the vault and its underlying storage mechanism.
/// These errors relate to loading, saving, or interacting with the vault's state.
/// 中文: 特定于保险库及其底层存储机制的错误。
/// 这些错误与加载、保存或与保险库状态交互有关。
#[derive(Error, Debug)]
pub enum VaultError {
    /// An error occurred in the encrypted key container, specific to the `secure-storage` feature.
    /// This typically involves failures in password-based key derivation (Argon2) or symmetric encryption (AES-GCM).
    /// 中文: 加密密钥容器发生错误，特定于 `secure-storage` 特性。
    /// 这通常涉及基于密码的密钥派生（Argon2）或对称加密（AES-GCM）的失败。
    #[cfg(feature = "secure-storage")]
    #[error("Container error: {0}")]
    Container(#[from] ContainerError),

    /// A password was required for an operation (e.g., opening an encrypted vault, rotating keys) but was not provided.
    /// 中文: 某个操作需要密码（例如，打开加密保险库、轮换密钥）但未提供。
    #[error("A password is required for this operation")]
    PasswordRequired,
}

/// Errors specific to cryptographic algorithm implementations.
/// This is a generic category for failures within the cryptographic primitives themselves.
/// 中文: 特定于加密算法实现的错误。
/// 这是加密原语本身内部失败的通用类别。
#[derive(Error, Debug)]
pub enum CryptographyError {
    /// Randomness generation failed.
    #[error("Randomness generation failed: {0}")]
    RandomnessError(String),

    /// Key derivation failed.
    #[error("Key derivation failed: {0}")]
    KeyDerivationError(String),
}

/// Errors related to the key management lifecycle.
/// These errors occur during processes like key rotation, selection, or type validation.
/// 中文: 与密钥管理生命周期相关的错误。
/// 这些错误发生在密钥轮换、选择或类型验证等过程中。
#[derive(Error, Debug)]
pub enum KeyManagementError {
    /// The operation is not supported in the current mode.
    #[error("The operation is not supported in the current mode: {0}")]
    ModeMismatch(String),

    /// No primary key is available to perform the operation.
    #[error("No primary key is available to perform the operation.")]
    NoPrimaryKey,

    /// The key type found in metadata does not match the expected type for this operation.
    #[error("The key type found in metadata does not match the expected type for this operation.")]
    KeyTypeMismatch,
}

// thiserror 自动处理 Display, StdError 和所有 #[from] 的实现

// 手动实现一些无法使用 #[from] 的转换
impl From<std::string::FromUtf8Error> for Error {
    fn from(err: std::string::FromUtf8Error) -> Self {
        Error::Format(format!("UTF-8 conversion error: {}", err))
    }
}

impl From<config::ConfigError> for Error {
    fn from(err: config::ConfigError) -> Self {
        Error::Config(err.to_string())
    }
}
