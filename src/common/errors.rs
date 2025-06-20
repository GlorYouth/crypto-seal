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

/// 加密操作可能遇到的错误类型
#[derive(Error, Debug)]
pub enum Error {
    #[error("I/O error")]
    Io(#[from] std::io::Error),

    #[error("Serialization error (JSON)")]
    Json(#[from] serde_json::Error),

    #[error("Serialization error (Bincode)")]
    Bincode(#[from] BincodeError),

    #[error("Configuration error")]
    Configuration(#[source] Box<config::ConfigError>),

    #[error("Secure storage container error")]
    Storage(#[from] ContainerError),

    #[error("Cryptography error: {0}")]
    Cryptography(String),

    #[error("Password hashing failed")]
    PasswordHash(#[from] argon2::password_hash::Error),

    #[error("Key management error: {0}")]
    KeyManagement(String),

    #[error("Key not found with id: {0}")]
    KeyNotFound(String),

    #[error("Invalid data format: {0}")]
    Format(String),

    #[error("Asymmetric cryptographic error")]
    Asymmetric(#[from] AsymmetricError),

    #[error("Symmetric cryptographic error")]
    Symmetric(#[from] SymmetricError),
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
        Error::Configuration(Box::from(err))
    }
}