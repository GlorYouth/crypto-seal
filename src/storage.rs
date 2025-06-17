//! 密钥安全存储模块
//!
//! 本模块提供密钥的加密存储、持久化和恢复功能

#[cfg(feature = "secure-storage")]
pub mod container;
pub mod file;

#[cfg(feature = "secure-storage")]
pub use container::EncryptedKeyContainer;
pub use file::KeyFileStorage; 