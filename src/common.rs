//! 通用模块
//! 
//! 包含错误处理、配置管理、通用特征和工具函数。
//!
pub mod config;
pub mod errors;
pub mod streaming;
pub mod traits;
pub mod utils;

pub use self::config::{ConfigManager, ConfigFile};
pub use self::errors::Error;
pub use self::traits::{SecureKeyStorage, KeyStatus, KeyMetadata};
pub use self::utils::{CryptoConfig, to_base64, from_base64, constant_time_eq};

#[cfg(any(feature = "traditional", feature = "post-quantum"))]
pub use self::traits::AuthenticatedCryptoSystem;

#[cfg(any(feature = "traditional", feature = "post-quantum"))]
pub use crate::asymmetric::primitives::streaming::*;

#[cfg(all(feature = "async-engine", any(feature = "traditional", feature = "post-quantum")))]
pub use crate::asymmetric::primitives::async_streaming::{AsyncStreamingDecryptor, AsyncStreamingEncryptor};

#[cfg(feature = "async-engine")]
pub use streaming::StreamingConfig;

