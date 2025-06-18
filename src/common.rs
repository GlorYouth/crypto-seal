//! 通用模块，包含错误处理、工具函数和共享的trait

pub mod config;
pub mod errors;
pub mod streaming;
pub mod traits;
pub mod utils;

pub use self::config::ConfigFile;
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

