//! 通用模块，包含错误处理、工具函数和共享的trait

pub mod config;
pub mod errors;
pub mod streaming;
pub mod traits;
pub mod utils;

pub use self::config::ConfigFile;
pub use self::errors::Error;
pub use self::traits::{KeyMetadata, KeyStatus, SecureKeyStorage};
pub use self::utils::constant_time_eq;

#[cfg(any(feature = "traditional", feature = "post-quantum"))]
pub use self::traits::AuthenticatedCryptoSystem;

#[cfg(any(feature = "traditional", feature = "post-quantum"))]
pub use crate::asymmetric::primitives::streaming::*;

pub use self::config::CryptoConfig;
#[cfg(feature = "async-engine")]
pub use self::config::StreamingConfig;
