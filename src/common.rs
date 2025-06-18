//! 基础工具模块，提供 Base64 编解码、ZeroizingVec、安全比较等工具

pub mod streaming;
pub mod utils;
pub mod traits;
pub mod errors;
pub mod config;

#[cfg(any(feature = "traditional", feature = "post-quantum"))]
pub use crate::asymmetric::primitives::streaming::*;

#[cfg(all(feature = "async-engine", any(feature = "traditional", feature = "post-quantum")))]
pub use crate::asymmetric::primitives::async_streaming::{AsyncStreamingDecryptor, AsyncStreamingEncryptor};

#[cfg(feature = "async-engine")]
pub use streaming::StreamingConfig;

