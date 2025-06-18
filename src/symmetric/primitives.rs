//! 对称加密实现
#[cfg(feature = "async-engine")]
pub mod async_streaming;
pub mod streaming;

pub use streaming::{SymmetricStreamingEncryptor, SymmetricStreamingDecryptor};
#[cfg(feature = "async-engine")]
pub use async_streaming::{AsyncStreamingEncryptor, AsyncStreamingDecryptor};