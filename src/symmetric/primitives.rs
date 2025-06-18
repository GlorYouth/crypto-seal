//! 对称加密实现
#[cfg(feature = "async-engine")]
pub mod async_streaming;
pub mod streaming;

#[cfg(feature = "async-engine")]
pub use async_streaming::{AsyncStreamingDecryptor, AsyncStreamingEncryptor};
pub use streaming::{SymmetricStreamingDecryptor, SymmetricStreamingEncryptor};
