//! 对称加密实现
#[cfg(feature = "async")]
pub mod async_streaming;
pub mod streaming;

#[cfg(feature = "parallel")]
pub mod parallel_streaming;

#[cfg(feature = "async")]
pub use async_streaming::{AsyncStreamingDecryptor, AsyncStreamingEncryptor};
pub use streaming::{SymmetricStreamingDecryptor, SymmetricStreamingEncryptor};
