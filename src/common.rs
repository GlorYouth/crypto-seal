//! 基础工具模块，提供 Base64 编解码、ZeroizingVec、安全比较等工具

pub mod streaming;
pub mod utils;
pub mod traits;
pub mod errors;
pub mod config;

pub use crate::asymmetric::primitives::streaming::*;

#[cfg(feature = "async-engine")]
pub use crate::asymmetric::primitives::async_streaming::{AsyncStreamingConfig, AsyncStreamingDecryptor, AsyncStreamingEncryptor};

use base64::Engine as _;
use zeroize::{Zeroize, ZeroizeOnDrop};
use std::ops::{Deref, DerefMut};
use serde::{Deserialize, Serialize};
use serde_bytes;

