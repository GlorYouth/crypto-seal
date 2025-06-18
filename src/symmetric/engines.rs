//! 对称加密引擎模块

#[cfg(feature = "async-engine")]
mod async_;
mod sync_;

#[cfg(feature = "async-engine")]
pub use async_::SymmetricQSealEngineAsync;
pub use sync_::SymmetricQSealEngine;