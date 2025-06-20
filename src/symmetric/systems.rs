//! # Symmetric Cryptographic Systems Module
//!
//! This module serves as a façade for all symmetric encryption algorithms supported by the crate.
//! It uses feature flags to conditionally compile and expose different symmetric systems,
//! such as AES-GCM. This allows users to include only the necessary cryptographic primitives,
//! optimizing the final binary size and dependency tree.
//!
//! Each symmetric system is expected to implement the `SymmetricCryptographicSystem` trait.
//!
//! ---
//!
//! # 对称加密系统模块
//!
//! 本模块是 `seal-kit` 库支持的所有对称加密算法的"门面"(façade)。
//! 它使用特性标志（feature flags）来条件性地编译和暴露不同的对称加密系统，例如AES-GCM。
//! 这种设计允许用户只包含他们需要的加密原语，从而优化最终二进制文件的大小和依赖树。
//!
//! 每个对称加密系统都应实现 `SymmetricCryptographicSystem` 特征。

#[cfg(feature = "aes-gcm-feature")]
pub mod aes_gcm;
