//! # Traditional Cryptographic Algorithm Module
//!
//! This module contains implementations of traditional cryptographic algorithms such as RSA.
//! It provides interfaces that conform to the `AsymmetricCryptographicSystem` trait,
//! acting as a unified entry point for all traditional asymmetric encryption systems.
//!
//! ---
//!
//! # 传统加密算法模块
//!
//! 本模块包含RSA等传统加密算法的实现。
//! 它提供符合 `AsymmetricCryptographicSystem` 特征的接口，
//! 作为所有传统非对称加密系统的统一入口。

pub mod rsa;

// Re-export the RSA system for convenient access by other modules.
//
// By re-exporting, users of this module can directly use `traditional::RsaCryptoSystem`
// without needing to know the internal file structure. This simplifies the module's public API.
//
// ---
//
// 重新导出RSA系统，方便其他模块调用。
//
// 通过重新导出，本模块的用户可以直接使用 `traditional::RsaCryptoSystem`，
// 无需关心内部的文件结构。这简化了模块的公共API。
pub use rsa::RsaCryptoSystem;
