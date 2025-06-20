//! # Post-Quantum Cryptography Algorithm Module
//!
//! This module contains implementations of post-quantum cryptography (PQC) algorithms, such as Kyber.
//! It provides interfaces that conform to the `AsymmetricCryptographicSystem` trait,
//! serving as a unified entry point for all PQC systems.
//!
//! ---
//!
//! # 后量子加密算法模块
//!
//! 本模块包含Kyber等后量子加密（PQC）算法的实现。
//! 它提供符合 `AsymmetricCryptographicSystem` 特征的接口，
//! 作为所有后量子加密系统的统一入口。

pub mod kyber;

// Re-export the Kyber system for convenient access.
//
// This allows other parts of the crate to use `post_quantum::KyberCryptoSystem`
// without being coupled to the internal module structure.
//
// ---
//
// 重新导出Kyber系统，方便调用。
//
// 这使得crate的其他部分可以使用 `post_quantum::KyberCryptoSystem`，
// 而不必与内部模块结构耦合。
pub use kyber::KyberCryptoSystem;
