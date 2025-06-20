//! # Hybrid Cryptographic System Module
//!
//! This module implements hybrid cryptographic systems that combine a traditional algorithm (e.g., RSA)
//! with a post-quantum algorithm (e.g., Kyber). This approach provides dual-layer security,
//! ensuring that data remains secure even if one of the algorithms is compromised in the future.
//!
//! ---
//!
//! # 混合加密系统模块
//!
//! 本模块实现了结合传统加密（如RSA）和后量子加密（如Kyber）的混合系统。
//! 这种方法提供双层安全保护，确保即使其中一种算法在未来被攻破，数据仍然安全。

pub mod rsa_kyber;

// Re-export the RSA-Kyber hybrid system and its associated key types for easy access.
//
// This allows other modules to conveniently use the hybrid system without referencing
// the specific implementation file (`rsa_kyber.rs`), simplifying the public API.
//
// ---
//
// 重新导出RSA-Kyber混合系统及其相关的密钥类型，以方便调用。
//
// 这使得其他模块可以方便地使用混合加密系统，而无需引用具体的实现文件（`rsa_kyber.rs`），
// 从而简化了公共API。
pub use rsa_kyber::{RsaKyberCryptoSystem, RsaKyberPrivateKey, RsaKyberPublicKey};
