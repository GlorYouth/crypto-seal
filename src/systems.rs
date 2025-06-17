// core/src/crypto/systems.rs
//! 算法系统集合
//!
//! 包含传统、后量子和混合加密算法实现
#[cfg(feature = "traditional")]
pub mod traditional;

#[cfg(feature = "post-quantum")]
pub mod post_quantum;

#[cfg(all(feature = "traditional", feature = "post-quantum"))]
pub mod hybrid; 