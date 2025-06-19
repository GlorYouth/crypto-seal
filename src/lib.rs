//! q-seal-core - 传统与后量子加密库
//!
//! 这个库提供了传统加密(RSA)和后量子加密(Kyber)的统一接口，
//! 以及安全的密钥存储功能。
//!
//! 新版本添加了混合加密系统，同时使用RSA和Kyber提供双重安全保障。

#[cfg(any(feature = "traditional", feature = "post-quantum"))]
pub mod asymmetric;
pub mod common;
pub mod engine;
pub mod rotation;
#[cfg(feature = "secure-storage")]
pub mod seal;
pub mod storage;
#[cfg(any(feature = "aes-gcm-feature", feature = "chacha"))]
pub mod symmetric;
pub mod vault;
#[cfg(all(feature = "traditional", feature = "post-quantum"))]
pub use asymmetric::systems::hybrid::rsa_kyber::RsaKyberCryptoSystem;
#[cfg(any(feature = "traditional", feature = "post-quantum"))]
pub use asymmetric::traits::AsymmetricCryptographicSystem;
pub use common::errors::Error;
#[cfg(any(feature = "traditional", feature = "post-quantum"))]
pub use common::traits::AuthenticatedCryptoSystem;
#[cfg(feature = "secure-storage")]
pub use common::traits::SecureKeyStorage;
// 条件编译特性
/// 传统RSA加密系统别名
#[cfg(feature = "traditional")]
pub use asymmetric::systems::traditional::rsa::RsaCryptoSystem as TraditionalRsa;

/// 后量子Kyber加密系统别名
#[cfg(feature = "post-quantum")]
pub use asymmetric::systems::post_quantum::kyber::KyberCryptoSystem as PostQuantumKyber;

/// 混合RSA+Kyber加密系统别名
#[cfg(all(feature = "traditional", feature = "post-quantum"))]
pub use asymmetric::systems::hybrid::rsa_kyber::RsaKyberCryptoSystem as HybridRsaKyber;

// 导出密钥存储
#[cfg(feature = "secure-storage")]
pub use seal::Seal;
#[cfg(feature = "secure-storage")]
pub use storage::container::EncryptedKeyContainer;

/// 库版本信息
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// 公开核心 API
pub use common::config::ConfigFile;
pub use common::header::SealMode;
pub use engine::SealEngine;
