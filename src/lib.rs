//! q-seal-core - 传统与后量子加密库
//! 
//! 这个库提供了传统加密(RSA)和后量子加密(Kyber)的统一接口，
//! 以及安全的密钥存储功能。
//!
//! 新版本添加了混合加密系统，同时使用RSA和Kyber提供双重安全保障。

pub mod storage;
pub mod primitives;
pub mod traits;
pub mod rotation;
pub mod config;
pub mod errors;
pub mod asymmetric;
pub mod symmetric;

pub use asymmetric::traits::CryptographicSystem;
#[cfg(feature = "secure-storage")]
pub use traits::SecureKeyStorage;
pub use traits::AuthenticatedCryptoSystem;
pub use errors::Error;
#[cfg(all(feature = "traditional", feature = "post-quantum"))]
pub use asymmetric::systems::hybrid::rsa_kyber::RsaKyberCryptoSystem;
pub use asymmetric::rotation::KeyRotationManager;
pub use config::ConfigManager;
pub use asymmetric::engines::QSealEngine;
#[cfg(feature = "async-engine")]
pub use asymmetric::engines::AsyncQSealEngine;
pub use symmetric::engines::SymmetricQSealEngine;

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
pub use storage::container::EncryptedKeyContainer;

/// 库版本信息
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::{constant_time_eq, CryptoConfig};
    
    #[test]
    #[cfg(all(feature = "traditional", feature = "post-quantum"))]
    fn test_unified_encrypt_decrypt() {
        // 使用统一特征进行跨不同加密系统的测试
        let systems: [&str; 3] = ["traditional", "post-quantum", "hybrid"];
        let test_message = b"Hello, unified crypto world!";
        let config = CryptoConfig::default();
        
        for system in systems.iter() {
            let result = match *system {
                "traditional" => {
                    let (pub_key, priv_key) = TraditionalRsa::generate_keypair(&config).unwrap();
                    let encrypted = TraditionalRsa::encrypt(&pub_key, test_message, None).unwrap();
                    let decrypted = TraditionalRsa::decrypt(&priv_key, &encrypted.to_string(), None).unwrap();
                    // 使用常量时间比较，提高安全性
                    constant_time_eq(&decrypted, test_message)
                },
                "post-quantum" => {
                    let (pub_key, priv_key) = PostQuantumKyber::generate_keypair(&config).unwrap();
                    let encrypted = PostQuantumKyber::encrypt(&pub_key, test_message, None).unwrap();
                    let decrypted = PostQuantumKyber::decrypt(&priv_key, &encrypted.to_string(), None).unwrap();
                    // 使用常量时间比较，提高安全性
                    constant_time_eq(&decrypted, test_message)
                },
                "hybrid" => {
                    let (pub_key, priv_key) = HybridRsaKyber::generate_keypair(&config).unwrap();
                    let encrypted = HybridRsaKyber::encrypt(&pub_key, test_message, None).unwrap();
                    let decrypted = HybridRsaKyber::decrypt(&priv_key, &encrypted.to_string(), None).unwrap();
                    // 使用常量时间比较，提高安全性
                    constant_time_eq(&decrypted, test_message)
                },
                _ => false
            };
            assert!(result, "Failed with system: {}", system);
        }
    }
}