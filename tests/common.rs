//!
//! 集成测试的通用辅助函数
//!

use seal_kit::{asymmetric::traits::AsymmetricCryptographicSystem};

/// (For testing primitives) 直接生成一个密钥对，不创建 Seal 文件。
pub fn setup_rsa_kyber_keys() -> (
    seal_kit::asymmetric::systems::hybrid::rsa_kyber::RsaKyberPublicKey,
    seal_kit::asymmetric::systems::hybrid::rsa_kyber::RsaKyberPrivateKey,
) {
    use seal_kit::asymmetric::systems::hybrid::rsa_kyber::RsaKyberCryptoSystem;
    RsaKyberCryptoSystem::generate_keypair(&Default::default()).unwrap()
} 