//! 定义了非对称加密系统的核心 Trait。
use crate::common::config::CryptoConfig;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

/// `AsymmetricCryptographicSystem` 定义了非对称加密算法必须实现的核心功能。
///
/// 在 `seal-kit` 框架中，非对称加密主要用作密钥封装机制 (Key Encapsulation Mechanism, KEM)，
/// 即安全地加密和解密数据加密密钥 (DEK)。
pub trait AsymmetricCryptographicSystem: Sized {
    /// 公钥类型
    type PublicKey: Clone + Serialize + for<'de> Deserialize<'de> + Debug;

    /// 私钥类型
    type PrivateKey: Clone + Serialize + for<'de> Deserialize<'de> + Debug;

    /// 错误类型
    type Error: std::error::Error + Send + Sync + 'static;

    /// 生成密钥对
    fn generate_keypair(
        config: &CryptoConfig,
    ) -> Result<(Self::PublicKey, Self::PrivateKey), Self::Error>;

    /// 使用公钥加密单个数据块（通常是DEK）。
    fn encrypt(
        public_key: &Self::PublicKey,
        plaintext: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, Self::Error>;

    /// 使用私钥解密单个数据块（通常是DEK）。
    fn decrypt(
        private_key: &Self::PrivateKey,
        ciphertext: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, Self::Error>;

    /// 将公钥导出为标准格式
    fn export_public_key(public_key: &Self::PublicKey) -> Result<String, Self::Error>;

    /// 将私钥导出为标准格式
    fn export_private_key(private_key: &Self::PrivateKey) -> Result<String, Self::Error>;

    /// 从标准格式导入公钥
    fn import_public_key(key_data: &str) -> Result<Self::PublicKey, Self::Error>;

    /// 从标准格式导入私钥
    fn import_private_key(key_data: &str) -> Result<Self::PrivateKey, Self::Error>;
}
