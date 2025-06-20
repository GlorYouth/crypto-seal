//! 定义了非对称加密系统的核心 Trait。
// English: Defines the core Trait for asymmetric cryptographic systems.

use crate::common::config::CryptoConfig;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

/// `AsymmetricCryptographicSystem` defines the core functionalities that an asymmetric encryption algorithm must implement.
///
/// In the `seal-kit` framework, asymmetric cryptography is primarily used as a Key Encapsulation Mechanism (KEM).
/// This means its main purpose is to securely encrypt and decrypt a Data Encryption Key (DEK).
/// It also provides digital signature capabilities to ensure data integrity and origin authentication.
///
/// 中文: `AsymmetricCryptographicSystem` 定义了非对称加密算法必须实现的核心功能。
/// 在 `seal-kit` 框架中，非对称加密主要用作密钥封装机制 (Key Encapsulation Mechanism, KEM)，
/// 即安全地加密和解密数据加密密钥 (DEK)。
/// 同时，它也提供签名和验证功能以确保数据的完整性和来源。
pub trait AsymmetricCryptographicSystem: Sized {
    /// The public key type for this system. Must be serializable for storage or transmission.
    /// 中文: 系统的公钥类型。必须是可序列化的，以便存储或传输。
    type PublicKey: Clone + Serialize + for<'de> Deserialize<'de> + Debug;

    /// The private key type for this system. Must be serializable for secure storage.
    /// 中文: 系统的私钥类型。必须是可序列化的，以便安全存储。
    type PrivateKey: Clone + Serialize + for<'de> Deserialize<'de> + Debug;

    /// The signature type produced by this system.
    /// 中文: 系统生成的签名类型。
    type Signature: Clone + Serialize + for<'de> Deserialize<'de> + Debug + AsRef<[u8]>;

    /// The error type associated with this system's operations.
    /// 中文: 与该系统操作相关的错误类型。
    type Error: std::error::Error + Send + Sync + 'static;

    /// Generates a new key pair (public and private).
    ///
    /// # Arguments
    /// * `config` - Configuration for key generation, such as key size.
    ///
    /// 中文: 生成新的密钥对（公钥和私钥）。
    /// # 参数
    /// * `config` - 用于密钥生成的配置，例如密钥大小。
    fn generate_keypair(
        config: &CryptoConfig,
    ) -> Result<(Self::PublicKey, Self::PrivateKey), Self::Error>;

    /// Encrypts a single block of data (typically a DEK) using the public key.
    ///
    /// # Arguments
    /// * `public_key` - The public key to use for encryption.
    /// * `plaintext` - The data to encrypt.
    /// * `additional_data` - Optional additional data to be authenticated but not encrypted. This is particularly useful in AEAD schemes.
    ///
    /// 中文: 使用公钥加密单个数据块（通常是DEK）。
    /// # 参数
    /// * `public_key` - 用于加密的公钥。
    /// * `plaintext` - 要加密的数据。
    /// * `additional_data` - 可选的附加数据，它将被认证但不会被加密，在 AEAD 方案中尤其有用。
    fn encrypt(
        public_key: &Self::PublicKey,
        plaintext: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, Self::Error>;

    /// Decrypts a single block of data (typically a DEK) using the private key.
    ///
    /// # Arguments
    /// * `private_key` - The private key to use for decryption.
    /// * `ciphertext` - The data to decrypt.
    /// * `additional_data` - Optional additional data that was used during encryption for authentication.
    ///
    /// 中文: 使用私钥解密单个数据块（通常是DEK）。
    /// # 参数
    /// * `private_key` - 用于解密的私钥。
    /// * `ciphertext` - 要解密的数据。
    /// * `additional_data` - 加密时用于认证的可选附加数据。
    fn decrypt(
        private_key: &Self::PrivateKey,
        ciphertext: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, Self::Error>;

    /// Signs a message with the private key to prove authenticity and integrity.
    ///
    /// # Arguments
    /// * `private_key` - The private key for signing.
    /// * `message` - The message to be signed.
    ///
    /// 中文: 使用私钥对消息进行签名，以证明其真实性和完整性。
    /// # 参数
    /// * `private_key` - 用于签名的私钥。
    /// * `message` - 要签名的消息。
    fn sign(private_key: &Self::PrivateKey, message: &[u8])
    -> Result<Self::Signature, Self::Error>;

    /// Verifies a signature against a message using the public key.
    ///
    /// # Arguments
    /// * `public_key` - The public key for verification.
    /// * `message` - The original message.
    /// * `signature` - The signature to verify.
    ///
    /// 中文: 使用公钥验证消息的签名。
    /// # 参数
    /// * `public_key` - 用于验证的公钥。
    /// * `message` - 原始消息。
    /// * `signature` - 要验证的签名。
    fn verify(
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<(), Self::Error>;

    /// Exports the public key to a standard string format (e.g., PEM).
    /// 中文: 将公钥导出为标准字符串格式（例如PEM）。
    fn export_public_key(public_key: &Self::PublicKey) -> Result<String, Self::Error>;

    /// Exports the private key to a standard string format (e.g., PEM).
    /// 中文: 将私钥导出为标准字符串格式（例如PEM）。
    fn export_private_key(private_key: &Self::PrivateKey) -> Result<String, Self::Error>;

    /// Imports a public key from a standard string format.
    /// 中文: 从标准字符串格式导入公钥。
    fn import_public_key(key_data: &str) -> Result<Self::PublicKey, Self::Error>;

    /// Imports a private key from a standard string format.
    /// 中文: 从标准字符串格式导入私钥。
    fn import_private_key(key_data: &str) -> Result<Self::PrivateKey, Self::Error>;
}
