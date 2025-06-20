//! # RSA-Kyber Hybrid Cryptographic System
//!
//! This module implements a hybrid cryptographic scheme that combines classic RSA with the
//! post-quantum Kyber Key Encapsulation Mechanism (KEM). This "hybrid" approach is designed to provide
//! robust security during the transition to post-quantum cryptography.
//!
//! ## Design
//! The core principle is to leverage the strengths of both algorithms:
//! - **Key Encapsulation (Encryption/Decryption)**: Handled by **Kyber**. This ensures that the
//!   confidentiality of the encapsulated keys (DEKs) is protected against future quantum attacks.
//! - **Digital Signatures (Signing/Verification)**: Handled by **RSA**. This provides authentication
//!   and integrity, relying on a mature and widely trusted traditional algorithm.
//!
//! By delegating tasks this way, the system ensures that a compromise of RSA by a quantum computer
//! would not break confidentiality, while a yet-undiscovered flaw in Kyber would not break authentication.
//!
//! ## Keys
//! The public and private keys for this system are composite structures, containing both the
//! RSA and Kyber key components.
//!
//! ---
//!
//! # RSA-Kyber 混合加密系统
//!
//! 本模块实现了一个混合加密方案，它结合了经典的RSA和后量子的Kyber密钥封装机制（KEM）。
//! 这种"混合"方法旨在向量子密码学过渡期间提供强大的安全保障。
//!
//! ## 设计思想
//! 核心原则是利用两种算法的优势：
//! - **密钥封装 (加密/解密)**: 由 **Kyber** 处理。这确保了被封装密钥（DEK）的机密性
//!   能够抵御未来的量子攻击。
//! - **数字签名 (签名/验证)**: 由 **RSA** 处理。这提供了认证和完整性，依赖于一个
//!   成熟且被广泛信任的传统算法。
//!
//! 通过这种任务分派方式，系统确保了即使RSA被量子计算机攻破，机密性也不会受损；
//! 而如果Kyber被发现存在未知漏洞，认证性也不会受损。
//!
//! ## 密钥
//! 本系统的公钥和私钥是复合结构，同时包含RSA和Kyber的密钥组件。
//!

use crate::asymmetric::systems::post_quantum::kyber::{
    KyberCryptoSystem, KyberPrivateKeyWrapper, KyberPublicKeyWrapper, KyberSystemError,
};
use crate::asymmetric::systems::traditional::rsa::{
    RsaCryptoSystem, RsaPrivateKeyWrapper, RsaPublicKeyWrapper, RsaSignature, RsaSystemError,
};
use crate::asymmetric::traits::AsymmetricCryptographicSystem;
use crate::common::config::CryptoConfig;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// --- Error Type ---

/// Dedicated error type for the RSA-Kyber hybrid system.
/// It encapsulates errors from both the underlying RSA and Kyber systems.
///
/// ---
///
/// RSA-Kyber 混合系统的专用错误类型。
/// 它封装了来自底层RSA和Kyber系统的错误。
#[derive(Error, Debug)]
pub enum RsaKyberSystemError {
    /// An error occurred during an RSA operation (e.g., signing, verification).
    /// ---
    /// 在RSA操作（如签名、验证）期间发生错误。
    #[error("RSA operation failed: {0}")]
    Rsa(#[from] RsaSystemError),

    /// An error occurred during a Kyber operation (e.g., encapsulation, decapsulation).
    /// ---
    /// 在Kyber操作（如封装、解封装）期间发生错误。
    #[error("Kyber operation failed: {0}")]
    Kyber(#[from] KyberSystemError),

    /// An error occurred during key serialization or deserialization (e.g., to/from JSON).
    /// ---
    /// 在密钥序列化或反序列化（例如，与JSON之间转换）期间发生错误。
    #[error("Key serialization or deserialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

// --- Key Structures ---

/// A hybrid public key containing both an RSA public key for verification
/// and a Kyber public key for key encapsulation.
///
/// ---
///
/// 混合公钥，包含用于验证的RSA公钥和用于密钥封装的Kyber公钥。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RsaKyberPublicKey {
    pub rsa_public_key: RsaPublicKeyWrapper,
    pub kyber_public_key: KyberPublicKeyWrapper,
}

/// A hybrid private key containing both an RSA private key for signing
/// and a Kyber private key for key decapsulation.
///
/// ---
///
/// 混合私钥，包含用于签名的RSA私钥和用于密钥解封装的Kyber私钥。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RsaKyberPrivateKey {
    pub rsa_private_key: RsaPrivateKeyWrapper,
    pub kyber_private_key: KyberPrivateKeyWrapper,
}

// --- Cryptographic System Implementation ---

/// The RSA-Kyber hybrid cryptographic system.
///
/// ---
///
/// RSA-Kyber混合加密系统。
pub struct RsaKyberCryptoSystem;

impl AsymmetricCryptographicSystem for RsaKyberCryptoSystem {
    type PublicKey = RsaKyberPublicKey;
    type PrivateKey = RsaKyberPrivateKey;
    type Signature = RsaSignature;
    type Error = RsaKyberSystemError;

    /// Generates a hybrid key pair, containing both an RSA and a Kyber key pair.
    ///
    /// ---
    ///
    /// 生成一个混合密钥对，同时包含一个RSA密钥对和一个Kyber密钥对。
    fn generate_keypair(
        config: &CryptoConfig,
    ) -> Result<(Self::PublicKey, Self::PrivateKey), Self::Error> {
        // First, generate a standard RSA key pair for signing and verification.
        // ---
        // 首先，生成一个标准的RSA密钥对，用于签名和验证。
        let (rsa_pk, rsa_sk) = RsaCryptoSystem::generate_keypair(config)?;

        // Second, generate a Kyber key pair for key encapsulation.
        // ---
        // 其次，生成一个Kyber密钥对，用于密钥封装。
        let (kyber_pk, kyber_sk) = KyberCryptoSystem::generate_keypair(config)?;

        // Finally, combine both pairs into the hybrid key structures.
        // ---
        // 最后，将这两个密钥对组合到混合密钥结构中。
        let public_key = RsaKyberPublicKey {
            rsa_public_key: rsa_pk,
            kyber_public_key: kyber_pk,
        };
        let private_key = RsaKyberPrivateKey {
            rsa_private_key: rsa_sk,
            kyber_private_key: kyber_sk,
        };

        Ok((public_key, private_key))
    }

    /// Exports the hybrid public key to a JSON string.
    ///
    /// ---
    ///
    /// 将混合公钥导出为JSON字符串。
    fn export_public_key(pk: &Self::PublicKey) -> Result<String, Self::Error> {
        serde_json::to_string(pk).map_err(Into::into)
    }

    /// Exports the hybrid private key to a JSON string.
    ///
    /// ---
    ///
    /// 将混合私钥导出为JSON字符串。
    fn export_private_key(sk: &Self::PrivateKey) -> Result<String, Self::Error> {
        serde_json::to_string(sk).map_err(Into::into)
    }

    /// Imports a hybrid public key from a JSON string.
    ///
    /// ---
    ///
    /// 从JSON字符串导入混合公钥。
    fn import_public_key(pk_str: &str) -> Result<Self::PublicKey, Self::Error> {
        serde_json::from_str(pk_str).map_err(Into::into)
    }

    /// Imports a hybrid private key from a JSON string.
    ///
    /// ---
    ///
    /// 从JSON字符串导入混合私钥。
    fn import_private_key(sk_str: &str) -> Result<Self::PrivateKey, Self::Error> {
        serde_json::from_str(sk_str).map_err(Into::into)
    }

    /// Encrypts a plaintext by delegating to the Kyber system.
    /// The `public_key`'s Kyber component is used for the operation.
    ///
    /// ---
    ///
    /// 通过委托给Kyber系统来加密明文。
    /// 操作将使用 `public_key` 中的Kyber组件。
    fn encrypt(
        public_key: &Self::PublicKey,
        plaintext: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, Self::Error> {
        // For encryption, we delegate the entire operation to the Kyber system,
        // using the Kyber component of the hybrid public key.
        // ---
        // 对于加密，我们将整个操作委托给Kyber系统，
        // 使用混合公钥中的Kyber组件。
        KyberCryptoSystem::encrypt(&public_key.kyber_public_key, plaintext, additional_data)
            .map_err(Into::into)
    }

    /// Decrypts a ciphertext by delegating to the Kyber system.
    /// The `private_key`'s Kyber component is used for the operation.
    ///
    /// ---
    ///
    /// 通过委托给Kyber系统来解密密文。
    /// 操作将使用 `private_key` 中的Kyber组件。
    fn decrypt(
        private_key: &Self::PrivateKey,
        ciphertext: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, Self::Error> {
        // For decryption, we delegate the entire operation to the Kyber system,
        // using the Kyber component of the hybrid private key.
        // ---
        // 对于解密，我们将整个操作委托给Kyber系统，
        // 使用混合私钥中的Kyber组件。
        KyberCryptoSystem::decrypt(&private_key.kyber_private_key, ciphertext, additional_data)
            .map_err(Into::into)
    }

    /// Signs a message by delegating to the RSA system.
    /// The `private_key`'s RSA component is used for the operation.
    ///
    /// ---
    ///
    /// 通过委托给RSA系统来对消息进行签名。
    /// 操作将使用 `private_key` 中的RSA组件。
    fn sign(
        private_key: &Self::PrivateKey,
        message: &[u8],
    ) -> Result<Self::Signature, Self::Error> {
        // For signing, we delegate the operation to the RSA system,
        // using the RSA component of the hybrid private key.
        // ---
        // 对于签名，我们将操作委托给RSA系统，
        // 使用混合私钥中的RSA组件。
        RsaCryptoSystem::sign(&private_key.rsa_private_key, message).map_err(Into::into)
    }

    /// Verifies a signature by delegating to the RSA system.
    /// The `public_key`'s RSA component is used for the operation.
    ///
    /// ---
    ///
    /// 通过委托给RSA系统来验证签名。
    /// 操作将使用 `public_key` 中的RSA组件。
    fn verify(
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<(), Self::Error> {
        // For verification, we delegate the operation to the RSA system,
        // using the RSA component of the hybrid public key.
        // ---
        // 对于验证，我们将操作委托给RSA系统，
        // 使用混合公钥中的RSA组件。
        RsaCryptoSystem::verify(&public_key.rsa_public_key, message, signature).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_keys() -> (RsaKyberPublicKey, RsaKyberPrivateKey) {
        let config = CryptoConfig::default();
        RsaKyberCryptoSystem::generate_keypair(&config).unwrap()
    }

    #[test]
    fn test_rsakyber_key_generation() {
        let config = CryptoConfig::default();
        let (public_key, private_key) = RsaKyberCryptoSystem::generate_keypair(&config).unwrap();

        // Check if keys are not empty
        assert!(!public_key.rsa_public_key.0.is_empty());
        assert!(!public_key.kyber_public_key.0.is_empty());
        assert!(!private_key.rsa_private_key.0.is_empty());
        assert!(!private_key.kyber_private_key.0.is_empty());
    }

    #[test]
    fn test_hybrid_key_export_import() {
        let (pk, sk) = setup_keys();
        let pk_str = RsaKyberCryptoSystem::export_public_key(&pk).unwrap();
        let sk_str = RsaKyberCryptoSystem::export_private_key(&sk).unwrap();

        let imported_pk = RsaKyberCryptoSystem::import_public_key(&pk_str).unwrap();
        let imported_sk = RsaKyberCryptoSystem::import_private_key(&sk_str).unwrap();

        assert_eq!(pk, imported_pk);
        assert_eq!(sk, imported_sk);
    }

    #[test]
    fn test_rsakyber_encryption_roundtrip() {
        let (pk, sk) = setup_keys();
        let plaintext = b"this is a secret message for KEM";

        // Test encryption
        let ciphertext = RsaKyberCryptoSystem::encrypt(&pk, plaintext, None).unwrap();
        assert_ne!(plaintext, ciphertext.as_slice());

        // Test decryption
        let decrypted = RsaKyberCryptoSystem::decrypt(&sk, &ciphertext, None).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_hybrid_signature_roundtrip() {
        let (pk, sk) = setup_keys();
        let data = b"this data will be signed";

        let signature = RsaKyberCryptoSystem::sign(&sk, data).unwrap();
        let result = RsaKyberCryptoSystem::verify(&pk, data, &signature);

        assert!(result.is_ok());
    }

    #[test]
    fn test_hybrid_verification_fails_with_tampered_data() {
        let (pk, sk) = setup_keys();
        let data = b"this data will be signed";
        let tampered_data = b"some other data";

        let signature = RsaKyberCryptoSystem::sign(&sk, data).unwrap();
        let result = RsaKyberCryptoSystem::verify(&pk, tampered_data, &signature);

        assert!(matches!(result, Err(RsaKyberSystemError::Rsa(_))));
    }

    #[test]
    #[should_panic]
    fn test_hybrid_decryption_fails_with_wrong_key() {
        let (pk, _) = setup_keys();
        let (_, sk2) = setup_keys();
        let plaintext = b"some secret data";

        let ciphertext = RsaKyberCryptoSystem::encrypt(&pk, plaintext, None).unwrap();
        // The underlying pqcrypto library panics on decapsulation failure,
        // so we expect a panic here rather than a returned error.
        let _ = RsaKyberCryptoSystem::decrypt(&sk2, &ciphertext, None).unwrap();
    }
}
