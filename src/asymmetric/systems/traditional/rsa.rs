//! # RSA Crypto System Implementation
//!
//! Provides an implementation of the `AsymmetricCryptographicSystem` trait using RSA.
//! This system uses PKCS#1 v1.5 for encryption/decryption and the Probabilistic Signature Scheme (PSS)
//! with SHA-256 for signing and verification.
//!
//! Within the `seal-kit` framework, this implementation serves as both a Key Encapsulation Mechanism (KEM)
//! for securely wrapping Data Encryption Keys (DEKs) and as a digital signature mechanism for ensuring
//! data integrity and authenticity.
//!
//! ## Key Management
//! - Keys are generated based on the specified bit size from the `CryptoConfig`.
//! - Internally, keys are stored in their raw DER (Distinguished Encoding Rules) format within wrapper types.
//! - The system provides functions to import and export keys in the standard PEM (Privacy-Enhanced Mail) format.
//!
//! ---
//!
//! # RSA 加密系统实现
//!
//! 提供基于 RSA 的 `AsymmetricCryptographicSystem` 特征实现。
//! 本系统使用 PKCS#1 v1.5 进行加密/解密，并使用带有 SHA-256 的概率签名方案 (PSS)
//! 进行签名和验证。
//!
//! 在 `seal-kit` 框架中，此实现既可作为密钥封装机制 (KEM) 安全地包装数据加密密钥 (DEK)，
//! 也可作为数字签名机制来确保数据的完整性和真实性。
//!
//! ## 密钥管理
//! - 密钥根据 `CryptoConfig` 中指定的比特大小生成。
//! - 在内部，密钥以其原生的 DER (Distinguished Encoding Rules) 格式存储在包装类型中。
//! - 系统提供功能以标准 PEM (Privacy-Enhanced Mail) 格式导入和导出密钥。

use crate::asymmetric::traits::AsymmetricCryptographicSystem;
use crate::common::config::CryptoConfig;
use crate::common::utils::ZeroizingVec;
use bincode::{Decode, Encode};
use rsa::pkcs8::{self, DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use rsa::pss::{Signature as PssSignature, SigningKey, VerifyingKey};
use rsa::rand_core::OsRng as RsaOsRng;
use rsa::signature::{RandomizedSigner, SignatureEncoding, Verifier};
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;

/// Dedicated error types for the RSA system.
///
/// ---
///
/// RSA 系统专用的错误类型。
#[derive(Error, Debug)]
pub enum RsaSystemError {
    /// Error during RSA key pair generation.
    /// ---
    /// RSA 密钥对生成期间出错。
    #[error("RSA key generation failed: {0}")]
    KeyGeneration(Box<rsa::errors::Error>),

    /// Error during RSA encryption.
    /// ---
    /// RSA 加密期间出错。
    #[error("RSA encryption failed: {0}")]
    Encryption(Box<rsa::errors::Error>),

    /// Error during RSA decryption.
    /// ---
    /// RSA 解密期间出错。
    #[error("RSA decryption failed: {0}")]
    Decryption(Box<rsa::errors::Error>),

    /// Error during RSA signing.
    /// ---
    /// RSA 签名期间出错。
    #[error("RSA signing failed: {0}")]
    Signing(Box<rsa::Error>),

    /// Error during RSA signature verification.
    /// ---
    /// RSA 签名验证期间出错。
    #[error("RSA verification failed: {0}")]
    Verification(rsa::signature::Error),

    /// Indicates that the signature data is not in a valid format.
    /// ---
    /// 表示签名数据格式无效。
    #[error("Invalid signature format: {0}")]
    InvalidSignatureFormat(rsa::signature::Error),

    /// Error related to PKCS#8 key encoding or decoding.
    /// ---
    /// 与 PKCS#8 密钥编码或解码相关的错误。
    #[error("PKCS#8 key encoding/decoding failed: {0}")]
    Pkcs8(Box<pkcs8::Error>),

    /// Error related to PEM key encoding or decoding (via SPKI).
    /// ---
    /// 与 PEM 密钥编码或解码相关的错误 (通过SPKI)。
    #[error("PEM key encoding/decoding failed: {0}")]
    Pem(Box<pkcs8::spki::Error>),
}

/// A wrapper for an RSA public key, stored in DER format, to provide serialization support.
///
/// ---
///
/// RSA 公钥包装器，以 DER 格式存储，提供序列化支持。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RsaPublicKeyWrapper(pub Vec<u8>);

impl RsaPublicKeyWrapper {
    /// Returns the inner DER-encoded public key data.
    /// ---
    /// 获取内部DER编码的公钥数据。
    pub fn inner_data(&self) -> &[u8] {
        &self.0
    }

    /// Returns the public key as a byte slice.
    /// ---
    /// 以字节切片形式返回公钥。
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A wrapper for an RSA private key, stored in DER format. It uses `ZeroizingVec`
/// to ensure the key material is securely wiped from memory when dropped.
///
/// ---
///
/// RSA 私钥包装器，以 DER 格式存储。它使用 `ZeroizingVec`
/// 确保密钥材料在被丢弃时能从内存中安全擦除。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RsaPrivateKeyWrapper(pub ZeroizingVec);

impl RsaPrivateKeyWrapper {
    /// Returns the inner DER-encoded private key data.
    /// ---
    /// 获取内部DER编码的私钥数据。
    pub fn inner_data(&self) -> &[u8] {
        &self.0
    }

    /// Returns the private key as a byte slice.
    /// ---
    /// 以字节切片形式返回私钥。
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A wrapper for an RSA signature to support serialization and encoding.
///
/// ---
///
/// RSA 签名包装器，以支持序列化和编码。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Decode, Encode)]
pub struct RsaSignature(pub Vec<u8>);

impl AsRef<[u8]> for RsaSignature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// An implementation of `AsymmetricCryptographicSystem` for RSA.
///
/// Provides standard RSA PKCS#1 v1.5 encryption and PSS signing functionalities.
///
/// ---
///
/// RSA 的 `AsymmetricCryptographicSystem` 实现。
///
/// 提供标准 RSA PKCS#1 v1.5 加密和 PSS 签名功能。
pub struct RsaCryptoSystem;

impl AsymmetricCryptographicSystem for RsaCryptoSystem {
    type PublicKey = RsaPublicKeyWrapper;
    type PrivateKey = RsaPrivateKeyWrapper;
    type Signature = RsaSignature;
    type Error = RsaSystemError;

    /// Generates an RSA key pair with the bit size specified in the configuration.
    /// The keys are stored internally in DER format.
    ///
    /// ---
    ///
    /// 根据配置中指定的比特大小生成一个RSA密钥对。
    /// 密钥在内部以DER格式存储。
    fn generate_keypair(
        config: &CryptoConfig,
    ) -> Result<(Self::PublicKey, Self::PrivateKey), Self::Error> {
        let bits = config.rsa_key_bits;
        let mut rsa_rng = RsaOsRng;

        // Use the `rsa` crate to generate a new private key with the specified bit length.
        // ---
        // 使用 `rsa` crate 生成一个具有指定比特长度的新私钥。
        let private_key = RsaPrivateKey::new(&mut rsa_rng, bits)
            .map_err(|e| RsaSystemError::KeyGeneration(Box::new(e)))?;
        // The public key can be derived from the private key.
        // ---
        // 公钥可以从私钥派生。
        let public_key = RsaPublicKey::from(&private_key);

        // Convert keys to PKCS#8 DER format for consistent internal storage.
        // ---
        // 将密钥转换为 PKCS#8 DER 格式，以便进行一致的内部存储。
        let public_der = public_key
            .to_public_key_der()
            .map_err(|e| RsaSystemError::Pem(Box::new(e)))?;
        let private_der = private_key
            .to_pkcs8_der()
            .map_err(|e| RsaSystemError::Pkcs8(Box::new(e)))?;

        // Wrap the raw DER bytes in our custom wrapper types.
        // ---
        // 将原始的 DER 字节包装在我们自定义的包装类型中。
        Ok((
            RsaPublicKeyWrapper(public_der.as_bytes().to_vec()),
            RsaPrivateKeyWrapper(ZeroizingVec(private_der.as_bytes().to_vec())),
        ))
    }

    /// Encrypts a plaintext using the public key with PKCS#1 v1.5 padding.
    /// Note: `additional_data` is not used in this RSA encryption scheme.
    ///
    /// ---
    ///
    /// 使用公钥和 PKCS#1 v1.5 填充来加密明文。
    /// 注意：此 RSA 加密方案不使用 `additional_data`。
    fn encrypt(
        public_key: &Self::PublicKey,
        plaintext: &[u8],
        _additional_data: Option<&[u8]>, // RSA PKCS#1 v1.5 does not use AAD. / RSA PKCS#1 v1.5不使用附加数据。
    ) -> Result<Vec<u8>, Self::Error> {
        // Before encryption, restore the `RsaPublicKey` instance from the raw DER bytes.
        // ---
        // 加密前，从原始 DER 字节恢复 `RsaPublicKey` 实例。
        let public_key = RsaPublicKey::from_public_key_der(&public_key.0)
            .map_err(|e| RsaSystemError::Pem(Box::new(e)))?;
        let mut rng = RsaOsRng;
        // Perform encryption using PKCS#1 v1.5 padding scheme.
        // ---
        // 使用 PKCS#1 v1.5 填充方案执行加密。
        public_key
            .encrypt(&mut rng, Pkcs1v15Encrypt, plaintext)
            .map_err(|e| RsaSystemError::Encryption(Box::new(e)))
    }

    /// Decrypts a ciphertext using the private key with PKCS#1 v1.5 padding.
    /// Note: `additional_data` is not used in this RSA decryption scheme.
    ///
    /// ---
    ///
    /// 使用私钥和 PKCS#1 v1.5 填充来解密密文。
    /// 注意：此 RSA 解密方案不使用 `additional_data`。
    fn decrypt(
        private_key: &Self::PrivateKey,
        ciphertext: &[u8],
        _additional_data: Option<&[u8]>, // RSA PKCS#1 v1.5 does not use AAD. / RSA PKCS#1 v1.5不使用附加数据。
    ) -> Result<Vec<u8>, Self::Error> {
        // Before decryption, restore the `RsaPrivateKey` instance from the raw PKCS#8 DER bytes.
        // ---
        // 解密前，从原始 PKCS#8 DER 字节恢复 `RsaPrivateKey` 实例。
        let private_key = RsaPrivateKey::from_pkcs8_der(&private_key.0)
            .map_err(|e| RsaSystemError::Pkcs8(Box::new(e)))?;
        // Perform decryption using the same PKCS#1 v1.5 padding scheme.
        // ---
        // 使用相同的 PKCS#1 v1.5 填充方案执行解密。
        private_key
            .decrypt(Pkcs1v15Encrypt, ciphertext)
            .map_err(|e| RsaSystemError::Decryption(Box::new(e)))
    }

    /// Signs a message using the private key with the PSS signing scheme and SHA-256.
    ///
    /// ---
    ///
    /// 使用私钥、PSS 签名方案和 SHA-256 对消息进行签名。
    fn sign(
        private_key: &Self::PrivateKey,
        message: &[u8],
    ) -> Result<Self::Signature, Self::Error> {
        // Restore the `RsaPrivateKey` from PKCS#8 DER format.
        // ---
        // 从 PKCS#8 DER 格式恢复 `RsaPrivateKey`。
        let rsa_private_key = RsaPrivateKey::from_pkcs8_der(&private_key.0)
            .map_err(|e| RsaSystemError::Pkcs8(Box::new(e)))?;
        // Create a PSS signing key using SHA-256 as the hash function.
        // ---
        // 使用 SHA-256 作为哈希函数，创建一个 PSS 签名密钥。
        let signing_key = SigningKey::<Sha256>::new(rsa_private_key);
        let mut rng = RsaOsRng;
        // Sign the message digest with the PSS scheme.
        // ---
        // 使用 PSS 方案对消息摘要进行签名。
        let signature = signing_key.sign_with_rng(&mut rng, message);
        Ok(RsaSignature(signature.to_vec()))
    }

    /// Verifies a signature for a message using the public key with the PSS scheme and SHA-256.
    ///
    /// ---
    ///
    /// 使用公钥、PSS 方案和 SHA-256 验证消息的签名。
    fn verify(
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<(), Self::Error> {
        // Restore the `RsaPublicKey` from DER format.
        // ---
        // 从 DER 格式恢复 `RsaPublicKey`。
        let rsa_public_key = RsaPublicKey::from_public_key_der(&public_key.0)
            .map_err(|e| RsaSystemError::Pem(Box::new(e)))?;
        // Create a PSS verifying key with the same hash function (SHA-256).
        // ---
        // 使用相同的哈希函数 (SHA-256) 创建一个 PSS 验证密钥。
        let verifying_key = VerifyingKey::<Sha256>::new(rsa_public_key);
        // Attempt to parse the raw signature bytes into a PSS signature structure.
        // ---
        // 尝试将原始签名字节解析为 PSS 签名结构。
        let rsa_signature = PssSignature::try_from(signature.as_ref())
            .map_err(|e| RsaSystemError::InvalidSignatureFormat(e))?;
        // Verify the signature against the message. This will return an error if verification fails.
        // ---
        // 对照消息验证签名。如果验证失败，这将返回一个错误。
        verifying_key
            .verify(message, &rsa_signature)
            .map_err(|e| RsaSystemError::Verification(e))
    }

    /// Exports the public key to a PEM-encoded string.
    ///
    /// ---
    ///
    /// 将公钥导出为 PEM 编码的字符串。
    fn export_public_key(public_key: &Self::PublicKey) -> Result<String, Self::Error> {
        // First, parse the key from its raw DER storage format.
        // ---
        // 首先，从其原始 DER 存储格式解析密钥。
        let public_key = RsaPublicKey::from_public_key_der(&public_key.0)
            .map_err(|e| RsaSystemError::Pem(Box::new(e)))?;
        // Then, encode the `RsaPublicKey` instance into a PEM string.
        // ---
        // 然后，将 `RsaPublicKey` 实例编码为 PEM 字符串。
        let pem = public_key
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|e| RsaSystemError::Pem(Box::new(e)))?;
        Ok(pem)
    }

    /// Exports the private key to a PEM-encoded string (PKCS#8 format).
    ///
    /// ---
    ///
    /// 将私钥导出为 PEM 编码的字符串（PKCS#8 格式）。
    fn export_private_key(private_key: &Self::PrivateKey) -> Result<String, Self::Error> {
        // First, parse the key from its raw PKCS#8 DER storage format.
        // ---
        // 首先，从其原始 PKCS#8 DER 存储格式解析密钥。
        let private_key = RsaPrivateKey::from_pkcs8_der(&private_key.0)
            .map_err(|e| RsaSystemError::Pkcs8(Box::new(e)))?;
        // Then, encode the `RsaPrivateKey` instance into a PEM string using PKCS#8 format.
        // ---
        // 然后，使用 PKCS#8 格式将 `RsaPrivateKey` 实例编码为 PEM 字符串。
        let pem = private_key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|e| RsaSystemError::Pkcs8(Box::new(e)))?;
        Ok(pem.to_string())
    }

    /// Imports a public key from a PEM-encoded string.
    /// The imported key is stored internally in DER format.
    ///
    /// ---
    ///
    /// 从 PEM 编码的字符串导入公钥。
    /// 导入的密钥在内部以 DER 格式存储。
    fn import_public_key(key_data: &str) -> Result<Self::PublicKey, Self::Error> {
        // Decode the PEM string into an `RsaPublicKey` instance.
        // ---
        // 将 PEM 字符串解码为 `RsaPublicKey` 实例。
        let public_key = RsaPublicKey::from_public_key_pem(key_data)
            .map_err(|e| RsaSystemError::Pem(Box::new(e)))?;
        // Convert the key back to DER format for internal storage.
        // ---
        // 将密钥转换回 DER 格式以供内部存储。
        let public_der = public_key
            .to_public_key_der()
            .map_err(|e| RsaSystemError::Pem(Box::new(e)))?;
        Ok(RsaPublicKeyWrapper(public_der.as_bytes().to_vec()))
    }

    /// Imports a private key from a PEM-encoded string (PKCS#8 format).
    /// The imported key is stored internally in DER format.
    ///
    /// ---
    ///
    /// 从 PEM 编码的字符串（PKCS#8 格式）导入私钥。
    /// 导入的密钥在内部以 DER 格式存储。
    fn import_private_key(key_data: &str) -> Result<Self::PrivateKey, Self::Error> {
        // Decode the PEM string into an `RsaPrivateKey` instance.
        // ---
        // 将 PEM 字符串解码为 `RsaPrivateKey` 实例。
        let private_key = RsaPrivateKey::from_pkcs8_pem(key_data)
            .map_err(|e| RsaSystemError::Pkcs8(Box::new(e)))?;
        // Convert the key back to PKCS#8 DER format for internal storage.
        // ---
        // 将密钥转换回 PKCS#8 DER 格式以供内部存储。
        let private_der = private_key
            .to_pkcs8_der()
            .map_err(|e| RsaSystemError::Pkcs8(Box::new(e)))?;
        Ok(RsaPrivateKeyWrapper(ZeroizingVec(
            private_der.as_bytes().to_vec(),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::config::CryptoConfig;
    use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
    use rsa::traits::PublicKeyParts;

    // Helper to get a valid key pair for tests
    fn setup_keys() -> (RsaPublicKeyWrapper, RsaPrivateKeyWrapper) {
        let config = CryptoConfig::default();
        RsaCryptoSystem::generate_keypair(&config).unwrap()
    }

    #[test]
    fn test_rsa_encryption_roundtrip() {
        let (public_key, private_key) = setup_keys();
        let plaintext = b"some secret data";

        let ciphertext = RsaCryptoSystem::encrypt(&public_key, plaintext, None).unwrap();
        let decrypted = RsaCryptoSystem::decrypt(&private_key, &ciphertext, None).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let (public_key, private_key) = setup_keys();
        let data = b"data to be signed";

        let signature = RsaCryptoSystem::sign(&private_key, data).unwrap();
        let verification_result = RsaCryptoSystem::verify(&public_key, data, &signature);

        assert!(verification_result.is_ok());
    }

    #[test]
    fn test_verify_tampered_signature_fails() {
        let (public_key, private_key) = setup_keys();
        let data = b"some important data";

        let mut signature = RsaCryptoSystem::sign(&private_key, data).unwrap();
        // Tamper with the signature
        signature.0[0] ^= 0xff;

        let verification_result = RsaCryptoSystem::verify(&public_key, data, &signature);
        assert!(matches!(
            verification_result,
            Err(RsaSystemError::Verification(_))
        ));
    }

    #[test]
    fn test_verify_tampered_data_fails() {
        let (public_key, private_key) = setup_keys();
        let data = b"some important data";
        let tampered_data = b"some tampered data";

        let signature = RsaCryptoSystem::sign(&private_key, data).unwrap();

        let verification_result = RsaCryptoSystem::verify(&public_key, tampered_data, &signature);
        assert!(matches!(
            verification_result,
            Err(RsaSystemError::Verification(_))
        ));
    }

    #[test]
    fn test_rsa_decrypt_wrong_key_fails() {
        let (public_key, _) = setup_keys();
        let (_, wrong_private_key) = setup_keys();
        let plaintext = b"some secret data";

        let ciphertext = RsaCryptoSystem::encrypt(&public_key, plaintext, None).unwrap();
        let result = RsaCryptoSystem::decrypt(&wrong_private_key, &ciphertext, None);

        assert!(matches!(result, Err(RsaSystemError::Decryption(_))));
    }

    #[test]
    fn test_rsa_decrypt_tampered_ciphertext_fails() {
        let (public_key, private_key) = setup_keys();
        let plaintext = b"some original text";

        let mut ciphertext = RsaCryptoSystem::encrypt(&public_key, plaintext, None).unwrap();
        // Tamper with the ciphertext
        ciphertext[0] ^= 0xff;

        let result = RsaCryptoSystem::decrypt(&private_key, &ciphertext, None);
        assert!(matches!(result, Err(RsaSystemError::Decryption(_))));
    }

    #[test]
    fn test_rsa_key_export_import() {
        let (public_key, private_key) = setup_keys();

        let exported_pub = RsaCryptoSystem::export_public_key(&public_key).unwrap();
        let exported_priv = RsaCryptoSystem::export_private_key(&private_key).unwrap();

        let imported_pub = RsaCryptoSystem::import_public_key(&exported_pub).unwrap();
        let imported_priv = RsaCryptoSystem::import_private_key(&exported_priv).unwrap();

        assert_eq!(public_key, imported_pub);
        assert_eq!(private_key, imported_priv);
    }

    #[test]
    fn test_rsa_import_invalid_key_fails() {
        let invalid_pem = "not-a-valid-pem";
        assert!(matches!(
            RsaCryptoSystem::import_public_key(invalid_pem),
            Err(RsaSystemError::Pem(_))
        ));
        assert!(matches!(
            RsaCryptoSystem::import_private_key(invalid_pem),
            Err(RsaSystemError::Pkcs8(_))
        ));
    }

    #[test]
    fn test_encrypt_empty_data() {
        let (public_key, private_key) = setup_keys();
        let plaintext = b"";

        let ciphertext = RsaCryptoSystem::encrypt(&public_key, plaintext, None).unwrap();
        let decrypted = RsaCryptoSystem::decrypt(&private_key, &ciphertext, None).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_data_too_long_fails() {
        let (public_key, _) = setup_keys();
        let pk = RsaPublicKey::from_public_key_der(&public_key.0).unwrap();
        // Create data that is definitely too long
        let long_data = vec![0u8; pk.size()];

        let result = RsaCryptoSystem::encrypt(&public_key, &long_data, None);
        assert!(matches!(result, Err(RsaSystemError::Encryption(_))));
    }

    #[test]
    fn test_key_generation_with_4096_bits() {
        let config = CryptoConfig {
            rsa_key_bits: 4096,
            ..Default::default()
        };
        let (public_key, private_key) = RsaCryptoSystem::generate_keypair(&config).unwrap();
        let pk = RsaPublicKey::from_public_key_der(&public_key.0).unwrap();
        assert_eq!(pk.size() * 8, 4096);
        let sk = RsaPrivateKey::from_pkcs8_der(&private_key.0).unwrap();
        assert_eq!(sk.size() * 8, 4096);
    }
}
