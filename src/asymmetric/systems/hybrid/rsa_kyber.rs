//!
//! 一个混合加密方案，结合了经典的RSA和后量子的Kyber密钥封装机制。
//! 在 `seal-kit` 框架中，此系统提供了一个可用于实现认证加密的密钥结构。
//! 实际的加密操作由 Kyber (KEM) 完成，而认证签名由 RSA (附加) 完成。
//!

use crate::asymmetric::systems::post_quantum::kyber::{
    KyberCryptoSystem, KyberPrivateKeyWrapper, KyberPublicKeyWrapper,
};
use crate::asymmetric::systems::traditional::rsa::{
    RsaCryptoSystem, RsaPrivateKeyWrapper, RsaPublicKeyWrapper, RsaSignature,
};
use crate::asymmetric::traits::AsymmetricCryptographicSystem;
use crate::common::config::CryptoConfig;
use crate::common::errors::Error;
use serde::{Deserialize, Serialize};

// --- 密钥结构 ---

/// 混合公钥，包含用于签名的RSA公钥和用于密钥封装的Kyber公钥。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RsaKyberPublicKey {
    pub rsa_public_key: RsaPublicKeyWrapper,
    pub kyber_public_key: KyberPublicKeyWrapper,
}

/// 混合私钥，包含用于签名的RSA私钥和用于密钥封装的Kyber私钥。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RsaKyberPrivateKey {
    pub rsa_private_key: RsaPrivateKeyWrapper,
    pub kyber_private_key: KyberPrivateKeyWrapper,
}

// --- 加密系统实现 ---

/// RSA-Kyber混合加密系统。
pub struct RsaKyberCryptoSystem;

impl AsymmetricCryptographicSystem for RsaKyberCryptoSystem {
    type PublicKey = RsaKyberPublicKey;
    type PrivateKey = RsaKyberPrivateKey;
    type Signature = RsaSignature;
    type Error = Error;

    fn generate_keypair(
        config: &CryptoConfig,
    ) -> Result<(Self::PublicKey, Self::PrivateKey), Self::Error> {
        // 生成RSA密钥对
        let (rsa_pk, rsa_sk) = RsaCryptoSystem::generate_keypair(config)?;

        // 生成Kyber密钥对
        let (kyber_pk, kyber_sk) = KyberCryptoSystem::generate_keypair(config)?;

        // 组合成混合密钥
        let public_key = RsaKyberPublicKey {
            rsa_public_key: rsa_pk,
            kyber_public_key: kyber_pk,
        };
        let private_key = RsaKyberPrivateKey {
            rsa_private_key: rsa_sk,
            kyber_private_key: kyber_sk,
        };

        // Perform a basic sanity check on the generated keys
        assert!(!public_key.rsa_public_key.0.is_empty());
        assert!(!public_key.kyber_public_key.0.is_empty());
        assert!(!private_key.rsa_private_key.0.is_empty());
        assert!(!private_key.kyber_private_key.0.is_empty());

        Ok((public_key, private_key))
    }

    fn export_public_key(pk: &Self::PublicKey) -> Result<String, Self::Error> {
        serde_json::to_string(pk).map_err(Into::into)
    }

    fn export_private_key(sk: &Self::PrivateKey) -> Result<String, Self::Error> {
        serde_json::to_string(sk).map_err(Into::into)
    }

    fn import_public_key(pk_str: &str) -> Result<Self::PublicKey, Self::Error> {
        serde_json::from_str(pk_str).map_err(Into::into)
    }

    fn import_private_key(sk_str: &str) -> Result<Self::PrivateKey, Self::Error> {
        serde_json::from_str(sk_str).map_err(Into::into)
    }

    /// 使用Kyber公钥执行加密（作为KEM的一部分）。
    fn encrypt(
        public_key: &Self::PublicKey,
        plaintext: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, Self::Error> {
        // 委托给Kyber系统进行加密
        KyberCryptoSystem::encrypt(&public_key.kyber_public_key, plaintext, additional_data)
    }

    /// 使用Kyber私钥执行解密（作为KEM的一部分）。
    fn decrypt(
        private_key: &Self::PrivateKey,
        ciphertext: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, Self::Error> {
        // 委托给Kyber系统进行解密
        KyberCryptoSystem::decrypt(&private_key.kyber_private_key, ciphertext, additional_data)
    }

    fn sign(
        private_key: &Self::PrivateKey,
        message: &[u8],
    ) -> Result<Self::Signature, Self::Error> {
        RsaCryptoSystem::sign(&private_key.rsa_private_key, message)
    }

    fn verify(
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<(), Self::Error> {
        RsaCryptoSystem::verify(&public_key.rsa_public_key, message, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
    use rsa::{
        pss::{SigningKey, VerifyingKey},
        signature::{RandomizedSigner, Verifier},
    };
    use sha2::{Digest, Sha256};

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

        assert!(result.is_err());
    }
}
