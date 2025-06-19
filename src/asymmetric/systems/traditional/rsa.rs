//! `RsaCryptoSystem` 提供了基于 RSA PKCS#1 v1.5 的非对称加解密功能。
//! 在 `seal-kit` 框架中，它主要作为密钥封装机制 (KEM) 使用。

use crate::asymmetric::traits::AsymmetricCryptographicSystem;
use crate::common::config::CryptoConfig;
use crate::common::errors::Error;
use crate::common::utils::ZeroizingVec;
use bincode::{Decode, Encode};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use rsa::pss::{Signature as PssSignature, SigningKey, VerifyingKey};
use rsa::rand_core::OsRng as RsaOsRng;
use rsa::signature::{RandomizedSigner, SignatureEncoding, Verifier};
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// RSA公钥包装器，提供序列化支持
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RsaPublicKeyWrapper(pub Vec<u8>);

impl RsaPublicKeyWrapper {
    /// 获取内部DER编码的公钥数据
    pub fn inner_data(&self) -> &[u8] {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// RSA私钥包装器，提供序列化和安全擦除支持
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RsaPrivateKeyWrapper(pub ZeroizingVec);

impl RsaPrivateKeyWrapper {
    /// 获取内部DER编码的私钥数据
    pub fn inner_data(&self) -> &[u8] {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// RSA 签名包装器
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Decode, Encode)]
pub struct RsaSignature(pub Vec<u8>);

impl AsRef<[u8]> for RsaSignature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// RSA加密系统实现
///
/// 提供标准RSA PKCS#1 v1.5加密和解密功能
pub struct RsaCryptoSystem;

impl AsymmetricCryptographicSystem for RsaCryptoSystem {
    type PublicKey = RsaPublicKeyWrapper;
    type PrivateKey = RsaPrivateKeyWrapper;
    type Signature = RsaSignature;
    type Error = Error;

    fn generate_keypair(
        config: &CryptoConfig,
    ) -> Result<(Self::PublicKey, Self::PrivateKey), Self::Error> {
        let bits = config.rsa_key_bits;
        let mut rsa_rng = RsaOsRng;

        let private_key = RsaPrivateKey::new(&mut rsa_rng, bits)
            .map_err(|e| Error::Traditional(format!("生成RSA密钥失败: {}", e)))?;
        let public_key = RsaPublicKey::from(&private_key);

        // 将密钥转换为DER格式，然后包装
        let public_der = public_key
            .to_public_key_der()
            .map_err(|e| Error::Traditional(format!("导出RSA公钥DER失败: {}", e)))?;

        let private_der = private_key
            .to_pkcs8_der()
            .map_err(|e| Error::Traditional(format!("导出RSA私钥DER失败: {}", e)))?;

        Ok((
            RsaPublicKeyWrapper(public_der.as_bytes().to_vec()),
            RsaPrivateKeyWrapper(ZeroizingVec(private_der.as_bytes().to_vec())),
        ))
    }

    fn encrypt(
        public_key: &Self::PublicKey,
        plaintext: &[u8],
        _additional_data: Option<&[u8]>, // RSA PKCS#1 v1.5不使用附加数据
    ) -> Result<Vec<u8>, Self::Error> {
        // 从DER数据恢复公钥
        let public_key = RsaPublicKey::from_public_key_der(&public_key.0)
            .map_err(|e| Error::Traditional(format!("解析RSA公钥失败: {}", e)))?;

        let mut rng = RsaOsRng;
        let ciphertext = public_key
            .encrypt(&mut rng, Pkcs1v15Encrypt, plaintext)
            .map_err(|e| Error::Traditional(format!("RSA加密失败: {}", e)))?;

        Ok(ciphertext)
    }

    fn decrypt(
        private_key: &Self::PrivateKey,
        ciphertext: &[u8],
        _additional_data: Option<&[u8]>, // RSA PKCS#1 v1.5不使用附加数据
    ) -> Result<Vec<u8>, Self::Error> {
        // 从DER数据恢复私钥
        let private_key = RsaPrivateKey::from_pkcs8_der(&private_key.0)
            .map_err(|e| Error::Traditional(format!("解析RSA私钥失败: {}", e)))?;

        private_key
            .decrypt(Pkcs1v15Encrypt, ciphertext)
            .map_err(|e| Error::Traditional(format!("RSA解密失败: {}", e)))
    }

    fn sign(
        private_key: &Self::PrivateKey,
        message: &[u8],
    ) -> Result<Self::Signature, Self::Error> {
        let rsa_private_key = RsaPrivateKey::from_pkcs8_der(&private_key.0)
            .map_err(|e| Error::Key(format!("解析RSA私钥失败: {}", e)))?;

        let signing_key = SigningKey::<Sha256>::new(rsa_private_key);
        let mut rng = RsaOsRng;
        let signature = signing_key.sign_with_rng(&mut rng, message);

        Ok(RsaSignature(signature.to_vec()))
    }

    fn verify(
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<(), Self::Error> {
        let rsa_public_key = RsaPublicKey::from_public_key_der(&public_key.0)
            .map_err(|e| Error::Key(format!("解析RSA公钥失败: {}", e)))?;

        let verifying_key = VerifyingKey::<Sha256>::new(rsa_public_key);
        let rsa_signature = PssSignature::try_from(signature.as_ref())
            .map_err(|e| Error::Signature(format!("无效的签名格式: {}", e)))?;

        verifying_key
            .verify(message, &rsa_signature)
            .map_err(|e| Error::Signature(format!("签名验证失败: {}", e)))
    }

    fn export_public_key(public_key: &Self::PublicKey) -> Result<String, Self::Error> {
        // 从DER数据恢复公钥
        let public_key = RsaPublicKey::from_public_key_der(&public_key.0)
            .map_err(|e| Error::Traditional(format!("解析RSA公钥失败: {}", e)))?;

        let pem = public_key
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|e| Error::Serialization(format!("RSA公钥导出失败: {}", e)))?;
        Ok(pem)
    }

    fn export_private_key(private_key: &Self::PrivateKey) -> Result<String, Self::Error> {
        // 从DER数据恢复私钥
        let private_key = RsaPrivateKey::from_pkcs8_der(&private_key.0)
            .map_err(|e| Error::Traditional(format!("解析RSA私钥失败: {}", e)))?;

        let pem = private_key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|e| Error::Serialization(format!("RSA私钥导出失败: {}", e)))?
            .to_string();
        Ok(pem)
    }

    fn import_public_key(key_data: &str) -> Result<Self::PublicKey, Self::Error> {
        let public_key = RsaPublicKey::from_public_key_pem(key_data)
            .map_err(|e| Error::Key(format!("导入RSA公钥失败: {}", e)))?;

        let public_der = public_key
            .to_public_key_der()
            .map_err(|e| Error::Traditional(format!("导出RSA公钥DER失败: {}", e)))?;

        Ok(RsaPublicKeyWrapper(public_der.as_bytes().to_vec()))
    }

    fn import_private_key(key_data: &str) -> Result<Self::PrivateKey, Self::Error> {
        let private_key = RsaPrivateKey::from_pkcs8_pem(key_data)
            .map_err(|e| Error::Key(format!("导入RSA私钥失败: {}", e)))?;

        let private_der = private_key
            .to_pkcs8_der()
            .map_err(|e| Error::Traditional(format!("导出RSA私钥DER失败: {}", e)))?;

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
        assert!(verification_result.is_err());
    }

    #[test]
    fn test_verify_tampered_data_fails() {
        let (public_key, private_key) = setup_keys();
        let data = b"some important data";
        let tampered_data = b"some tampered data";

        let signature = RsaCryptoSystem::sign(&private_key, data).unwrap();

        let verification_result = RsaCryptoSystem::verify(&public_key, tampered_data, &signature);
        assert!(verification_result.is_err());
    }

    #[test]
    fn test_rsa_decrypt_wrong_key_fails() {
        let (public_key, _) = setup_keys();
        let (_, wrong_private_key) = setup_keys();
        let plaintext = b"some secret data";

        let ciphertext = RsaCryptoSystem::encrypt(&public_key, plaintext, None).unwrap();
        let result = RsaCryptoSystem::decrypt(&wrong_private_key, &ciphertext, None);

        assert!(result.is_err());
    }

    #[test]
    fn test_rsa_decrypt_tampered_ciphertext_fails() {
        let (public_key, private_key) = setup_keys();
        let plaintext = b"some original text";

        let mut ciphertext = RsaCryptoSystem::encrypt(&public_key, plaintext, None).unwrap();
        // Tamper with the ciphertext
        ciphertext[0] ^= 0xff;

        let result = RsaCryptoSystem::decrypt(&private_key, &ciphertext, None);
        assert!(result.is_err());
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
        assert!(RsaCryptoSystem::import_public_key(invalid_pem).is_err());
        assert!(RsaCryptoSystem::import_private_key(invalid_pem).is_err());
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
        assert!(result.is_err());
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

    #[test]
    fn test_rsa_key_generation_and_export_import() {
        let (public_key, private_key) = setup_keys();

        let exported_pub = RsaCryptoSystem::export_public_key(&public_key).unwrap();
        let exported_priv = RsaCryptoSystem::export_private_key(&private_key).unwrap();

        let imported_pub = RsaCryptoSystem::import_public_key(&exported_pub).unwrap();
        let imported_priv = RsaCryptoSystem::import_private_key(&exported_priv).unwrap();

        assert_eq!(public_key, imported_pub);
        assert_eq!(private_key, imported_priv);
    }

    #[test]
    fn test_rsa_key_generation_and_validation_4096() {
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
