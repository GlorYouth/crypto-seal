//!
//! 一个混合加密方案，结合了经典的RSA-PSS签名和后量子的Kyber密钥封装机制。
//!

use crate::asymmetric::systems::post_quantum::kyber::{
    KyberCryptoSystem, KyberPrivateKeyWrapper, KyberPublicKeyWrapper,
};
use crate::asymmetric::systems::traditional::rsa::{
    RsaCryptoSystem, RsaPrivateKeyWrapper, RsaPublicKeyWrapper,
};
use crate::asymmetric::traits::AsymmetricCryptographicSystem;
use crate::common::config::CryptoConfig;
use crate::common::errors::Error;
use crate::common::traits::AuthenticatedCryptoSystem;
use crate::symmetric::systems::aes_gcm::AesGcmSystem;
use aes_gcm::KeyInit;
use aes_gcm::aead::Aead;
use aes_gcm::aead::AeadCore;
#[cfg(not(feature = "chacha"))]
use aes_gcm::{Aes256Gcm, Nonce};
#[cfg(feature = "chacha")]
#[allow(unused_imports)]
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce as ChaNonce,
    aead::generic_array::GenericArray,
    aead::{Aead as ChaAead, AeadCore as ChaAeadCore, KeyInit as ChaKeyInit},
};
use rsa::RsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[cfg(feature = "parallel")]
use crate::{
    asymmetric::traits::AsymmetricParallelSystem,
    common::config::ParallelismConfig,
    symmetric::{
        systems::aes_gcm::AesGcmKey,
        traits::{SymmetricCryptographicSystem, SymmetricParallelSystem},
    },
};
#[cfg(feature = "parallel")]
use rsa::{RsaPrivateKey, pkcs8::DecodePrivateKey, traits::PublicKeyParts};

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
    type Error = Error;
    type CiphertextOutput = Vec<u8>;

    fn generate_keypair(
        config: &CryptoConfig,
    ) -> Result<(Self::PublicKey, Self::PrivateKey), Self::Error> {
        let (rsa_pk, rsa_sk) = RsaCryptoSystem::generate_keypair(config)?;
        let (kyber_pk, kyber_sk) = KyberCryptoSystem::generate_keypair(config)?;

        let public_key = Self::PublicKey {
            rsa_public_key: rsa_pk,
            kyber_public_key: kyber_pk,
        };
        let private_key = Self::PrivateKey {
            rsa_private_key: rsa_sk,
            kyber_private_key: kyber_sk,
        };

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

    /// 执行无签名的KEM-DEM加密。
    fn encrypt(
        public_key: &Self::PublicKey,
        plaintext: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<Self::CiphertextOutput, Self::Error> {
        // 1. 生成一个一次性的AES-256密钥。
        let mut aes_key = [0u8; 32];
        OsRng.fill_bytes(&mut aes_key);

        // 2. KEM: 使用Kyber公钥封装（加密）AES密钥。
        let kem_ciphertext =
            KyberCryptoSystem::encrypt(&public_key.kyber_public_key, &aes_key, None)?;

        // 3. DEM: 使用AES密钥加密实际数据。
        #[cfg(feature = "chacha")]
        let cipher = ChaCha20Poly1305::new((&aes_key).into());
        #[cfg(not(feature = "chacha"))]
        let cipher = Aes256Gcm::new(&aes_key.into());
        #[cfg(feature = "chacha")]
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        #[cfg(not(feature = "chacha"))]
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        use aes_gcm::aead::Payload;
        let payload = Payload {
            msg: plaintext,
            aad: additional_data.unwrap_or_default(),
        };
        let dem_ciphertext = cipher
            .encrypt(&nonce, payload)
            .map_err(|e| Error::Operation(format!("AEAD 加密失败: {}", e)))?;

        // 4. 组合: KEM密文长度(2字节) + KEM密文 + Nonce + DEM密文
        let kem_len = kem_ciphertext.len() as u16;
        let mut combined = Vec::new();
        combined.extend_from_slice(&kem_len.to_be_bytes());
        combined.extend_from_slice(&kem_ciphertext);
        combined.extend_from_slice(nonce.as_slice());
        combined.extend_from_slice(&dem_ciphertext);

        Ok(combined)
    }

    /// 执行无签名的KEM-DEM解密。
    fn decrypt(
        private_key: &Self::PrivateKey,
        ciphertext: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, Self::Error> {
        // 1. 解析组合密文
        if ciphertext.len() < 2 {
            return Err(Error::Format("密文过短，无法解析长度".to_string()));
        }
        let kem_len = u16::from_be_bytes(ciphertext[0..2].try_into().unwrap()) as usize;

        #[cfg(feature = "chacha")]
        let nonce_len = 12; // ChaCha20Poly1305 nonce size
        #[cfg(not(feature = "chacha"))]
        let nonce_len = 12; // AES-GCM nonce size

        let kem_end = 2 + kem_len;
        if ciphertext.len() < kem_end + nonce_len {
            return Err(Error::Format("密文格式错误，长度不足".to_string()));
        }

        let kem_part = &ciphertext[2..kem_end];
        let nonce_part = &ciphertext[kem_end..kem_end + nonce_len];
        let dem_part = &ciphertext[kem_end + nonce_len..];

        // 2. KEM: 使用Kyber私钥解封AES密钥。
        let aes_key_bytes =
            KyberCryptoSystem::decrypt(&private_key.kyber_private_key, kem_part, None)?;

        // 3. DEM: 使用AES密钥和Nonce解密数据。
        #[cfg(feature = "chacha")]
        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&aes_key_bytes));
        #[cfg(not(feature = "chacha"))]
        let cipher = Aes256Gcm::new_from_slice(&aes_key_bytes)
            .map_err(|_| Error::Key("无效的对称密钥".to_string()))?;
        #[cfg(feature = "chacha")]
        let nonce = ChaNonce::from_slice(nonce_part);
        #[cfg(not(feature = "chacha"))]
        let nonce = Nonce::from_slice(nonce_part);

        use aes_gcm::aead::Payload;
        let payload = Payload {
            msg: dem_part,
            aad: additional_data.unwrap_or_default(),
        };
        cipher
            .decrypt(&nonce, payload)
            .map_err(|_| Error::Operation("AEAD 解密或认证失败".to_string()))
    }
}

impl AuthenticatedCryptoSystem for RsaKyberCryptoSystem {
    type AuthenticatedOutput = Vec<u8>;

    fn sign(private_key: &Self::PrivateKey, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let digest = Sha256::digest(data);
        RsaCryptoSystem::sign(&private_key.rsa_private_key, &digest)
    }

    fn verify(
        public_key: &Self::PublicKey,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, Self::Error> {
        let digest = Sha256::digest(data);
        RsaCryptoSystem::verify(&public_key.rsa_public_key, &digest, signature)
    }

    fn encrypt_authenticated(
        public_key: &Self::PublicKey,
        plaintext: &[u8],
        additional_data: Option<&[u8]>,
        signer_key: Option<&Self::PrivateKey>,
    ) -> Result<Self::AuthenticatedOutput, Self::Error> {
        let encrypted_data = Self::encrypt(public_key, plaintext, additional_data)?;

        if let Some(sk) = signer_key {
            let signature = Self::sign(sk, &encrypted_data)?;
            // 组合: 签名长度(2字节) + 签名 + 加密数据
            let sig_len = signature.len() as u16;
            let mut combined = Vec::new();
            combined.extend_from_slice(&sig_len.to_be_bytes());
            combined.extend_from_slice(&signature);
            combined.extend_from_slice(&encrypted_data);
            Ok(combined)
        } else {
            // 如果没有签名密钥，只返回加密数据 (前面加个0长度的签名)
            let sig_len: u16 = 0;
            let mut combined = Vec::new();
            combined.extend_from_slice(&sig_len.to_be_bytes());
            combined.extend_from_slice(&encrypted_data);
            Ok(combined)
        }
    }

    fn decrypt_authenticated(
        private_key: &Self::PrivateKey,
        ciphertext: &[u8],
        additional_data: Option<&[u8]>,
        verifier_key: Option<&Self::PublicKey>,
    ) -> Result<Vec<u8>, Self::Error> {
        if ciphertext.len() < 2 {
            return Err(Error::Format("认证密文过短，无法解析签名长度".to_string()));
        }
        let sig_len = u16::from_be_bytes(ciphertext[0..2].try_into().unwrap()) as usize;
        let sig_end = 2 + sig_len;

        if ciphertext.len() < sig_end {
            return Err(Error::Format("认证密文格式错误，长度不足".to_string()));
        }

        let signature = &ciphertext[2..sig_end];
        let encrypted_data = &ciphertext[sig_end..];

        if let Some(verifier_key) = verifier_key {
            if sig_len > 0 {
                let is_valid = Self::verify(verifier_key, encrypted_data, signature)?;
                if !is_valid {
                    return Err(Error::Verification("签名验证失败".to_string()));
                }
            }
        } else if sig_len > 0 {
            // 如果有签名但没有提供公钥用于验证，这也是一种错误
            return Err(Error::Key("缺少用于验证签名的公钥".to_string()));
        }

        Self::decrypt(private_key, encrypted_data, additional_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::config::CryptoConfig;

    fn setup_keys() -> (RsaKyberPublicKey, RsaKyberPrivateKey) {
        let config = CryptoConfig::default();
        RsaKyberCryptoSystem::generate_keypair(&config).unwrap()
    }

    #[test]
    fn test_hybrid_roundtrip_unauthenticated() {
        let (public_key, private_key) = setup_keys();
        let plaintext = b"a very secret message";

        let ciphertext = RsaKyberCryptoSystem::encrypt(&public_key, plaintext, None).unwrap();
        let decrypted = RsaKyberCryptoSystem::decrypt(&private_key, &ciphertext, None).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_hybrid_roundtrip_authenticated() {
        let (public_key, private_key) = setup_keys();
        let plaintext = b"an even more secret message";
        let aad = b"metadata";

        let ciphertext = RsaKyberCryptoSystem::encrypt_authenticated(
            &public_key,
            plaintext,
            Some(aad),
            Some(&private_key),
        )
        .unwrap();
        let decrypted = RsaKyberCryptoSystem::decrypt_authenticated(
            &private_key,
            &ciphertext,
            Some(aad),
            Some(&public_key),
        )
        .unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_hybrid_tampered_data_fails_decryption() {
        let (public_key, private_key) = setup_keys();
        let plaintext = b"do not tamper with this";

        let mut ciphertext = RsaKyberCryptoSystem::encrypt(&public_key, plaintext, None).unwrap();
        let len = ciphertext.len();
        ciphertext[len - 5] ^= 0xff; // Tamper DEM part

        let result = RsaKyberCryptoSystem::decrypt(&private_key, &ciphertext, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_hybrid_tampered_signature_fails_verification() {
        let (public_key, private_key) = setup_keys();
        let plaintext = b"authentic message";

        let mut ciphertext = RsaKyberCryptoSystem::encrypt_authenticated(
            &public_key,
            plaintext,
            None,
            Some(&private_key),
        )
        .unwrap();

        // The signature is at the beginning, right after the 2-byte length
        if ciphertext.len() > 4 {
            ciphertext[3] ^= 0xff; // Tamper the signature
        }

        let result = RsaKyberCryptoSystem::decrypt_authenticated(
            &private_key,
            &ciphertext,
            None,
            Some(&public_key),
        );
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Verification(_)));
    }

    #[test]
    fn test_hybrid_tampered_kem_part_fails() {
        let (public_key, private_key) = setup_keys();
        let plaintext = b"secret that depends on KEM";

        let mut ciphertext = RsaKyberCryptoSystem::encrypt(&public_key, plaintext, None).unwrap();

        // KEM part is right after the 2-byte length
        if ciphertext.len() > 4 {
            ciphertext[3] ^= 0xff;
        }

        let result = RsaKyberCryptoSystem::decrypt(&private_key, &ciphertext, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_hybrid_decrypt_with_wrong_key_fails() {
        let (public_key, _) = setup_keys();
        let (_, wrong_private_key) = setup_keys();
        let plaintext = b"a secret for a specific key";

        let ciphertext = RsaKyberCryptoSystem::encrypt(&public_key, plaintext, None).unwrap();
        let result = RsaKyberCryptoSystem::decrypt(&wrong_private_key, &ciphertext, None);
        assert!(result.is_err());
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
    fn test_encrypt_decrypt_empty_plaintext() {
        let (pk, sk) = setup_keys();
        let plaintext = b"";
        let encrypted = RsaKyberCryptoSystem::encrypt(&pk, plaintext, None).unwrap();
        let decrypted = RsaKyberCryptoSystem::decrypt(&sk, &encrypted, None).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_with_empty_aad() {
        let (pk, sk) = setup_keys();
        let plaintext = b"some data";
        let aad = b"";
        let encrypted = RsaKyberCryptoSystem::encrypt(&pk, plaintext, Some(aad)).unwrap();
        let decrypted = RsaKyberCryptoSystem::decrypt(&sk, &encrypted, Some(aad)).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[cfg(feature = "async-engine")]
    mod async_tests {
        use super::*;
        use crate::asymmetric::traits::AsyncStreamingSystem;
        use crate::common::config::StreamingConfig;
        use crate::symmetric::systems::aes_gcm::AesGcmSystem;
        use std::io::Cursor;

        #[tokio::test]
        async fn test_async_streaming_roundtrip() {
            let (pk, sk) = setup_keys();
            let config = StreamingConfig::default();
            let original_data =
                b"async streaming test data that is long enough to cover multiple chunks".to_vec();

            let mut encrypted = Vec::new();
            RsaKyberCryptoSystem::encrypt_stream_async::<AesGcmSystem, _, _>(
                &pk,
                Cursor::new(original_data.clone()),
                &mut encrypted,
                &config,
                None,
            )
            .await
            .unwrap();

            let mut decrypted = Vec::new();
            RsaKyberCryptoSystem::decrypt_stream_async::<AesGcmSystem, _, _>(
                &sk,
                Cursor::new(encrypted),
                &mut decrypted,
                &config,
                None,
            )
            .await
            .unwrap();

            assert_eq!(original_data, decrypted);
        }
    }
}

#[cfg(feature = "parallel")]
impl AsymmetricParallelSystem for RsaKyberCryptoSystem {
    fn par_encrypt(
        key: &Self::PublicKey,
        plaintext: &[u8],
        parallelism_config: &ParallelismConfig,
    ) -> Result<Vec<u8>, Self::Error> {
        // 1. 生成一次性对称密钥
        let symmetric_key = AesGcmSystem::generate_key(&Default::default())?;

        // 2. 使用对称密钥并行加密数据
        let encrypted_data =
            AesGcmSystem::par_encrypt(&symmetric_key, plaintext, None, parallelism_config)?;

        // 3. 使用非对称密钥加密对称密钥
        let rsa_public_key = RsaPublicKey::from_public_key_der(&key.rsa_public_key.0)
            .map_err(|e| Error::Traditional(format!("Failed to parse RSA public key: {}", e)))?;
        let mut rng = rsa::rand_core::OsRng;
        let encrypted_symmetric_key = rsa_public_key
            .encrypt(&mut rng, rsa::Pkcs1v15Encrypt, &symmetric_key.0)
            .map_err(|e| Error::Traditional(format!("RSA encryption failed: {}", e)))?;

        // 4. 将加密后的对称密钥和加密后的数据打包在一起
        Ok([encrypted_symmetric_key, encrypted_data].concat())
    }

    fn par_decrypt(
        key: &Self::PrivateKey,
        ciphertext: &[u8],
        parallelism_config: &ParallelismConfig,
    ) -> Result<Vec<u8>, Self::Error> {
        // 1. 拆分出加密的对称密钥和加密的数据
        let rsa_private_key = RsaPrivateKey::from_pkcs8_der(&key.rsa_private_key.0)
            .map_err(|e| Error::Traditional(format!("Failed to parse RSA private key: {}", e)))?;
        let rsa_key_size = rsa_private_key.size();

        if ciphertext.len() < rsa_key_size {
            return Err(Error::Format("Ciphertext too short".to_string()));
        }
        let (encrypted_symmetric_key, encrypted_data) = ciphertext.split_at(rsa_key_size);

        // 2. 解密对称密钥
        let symmetric_key_bytes = rsa_private_key
            .decrypt(rsa::Pkcs1v15Encrypt, encrypted_symmetric_key)
            .map_err(|e| Error::Traditional(format!("RSA decryption failed: {}", e)))?;
        let symmetric_key = AesGcmKey(symmetric_key_bytes);

        // 3. 使用对称密钥并行解密数据
        AesGcmSystem::par_decrypt(&symmetric_key, encrypted_data, None, parallelism_config)
    }
}
