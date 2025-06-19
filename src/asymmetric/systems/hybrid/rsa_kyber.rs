//!
//! 一个混合加密方案，结合了经典的RSA-PSS签名和后量子的Kyber密钥封装机制。
//!

use crate::asymmetric::systems::post_quantum::kyber::{
    KyberCryptoSystem, KyberPrivateKeyWrapper, KyberPublicKeyWrapper,
};
use crate::asymmetric::systems::traditional::rsa::{
    RsaCryptoSystem, RsaPrivateKeyWrapper, RsaPublicKeyWrapper,
};
use crate::common::config::CryptoConfig;
use crate::common::errors::Error;
use crate::common::traits::AuthenticatedCryptoSystem;
use crate::common::utils::{Base64String, from_base64, to_base64};
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
use rsa::rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use crate::asymmetric::traits::{
    AsymmetricCryptographicSystem
};
use crate::symmetric::systems::aes_gcm::AesGcmSystem;
use rsa::pkcs8::DecodePublicKey;
use rsa::RsaPublicKey;

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
use rsa::{pkcs8::DecodePrivateKey, traits::PublicKeyParts, RsaPrivateKey};

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
    type CiphertextOutput = Base64String;

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

        // 4. 将 KEM 密文的 Base64 ASCII 与 DEM 密文及 Nonce 组合
        let kem_str = kem_ciphertext.to_string();
        let combined = [
            kem_str.as_bytes(),
            b"::",
            nonce.as_slice(),
            b"::",
            &dem_ciphertext,
        ]
        .concat();

        Ok(Base64String::from(combined))
    }

    /// 执行无签名的KEM-DEM解密。
    fn decrypt(
        private_key: &Self::PrivateKey,
        ciphertext: &str,
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, Self::Error> {
        // 解码Base64得到原始字节
        let combined = from_base64(ciphertext)?;
        let delim = b"::";
        // 查找第一个分隔符，将KEM部分与Nonce部分分开
        let first_pos = combined
            .windows(delim.len())
            .position(|window| window == delim)
            .ok_or_else(|| Error::Format("密文格式错误：缺少KEM-Nonce分隔符".to_string()))?;
        let kem_part = &combined[..first_pos];
        // 跳过第一个分隔符
        let rest = &combined[first_pos + delim.len()..];
        // 查找第二个分隔符，将Nonce与AES密文分开
        let second_pos = rest
            .windows(delim.len())
            .position(|window| window == delim)
            .ok_or_else(|| Error::Format("密文格式错误：缺少Nonce-DEM分隔符".to_string()))?;
        let nonce_part = &rest[..second_pos];
        let dem_part = &rest[second_pos + delim.len()..];

        // 1. KEM: 使用Kyber私钥解封AES密钥。
        let kem_ciphertext_str = String::from_utf8(kem_part.to_vec())
            .map_err(|e| Error::Format(format!("无效的PQ Base64密文: {}", e)))?;
        let aes_key_bytes =
            KyberCryptoSystem::decrypt(&private_key.kyber_private_key, &kem_ciphertext_str, None)?;

        // 2. DEM: 使用AES密钥和Nonce解密数据。
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
    type AuthenticatedOutput = Base64String;

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
        let encrypted_data_b64 = Self::encrypt(public_key, plaintext, additional_data)?;

        if let Some(sk) = signer_key {
            let signature = Self::sign(sk, encrypted_data_b64.as_bytes())?;
            let combined = [
                encrypted_data_b64.as_bytes(),
                b"::",
                to_base64(&signature).as_bytes(),
            ]
            .concat();
            Ok(Base64String::from(combined))
        } else {
            // 如果没有签名密钥，只返回加密数据
            Ok(encrypted_data_b64)
        }
    }

    fn decrypt_authenticated(
        private_key: &Self::PrivateKey,
        ciphertext: &str,
        additional_data: Option<&[u8]>,
        verifier_key: Option<&Self::PublicKey>,
    ) -> Result<Vec<u8>, Self::Error> {
        // 解码Base64以获取原始字节
        let combined = from_base64(ciphertext)?;
        let delim = b"::";
        // 寻找最后一个 "::" 以分离签名（如果存在）
        let split_pos_opt = combined
            .windows(delim.len())
            .rposition(|window| window == delim);
        // 拆分为加密数据和可选的签名部分
        let (encrypted_data_raw, signature_ascii_opt) = if let Some(pos) = split_pos_opt {
            (&combined[..pos], Some(&combined[pos + delim.len()..]))
        } else {
            (&combined[..], None)
        };
        // 验证签名（如果同时提供了验证密钥和签名）
        if let (Some(sig_ascii_bytes), Some(pk)) = (signature_ascii_opt, verifier_key) {
            // 将签名的ASCII Base64转为原始签名字节，如有任何错误，则视为签名验证失败
            let sig_str = std::str::from_utf8(sig_ascii_bytes)
                .map_err(|_| Error::Operation("签名验证失败".to_string()))?;
            let signature_bytes =
                from_base64(sig_str).map_err(|_| Error::Operation("签名验证失败".to_string()))?;
            if !Self::verify(pk, encrypted_data_raw, &signature_bytes)? {
                return Err(Error::Operation("签名验证失败".to_string()));
            }
        }
        // 将原始加密数据重新Base64编码后解密
        let encrypted_data_b64 = to_base64(encrypted_data_raw);
        Self::decrypt(private_key, &encrypted_data_b64, additional_data)
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
        let (pk, sk) = setup_keys();
        let plaintext = b"test message";
        let encrypted = RsaKyberCryptoSystem::encrypt(&pk, plaintext, None).unwrap();
        let decrypted = RsaKyberCryptoSystem::decrypt(&sk, &encrypted.to_string(), None).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_hybrid_roundtrip_authenticated() {
        let (pk, sk) = setup_keys();
        let plaintext = b"authenticated test message";
        let encrypted =
            RsaKyberCryptoSystem::encrypt_authenticated(&pk, plaintext, None, Some(&sk)).unwrap();
        let decrypted = RsaKyberCryptoSystem::decrypt_authenticated(
            &sk,
            &encrypted.to_string(),
            None,
            Some(&pk),
        )
        .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_hybrid_tampered_data_fails_decryption() {
        let (pk, sk) = setup_keys();
        let plaintext = b"some secret data";
        let encrypted_b64 = RsaKyberCryptoSystem::encrypt(&pk, plaintext, None).unwrap();

        let mut encrypted_bytes = from_base64(&encrypted_b64.to_string()).unwrap();
        let len = encrypted_bytes.len();
        encrypted_bytes[len - 5] ^= 0xff; // Tamper with DEM ciphertext
        let tampered_b64 = to_base64(&encrypted_bytes);

        let result = RsaKyberCryptoSystem::decrypt(&sk, &tampered_b64, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_hybrid_tampered_signature_fails_verification() {
        let (pk, sk) = setup_keys();
        let plaintext = b"another authenticated message";
        let encrypted_b64 =
            RsaKyberCryptoSystem::encrypt_authenticated(&pk, plaintext, None, Some(&sk)).unwrap();

        let mut encrypted_bytes = from_base64(&encrypted_b64.to_string()).unwrap();
        if let Some(pos) = encrypted_bytes.windows(2).rposition(|w| w == b"::") {
            let sig_part_index = pos + 2;
            if sig_part_index + 5 < encrypted_bytes.len() {
                encrypted_bytes[sig_part_index + 5] ^= 0xff; // Tamper with signature
            }
        }
        let tampered_b64 = to_base64(&encrypted_bytes);

        let result =
            RsaKyberCryptoSystem::decrypt_authenticated(&sk, &tampered_b64, None, Some(&pk));
        assert!(result.is_err());
    }

    #[test]
    fn test_hybrid_tampered_kem_part_fails() {
        let (pk, sk) = setup_keys();
        let plaintext = b"yet another secret";
        let encrypted_b64 = RsaKyberCryptoSystem::encrypt(&pk, plaintext, None).unwrap();

        let mut encrypted_bytes = from_base64(&encrypted_b64.to_string()).unwrap();
        encrypted_bytes[10] ^= 0xff; // Tamper KEM part
        let tampered_b64 = to_base64(&encrypted_bytes);

        let result = RsaKyberCryptoSystem::decrypt(&sk, &tampered_b64, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_hybrid_decrypt_with_wrong_key_fails() {
        let (pk, _) = setup_keys();
        let (_, sk2) = setup_keys();
        let plaintext = b"secret for wrong key test";
        let encrypted = RsaKyberCryptoSystem::encrypt(&pk, plaintext, None).unwrap();
        let result = RsaKyberCryptoSystem::decrypt(&sk2, &encrypted.to_string(), None);
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
        let decrypted = RsaKyberCryptoSystem::decrypt(&sk, &encrypted.to_string(), None).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_with_empty_aad() {
        let (pk, sk) = setup_keys();
        let plaintext = b"some data";
        let aad = b"";
        let encrypted = RsaKyberCryptoSystem::encrypt(&pk, plaintext, Some(aad)).unwrap();
        let decrypted =
            RsaKyberCryptoSystem::decrypt(&sk, &encrypted.to_string(), Some(aad)).unwrap();
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
        let rsa_public_key =
            RsaPublicKey::from_public_key_der(&key.rsa_public_key.0).map_err(|e| {
                Error::Traditional(format!("Failed to parse RSA public key: {}", e))
            })?;
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
