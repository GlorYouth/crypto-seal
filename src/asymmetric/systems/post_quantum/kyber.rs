use crate::asymmetric::traits::AsymmetricCryptographicSystem;
use crate::common::config::CryptoConfig;
use crate::common::errors::Error;
use crate::common::utils::ZeroizingVec;
use aes_gcm::aead::{AeadCore, KeyInit};
#[cfg(not(feature = "chacha"))]
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, OsRng},
};
use base64::{Engine, engine::general_purpose::STANDARD};
#[cfg(feature = "chacha")]
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce as ChaNonce,
    aead::{Aead as ChaAead, generic_array::GenericArray},
};
use pqcrypto_kyber::{kyber512, kyber768, kyber1024};
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};
#[cfg(feature = "chacha")]
use rsa::rand_core::OsRng;
use serde::{Deserialize, Serialize};

/// Kyber公钥包装器
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KyberPublicKeyWrapper(pub Vec<u8>);

/// Kyber私钥包装器
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KyberPrivateKeyWrapper(pub ZeroizingVec);

/// Kyber后量子加密系统实现
///
/// 使用Kyber进行密钥封装，然后用AES-GCM进行数据加密
pub struct KyberCryptoSystem;

// Kyber常量
const KYBER512_PUBLICKEYBYTES: usize = kyber512::public_key_bytes();
const KYBER512_SECRETKEYBYTES: usize = kyber512::secret_key_bytes();
const KYBER512_CIPHERTEXTBYTES: usize = kyber512::ciphertext_bytes();

const KYBER768_PUBLICKEYBYTES: usize = kyber768::public_key_bytes();
const KYBER768_SECRETKEYBYTES: usize = kyber768::secret_key_bytes();
const KYBER768_CIPHERTEXTBYTES: usize = kyber768::ciphertext_bytes();

const KYBER1024_PUBLICKEYBYTES: usize = kyber1024::public_key_bytes();
const KYBER1024_SECRETKEYBYTES: usize = kyber1024::secret_key_bytes();
const KYBER1024_CIPHERTEXTBYTES: usize = kyber1024::ciphertext_bytes();

impl AsymmetricCryptographicSystem for KyberCryptoSystem {
    type PublicKey = KyberPublicKeyWrapper;
    type PrivateKey = KyberPrivateKeyWrapper;
    type CiphertextOutput = Vec<u8>;
    type Error = Error;

    fn generate_keypair(
        config: &CryptoConfig,
    ) -> Result<(Self::PublicKey, Self::PrivateKey), Self::Error> {
        let (public_key_vec, private_key_vec) = match config.kyber_parameter_k {
            512 => {
                let (pk, sk) = kyber512::keypair();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
            768 => {
                let (pk, sk) = kyber768::keypair();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
            1024 => {
                let (pk, sk) = kyber1024::keypair();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
            k => return Err(Error::PostQuantum(format!("不支持的Kyber安全级别: {}", k))),
        };

        Ok((
            KyberPublicKeyWrapper(public_key_vec),
            KyberPrivateKeyWrapper(ZeroizingVec(private_key_vec)),
        ))
    }

    fn encrypt(
        public_key: &Self::PublicKey,
        plaintext: &[u8],
        _additional_data: Option<&[u8]>, // AAD在KEM+DEM中不由KEM部分直接处理
    ) -> Result<Self::CiphertextOutput, Self::Error> {
        let pk_bytes = &public_key.0;
        let (variant_id, shared_secret_bytes, kyber_ciphertext_bytes) = match pk_bytes.len() {
            KYBER512_PUBLICKEYBYTES => {
                let pk = kyber512::PublicKey::from_bytes(pk_bytes)
                    .map_err(|_| Error::PostQuantum("无效的Kyber512公钥格式".to_string()))?;
                let (ss, ct) = kyber512::encapsulate(&pk);
                (1u8, ss.as_bytes().to_vec(), ct.as_bytes().to_vec())
            }
            KYBER768_PUBLICKEYBYTES => {
                let pk = kyber768::PublicKey::from_bytes(pk_bytes)
                    .map_err(|_| Error::PostQuantum("无效的Kyber768公钥格式".to_string()))?;
                let (ss, ct) = kyber768::encapsulate(&pk);
                (2u8, ss.as_bytes().to_vec(), ct.as_bytes().to_vec())
            }
            KYBER1024_PUBLICKEYBYTES => {
                let pk = kyber1024::PublicKey::from_bytes(pk_bytes)
                    .map_err(|_| Error::PostQuantum("无效的Kyber1024公钥格式".to_string()))?;
                let (ss, ct) = kyber1024::encapsulate(&pk);
                (3u8, ss.as_bytes().to_vec(), ct.as_bytes().to_vec())
            }
            len => return Err(Error::PostQuantum(format!("无效的Kyber公钥长度: {}", len))),
        };

        // 使用共享密钥执行AEAD加密
        #[cfg(feature = "chacha")]
        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&shared_secret_bytes));
        #[cfg(not(feature = "chacha"))]
        let cipher = Aes256Gcm::new_from_slice(&shared_secret_bytes)
            .map_err(|e| Error::Operation(format!("创建AEAD加密器失败: {}", e)))?;
        #[cfg(feature = "chacha")]
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        #[cfg(not(feature = "chacha"))]
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        use aes_gcm::aead::Payload;
        let payload = Payload {
            msg: plaintext,
            aad: _additional_data.unwrap_or_default(),
        };

        // 加密数据
        let aes_ciphertext = cipher
            .encrypt(&nonce, payload)
            .map_err(|e| Error::PostQuantum(format!("AEAD加密失败: {}", e)))?;

        // 组合数据：变体ID(1字节) + kyber密文 + nonce + AEAD密文
        let mut combined = vec![variant_id];
        combined.extend_from_slice(&kyber_ciphertext_bytes);
        combined.extend_from_slice(&nonce);
        combined.extend_from_slice(&aes_ciphertext);

        Ok(combined)
    }

    fn decrypt(
        private_key: &Self::PrivateKey,
        ciphertext: &[u8],
        additional_data: Option<&[u8]>, // AAD在KEM+DEM中不由KEM部分直接处理
    ) -> Result<Vec<u8>, Self::Error> {
        if ciphertext.is_empty() {
            return Err(Error::Format("密文为空".to_string()));
        }

        // 提取变体ID
        let variant_id = ciphertext[0];
        let rest = &ciphertext[1..];

        let (kyber_ct_len, shared_secret_bytes) = match variant_id {
            1 => {
                // Kyber512
                if private_key.0.len() != KYBER512_SECRETKEYBYTES {
                    return Err(Error::Key("私钥与密文的Kyber级别不匹配".to_string()));
                }
                if rest.len() < KYBER512_CIPHERTEXTBYTES {
                    return Err(Error::Format("Kyber512密文格式无效".to_string()));
                }
                let ct_bytes = &rest[..KYBER512_CIPHERTEXTBYTES];
                let sk = kyber512::SecretKey::from_bytes(private_key.0.as_ref())
                    .map_err(|_| Error::PostQuantum("无效的Kyber512私钥格式".to_string()))?;
                let ct = kyber512::Ciphertext::from_bytes(ct_bytes)
                    .map_err(|_| Error::PostQuantum("无效的Kyber512密文格式".to_string()))?;
                let ss = kyber512::decapsulate(&ct, &sk);
                (KYBER512_CIPHERTEXTBYTES, ss.as_bytes().to_vec())
            }
            2 => {
                // Kyber768
                if private_key.0.len() != KYBER768_SECRETKEYBYTES {
                    return Err(Error::Key("私钥与密文的Kyber级别不匹配".to_string()));
                }
                if rest.len() < KYBER768_CIPHERTEXTBYTES {
                    return Err(Error::Format("Kyber768密文格式无效".to_string()));
                }
                let ct_bytes = &rest[..KYBER768_CIPHERTEXTBYTES];
                let sk = kyber768::SecretKey::from_bytes(private_key.0.as_ref())
                    .map_err(|_| Error::PostQuantum("无效的Kyber768私钥格式".to_string()))?;
                let ct = kyber768::Ciphertext::from_bytes(ct_bytes)
                    .map_err(|_| Error::PostQuantum("无效的Kyber768密文格式".to_string()))?;
                let ss = kyber768::decapsulate(&ct, &sk);
                (KYBER768_CIPHERTEXTBYTES, ss.as_bytes().to_vec())
            }
            3 => {
                // Kyber1024
                if private_key.0.len() != KYBER1024_SECRETKEYBYTES {
                    return Err(Error::Key("私钥与密文的Kyber级别不匹配".to_string()));
                }
                if rest.len() < KYBER1024_CIPHERTEXTBYTES {
                    return Err(Error::Format("Kyber1024密文格式无效".to_string()));
                }
                let ct_bytes = &rest[..KYBER1024_CIPHERTEXTBYTES];
                let sk = kyber1024::SecretKey::from_bytes(private_key.0.as_ref())
                    .map_err(|_| Error::PostQuantum("无效的Kyber1024私钥格式".to_string()))?;
                let ct = kyber1024::Ciphertext::from_bytes(ct_bytes)
                    .map_err(|_| Error::PostQuantum("无效的Kyber1024密文格式".to_string()))?;
                let ss = kyber1024::decapsulate(&ct, &sk);
                (KYBER1024_CIPHERTEXTBYTES, ss.as_bytes().to_vec())
            }
            _ => return Err(Error::PostQuantum("未知的Kyber变体ID".to_string())),
        };

        // 提取nonce和AEAD密文
        if rest.len() < kyber_ct_len + 12 {
            return Err(Error::Format("密文缺少nonce或主体部分".to_string()));
        }
        let nonce_bytes = &rest[kyber_ct_len..kyber_ct_len + 12];
        let aes_ciphertext = &rest[kyber_ct_len + 12..];

        // 使用共享密钥执行AEAD解密
        #[cfg(feature = "chacha")]
        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&shared_secret_bytes));
        #[cfg(not(feature = "chacha"))]
        let cipher = Aes256Gcm::new_from_slice(&shared_secret_bytes)
            .map_err(|e| Error::Operation(format!("创建AEAD解密器失败: {}", e)))?;
        #[cfg(feature = "chacha")]
        let nonce = ChaNonce::from_slice(nonce_bytes);
        #[cfg(not(feature = "chacha"))]
        let nonce = Nonce::from_slice(nonce_bytes);

        use aes_gcm::aead::Payload;
        let payload = Payload {
            msg: aes_ciphertext,
            aad: additional_data.unwrap_or_default(),
        };

        cipher
            .decrypt(&nonce, payload)
            .map_err(|e| Error::PostQuantum(format!("AEAD解密失败: {}", e)))
    }

    fn export_public_key(public_key: &Self::PublicKey) -> Result<String, Self::Error> {
        Ok(STANDARD.encode(&public_key.0))
    }

    fn export_private_key(private_key: &Self::PrivateKey) -> Result<String, Self::Error> {
        Ok(STANDARD.encode(private_key.0.as_ref()))
    }

    fn import_public_key(key_data: &str) -> Result<Self::PublicKey, Self::Error> {
        let decoded = STANDARD.decode(key_data)?;

        match decoded.len() {
            KYBER512_PUBLICKEYBYTES | KYBER768_PUBLICKEYBYTES | KYBER1024_PUBLICKEYBYTES => {}
            len => {
                return Err(Error::Key(format!(
                    "无效的Kyber公钥大小: {}字节, 预期值为 {}, {} 或 {}",
                    len, KYBER512_PUBLICKEYBYTES, KYBER768_PUBLICKEYBYTES, KYBER1024_PUBLICKEYBYTES
                )));
            }
        }

        Ok(KyberPublicKeyWrapper(decoded))
    }

    fn import_private_key(key_data: &str) -> Result<Self::PrivateKey, Self::Error> {
        let decoded = STANDARD.decode(key_data)?;

        match decoded.len() {
            KYBER512_SECRETKEYBYTES | KYBER768_SECRETKEYBYTES | KYBER1024_SECRETKEYBYTES => {}
            len => {
                return Err(Error::Key(format!(
                    "无效的Kyber私钥大小: {}字节, 预期值为 {}, {} 或 {}",
                    len, KYBER512_SECRETKEYBYTES, KYBER768_SECRETKEYBYTES, KYBER1024_SECRETKEYBYTES
                )));
            }
        }

        Ok(KyberPrivateKeyWrapper(ZeroizingVec(decoded)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::config::CryptoConfig;

    fn setup_keys(k: usize) -> (KyberPublicKeyWrapper, KyberPrivateKeyWrapper) {
        let config = CryptoConfig {
            kyber_parameter_k: k,
            ..Default::default()
        };
        KyberCryptoSystem::generate_keypair(&config).unwrap()
    }

    #[test]
    fn test_kyber_roundtrip_all_levels() {
        for &k in &[512, 768, 1024] {
            let (public_key, private_key) = setup_keys(k);
            let plaintext = b"some secret data";

            let ciphertext = KyberCryptoSystem::encrypt(&public_key, plaintext, None).unwrap();
            let decrypted = KyberCryptoSystem::decrypt(&private_key, &ciphertext, None).unwrap();

            assert_eq!(plaintext, decrypted.as_slice());
        }
    }

    #[test]
    fn test_kyber_with_aad_roundtrip() {
        let (public_key, private_key) = setup_keys(768);
        let plaintext = b"some secret data with aad";
        let aad = b"additional authenticated data";

        let ciphertext = KyberCryptoSystem::encrypt(&public_key, plaintext, Some(aad)).unwrap();
        let decrypted = KyberCryptoSystem::decrypt(&private_key, &ciphertext, Some(aad)).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_kyber_wrong_aad_fails() {
        let (public_key, private_key) = setup_keys(768);
        let plaintext = b"some secret data";
        let aad = b"correct aad";
        let wrong_aad = b"wrong aad";

        let ciphertext = KyberCryptoSystem::encrypt(&public_key, plaintext, Some(aad)).unwrap();
        let result = KyberCryptoSystem::decrypt(&private_key, &ciphertext, Some(wrong_aad));

        assert!(result.is_err());
    }

    #[test]
    fn test_kyber_tampered_ciphertext_fails() {
        let (public_key, private_key) = setup_keys(768);
        let plaintext = b"some important data";

        let mut ciphertext = KyberCryptoSystem::encrypt(&public_key, plaintext, None).unwrap();

        // Tamper
        let len = ciphertext.len();
        if len > 0 {
            ciphertext[len / 2] ^= 0xff;
        }

        let result = KyberCryptoSystem::decrypt(&private_key, &ciphertext, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_kyber_decrypt_wrong_key_fails() {
        let (public_key, _) = setup_keys(768);
        let (_, wrong_private_key) = setup_keys(768);
        let plaintext = b"a secret only for the right key";

        let ciphertext = KyberCryptoSystem::encrypt(&public_key, plaintext, None).unwrap();
        let result = KyberCryptoSystem::decrypt(&wrong_private_key, &ciphertext, None);

        assert!(result.is_err());
    }

    #[test]
    fn test_kyber_decrypt_with_different_key_of_same_level_fails() {
        let (pk1, _) = setup_keys(768);
        let (_, sk2) = setup_keys(768);
        let plaintext = b"test message";
        let ciphertext = KyberCryptoSystem::encrypt(&pk1, plaintext, None).unwrap();
        let result = KyberCryptoSystem::decrypt(&sk2, &ciphertext, None);
        assert!(
            result.is_err(),
            "Decryption should fail with a different key"
        );
    }

    #[test]
    fn test_ciphertext_uniqueness() {
        let (public_key, _) = setup_keys(768);
        let plaintext = b"this should result in different ciphertexts";
        let ciphertext1 = KyberCryptoSystem::encrypt(&public_key, plaintext, None).unwrap();
        let ciphertext2 = KyberCryptoSystem::encrypt(&public_key, plaintext, None).unwrap();
        assert_ne!(
            ciphertext1, ciphertext2,
            "Two encryptions of the same plaintext should not be identical"
        );
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
            let (pk, sk) = setup_keys(512);
            let config = StreamingConfig::default();
            let original_data = b"This is a test for Kyber async streaming.".to_vec();

            // Encrypt
            let mut encrypted_dest = Vec::new();
            KyberCryptoSystem::encrypt_stream_async::<AesGcmSystem, _, _>(
                &pk,
                Cursor::new(original_data.clone()),
                &mut encrypted_dest,
                &config,
                None,
            )
            .await
            .unwrap();

            // Decrypt
            let mut decrypted_dest = Vec::new();
            KyberCryptoSystem::decrypt_stream_async::<AesGcmSystem, _, _>(
                &sk,
                Cursor::new(encrypted_dest),
                &mut decrypted_dest,
                &config,
                None,
            )
            .await
            .unwrap();

            assert_eq!(original_data, decrypted_dest);
        }
    }
}
