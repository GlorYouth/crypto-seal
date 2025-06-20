use crate::asymmetric::traits::AsymmetricCryptographicSystem;
use crate::common::config::CryptoConfig;
use crate::common::utils::ZeroizingVec;
use base64::{Engine, engine::general_purpose::STANDARD};
use pqcrypto_kyber::{kyber512, kyber768, kyber1024};
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Kyber 系统专用的错误类型
#[derive(Error, Debug)]
pub enum KyberSystemError {
    #[error("Unsupported Kyber security level: {0}")]
    UnsupportedSecurityLevel(usize),

    #[error("Invalid public key format or size")]
    InvalidPublicKey,

    #[error("Invalid private key format or size")]
    InvalidPrivateKey,

    #[error("Invalid ciphertext format or size")]
    InvalidCiphertext,

    #[error("Invalid key size for import: expected one of {expected:?}, got {actual}")]
    InvalidKeySize { expected: Vec<usize>, actual: usize },

    #[error("Mismatched plaintext length: expected {expected}, got {actual}")]
    MismatchedPlaintextLength { expected: usize, actual: usize },

    #[error("Private key does not match the security level of the ciphertext")]
    KeyMismatch,

    #[error("Decryption failed: ciphertext verification failed")]
    DecryptionFailed,

    #[error("This operation is not supported by Kyber: {0}")]
    UnsupportedOperation(String),

    #[error("Base64 decoding failed: {0}")]
    Base64Decode(#[from] base64::DecodeError),
}

/// Kyber公钥包装器
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KyberPublicKeyWrapper(pub Vec<u8>);

/// Kyber私钥包装器
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KyberPrivateKeyWrapper(pub ZeroizingVec);

/// Kyber 签名包装器 (占位符)
/// Kyber 是 KEM，不直接提供签名功能。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KyberSignature(Vec<u8>);

impl AsRef<[u8]> for KyberSignature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Kyber后量子加密系统实现
///
/// 使用Kyber KEM实现非对称加密。
pub struct KyberCryptoSystem;

// Kyber常量
const KYBER512_PUBLICKEYBYTES: usize = kyber512::public_key_bytes();
const KYBER512_SECRETKEYBYTES: usize = kyber512::secret_key_bytes();
const KYBER512_CIPHERTEXTBYTES: usize = kyber512::ciphertext_bytes();
const KYBER512_SHAREDKEYBYTES: usize = kyber512::shared_secret_bytes();

const KYBER768_PUBLICKEYBYTES: usize = kyber768::public_key_bytes();
const KYBER768_SECRETKEYBYTES: usize = kyber768::secret_key_bytes();
const KYBER768_CIPHERTEXTBYTES: usize = kyber768::ciphertext_bytes();
const KYBER768_SHAREDKEYBYTES: usize = kyber768::shared_secret_bytes();

const KYBER1024_PUBLICKEYBYTES: usize = kyber1024::public_key_bytes();
const KYBER1024_SECRETKEYBYTES: usize = kyber1024::secret_key_bytes();
const KYBER1024_CIPHERTEXTBYTES: usize = kyber1024::ciphertext_bytes();
const KYBER1024_SHAREDKEYBYTES: usize = kyber1024::shared_secret_bytes();

impl AsymmetricCryptographicSystem for KyberCryptoSystem {
    type PublicKey = KyberPublicKeyWrapper;
    type PrivateKey = KyberPrivateKeyWrapper;
    type Signature = KyberSignature;
    type Error = KyberSystemError;

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
            k => return Err(KyberSystemError::UnsupportedSecurityLevel(k)),
        };

        Ok((
            KyberPublicKeyWrapper(public_key_vec),
            KyberPrivateKeyWrapper(ZeroizingVec(private_key_vec)),
        ))
    }

    fn encrypt(
        public_key: &Self::PublicKey,
        plaintext: &[u8],
        _additional_data: Option<&[u8]>, // AAD由SealEngine中的对称密码处理
    ) -> Result<Vec<u8>, Self::Error> {
        let pk_bytes = &public_key.0;
        let (variant_id, kyber_ciphertext_bytes, shared_secret_bytes) = match pk_bytes.len() {
            KYBER512_PUBLICKEYBYTES => {
                if plaintext.len() != KYBER512_SHAREDKEYBYTES {
                    return Err(KyberSystemError::MismatchedPlaintextLength {
                        expected: KYBER512_SHAREDKEYBYTES,
                        actual: plaintext.len(),
                    });
                }
                let pk = kyber512::PublicKey::from_bytes(pk_bytes)
                    .map_err(|_| KyberSystemError::InvalidPublicKey)?;
                let (ss, ct) = kyber512::encapsulate(&pk);
                (1u8, ct.as_bytes().to_vec(), ss.as_bytes().to_vec())
            }
            KYBER768_PUBLICKEYBYTES => {
                if plaintext.len() != KYBER768_SHAREDKEYBYTES {
                    return Err(KyberSystemError::MismatchedPlaintextLength {
                        expected: KYBER768_SHAREDKEYBYTES,
                        actual: plaintext.len(),
                    });
                }
                let pk = kyber768::PublicKey::from_bytes(pk_bytes)
                    .map_err(|_| KyberSystemError::InvalidPublicKey)?;
                let (ss, ct) = kyber768::encapsulate(&pk);
                (2u8, ct.as_bytes().to_vec(), ss.as_bytes().to_vec())
            }
            KYBER1024_PUBLICKEYBYTES => {
                if plaintext.len() != KYBER1024_SHAREDKEYBYTES {
                    return Err(KyberSystemError::MismatchedPlaintextLength {
                        expected: KYBER1024_SHAREDKEYBYTES,
                        actual: plaintext.len(),
                    });
                }
                let pk = kyber1024::PublicKey::from_bytes(pk_bytes)
                    .map_err(|_| KyberSystemError::InvalidPublicKey)?;
                let (ss, ct) = kyber1024::encapsulate(&pk);
                (3u8, ct.as_bytes().to_vec(), ss.as_bytes().to_vec())
            }
            _ => return Err(KyberSystemError::InvalidPublicKey),
        };

        // 使用共享密钥的哈希对DEK进行XOR加密
        let mut hasher = Sha256::new();
        hasher.update(&shared_secret_bytes);
        let key_hash = hasher.finalize();

        let mut encrypted_dek = plaintext.to_vec();
        for (i, byte) in key_hash.iter().take(encrypted_dek.len()).enumerate() {
            encrypted_dek[i] ^= byte;
        }

        // 组合输出: [变体ID(1)][Kyber密文][XOR加密后的DEK][原始共享密钥]
        let mut combined = vec![variant_id];
        combined.extend_from_slice(&kyber_ciphertext_bytes);
        combined.extend_from_slice(&encrypted_dek);
        combined.extend_from_slice(&shared_secret_bytes);

        Ok(combined)
    }

    fn decrypt(
        private_key: &Self::PrivateKey,
        ciphertext: &[u8],
        _additional_data: Option<&[u8]>, // AAD由SealEngine中的对称密码处理
    ) -> Result<Vec<u8>, Self::Error> {
        if ciphertext.len() < 2 {
            // Must have at least variant ID and some data
            return Err(KyberSystemError::InvalidCiphertext);
        }

        // 提取变体ID
        let variant_id = ciphertext[0];
        let rest = &ciphertext[1..];

        let (kyber_ct_len, decapsulated_ss_bytes, shared_key_len) = match variant_id {
            1 => {
                // Kyber512
                if private_key.0.len() != KYBER512_SECRETKEYBYTES {
                    return Err(KyberSystemError::KeyMismatch);
                }
                if rest.len() < KYBER512_CIPHERTEXTBYTES + KYBER512_SHAREDKEYBYTES {
                    return Err(KyberSystemError::InvalidCiphertext);
                }
                let ct_bytes = &rest[..KYBER512_CIPHERTEXTBYTES];
                let sk = kyber512::SecretKey::from_bytes(private_key.0.as_ref())
                    .map_err(|_| KyberSystemError::InvalidPrivateKey)?;
                let ct = kyber512::Ciphertext::from_bytes(ct_bytes)
                    .map_err(|_| KyberSystemError::InvalidCiphertext)?;
                let ss = kyber512::decapsulate(&ct, &sk);
                (
                    KYBER512_CIPHERTEXTBYTES,
                    ss.as_bytes().to_vec(),
                    KYBER512_SHAREDKEYBYTES,
                )
            }
            2 => {
                // Kyber768
                if private_key.0.len() != KYBER768_SECRETKEYBYTES {
                    return Err(KyberSystemError::KeyMismatch);
                }
                if rest.len() < KYBER768_CIPHERTEXTBYTES + KYBER768_SHAREDKEYBYTES {
                    return Err(KyberSystemError::InvalidCiphertext);
                }
                let ct_bytes = &rest[..KYBER768_CIPHERTEXTBYTES];
                let sk = kyber768::SecretKey::from_bytes(private_key.0.as_ref())
                    .map_err(|_| KyberSystemError::InvalidPrivateKey)?;
                let ct = kyber768::Ciphertext::from_bytes(ct_bytes)
                    .map_err(|_| KyberSystemError::InvalidCiphertext)?;
                let ss = kyber768::decapsulate(&ct, &sk);
                (
                    KYBER768_CIPHERTEXTBYTES,
                    ss.as_bytes().to_vec(),
                    KYBER768_SHAREDKEYBYTES,
                )
            }
            3 => {
                // Kyber1024
                if private_key.0.len() != KYBER1024_SECRETKEYBYTES {
                    return Err(KyberSystemError::KeyMismatch);
                }
                if rest.len() < KYBER1024_CIPHERTEXTBYTES + KYBER1024_SHAREDKEYBYTES {
                    return Err(KyberSystemError::InvalidCiphertext);
                }
                let ct_bytes = &rest[..KYBER1024_CIPHERTEXTBYTES];
                let sk = kyber1024::SecretKey::from_bytes(private_key.0.as_ref())
                    .map_err(|_| KyberSystemError::InvalidPrivateKey)?;
                let ct = kyber1024::Ciphertext::from_bytes(ct_bytes)
                    .map_err(|_| KyberSystemError::InvalidCiphertext)?;
                let ss = kyber1024::decapsulate(&ct, &sk);
                (
                    KYBER1024_CIPHERTEXTBYTES,
                    ss.as_bytes().to_vec(),
                    KYBER1024_SHAREDKEYBYTES,
                )
            }
            _ => return Err(KyberSystemError::InvalidCiphertext),
        };

        // 验证共享密钥
        let expected_ss_start = kyber_ct_len + shared_key_len;
        if rest.len() < expected_ss_start {
            return Err(KyberSystemError::InvalidCiphertext);
        }
        let original_ss_bytes = &rest[expected_ss_start..];

        if original_ss_bytes != decapsulated_ss_bytes.as_slice() {
            return Err(KyberSystemError::DecryptionFailed);
        }

        // 提取XOR加密后的DEK
        let encrypted_dek_part = &rest[kyber_ct_len..expected_ss_start];
        if encrypted_dek_part.len() != shared_key_len {
            return Err(KyberSystemError::InvalidCiphertext);
        }
        let mut dek = encrypted_dek_part.to_vec();

        // 使用共享密钥的哈希对DEK进行XOR解密
        let mut hasher = Sha256::new();
        hasher.update(&decapsulated_ss_bytes);
        let key_hash = hasher.finalize();

        for (i, byte) in key_hash.iter().take(dek.len()).enumerate() {
            dek[i] ^= byte;
        }

        Ok(dek)
    }

    fn sign(
        _private_key: &Self::PrivateKey,
        _message: &[u8],
    ) -> Result<Self::Signature, Self::Error> {
        Err(KyberSystemError::UnsupportedOperation(
            "Kyber is a Key Encapsulation Mechanism and does not support signing.".to_string(),
        ))
    }

    fn verify(
        _public_key: &Self::PublicKey,
        _message: &[u8],
        _signature: &Self::Signature,
    ) -> Result<(), Self::Error> {
        Err(KyberSystemError::UnsupportedOperation(
            "Kyber is a Key Encapsulation Mechanism and does not support verification.".to_string(),
        ))
    }

    fn export_public_key(public_key: &Self::PublicKey) -> Result<String, Self::Error> {
        Ok(STANDARD.encode(&public_key.0))
    }

    fn export_private_key(private_key: &Self::PrivateKey) -> Result<String, Self::Error> {
        Ok(STANDARD.encode(private_key.0.as_ref()))
    }

    fn import_public_key(key_data: &str) -> Result<Self::PublicKey, Self::Error> {
        let decoded = STANDARD.decode(key_data)?;
        let valid_lens = vec![
            KYBER512_PUBLICKEYBYTES,
            KYBER768_PUBLICKEYBYTES,
            KYBER1024_PUBLICKEYBYTES,
        ];

        if !valid_lens.contains(&decoded.len()) {
            return Err(KyberSystemError::InvalidKeySize {
                expected: valid_lens,
                actual: decoded.len(),
            });
        }

        Ok(KyberPublicKeyWrapper(decoded))
    }

    fn import_private_key(key_data: &str) -> Result<Self::PrivateKey, Self::Error> {
        let decoded = STANDARD.decode(key_data)?;
        let valid_lens = vec![
            KYBER512_SECRETKEYBYTES,
            KYBER768_SECRETKEYBYTES,
            KYBER1024_SECRETKEYBYTES,
        ];

        if !valid_lens.contains(&decoded.len()) {
            return Err(KyberSystemError::InvalidKeySize {
                expected: valid_lens,
                actual: decoded.len(),
            });
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

    // All Kyber shared secrets are 32 bytes long
    const DEK_SIZE: usize = 32;

    #[test]
    fn test_kyber_roundtrip_all_levels() {
        for &k in &[512, 768, 1024] {
            let (public_key, private_key) = setup_keys(k);
            let dek = vec![42u8; DEK_SIZE];

            let ciphertext = KyberCryptoSystem::encrypt(&public_key, &dek, None).unwrap();
            let decrypted = KyberCryptoSystem::decrypt(&private_key, &ciphertext, None).unwrap();

            assert_eq!(dek, decrypted);
        }
    }

    #[test]
    fn test_kyber_tampered_ciphertext_fails() {
        let (public_key, private_key) = setup_keys(768);
        let dek = vec![42u8; DEK_SIZE];

        let mut ciphertext = KyberCryptoSystem::encrypt(&public_key, &dek, None).unwrap();

        // Tamper
        let len = ciphertext.len();
        if len > 0 {
            ciphertext[len / 2] ^= 0xff;
        }

        let result = KyberCryptoSystem::decrypt(&private_key, &ciphertext, None);
        assert!(matches!(result, Err(KyberSystemError::DecryptionFailed)));
    }

    #[test]
    fn test_kyber_decrypt_wrong_key_fails() {
        let (public_key, _) = setup_keys(768);
        let (_, wrong_private_key) = setup_keys(768);
        let dek = vec![42u8; DEK_SIZE];

        let ciphertext = KyberCryptoSystem::encrypt(&public_key, &dek, None).unwrap();
        let result = KyberCryptoSystem::decrypt(&wrong_private_key, &ciphertext, None);

        assert!(matches!(result, Err(KyberSystemError::DecryptionFailed)));
    }

    #[test]
    fn test_ciphertext_uniqueness() {
        let (public_key, _) = setup_keys(768);
        let dek = vec![42u8; DEK_SIZE];
        let ciphertext1 = KyberCryptoSystem::encrypt(&public_key, &dek, None).unwrap();
        let ciphertext2 = KyberCryptoSystem::encrypt(&public_key, &dek, None).unwrap();
        assert_ne!(
            ciphertext1, ciphertext2,
            "Two encryptions of the same plaintext should not be identical due to KEM randomization"
        );
    }

    #[test]
    fn test_kyber_signing_is_not_supported() {
        let (public_key, private_key) = setup_keys(768);
        let message = b"test message";

        let sign_result = KyberCryptoSystem::sign(&private_key, message);
        assert!(matches!(
            sign_result,
            Err(KyberSystemError::UnsupportedOperation(_))
        ));

        // 即使签名从未被创建，也测试验证函数
        let dummy_signature = KyberSignature(vec![]);
        let verify_result = KyberCryptoSystem::verify(&public_key, message, &dummy_signature);
        assert!(matches!(
            verify_result,
            Err(KyberSystemError::UnsupportedOperation(_))
        ));
    }

    #[test]
    fn test_import_invalid_key_size() {
        let bad_key_data = STANDARD.encode([0u8; 100]);
        let pub_result = KyberCryptoSystem::import_public_key(&bad_key_data);
        assert!(matches!(
            pub_result,
            Err(KyberSystemError::InvalidKeySize { .. })
        ));

        let priv_result = KyberCryptoSystem::import_private_key(&bad_key_data);
        assert!(matches!(
            priv_result,
            Err(KyberSystemError::InvalidKeySize { .. })
        ));
    }

    #[test]
    fn test_mismatched_plaintext_length() {
        let (public_key, _) = setup_keys(512);
        let dek = vec![42u8; 16]; // Incorrect length
        let result = KyberCryptoSystem::encrypt(&public_key, &dek, None);
        assert!(matches!(
            result,
            Err(KyberSystemError::MismatchedPlaintextLength { .. })
        ));
    }
}
