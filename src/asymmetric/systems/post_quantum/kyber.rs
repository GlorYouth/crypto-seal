use crate::asymmetric::traits::AsymmetricCryptographicSystem;
use crate::common::config::CryptoConfig;
use crate::common::errors::Error;
use crate::common::utils::ZeroizingVec;
use base64::{engine::general_purpose::STANDARD, Engine};
use pqcrypto_kyber::{kyber1024, kyber512, kyber768};
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};
use serde::{Deserialize, Serialize};

/// Kyber公钥包装器
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KyberPublicKeyWrapper(pub Vec<u8>);

/// Kyber私钥包装器
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KyberPrivateKeyWrapper(pub ZeroizingVec);

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
        _additional_data: Option<&[u8]>, // AAD由SealEngine中的对称密码处理
    ) -> Result<Vec<u8>, Self::Error> {
        let pk_bytes = &public_key.0;
        let (variant_id, kyber_ciphertext_bytes, shared_secret_bytes) = match pk_bytes.len() {
            KYBER512_PUBLICKEYBYTES => {
                if plaintext.len() != KYBER512_SHAREDKEYBYTES {
                    return Err(Error::PostQuantum(format!(
                        "Kyber512期望的明文长度为{}字节",
                        KYBER512_SHAREDKEYBYTES
                    )));
                }
                let pk = kyber512::PublicKey::from_bytes(pk_bytes)
                    .map_err(|_| Error::PostQuantum("无效的Kyber512公钥格式".to_string()))?;
                let (ss, ct) = kyber512::encapsulate(&pk);
                (1u8, ct.as_bytes().to_vec(), ss.as_bytes().to_vec())
            }
            KYBER768_PUBLICKEYBYTES => {
                if plaintext.len() != KYBER768_SHAREDKEYBYTES {
                    return Err(Error::PostQuantum(format!(
                        "Kyber768期望的明文长度为{}字节",
                        KYBER768_SHAREDKEYBYTES
                    )));
                }
                let pk = kyber768::PublicKey::from_bytes(pk_bytes)
                    .map_err(|_| Error::PostQuantum("无效的Kyber768公钥格式".to_string()))?;
                let (ss, ct) = kyber768::encapsulate(&pk);
                (2u8, ct.as_bytes().to_vec(), ss.as_bytes().to_vec())
            }
            KYBER1024_PUBLICKEYBYTES => {
                if plaintext.len() != KYBER1024_SHAREDKEYBYTES {
                    return Err(Error::PostQuantum(format!(
                        "Kyber1024期望的明文长度为{}字节",
                        KYBER1024_SHAREDKEYBYTES
                    )));
                }
                let pk = kyber1024::PublicKey::from_bytes(pk_bytes)
                    .map_err(|_| Error::PostQuantum("无效的Kyber1024公钥格式".to_string()))?;
                let (ss, ct) = kyber1024::encapsulate(&pk);
                (3u8, ct.as_bytes().to_vec(), ss.as_bytes().to_vec())
            }
            len => return Err(Error::PostQuantum(format!("无效的Kyber公钥长度: {}", len))),
        };

        // 使用共享密钥对DEK进行XOR加密
        let mut encrypted_dek = plaintext.to_vec();
        for (i, byte) in shared_secret_bytes.iter().enumerate() {
            encrypted_dek[i] ^= byte;
        }

        // 组合输出: [变体ID(1)][Kyber密文][XOR加密后的DEK]
        let mut combined = vec![variant_id];
        combined.extend_from_slice(&kyber_ciphertext_bytes);
        combined.extend_from_slice(&encrypted_dek);

        Ok(combined)
    }

    fn decrypt(
        private_key: &Self::PrivateKey,
        ciphertext: &[u8],
        _additional_data: Option<&[u8]>, // AAD由SealEngine中的对称密码处理
    ) -> Result<Vec<u8>, Self::Error> {
        if ciphertext.is_empty() {
            return Err(Error::Format("密文为空".to_string()));
        }

        // 提取变体ID
        let variant_id = ciphertext[0];
        let rest = &ciphertext[1..];

        let (kyber_ct_len, shared_secret_bytes, shared_key_len) = match variant_id {
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
                (
                    KYBER512_CIPHERTEXTBYTES,
                    ss.as_bytes().to_vec(),
                    KYBER512_SHAREDKEYBYTES,
                )
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
                (
                    KYBER768_CIPHERTEXTBYTES,
                    ss.as_bytes().to_vec(),
                    KYBER768_SHAREDKEYBYTES,
                )
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
                (
                    KYBER1024_CIPHERTEXTBYTES,
                    ss.as_bytes().to_vec(),
                    KYBER1024_SHAREDKEYBYTES,
                )
            }
            _ => return Err(Error::PostQuantum("未知的Kyber变体ID".to_string())),
        };

        // 提取XOR加密后的DEK
        let encrypted_dek_part = &rest[kyber_ct_len..];
        if encrypted_dek_part.len() != shared_key_len {
            return Err(Error::Format("密文的DEK部分长度无效".to_string()));
        }
        let mut dek = encrypted_dek_part.to_vec();

        // 对DEK进行XOR解密
        for (i, byte) in shared_secret_bytes.iter().enumerate() {
            dek[i] ^= byte;
        }

        Ok(dek)
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
        assert!(result.is_err());
    }

    #[test]
    fn test_kyber_decrypt_wrong_key_fails() {
        let (public_key, _) = setup_keys(768);
        let (_, wrong_private_key) = setup_keys(768);
        let dek = vec![42u8; DEK_SIZE];

        let ciphertext = KyberCryptoSystem::encrypt(&public_key, &dek, None).unwrap();
        let result = KyberCryptoSystem::decrypt(&wrong_private_key, &ciphertext, None);

        assert!(result.is_err());
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
}
