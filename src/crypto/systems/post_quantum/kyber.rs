use pqcrypto_kyber::{kyber1024, kyber512, kyber768};
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};
use serde::{Serialize, Deserialize};
use crate::crypto::traits::CryptographicSystem;
use crate::crypto::common::{Base64String, to_base64, from_base64, CryptoConfig, ZeroizingVec};
use crate::crypto::errors::Error;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
};
#[cfg(not(feature = "chacha"))]
use aes_gcm::{
    Aes256Gcm, Nonce, aead::OsRng
};
#[cfg(feature = "chacha")]
use chacha20poly1305::{
    ChaCha20Poly1305,
    aead::{Aead as ChaAead, AeadCore as ChaAeadCore, KeyInit as ChaKeyInit, generic_array::GenericArray},
    Nonce as ChaNonce
};
#[cfg(feature = "chacha")]
use rsa::rand_core::OsRng;

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

impl CryptographicSystem for KyberCryptoSystem {
    type PublicKey = KyberPublicKeyWrapper;
    type PrivateKey = KyberPrivateKeyWrapper;
    type CiphertextOutput = Base64String;
    type Error = Error;
    
    fn generate_keypair(config: &CryptoConfig) -> Result<(Self::PublicKey, Self::PrivateKey), Self::Error> {
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

        Ok(
            (
                KyberPublicKeyWrapper(public_key_vec),
                KyberPrivateKeyWrapper(ZeroizingVec(private_key_vec)),
            )
        )
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
        // 加密数据
        let aes_ciphertext = cipher.encrypt(&nonce, plaintext)
            .map_err(|e| Error::PostQuantum(format!("AEAD加密失败: {}", e)))?;
        
        // 组合数据：变体ID(1字节) + kyber密文 + nonce + AEAD密文
        let mut combined = vec![variant_id];
        combined.extend_from_slice(&kyber_ciphertext_bytes);
        combined.extend_from_slice(&nonce);
        combined.extend_from_slice(&aes_ciphertext);
        
        Ok(Base64String::from(combined))
    }
    
    fn decrypt(
        private_key: &Self::PrivateKey,
        ciphertext: &str,
        _additional_data: Option<&[u8]>, // AAD在KEM+DEM中不由KEM部分直接处理
    ) -> Result<Vec<u8>, Self::Error> {
        // 解码Base64
        let combined = from_base64(ciphertext)?;
        
        if combined.is_empty() {
            return Err(Error::Format("密文为空".to_string()));
        }

        // 提取变体ID
        let variant_id = combined[0];
        let rest = &combined[1..];

        let (kyber_ct_len, shared_secret_bytes) = match variant_id {
            1 => { // Kyber512
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
            2 => { // Kyber768
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
            3 => { // Kyber1024
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
            },
            _ => return Err(Error::PostQuantum("未知的Kyber变体ID".to_string())),
        };

        // 检查私钥是否与密文匹配
        let expected_sk_len = match variant_id {
            1 => KYBER512_SECRETKEYBYTES,
            2 => KYBER768_SECRETKEYBYTES,
            3 => KYBER1024_SECRETKEYBYTES,
            _ => 0,
        };
        if private_key.0.len() != expected_sk_len {
            return Err(Error::Key("私钥与密文的Kyber级别不匹配".to_string()));
        }

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
        cipher.decrypt(&nonce, aes_ciphertext)
            .map_err(|e| Error::PostQuantum(format!("AEAD解密失败: {}", e)))
    }
    
    fn export_public_key(public_key: &Self::PublicKey) -> Result<String, Self::Error> {
        Ok(to_base64(&public_key.0))
    }
    
    fn export_private_key(private_key: &Self::PrivateKey) -> Result<String, Self::Error> {
        Ok(to_base64(private_key.0.as_ref()))
    }
    
    fn import_public_key(key_data: &str) -> Result<Self::PublicKey, Self::Error> {
        let decoded = from_base64(key_data)?;
        
        match decoded.len() {
            KYBER512_PUBLICKEYBYTES | KYBER768_PUBLICKEYBYTES | KYBER1024_PUBLICKEYBYTES => {},
            len => return Err(Error::Key(format!(
                "无效的Kyber公钥大小: {}字节, 预期值为 {}, {} 或 {}",
                len, KYBER512_PUBLICKEYBYTES, KYBER768_PUBLICKEYBYTES, KYBER1024_PUBLICKEYBYTES
            ))),
        }
        
        Ok(KyberPublicKeyWrapper(decoded))
    }
    
    fn import_private_key(key_data: &str) -> Result<Self::PrivateKey, Self::Error> {
        let decoded = from_base64(key_data)?;
        
        match decoded.len() {
            KYBER512_SECRETKEYBYTES | KYBER768_SECRETKEYBYTES | KYBER1024_SECRETKEYBYTES => {},
            len => return Err(Error::Key(format!(
                "无效的Kyber私钥大小: {}字节, 预期值为 {}, {} 或 {}",
                len, KYBER512_SECRETKEYBYTES, KYBER768_SECRETKEYBYTES, KYBER1024_SECRETKEYBYTES
            ))),
        }
        
        Ok(KyberPrivateKeyWrapper(ZeroizingVec(decoded)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::common::{constant_time_eq, CryptoConfig};
    
    #[test]
    fn kyber_encryption_roundtrip() {
        let config = CryptoConfig::default(); // Kyber768
        let (public_key, private_key) = KyberCryptoSystem::generate_keypair(&config).unwrap();
        
        let plaintext = b"Hello, Kyber post-quantum world!";
        let ciphertext = KyberCryptoSystem::encrypt(&public_key, plaintext, None).unwrap();
        
        let decrypted = KyberCryptoSystem::decrypt(&private_key, &ciphertext.to_string(), None).unwrap();
        assert_eq!(decrypted, plaintext);
        
        // Use constant_time_eq for secure comparison
        assert!(constant_time_eq(&decrypted, plaintext));
    }
    
    #[test]
    fn kyber_key_export_import() {
        let config = CryptoConfig::default();
        let (public_key, private_key) = KyberCryptoSystem::generate_keypair(&config).unwrap();
        
        let public_base64 = KyberCryptoSystem::export_public_key(&public_key).unwrap();
        let private_base64 = KyberCryptoSystem::export_private_key(&private_key).unwrap();
        
        let imported_public = KyberCryptoSystem::import_public_key(&public_base64).unwrap();
        let imported_private = KyberCryptoSystem::import_private_key(&private_base64).unwrap();
        
        // 测试导入的密钥是否可用
        let plaintext = b"Test exported/imported Kyber keys";
        let ciphertext = KyberCryptoSystem::encrypt(&imported_public, plaintext, None).unwrap();
        
        let decrypted = KyberCryptoSystem::decrypt(&imported_private, &ciphertext.to_string(), None).unwrap();
        
        // Use constant_time_eq for secure comparison
        assert!(constant_time_eq(&decrypted, plaintext));
    }
} 