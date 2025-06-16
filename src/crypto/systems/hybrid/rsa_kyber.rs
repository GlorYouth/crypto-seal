//!
//! 一个混合加密方案，结合了经典的RSA-PSS签名和后量子的Kyber密钥封装机制。
//!

use serde::{Serialize, Deserialize};
use crate::crypto::traits::{CryptographicSystem, AuthenticatedCryptoSystem};
use crate::crypto::systems::traditional::rsa::{RsaCryptoSystem, RsaPublicKeyWrapper, RsaPrivateKeyWrapper};
use crate::crypto::systems::post_quantum::kyber::{KyberCryptoSystem, KyberPublicKeyWrapper, KyberPrivateKeyWrapper};
use crate::crypto::errors::Error;
use crate::crypto::common::{Base64String, to_base64, from_base64, CryptoConfig};
use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, AeadCore, Nonce}};
use rsa::rand_core::{OsRng, RngCore};
use sha2::{Sha256, Digest};

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

impl CryptographicSystem for RsaKyberCryptoSystem {
    type PublicKey = RsaKyberPublicKey;
    type PrivateKey = RsaKyberPrivateKey;
    type Error = Error;
    type CiphertextOutput = Base64String;

    fn generate_keypair(config: &CryptoConfig) -> Result<(Self::PublicKey, Self::PrivateKey), Self::Error> {
        let (rsa_pk, rsa_sk) = RsaCryptoSystem::generate_keypair(config)?;
        let (kyber_pk, kyber_sk) = KyberCryptoSystem::generate_keypair(config)?;
        
        let public_key = Self::PublicKey { rsa_public_key: rsa_pk, kyber_public_key: kyber_pk };
        let private_key = Self::PrivateKey { rsa_private_key: rsa_sk, kyber_private_key: kyber_sk };
        
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
        _additional_data: Option<&[u8]>,
    ) -> Result<Self::CiphertextOutput, Self::Error> {
        // 1. 生成一个一次性的AES-256密钥。
        let mut aes_key = [0u8; 32];
        OsRng.fill_bytes(&mut aes_key);

        // 2. KEM: 使用Kyber公钥封装（加密）AES密钥。
        let kem_ciphertext = KyberCryptoSystem::encrypt(&public_key.kyber_public_key, &aes_key, None)?;

        // 3. DEM: 使用AES密钥加密实际数据。
        let cipher = Aes256Gcm::new(&aes_key.into());
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 12字节 Nonce
        let dem_ciphertext = cipher.encrypt(&nonce, plaintext)
            .map_err(|e| Error::Operation(format!("AES加密失败: {}", e)))?;
        
        // 4. 将 Kyber密文、Nonce 和 AES密文 组合在一起。
        // 格式: [Kyber密文]::[Nonce]::[AES密文]
        let combined = [
            kem_ciphertext.as_bytes(),
            b"::",
            nonce.as_slice(),
            b"::",
            &dem_ciphertext
        ].concat();
        
        Ok(Base64String::from(combined))
    }

    /// 执行无签名的KEM-DEM解密。
    fn decrypt(
        private_key: &Self::PrivateKey,
        ciphertext: &str,
        _additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, Self::Error> {
        // 解码Base64得到原始字节
        let combined = from_base64(ciphertext)?;
        let delim = b"::";
        // 查找第一个分隔符，将KEM部分与Nonce部分分开
        let first_pos = combined.windows(delim.len())
            .position(|window| window == delim)
            .ok_or_else(|| Error::Format("密文格式错误：缺少KEM-Nonce分隔符".to_string()))?;
        let kem_part = &combined[..first_pos];
        // 跳过第一个分隔符
        let rest = &combined[first_pos + delim.len()..];
        // 查找第二个分隔符，将Nonce与AES密文分开
        let second_pos = rest.windows(delim.len())
            .position(|window| window == delim)
            .ok_or_else(|| Error::Format("密文格式错误：缺少Nonce-DEM分隔符".to_string()))?;
        let nonce_part = &rest[..second_pos];
        let dem_part = &rest[second_pos + delim.len()..];

        // 1. KEM: 使用Kyber私钥解封AES密钥。
        let kem_ciphertext_b64 = to_base64(kem_part);
        let aes_key_bytes = KyberCryptoSystem::decrypt(&private_key.kyber_private_key, &kem_ciphertext_b64, None)?;

        // 2. DEM: 使用AES密钥和Nonce解密数据。
        let cipher = Aes256Gcm::new_from_slice(&aes_key_bytes)
             .map_err(|_| Error::Key("无效的AES密钥".to_string()))?;
        
        let nonce = Nonce::<Aes256Gcm>::from_slice(nonce_part);
        
        cipher.decrypt(nonce, dem_part)
            .map_err(|_| Error::Operation("AES解密或认证失败".to_string()))
    }
}

impl AuthenticatedCryptoSystem for RsaKyberCryptoSystem {
    type AuthenticatedOutput = Base64String;

    fn sign(private_key: &Self::PrivateKey, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let digest = Sha256::digest(data);
        RsaCryptoSystem::sign(&private_key.rsa_private_key, &digest)
    }

    fn verify(public_key: &Self::PublicKey, data: &[u8], signature: &[u8]) -> Result<bool, Self::Error> {
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
            let combined = [encrypted_data_b64.as_bytes(), b"::", to_base64(&signature).as_bytes()].concat();
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
        let split_pos_opt = combined.windows(delim.len())
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
            let signature_bytes = from_base64(sig_str)
                .map_err(|_| Error::Operation("签名验证失败".to_string()))?;
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

    #[test]
    fn test_hybrid_roundtrip_unauthenticated() {
        let config = CryptoConfig::default();
        let (pk, sk) = RsaKyberCryptoSystem::generate_keypair(&config).unwrap();
        let plaintext = b"this is a test message for unauthenticated hybrid encryption";

        let ciphertext = RsaKyberCryptoSystem::encrypt(&pk, plaintext, None).unwrap();
        let decrypted = RsaKyberCryptoSystem::decrypt(&sk, ciphertext.to_string().as_ref(), None).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_hybrid_roundtrip_authenticated() {
        let config = CryptoConfig::default();
        let (pk, sk) = RsaKyberCryptoSystem::generate_keypair(&config).unwrap();
        let plaintext = b"this is a test message for authenticated hybrid encryption";

        let ciphertext = RsaKyberCryptoSystem::encrypt_authenticated(&pk, plaintext, None, Some(&sk)).unwrap();
        let decrypted = RsaKyberCryptoSystem::decrypt_authenticated(&sk, ciphertext.to_string().as_ref(), None, Some(&pk)).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_hybrid_tampered_data_fails_decryption() {
        let config = CryptoConfig::default();
        let (pk, sk) = RsaKyberCryptoSystem::generate_keypair(&config).unwrap();
        let plaintext = b"this is a test message";
        
        let ciphertext_b64 = RsaKyberCryptoSystem::encrypt(&pk, plaintext, None).unwrap();
        let mut combined = from_base64(ciphertext_b64.to_string().as_ref()).unwrap();

        // 在密文的最后篡改一个字节
        let last_byte_index = combined.len() - 1;
        combined[last_byte_index] ^= 0xff;
        
        let tampered_ciphertext = to_base64(&combined);

        let result = RsaKyberCryptoSystem::decrypt(&sk, &tampered_ciphertext, None);
        assert!(result.is_err(), "解密被篡改的数据应该失败");
    }

    #[test]
    fn test_hybrid_tampered_signature_fails_verification() {
        let config = CryptoConfig::default();
        let (pk, sk) = RsaKyberCryptoSystem::generate_keypair(&config).unwrap();
        let plaintext = b"this is a test message";
        
        let auth_ciphertext_b64 = RsaKyberCryptoSystem::encrypt_authenticated(&pk, plaintext, None, Some(&sk)).unwrap();
        let mut combined = from_base64(auth_ciphertext_b64.to_string().as_ref()).unwrap();
        
        // 在签名的部分篡改一个字节
        let last_byte_index = combined.len() - 1;
        combined[last_byte_index] ^= 0xff;
        
        let tampered_ciphertext = to_base64(&combined);
        
        let result = RsaKyberCryptoSystem::decrypt_authenticated(&sk, tampered_ciphertext.as_ref(), None, Some(&pk));
        assert!(result.is_err(), "认证解密被篡改的签名应该失败");
        assert_eq!(result.unwrap_err().to_string(), "操作失败: 签名验证失败");
    }
} 