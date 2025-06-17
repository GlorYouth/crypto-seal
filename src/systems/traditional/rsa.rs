use rsa::{RsaPrivateKey, RsaPublicKey, Pkcs1v15Encrypt};
use rsa::pkcs8::{EncodePublicKey, EncodePrivateKey, DecodePublicKey, DecodePrivateKey};
use rsa::pss::{SigningKey, VerifyingKey};
use rsa::signature::{RandomizedSigner, Verifier, SignatureEncoding};
use sha2::Sha256;
use rsa::rand_core::OsRng as RsaOsRng;
use serde::{Serialize, Deserialize};
use crate::traits::CryptographicSystem;
use crate::primitives::{Base64String, from_base64, CryptoConfig, ZeroizingVec};
use crate::errors::Error;

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

/// RSA加密系统实现
/// 
/// 提供标准RSA PKCS#1 v1.5加密和解密功能
pub struct RsaCryptoSystem;

impl RsaCryptoSystem {
    /// 使用PSS方案和SHA-256生成数字签名
    ///
    /// # 参数
    /// * `private_key` - 用于签名的RSA私钥
    /// * `data` - 需要被签名的数据
    ///
    /// # 返回
    /// 成功时返回签名的字节向量
    pub fn sign(private_key: &RsaPrivateKeyWrapper, data: &[u8]) -> Result<Vec<u8>, Error> {
        let rsa_private_key = RsaPrivateKey::from_pkcs8_der(&private_key.0)
            .map_err(|e| Error::Traditional(format!("解析RSA私钥失败: {}", e)))?;
        
        let signing_key = SigningKey::<Sha256>::new(rsa_private_key);
        let mut rng = RsaOsRng;
        let signature = signing_key.sign_with_rng(&mut rng, data);
        Ok(signature.to_vec())
    }

    /// 使用PSS方案和SHA-256验证数字签名
    ///
    /// # 参数
    /// * `public_key` - 用于验证的RSA公钥
    /// * `data` - 原始数据
    /// * `signature` - 需要被验证的签名
    ///
    /// # 返回
    /// 签名有效则返回 `Ok(true)`，否则返回 `Ok(false)`
    pub fn verify(public_key: &RsaPublicKeyWrapper, data: &[u8], signature: &[u8]) -> Result<bool, Error> {
        let rsa_public_key = RsaPublicKey::from_public_key_der(&public_key.0)
            .map_err(|e| Error::Traditional(format!("解析RSA公钥失败: {}", e)))?;

        let verifying_key = VerifyingKey::<Sha256>::new(rsa_public_key);
        
        let signature_obj = match rsa::pss::Signature::try_from(signature) {
            Ok(sig) => sig,
            // 如果签名切片长度不正确，则为无效签名
            Err(_) => return Ok(false),
        };
        
        match verifying_key.verify(data, &signature_obj) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

impl CryptographicSystem for RsaCryptoSystem {
    type PublicKey = RsaPublicKeyWrapper;
    type PrivateKey = RsaPrivateKeyWrapper;
    type CiphertextOutput = Base64String;
    type Error = Error;
    
    fn generate_keypair(config: &CryptoConfig) -> Result<(Self::PublicKey, Self::PrivateKey), Self::Error> {
        let bits = config.rsa_key_bits;
        let mut rsa_rng = RsaOsRng;
        
        let private_key = RsaPrivateKey::new(&mut rsa_rng, bits)
            .map_err(|e| Error::Traditional(format!("生成RSA密钥失败: {}", e)))?;
        let public_key = RsaPublicKey::from(&private_key);
        
        // 将密钥转换为DER格式，然后包装
        let public_der = public_key.to_public_key_der()
            .map_err(|e| Error::Traditional(format!("导出RSA公钥DER失败: {}", e)))?;
        
        let private_der = private_key.to_pkcs8_der()
            .map_err(|e| Error::Traditional(format!("导出RSA私钥DER失败: {}", e)))?;
        
        Ok(
            (
                RsaPublicKeyWrapper(public_der.as_bytes().to_vec()),
                RsaPrivateKeyWrapper(ZeroizingVec(private_der.as_bytes().to_vec()))
            )
        )
    }
    
    fn encrypt(
        public_key: &Self::PublicKey,
        plaintext: &[u8],
        _additional_data: Option<&[u8]> // RSA PKCS#1 v1.5不使用附加数据
    ) -> Result<Self::CiphertextOutput, Self::Error> {
        // 从DER数据恢复公钥
        let public_key = RsaPublicKey::from_public_key_der(&public_key.0)
            .map_err(|e| Error::Traditional(format!("解析RSA公钥失败: {}", e)))?;
        
        let mut rng = RsaOsRng;
        let ciphertext = public_key.encrypt(&mut rng, Pkcs1v15Encrypt, plaintext)
            .map_err(|e| Error::Traditional(format!("RSA加密失败: {}", e)))?;
        
        Ok(Base64String::from(ciphertext))
    }
    
    fn decrypt(
        private_key: &Self::PrivateKey,
        ciphertext: &str,
        _additional_data: Option<&[u8]> // RSA PKCS#1 v1.5不使用附加数据
    ) -> Result<Vec<u8>, Self::Error> {
        // 从DER数据恢复私钥
        let private_key = RsaPrivateKey::from_pkcs8_der(&private_key.0)
            .map_err(|e| Error::Traditional(format!("解析RSA私钥失败: {}", e)))?;
        
        // 使用公共函数解码Base64
        let ciphertext_bytes = from_base64(ciphertext)?;
        
        private_key.decrypt(Pkcs1v15Encrypt, &ciphertext_bytes)
            .map_err(|e| Error::Traditional(format!("RSA解密失败: {}", e)))
    }
    
    fn export_public_key(public_key: &Self::PublicKey) -> Result<String, Self::Error> {
        // 从DER数据恢复公钥
        let public_key = RsaPublicKey::from_public_key_der(&public_key.0)
            .map_err(|e| Error::Traditional(format!("解析RSA公钥失败: {}", e)))?;
        
        let pem = public_key.to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|e| Error::Serialization(format!("RSA公钥导出失败: {}", e)))?;
        Ok(pem)
    }
    
    fn export_private_key(private_key: &Self::PrivateKey) -> Result<String, Self::Error> {
        // 从DER数据恢复私钥
        let private_key = RsaPrivateKey::from_pkcs8_der(&private_key.0)
            .map_err(|e| Error::Traditional(format!("解析RSA私钥失败: {}", e)))?;
        
        let pem = private_key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|e| Error::Serialization(format!("RSA私钥导出失败: {}", e)))?
            .to_string();
        Ok(pem)
    }
    
    fn import_public_key(key_data: &str) -> Result<Self::PublicKey, Self::Error> {
        let public_key = RsaPublicKey::from_public_key_pem(key_data)
            .map_err(|e| Error::Key(format!("导入RSA公钥失败: {}", e)))?;
            
        let public_der = public_key.to_public_key_der()
            .map_err(|e| Error::Traditional(format!("导出RSA公钥DER失败: {}", e)))?;
            
        Ok(RsaPublicKeyWrapper(public_der.as_bytes().to_vec()))
    }
    
    fn import_private_key(key_data: &str) -> Result<Self::PrivateKey, Self::Error> {
        let private_key = RsaPrivateKey::from_pkcs8_pem(key_data)
            .map_err(|e| Error::Key(format!("导入RSA私钥失败: {}", e)))?;
            
        let private_der = private_key.to_pkcs8_der()
            .map_err(|e| Error::Traditional(format!("导出RSA私钥DER失败: {}", e)))?;
            
        Ok(RsaPrivateKeyWrapper(ZeroizingVec(private_der.as_bytes().to_vec())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::constant_time_eq;
    
    #[test]
    fn rsa_encryption_roundtrip() {
        let config = CryptoConfig::default();
        let (public_key, private_key) = RsaCryptoSystem::generate_keypair(&config).unwrap();
        
        let plaintext = b"Hello, RSA world!";
        let ciphertext = RsaCryptoSystem::encrypt(&public_key, plaintext, None).unwrap();
        
        let decrypted = RsaCryptoSystem::decrypt(&private_key, &ciphertext.to_string(), None).unwrap();
        
        // Use constant_time_eq for secure comparison
        assert!(constant_time_eq(&decrypted, plaintext));
    }
    
    #[test]
    fn rsa_key_export_import() {
        let config = CryptoConfig::default();
        let (public_key, private_key) = RsaCryptoSystem::generate_keypair(&config).unwrap();
        
        let public_pem = RsaCryptoSystem::export_public_key(&public_key).unwrap();
        let private_pem = RsaCryptoSystem::export_private_key(&private_key).unwrap();
        
        let imported_public = RsaCryptoSystem::import_public_key(&public_pem).unwrap();
        let imported_private = RsaCryptoSystem::import_private_key(&private_pem).unwrap();
        
        // 测试导入的密钥是否可用
        let plaintext = b"Test exported/imported keys";
        let ciphertext = RsaCryptoSystem::encrypt(&imported_public, plaintext, None).unwrap();
        
        let decrypted = RsaCryptoSystem::decrypt(&imported_private, &ciphertext.to_string(), None).unwrap();
        
        // Use constant_time_eq for secure comparison
        assert!(constant_time_eq(&decrypted, plaintext));
    }
} 