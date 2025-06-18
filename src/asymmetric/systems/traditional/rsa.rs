use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use rsa::pss::{SigningKey, VerifyingKey};
use rsa::signature::{RandomizedSigner, SignatureEncoding, Verifier};
use sha2::Sha256;
use rsa::rand_core::OsRng as RsaOsRng;
use serde::{Deserialize, Serialize};
use crate::asymmetric::traits::AsymmetricCryptographicSystem;
#[cfg(feature = "async-engine")]
use crate::asymmetric::traits::AsyncStreamingSystem;
use crate::common::errors::Error;
#[cfg(feature = "async-engine")]
use crate::common::streaming::StreamingConfig;
#[cfg(feature = "async-engine")]
use crate::common::streaming::StreamingResult;
#[cfg(feature = "async-engine")]
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use crate::common::utils::{from_base64, Base64String, CryptoConfig, ZeroizingVec};

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

impl AsymmetricCryptographicSystem for RsaCryptoSystem {
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

#[cfg(feature = "async-engine")]
#[async_trait::async_trait]
impl AsyncStreamingSystem for RsaCryptoSystem {
    async fn encrypt_stream_async<R, W>(
        public_key: &Self::PublicKey,
        mut reader: R,
        mut writer: W,
        config: &StreamingConfig,
        additional_data: Option<&[u8]>,
    ) -> Result<StreamingResult, Error>
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send,
    {
        let mut buffer = vec![0u8; config.buffer_size];
        let mut bytes_processed = 0;
        let mut output_buffer = if config.keep_in_memory { Some(Vec::new()) } else { None };

        loop {
            let read_bytes = reader.read(&mut buffer).await.map_err(Error::Io)?;
            if read_bytes == 0 {
                break;
            }

            let plaintext = &buffer[..read_bytes];
            let ciphertext_output = Self::encrypt(public_key, plaintext, additional_data)?;

            let ciphertext_str = ciphertext_output.to_string();
            let ciphertext_bytes = ciphertext_str.as_bytes();
            let length = ciphertext_bytes.len() as u32;

            writer.write_all(&length.to_le_bytes()).await.map_err(Error::Io)?;
            writer.write_all(ciphertext_bytes).await.map_err(Error::Io)?;

            if let Some(buf) = output_buffer.as_mut() {
                buf.extend_from_slice(ciphertext_bytes);
            }

            bytes_processed += read_bytes as u64;
        }

        writer.flush().await.map_err(Error::Io)?;

        Ok(StreamingResult {
            bytes_processed,
            buffer: output_buffer,
        })
    }

    async fn decrypt_stream_async<R, W>(
        private_key: &Self::PrivateKey,
        mut reader: R,
        mut writer: W,
        _config: &StreamingConfig,
        additional_data: Option<&[u8]>,
    ) -> Result<StreamingResult, Error>
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send,
    {
        let mut length_buffer = [0u8; 4];
        let mut bytes_processed = 0;
        let mut output_buffer = if _config.keep_in_memory { Some(Vec::new()) } else { None };

        while reader.read_exact(&mut length_buffer).await.is_ok() {
            let length = u32::from_le_bytes(length_buffer) as usize;
            let mut ciphertext_buffer = vec![0u8; length];
            reader.read_exact(&mut ciphertext_buffer).await.map_err(Error::Io)?;

            let ciphertext_str = String::from_utf8(ciphertext_buffer)
                .map_err(|e| Error::Format(format!("Invalid UTF-8 ciphertext chunk: {}", e)))?;
            
            let plaintext = Self::decrypt(private_key, &ciphertext_str, additional_data)?;
            
            writer.write_all(&plaintext).await.map_err(Error::Io)?;

            if let Some(buf) = output_buffer.as_mut() {
                buf.extend_from_slice(&plaintext);
            }
            bytes_processed += length as u64;
        }

        writer.flush().await.map_err(Error::Io)?;

        Ok(StreamingResult {
            bytes_processed,
            buffer: output_buffer,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::utils::CryptoConfig;

    fn setup_keys() -> (RsaPublicKeyWrapper, RsaPrivateKeyWrapper) {
        let config = CryptoConfig { rsa_key_bits: 2048, ..Default::default() };
        RsaCryptoSystem::generate_keypair(&config).unwrap()
    }

    #[test]
    fn test_rsa_encryption_roundtrip() {
        let (public_key, private_key) = setup_keys();
        let plaintext = b"some secret data";

        let ciphertext = RsaCryptoSystem::encrypt(&public_key, plaintext, None).unwrap();
        let decrypted = RsaCryptoSystem::decrypt(&private_key, &ciphertext.to_string(), None).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_rsa_sign_verify_roundtrip() {
        let (public_key, private_key) = setup_keys();
        let data = b"data to be signed";

        let signature = RsaCryptoSystem::sign(&private_key, data).unwrap();
        let is_valid = RsaCryptoSystem::verify(&public_key, data, &signature).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_rsa_verify_tampered_signature_fails() {
        let (public_key, private_key) = setup_keys();
        let data = b"some important data";

        let mut signature = RsaCryptoSystem::sign(&private_key, data).unwrap();
        // Tamper with the signature
        signature[0] ^= 0xff;

        let is_valid = RsaCryptoSystem::verify(&public_key, data, &signature).unwrap();
        assert!(!is_valid);
    }
    
    #[test]
    fn test_rsa_verify_wrong_key_fails() {
        let (_public_key, private_key) = setup_keys();
        let (wrong_public_key, _) = setup_keys(); // A different key pair
        let data = b"data for signature";

        let signature = RsaCryptoSystem::sign(&private_key, data).unwrap();
        // Verify with the wrong public key
        let is_valid = RsaCryptoSystem::verify(&wrong_public_key, data, &signature).unwrap();

        assert!(!is_valid);
    }

    #[test]
    fn test_rsa_decrypt_wrong_key_fails() {
        let (public_key, _) = setup_keys();
        let (_, wrong_private_key) = setup_keys();
        let plaintext = b"top secret";

        let ciphertext = RsaCryptoSystem::encrypt(&public_key, plaintext, None).unwrap();
        let result = RsaCryptoSystem::decrypt(&wrong_private_key, &ciphertext.to_string(), None);
        
        assert!(result.is_err());
    }
    
    #[test]
    fn test_rsa_decrypt_tampered_ciphertext_fails() {
        let (public_key, private_key) = setup_keys();
        let plaintext = b"another secret";

        let ciphertext_b64 = RsaCryptoSystem::encrypt(&public_key, plaintext, None).unwrap();
        let mut ciphertext_bytes = from_base64(&ciphertext_b64.to_string()).unwrap();
        
        // Tamper
        let len = ciphertext_bytes.len();
        ciphertext_bytes[len / 2] ^= 0xff;
        let tampered_ciphertext_b64 = Base64String::from(ciphertext_bytes);

        let result = RsaCryptoSystem::decrypt(&private_key, &tampered_ciphertext_b64.to_string(), None);
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
        // 尝试导入非PEM格式的密钥
        let invalid_pem = "this is not a pem";
        assert!(RsaCryptoSystem::import_public_key(invalid_pem).is_err());
        assert!(RsaCryptoSystem::import_private_key(invalid_pem).is_err());
    }

    #[test]
    fn test_sign_verify_empty_data() {
        let (public_key, private_key) = setup_keys();
        let data = b""; // 空数据
        
        let signature = RsaCryptoSystem::sign(&private_key, data).unwrap();
        let is_valid = RsaCryptoSystem::verify(&public_key, data, &signature).unwrap();
        
        assert!(is_valid);
    }

    #[test]
    fn test_verify_different_data_fails() {
        let (public_key, private_key) = setup_keys();
        let data1 = b"some important data";
        let data2 = b"different important data";
        
        let signature = RsaCryptoSystem::sign(&private_key, data1).unwrap();
        let is_valid = RsaCryptoSystem::verify(&public_key, data2, &signature).unwrap();
        
        assert!(!is_valid);
    }
    
    #[test]
    fn test_encrypt_empty_data() {
        let (public_key, private_key) = setup_keys();
        let plaintext = b""; // 空数据
        
        let encrypted = RsaCryptoSystem::encrypt(&public_key, plaintext, None).unwrap();
        let decrypted = RsaCryptoSystem::decrypt(&private_key, &encrypted.to_string(), None).unwrap();
        
        assert_eq!(plaintext.as_ref(), decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_data_too_long_fails() {
        let config = CryptoConfig { rsa_key_bits: 2048, ..Default::default() };
        let (public_key, _) = RsaCryptoSystem::generate_keypair(&config).unwrap();

        // 对于2048位的RSA和PKCS#1 v1.5填充，最大数据长度是 2048/8 - 11 = 245 字节
        let long_data = vec![0u8; 256];
        
        let result = RsaCryptoSystem::encrypt(&public_key, &long_data, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_key_generation_with_4096_bits() {
        let config = CryptoConfig { rsa_key_bits: 4096, ..Default::default() };
        let (public_key, private_key) = RsaCryptoSystem::generate_keypair(&config).unwrap();
        
        let plaintext = b"data for 4096-bit key";
        let encrypted = RsaCryptoSystem::encrypt(&public_key, plaintext, None).unwrap();
        let decrypted = RsaCryptoSystem::decrypt(&private_key, &encrypted.to_string(), None).unwrap();
        
        assert_eq!(plaintext.as_ref(), decrypted.as_slice());
    }
}

#[cfg(all(test, feature = "async-engine"))]
mod async_tests {
    use super::*;
    use crate::common::utils::CryptoConfig;
    use std::io::Cursor;
    use tokio::io::BufWriter;
    use crate::common::streaming::StreamingConfig;

    #[tokio::test]
    async fn test_async_streaming_roundtrip() {
        let config = CryptoConfig::default();
        let (public_key, private_key) = RsaCryptoSystem::generate_keypair(&config).unwrap();
        
        let original_data = b"This is a test for RSA async streaming.";
        
        // Encrypt
        let mut encrypted_buffer = Vec::new();
        {
            let reader = Cursor::new(original_data);
            let writer = BufWriter::new(&mut encrypted_buffer);
            let stream_config = StreamingConfig {
                buffer_size: 16,
                keep_in_memory: true,
                ..Default::default()
            };

            let result = RsaCryptoSystem::encrypt_stream_async(
                &public_key,
                reader,
                writer,
                &stream_config,
                None,
            )
            .await
            .unwrap();
            
            assert_eq!(result.bytes_processed, original_data.len() as u64);
        }

        // Decrypt
        let mut decrypted_buffer = Vec::new();
        {
            let reader = Cursor::new(&encrypted_buffer);
            let writer = BufWriter::new(&mut decrypted_buffer);
            let stream_config = StreamingConfig {
                buffer_size: 32,
                ..Default::default()
            };

            RsaCryptoSystem::decrypt_stream_async(
                &private_key,
                reader,
                writer,
                &stream_config,
                None,
            )
            .await
            .unwrap();
        }

        assert_eq!(decrypted_buffer, original_data);
    }
} 