//!
//! 一个混合加密方案，结合了经典的RSA-PSS签名和后量子的Kyber密钥封装机制。
//!

use aes_gcm::KeyInit;
use crate::primitives::{from_base64, to_base64, Base64String, CryptoConfig};
use crate::errors::Error;
use crate::systems::post_quantum::kyber::{KyberCryptoSystem, KyberPrivateKeyWrapper, KyberPublicKeyWrapper};
use crate::systems::traditional::rsa::{RsaCryptoSystem, RsaPrivateKeyWrapper, RsaPublicKeyWrapper};
use crate::traits::{AuthenticatedCryptoSystem, CryptographicSystem};
use aes_gcm::aead::Aead;
use aes_gcm::aead::AeadCore;
#[cfg(feature = "chacha")]
#[allow(unused_imports)]
use chacha20poly1305::{aead::{Aead as ChaAead, AeadCore as ChaAeadCore, KeyInit as ChaKeyInit}, ChaCha20Poly1305, Nonce as ChaNonce, aead::generic_array::GenericArray};
use rsa::rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(feature = "async-engine")]
use crate::traits::AsyncStreamingSystem;
#[cfg(feature = "async-engine")]
use crate::primitives::async_streaming::AsyncStreamingConfig;
#[cfg(feature = "async-engine")]
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

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
        #[cfg(feature = "chacha")]
        let cipher = ChaCha20Poly1305::new((&aes_key).into());
        #[cfg(not(feature = "chacha"))]
        let cipher = Aes256Gcm::new(&aes_key.into());
        #[cfg(feature = "chacha")]
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        #[cfg(not(feature = "chacha"))]
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let dem_ciphertext = cipher.encrypt(&nonce, plaintext)
            .map_err(|e| Error::Operation(format!("AEAD 加密失败: {}", e)))?;
        
        // 4. 将 KEM 密文的 Base64 ASCII 与 DEM 密文及 Nonce 组合
        let kem_str = kem_ciphertext.to_string();
        let combined = [
            kem_str.as_bytes(),
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
        let kem_ciphertext_str = String::from_utf8(kem_part.to_vec())
            .map_err(|e| Error::Format(format!("无效的PQ Base64密文: {}", e)))?;
        let aes_key_bytes = KyberCryptoSystem::decrypt(&private_key.kyber_private_key, &kem_ciphertext_str, None)?;

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
        cipher.decrypt(&nonce, dem_part)
            .map_err(|_| Error::Operation("AEAD 解密或认证失败".to_string()))
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

#[cfg(feature = "async-engine")]
#[async_trait::async_trait]
impl AsyncStreamingSystem for RsaKyberCryptoSystem {
    async fn encrypt_stream_async<R, W>(
        public_key: &Self::PublicKey,
        mut reader: R,
        mut writer: W,
        config: &AsyncStreamingConfig,
        additional_data: Option<&[u8]>,
    ) -> Result<crate::primitives::StreamingResult, Error>
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

            if let Some(cb) = &config.progress_callback {
                cb(bytes_processed, config.total_bytes);
            }
            if config.show_progress {
                if let Some(total) = config.total_bytes {
                    println!("[Async Encrypt] Processed {}/{} bytes", bytes_processed, total);
                } else {
                    println!("[Async Encrypt] Processed {} bytes", bytes_processed);
                }
            }
        }

        writer.flush().await.map_err(Error::Io)?;

        Ok(crate::primitives::StreamingResult {
            bytes_processed,
            buffer: output_buffer,
        })
    }

    async fn decrypt_stream_async<R, W>(
        private_key: &Self::PrivateKey,
        mut reader: R,
        mut writer: W,
        config: &AsyncStreamingConfig,
        additional_data: Option<&[u8]>,
    ) -> Result<crate::primitives::StreamingResult, Error>
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send,
    {
        let mut length_buffer = [0u8; 4];
        let mut bytes_processed = 0;
        let mut output_buffer = if config.keep_in_memory { Some(Vec::new()) } else { None };

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

            if let Some(cb) = &config.progress_callback {
                cb(bytes_processed, config.total_bytes);
            }
            if config.show_progress {
                if let Some(total) = config.total_bytes {
                    println!("[Async Decrypt] Processed approx. {}/{} bytes", bytes_processed, total);
                } else {
                    println!("[Async Decrypt] Processed approx. {} bytes", bytes_processed);
                }
            }
        }

        writer.flush().await.map_err(Error::Io)?;

        Ok(crate::primitives::StreamingResult {
            bytes_processed,
            buffer: output_buffer,
        })
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

#[cfg(all(test, feature = "async-engine"))]
mod async_tests {
    use super::*;
    use crate::primitives::CryptoConfig;
    use std::io::Cursor;
    use tokio::io::BufWriter;

    #[tokio::test]
    async fn test_async_streaming_roundtrip() {
        // 1. Setup
        let config = CryptoConfig::default();
        let (public_key, private_key) = RsaKyberCryptoSystem::generate_keypair(&config).unwrap();
        
        let original_data = b"This is a larger block of data for testing asynchronous streaming encryption and decryption.";
        
        // 2. Encrypt
        let mut encrypted_buffer = Vec::new();
        {
            let reader = Cursor::new(original_data);
            let writer = BufWriter::new(&mut encrypted_buffer);
            let stream_config = AsyncStreamingConfig {
                buffer_size: 64, // Small buffer to force multiple chunks
                keep_in_memory: true,
                ..Default::default()
            };

            let result = RsaKyberCryptoSystem::encrypt_stream_async(
                &public_key,
                reader,
                writer,
                &stream_config,
                None,
            )
            .await
            .unwrap();
            
            assert!(result.bytes_processed > 0);
            assert_eq!(result.bytes_processed, original_data.len() as u64);
        }

        // 3. Decrypt
        let mut decrypted_buffer = Vec::new();
        {
            let reader = Cursor::new(&encrypted_buffer);
            let writer = BufWriter::new(&mut decrypted_buffer);
            let stream_config = AsyncStreamingConfig {
                buffer_size: 128,
                ..Default::default()
            };

            let result = RsaKyberCryptoSystem::decrypt_stream_async(
                &private_key,
                reader,
                writer,
                &stream_config,
                None,
            )
            .await
            .unwrap();
            
            assert!(result.bytes_processed > 0);
        }

        // 4. Verify
        assert_eq!(decrypted_buffer, original_data);
    }
} 