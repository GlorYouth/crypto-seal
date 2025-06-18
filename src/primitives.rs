//! 基础工具模块，提供 Base64 编解码、ZeroizingVec、安全比较等工具
pub mod streaming; 
pub use streaming::*;

#[cfg(feature = "async-engine")]
pub mod async_streaming;
#[cfg(feature = "async-engine")]
pub use async_streaming::{AsyncStreamingConfig, AsyncStreamingEncryptor, AsyncStreamingDecryptor};

pub mod symmetric_streaming;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use zeroize::{Zeroize, ZeroizeOnDrop};
use std::ops::{Deref, DerefMut};
use serde::{Serialize, Deserialize};
use serde_bytes;

/// 将字节数组转换为Base64字符串
pub fn to_base64(data: &[u8]) -> String {
    BASE64.encode(data)
}

/// 从Base64字符串解码为字节数组
pub fn from_base64(encoded: &str) -> Result<Vec<u8>, base64::DecodeError> {
    BASE64.decode(encoded)
}

/// Base64编码的字符串类型
#[derive(Debug, Clone)]
pub struct Base64String(pub Vec<u8>);

impl Base64String {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for Base64String {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for Base64String {
    fn from(data: Vec<u8>) -> Self {
        Self(data)
    }
}

impl ToString for Base64String {
    fn to_string(&self) -> String {
        to_base64(&self.0)
    }
}

/// 安全地比较两个字节序列，防止时序攻击
///
/// 无论输入如何，此函数总是比较所有字节，但只有所有字节都匹配才返回true
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0;
    for (byte_a, byte_b) in a.iter().zip(b.iter()) {
        result |= byte_a ^ byte_b;
    }
    
    result == 0
}

/// 安全字节容器，提供自动内存擦除
/// 
/// 当对象离开作用域时，自动清除内存中的敏感数据
#[derive(Clone, Debug)]
pub struct SecureBytes {
    bytes: Vec<u8>,
}

impl SecureBytes {
    /// 创建新的安全字节容器
    pub fn new(data: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: data.into(),
        }
    }
    
    /// 将内容转换为Base64编码的字符串
    pub fn to_base64(&self) -> String {
        to_base64(&self.bytes)
    }
    
    /// 从Base64字符串创建SecureBytes
    pub fn from_base64(encoded: &str) -> Result<Self, base64::DecodeError> {
        let bytes = from_base64(encoded)?;
        Ok(Self::new(bytes))
    }
    
    /// 安全地比较两个SecureBytes实例
    pub fn constant_time_eq(&self, other: &Self) -> bool {
        constant_time_eq(&self.bytes, &other.bytes)
    }
}

impl Deref for SecureBytes {
    type Target = [u8];
    
    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl DerefMut for SecureBytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.bytes
    }
}

impl Zeroize for SecureBytes {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl ZeroizeOnDrop for SecureBytes {}

impl Drop for SecureBytes {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl AsRef<[u8]> for SecureBytes {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// 加密系统配置
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CryptoConfig {
    /// 是否使用传统密码学（如RSA）
    pub use_traditional: bool,
    /// 是否使用后量子密码学
    pub use_post_quantum: bool,
    /// RSA密钥位数
    pub rsa_key_bits: usize,
    /// Kyber安全级别 (512/768/1024)
    pub kyber_parameter_k: usize,
    /// 是否使用认证加密
    pub use_authenticated_encryption: bool,
    /// 是否自动验证签名
    pub auto_verify_signatures: bool,
    /// 默认签名算法
    pub default_signature_algorithm: String,
    /// Argon2内存成本（默认19456 KB）
    pub argon2_memory_cost: u32,
    /// Argon2时间成本（默认2）
    pub argon2_time_cost: u32,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            use_traditional: true,
            use_post_quantum: true,
            rsa_key_bits: 3072,  // NIST建议的安全位数
            kyber_parameter_k: 768, // NIST竞赛中的推荐级别
            use_authenticated_encryption: true,
            auto_verify_signatures: true,
            default_signature_algorithm: "RSA-PSS-SHA256".to_string(),
            argon2_memory_cost: 19456, // 19MB
            argon2_time_cost: 2,
        }
    }
}

/// 自动清零的字节向量，用于私钥等敏感数据
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ZeroizingVec(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl std::ops::Deref for ZeroizingVec {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for ZeroizingVec {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_base64_roundtrip() {
        let original = b"Hello, crypto world!";
        let encoded = to_base64(original);
        let decoded = from_base64(&encoded).unwrap();
        assert_eq!(decoded, original);
    }
    
    #[test]
    fn test_base64string_traits() {
        let data = vec![1, 2, 3, 4, 5];
        let b64_string = Base64String::from(data.clone());
        
        // 测试From<Vec<u8>>
        assert_eq!(from_base64(&b64_string.to_string()).unwrap(), data);
        
        // 测试AsRef<[u8]>
        assert_eq!(b64_string.as_ref(), b64_string.0.as_slice());
        
        // 测试ToString
        assert_eq!(b64_string.to_string(), to_base64(&b64_string.0));
    }
    
    #[test]
    fn test_constant_time_eq() {
        let a = b"sensitive data";
        let b = b"sensitive data";
        let c = b"different data";
        
        assert!(constant_time_eq(a, b));
        assert!(!constant_time_eq(a, c));
        assert!(!constant_time_eq(a, &c[0..5]));
    }
    
    #[test]
    fn test_secure_bytes() {
        let data = b"sensitive information";
        let secure = SecureBytes::new(data.to_vec());
        
        // 测试内容是否正确
        assert_eq!(&*secure, data);
        
        // 测试Base64转换
        let b64 = secure.to_base64();
        let recovered = SecureBytes::from_base64(&b64).unwrap();
        assert!(secure.constant_time_eq(&recovered));
        
        // 注：内存擦除功能在离开作用域时自动触发，无法直接测试
    }
    
    #[test]
    fn test_crypto_config_default() {
        let config = CryptoConfig::default();
        
        assert!(config.use_post_quantum);
        assert!(config.use_traditional);
        assert_eq!(config.rsa_key_bits, 3072);
        assert_eq!(config.kyber_parameter_k, 768);
        assert!(config.use_authenticated_encryption);
        assert!(config.auto_verify_signatures);
        assert_eq!(config.default_signature_algorithm, "RSA-PSS-SHA256");
    }
} 

