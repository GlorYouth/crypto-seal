use serde::{Deserialize, Serialize};
use std::ops::{Deref, DerefMut};
use zeroize::{Zeroize, ZeroizeOnDrop};

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
        Self { bytes: data.into() }
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
    use crate::common::config::CryptoConfig;
    use crate::common::utils::{SecureBytes, constant_time_eq};

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
        let mut secure = SecureBytes::new(data.to_vec());

        // 测试内容是否正确
        assert_eq!(&*secure, data);

        // 使用可变引用来模拟一些操作
        secure[0] = b'S';
        assert_eq!(secure[0], b'S');

        // 注：内存擦除功能在离开作用域时自动触发，无法直接测试
    }

    #[test]
    fn test_crypto_config_default() {
        let config = CryptoConfig::default();

        assert!(config.use_post_quantum);
        assert!(config.use_traditional);
        assert_eq!(config.rsa_key_bits, 3072);
        assert_eq!(config.kyber_parameter_k, 768);
    }
}
