use std::fmt::Debug;
use serde::{Deserialize, Serialize};
use crate::asymmetric::traits::CryptographicSystem;

/// 密钥状态
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum KeyStatus {
    /// 活跃状态，当前正在使用
    Active,
    /// 轮换中，正在逐步替换
    Rotating,
    /// 已过期，仅用于解密旧数据
    Expired,
}

/// 密钥元数据结构
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// 密钥唯一标识符
    pub id: String,
    /// 密钥创建时间
    pub created_at: String,
    /// 密钥过期时间
    pub expires_at: Option<String>,
    /// 密钥使用计数
    pub usage_count: u64,
    /// 密钥状态
    pub status: KeyStatus,
    /// 密钥版本
    pub version: u32,
    /// 算法标识符
    pub algorithm: String,
}

/// 认证加密系统扩展特征
pub trait AuthenticatedCryptoSystem: CryptographicSystem {
    /// 认证加密输出类型
    type AuthenticatedOutput: AsRef<[u8]> + From<Vec<u8>> + ToString;
    
    /// 生成签名
    fn sign(
        private_key: &Self::PrivateKey,
        data: &[u8]
    ) -> Result<Vec<u8>, Self::Error>;
    
    /// 验证签名
    fn verify(
        public_key: &Self::PublicKey,
        data: &[u8],
        signature: &[u8]
    ) -> Result<bool, Self::Error>;
    
    /// 带认证的加密
    fn encrypt_authenticated(
        public_key: &Self::PublicKey,
        plaintext: &[u8],
        additional_data: Option<&[u8]>,
        signer_key: Option<&Self::PrivateKey>
    ) -> Result<Self::AuthenticatedOutput, Self::Error>;
    
    /// 带认证的解密
    fn decrypt_authenticated(
        private_key: &Self::PrivateKey,
        ciphertext: &str,
        additional_data: Option<&[u8]>,
        verifier_key: Option<&Self::PublicKey>
    ) -> Result<Vec<u8>, Self::Error>;
}

#[cfg(feature = "secure-storage")]
/// 密钥容器特征，提供密钥的安全存储能力
pub trait SecureKeyStorage {
    /// 错误类型
    type Error: std::error::Error;
    
    /// 加密并存储密钥
    fn encrypt_key<K: AsRef<[u8]>>(
        password: &secrecy::SecretString,
        key_data: K,
        algorithm_id: &str
    ) -> Result<Self, Self::Error> where Self: Sized;
    
    /// 解密并获取密钥数据
    fn decrypt_key(&self, password: &secrecy::SecretString) -> Result<Vec<u8>, Self::Error>;
    
    /// 获取算法标识符
    fn algorithm_id(&self) -> &str;
    
    /// 获取创建时间
    fn created_at(&self) -> &str;
    
    /// 序列化为JSON
    fn to_json(&self) -> Result<String, Self::Error>;
    
    /// 从JSON反序列化
    fn from_json(json: &str) -> Result<Self, Self::Error> where Self: Sized;
}

