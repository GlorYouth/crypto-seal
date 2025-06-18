use std::io::{Read, Write};
use std::fmt::Debug;
use crate::Error;
use crate::common::utils::CryptoConfig;
use crate::common::streaming::{StreamingConfig, StreamingResult};

/// 对称加密系统的公共特征
pub trait SymmetricCryptographicSystem: Sized {
    /// 用于加密和解密的单一密钥。
    type Key: Clone + Debug; 
    
    /// 密文的输出格式。
    type CiphertextOutput: AsRef<[u8]> + From<Vec<u8>> + ToString;
    
    /// 该系统的错误类型。
    type Error: std::error::Error;
    
    /// 生成一个新的密钥。
    fn generate_key(config: &CryptoConfig) -> Result<Self::Key, Self::Error>;
    
    /// 使用密钥加密数据。
    fn encrypt(
        key: &Self::Key,
        plaintext: &[u8],
        additional_data: Option<&[u8]>
    ) -> Result<Self::CiphertextOutput, Self::Error>;
    
    /// 使用密钥解密数据。
    fn decrypt(
        key: &Self::Key,
        ciphertext: &str,
        additional_data: Option<&[u8]>
    ) -> Result<Vec<u8>, Self::Error>;

    /// 导出密钥为字符串
    fn export_key(key: &Self::Key) -> Result<String, Self::Error>;

    /// 从字符串导入密钥
    fn import_key(key_data: &str) -> Result<Self::Key, Self::Error>;
}

/// 同步对称流式加密系统扩展
pub trait SymmetricSyncStreamingSystem: SymmetricCryptographicSystem
where
    Error: From<Self::Error>,
{
    /// 同步流式加密
    fn encrypt_stream<R: Read, W: Write>(
        key: &Self::Key,
        reader: R,
        writer: W,
        config: &StreamingConfig,
        additional_data: Option<&[u8]>,
    ) -> Result<StreamingResult, Error>;

    /// 同步流式解密
    fn decrypt_stream<R: Read, W: Write>(
        key: &Self::Key,
        reader: R,
        writer: W,
        config: &StreamingConfig,
        additional_data: Option<&[u8]>,
    ) -> Result<StreamingResult, Error>;
}