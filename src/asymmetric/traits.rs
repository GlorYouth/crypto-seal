use crate::Error;
use crate::common::config::ParallelismConfig;
use crate::common::config::{CryptoConfig, StreamingConfig};
use crate::common::streaming::StreamingResult;
use crate::symmetric::traits::SymmetricParallelStreamingSystem;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::io::{Read, Write};
#[cfg(feature = "async-engine")]
use tokio::io::{AsyncRead, AsyncWrite};

/// 加密系统的公共特征，统一各种加密算法的接口
pub trait AsymmetricCryptographicSystem: Sized {
    /// 公钥类型
    type PublicKey: Clone + Serialize + for<'de> Deserialize<'de> + Debug;

    /// 私钥类型
    type PrivateKey: Clone + Serialize + for<'de> Deserialize<'de> + Debug;

    /// 密文类型，可能是字符串或二进制数据
    type CiphertextOutput: AsRef<[u8]> + From<Vec<u8>> + ToString + Send + Sync;

    /// 错误类型
    type Error: std::error::Error;

    /// 生成密钥对
    fn generate_keypair(
        config: &CryptoConfig,
    ) -> Result<(Self::PublicKey, Self::PrivateKey), Self::Error>;

    /// 使用公钥加密数据
    fn encrypt(
        public_key: &Self::PublicKey,
        plaintext: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<Self::CiphertextOutput, Self::Error>;

    /// 使用私钥解密数据
    fn decrypt(
        private_key: &Self::PrivateKey,
        ciphertext: &str,
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, Self::Error>;

    /// 将公钥导出为标准格式
    fn export_public_key(public_key: &Self::PublicKey) -> Result<String, Self::Error>;

    /// 将私钥导出为标准格式
    fn export_private_key(private_key: &Self::PrivateKey) -> Result<String, Self::Error>;

    /// 从标准格式导入公钥
    fn import_public_key(key_data: &str) -> Result<Self::PublicKey, Self::Error>;

    /// 从标准格式导入私钥
    fn import_private_key(key_data: &str) -> Result<Self::PrivateKey, Self::Error>;
}

/// 同步流式加密系统扩展
pub trait AsymmetricSyncStreamingSystem: AsymmetricCryptographicSystem
where
    Error: From<Self::Error>,
{
    /// 同步流式加密
    fn encrypt_stream<S, R, W>(
        public_key: &Self::PublicKey,
        reader: R,
        writer: W,
        config: &StreamingConfig,
        additional_data: Option<&[u8]>,
    ) -> Result<StreamingResult, Error>
    where
        S: crate::symmetric::traits::SymmetricCryptographicSystem,
        Error: From<S::Error>,
        R: Read,
        W: Write;

    /// 同步流式解密
    fn decrypt_stream<S, R, W>(
        private_key: &Self::PrivateKey,
        reader: R,
        writer: W,
        config: &StreamingConfig,
        additional_data: Option<&[u8]>,
    ) -> Result<StreamingResult, Error>
    where
        S: crate::symmetric::traits::SymmetricCryptographicSystem,
        Error: From<S::Error>,
        R: Read,
        W: Write;
}

/// 异步流式加密系统扩展
#[cfg(feature = "async-engine")]
#[async_trait::async_trait]
pub trait AsyncStreamingSystem: AsymmetricCryptographicSystem + Send + Sync
where
    Self::Error: Send,
    Error: From<Self::Error>,
{
    /// 异步流式加密
    async fn encrypt_stream_async<S, R, W>(
        public_key: &Self::PublicKey,
        reader: R,
        writer: W,
        config: &StreamingConfig,
        additional_data: Option<&[u8]>,
    ) -> Result<StreamingResult, Error>
    where
        S: crate::symmetric::traits::SymmetricAsyncStreamingSystem + 'static,
        S::Key: Send + Sync,
        S::Error: Send,
        Error: From<S::Error>,
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send;

    /// 异步流式解密
    async fn decrypt_stream_async<S, R, W>(
        private_key: &Self::PrivateKey,
        reader: R,
        writer: W,
        config: &StreamingConfig,
        additional_data: Option<&[u8]>,
    ) -> Result<StreamingResult, Error>
    where
        S: crate::symmetric::traits::SymmetricAsyncStreamingSystem + 'static,
        S::Key: Send + Sync,
        S::Error: Send,
        Error: From<S::Error>,
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send;
}

#[cfg(feature = "parallel")]
/// 支持并行流式处理的非对称加密系统
pub trait AsymmetricParallelStreamingSystem: AsymmetricCryptographicSystem {
    /// 并行流式加密
    fn par_encrypt_stream<S, R, W>(
        public_key: &Self::PublicKey,
        reader: R,
        writer: W,
        stream_config: &StreamingConfig,
        parallel_config: &ParallelismConfig,
        additional_data: Option<&[u8]>,
    ) -> Result<StreamingResult, Error>
    where
        S: SymmetricParallelStreamingSystem,
        Error: From<S::Error>,
        R: Read + Send,
        W: Write + Send;

    /// 并行流式解密
    fn par_decrypt_stream<S, R, W>(
        private_key: &Self::PrivateKey,
        reader: R,
        writer: W,
        stream_config: &StreamingConfig,
        parallel_config: &ParallelismConfig,
        additional_data: Option<&[u8]>,
    ) -> Result<StreamingResult, Error>
    where
        S: SymmetricParallelStreamingSystem,
        Error: From<S::Error>,
        R: Read + Send,
        W: Write + Send;
}

#[async_trait::async_trait]
/// 异步并行流式加密系统扩展
pub trait AsymmetricAsyncParallelStreamingSystem:
    AsymmetricCryptographicSystem + Send + Sync
where
    Self::Error: Send,
    Self::PublicKey: 'static,
    Self::PrivateKey: 'static,
    Error: From<Self::Error>,
{
    /// 异步并行流式加密
    async fn par_encrypt_stream_async<S, R, W>(
        public_key: &Self::PublicKey,
        reader: R,
        writer: W,
        streaming_config: &StreamingConfig,
        parallelism_config: &ParallelismConfig,
        additional_data: Option<&[u8]>,
    ) -> Result<(StreamingResult, W), Error>
    where
        S: crate::symmetric::traits::SymmetricAsyncParallelStreamingSystem + 'static,
        S::Key: Send + Sync,
        S::Error: Send,
        Error: From<S::Error>,
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static;

    /// 异步并行流式解密
    async fn par_decrypt_stream_async<S, R, W>(
        private_key: &Self::PrivateKey,
        reader: R,
        writer: W,
        streaming_config: &StreamingConfig,
        parallelism_config: &ParallelismConfig,
        additional_data: Option<&[u8]>,
    ) -> Result<(StreamingResult, W), Error>
    where
        S: crate::symmetric::traits::SymmetricAsyncParallelStreamingSystem + 'static,
        S::Key: Send + Sync,
        S::Error: Send,
        Error: From<S::Error>,
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static;
}

/// `AsymmetricParallelSystem` 为支持并行处理的非对称加密系统提供了扩展。
/// 这主要适用于混合加密方案，其中对称加密部分可以从并行化中受益。
#[cfg(feature = "parallel")]
pub trait AsymmetricParallelSystem: AsymmetricCryptographicSystem {
    /// [并行] 加密数据。
    fn par_encrypt(
        key: &Self::PublicKey,
        plaintext: &[u8],
        parallelism_config: &crate::common::config::ParallelismConfig,
    ) -> Result<Vec<u8>, Self::Error>;

    /// [并行] 解密数据。
    fn par_decrypt(
        key: &Self::PrivateKey,
        ciphertext: &[u8],
        parallelism_config: &crate::common::config::ParallelismConfig,
    ) -> Result<Vec<u8>, Self::Error>;
}
