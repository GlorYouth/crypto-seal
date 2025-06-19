use crate::common::config::ParallelismConfig;
use crate::common::config::{CryptoConfig, StreamingConfig};
use crate::common::errors::Error;
use crate::common::streaming::StreamingResult;
use std::fmt::Debug;
use std::io::{Read, Write};

#[cfg(feature = "async-engine")]
use tokio::io::{AsyncRead, AsyncWrite};

/// 对称加密系统的公共特征
pub trait SymmetricCryptographicSystem: Sized {
    /// 密钥的期望长度（以字节为单位）。
    const KEY_SIZE: usize;

    /// 密文类型，现在是原始字节
    type CiphertextOutput: AsRef<[u8]> + From<Vec<u8>> + Send + Sync;

    /// 用于加密和解密的单一密钥。
    type Key: Clone + Debug;

    /// 该系统的错误类型。
    type Error: std::error::Error + Send + Sync + 'static;

    /// 生成一个新的密钥。
    fn generate_key(config: &CryptoConfig) -> Result<Self::Key, Self::Error>;

    /// 使用密钥加密数据。
    fn encrypt(
        key: &Self::Key,
        plaintext: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<Self::CiphertextOutput, Self::Error>;

    /// 使用密钥解密数据。
    fn decrypt(
        key: &Self::Key,
        ciphertext: &[u8],
        additional_data: Option<&[u8]>,
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

/// 异步对称流式加密系统扩展
#[cfg(feature = "async-engine")]
#[async_trait::async_trait]
pub trait SymmetricAsyncStreamingSystem: SymmetricCryptographicSystem + Send + Sync
where
    Self::Error: Send,
    Error: From<Self::Error>,
{
    /// 异步流式加密
    async fn encrypt_stream_async<R, W>(
        key: &Self::Key,
        reader: R,
        writer: W,
        config: &StreamingConfig,
        additional_data: Option<&[u8]>,
    ) -> Result<(StreamingResult, W), Error>
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send;

    /// 异步流式解密
    async fn decrypt_stream_async<R, W>(
        key: &Self::Key,
        reader: R,
        writer: W,
        config: &StreamingConfig,
        additional_data: Option<&[u8]>,
    ) -> Result<(StreamingResult, W), Error>
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send;
}

/// `SymmetricParallelSystem` 提供了使用数据并行性（例如通过 Rayon）进行对称加解密的接口。
/// 它适用于可以被分解成独立块进行并行处理的加密算法。
#[cfg(feature = "parallel")]
pub trait SymmetricParallelSystem: SymmetricCryptographicSystem
where
    Error: From<Self::Error>,
{
    /// [并行] 加密一段明文。
    fn par_encrypt(
        key: &Self::Key,
        plaintext: &[u8],
        additional_data: Option<&[u8]>,
        parallelism_config: &crate::common::config::ParallelismConfig,
    ) -> Result<Vec<u8>, Self::Error>;

    /// [并行] 解密一段密文。
    fn par_decrypt(
        key: &Self::Key,
        ciphertext: &[u8],
        additional_data: Option<&[u8]>,
        parallelism_config: &crate::common::config::ParallelismConfig,
    ) -> Result<Vec<u8>, Self::Error>;
}

/// `SymmetricParallelStreamingSystem` 结合了并行和流式处理，用于高效处理大型数据流。
/// 数据流被分割成块，这些块被并行地进行加密或解密。
#[cfg(feature = "parallel")]
pub trait SymmetricParallelStreamingSystem: SymmetricCryptographicSystem
where
    Error: From<Self::Error>,
{
    /// 并行流式加密
    fn par_encrypt_stream<R: Read + Send, W: Write + Send>(
        key: &Self::Key,
        reader: R,
        writer: W,
        stream_config: &StreamingConfig,
        parallel_config: &ParallelismConfig,
        additional_data: Option<&[u8]>,
    ) -> Result<StreamingResult, Error>;

    /// 并行流式解密
    fn par_decrypt_stream<R: Read + Send, W: Write + Send>(
        key: &Self::Key,
        reader: R,
        writer: W,
        stream_config: &StreamingConfig,
        parallel_config: &ParallelismConfig,
        additional_data: Option<&[u8]>,
    ) -> Result<StreamingResult, Error>;
}

#[cfg(all(feature = "parallel", feature = "async-engine"))]
#[async_trait::async_trait]
/// 异步对称并行流式加密系统扩展
pub trait SymmetricAsyncParallelStreamingSystem: SymmetricParallelStreamingSystem
where
    Error: From<Self::Error>,
    Self::Key: Clone + Send + Sync,
{
    /// 异步并行流式加密
    async fn par_encrypt_stream_async<R, W>(
        key: &Self::Key,
        reader: R,
        writer: W,
        stream_config: &StreamingConfig,
        parallel_config: &ParallelismConfig,
        additional_data: Option<&[u8]>,
    ) -> Result<(StreamingResult, W), Error>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static;

    /// 异步并行流式解密
    async fn par_decrypt_stream_async<R, W>(
        key: &Self::Key,
        reader: R,
        writer: W,
        stream_config: &StreamingConfig,
        parallel_config: &ParallelismConfig,
        additional_data: Option<&[u8]>,
    ) -> Result<(StreamingResult, W), Error>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static;
}
