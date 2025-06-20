//! 定义了对称加密系统的核心 Trait。
// English: Defines the core Traits for symmetric cryptographic systems.

use crate::common::config::ParallelismConfig;
use crate::common::config::{CryptoConfig, StreamingConfig};
use crate::common::streaming::StreamingResult;
use std::fmt::Debug;
use std::io::{Read, Write};

use crate::symmetric::errors::SymmetricError;
#[cfg(feature = "async-engine")]
use tokio::io::{AsyncRead, AsyncWrite};

/// `SymmetricCryptographicSystem` defines the common interface for symmetric encryption algorithms.
/// This trait provides the fundamental operations for key generation, encryption, and decryption of in-memory data.
///
/// 中文: `SymmetricCryptographicSystem` 定义了对称加密算法的公共特征。
/// 该 trait 为密钥生成、内存中数据的加密和解密提供了基本操作。
pub trait SymmetricCryptographicSystem: Sized {
    /// The expected length of the key in bytes.
    /// 中文: 密钥的期望长度（以字节为单位）。
    const KEY_SIZE: usize;

    /// The output type of the encryption function, typically raw bytes. It's designed to be flexible.
    /// 中文: 加密函数的输出类型，通常是原始字节。其设计旨在保持灵活性。
    type CiphertextOutput: AsRef<[u8]> + From<Vec<u8>> + Send + Sync;

    /// The key used for both encryption and decryption.
    /// 中文: 用于加密和解密的单一密钥。
    type Key: Clone + Debug;

    /// The error type for operations within this system.
    /// 中文: 该系统的错误类型。
    type Error: Into<SymmetricError> + Send + Sync + 'static;

    /// Generates a new secret key.
    ///
    /// # Arguments
    /// * `config` - Cryptographic configuration, may be unused by some simple systems.
    ///
    /// 中文: 生成一个新的密钥。
    /// # 参数
    /// * `config` - 加密配置，一些简单的系统可能不会使用。
    fn generate_key(config: &CryptoConfig) -> Result<Self::Key, Self::Error>;

    /// Encrypts plaintext data using the key.
    ///
    /// # Arguments
    /// * `key` - The secret key.
    /// * `plaintext` - The data to encrypt.
    /// * `additional_data` - Optional data to authenticate but not encrypt.
    ///
    /// 中文: 使用密钥加密数据。
    /// # 参数
    /// * `key` - 密钥。
    /// * `plaintext` - 要加密的明文。
    /// * `additional_data` - 可选的附加数据，用于认证但不会被加密。
    fn encrypt(
        key: &Self::Key,
        plaintext: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<Self::CiphertextOutput, Self::Error>;

    /// Decrypts ciphertext data using the key.
    ///
    /// # Arguments
    /// * `key` - The secret key.
    /// * `ciphertext` - The data to decrypt.
    /// * `additional_data` - Optional data used during encryption for authentication.
    ///
    /// 中文: 使用密钥解密数据。
    /// # 参数
    /// * `key` - 密钥。
    /// * `ciphertext` - 要解密的密文。
    /// * `additional_data` - 加密时用于认证的可选附加数据。
    fn decrypt(
        key: &Self::Key,
        ciphertext: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, Self::Error>;

    /// Exports the key to a string representation (e.g., base64 encoded).
    /// 中文: 将密钥导出为字符串表示（例如 base64 编码）。
    fn export_key(key: &Self::Key) -> Result<String, Self::Error>;

    /// Imports a key from its string representation.
    /// 中文: 从字符串表示导入密钥。
    fn import_key(key_data: &str) -> Result<Self::Key, Self::Error>;
}

/// `SymmetricSyncStreamingSystem` extends `SymmetricCryptographicSystem` with synchronous streaming capabilities.
/// This is useful for processing large files or data streams without loading the entire content into memory.
///
/// 中文: `SymmetricSyncStreamingSystem` 扩展了 `SymmetricCryptographicSystem`，提供了同步流式处理能力。
/// 这对于处理大文件或数据流非常有用，可以避免将全部内容加载到内存中。
pub trait SymmetricSyncStreamingSystem: SymmetricCryptographicSystem {
    /// Encrypts a data stream synchronously.
    ///
    /// # Arguments
    /// * `key` - The secret key.
    /// * `reader` - The input stream providing plaintext.
    /// * `writer` - The output stream to write ciphertext to.
    /// * `config` - Streaming configuration, like buffer size.
    /// * `additional_data` - Optional global AAD for the entire stream.
    ///
    /// 中文: 同步流式加密。
    /// # 参数
    /// * `key` - 密钥。
    /// * `reader` - 提供明文的输入流。
    /// * `writer` - 用于写入密文的输出流。
    /// * `config` - 流式处理配置，如缓冲区大小。
    /// * `additional_data` - 可选的、用于整个流的全局 AAD。
    fn encrypt_stream<R: Read, W: Write>(
        key: &Self::Key,
        reader: R,
        writer: W,
        config: &StreamingConfig,
        additional_data: Option<&[u8]>,
    ) -> Result<StreamingResult, SymmetricError>;

    /// Decrypts a data stream synchronously.
    ///
    /// # Arguments
    /// * `key` - The secret key.
    /// * `reader` - The input stream providing ciphertext.
    /// * `writer` - The output stream to write plaintext to.
    /// * `config` - Streaming configuration.
    /// * `additional_data` - Optional global AAD for the entire stream.
    ///
    /// 中文: 同步流式解密。
    /// # 参数
    /// * `key` - 密钥。
    /// * `reader` - 提供密文的输入流。
    /// * `writer` - 用于写入明文的输出流。
    /// * `config` - 流式处理配置。
    /// * `additional_data` - 可选的、用于整个流的全局 AAD。
    fn decrypt_stream<R: Read, W: Write>(
        key: &Self::Key,
        reader: R,
        writer: W,
        config: &StreamingConfig,
        additional_data: Option<&[u8]>,
    ) -> Result<StreamingResult, SymmetricError>;
}

/// `SymmetricAsyncStreamingSystem` provides asynchronous streaming capabilities.
/// Requires the `async-engine` feature. This trait is designed for non-blocking I/O operations,
/// making it suitable for high-performance network services and applications.
///
/// 中文: `SymmetricAsyncStreamingSystem` 提供异步流式处理能力。
/// 需要 `async-engine` 特性。该 trait 专为非阻塞 I/O 操作设计，
/// 适用于高性能网络服务和应用。
#[cfg(feature = "async-engine")]
#[async_trait::async_trait]
pub trait SymmetricAsyncStreamingSystem: SymmetricCryptographicSystem + Send + Sync
where
    Self::Error: Send,
{
    /// Encrypts a data stream asynchronously.
    ///
    /// 中文: 异步流式加密。
    async fn encrypt_stream_async<R, W>(
        key: &Self::Key,
        reader: R,
        writer: W,
        config: &StreamingConfig,
        additional_data: Option<&[u8]>,
    ) -> Result<(StreamingResult, W), SymmetricError>
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send;

    /// Decrypts a data stream asynchronously.
    ///
    /// 中文: 异步流式解密。
    async fn decrypt_stream_async<R, W>(
        key: &Self::Key,
        reader: R,
        writer: W,
        config: &StreamingConfig,
        additional_data: Option<&[u8]>,
    ) -> Result<(StreamingResult, W), SymmetricError>
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send;
}

/// `SymmetricParallelSystem` provides an interface for parallel in-memory encryption and decryption.
/// It leverages data parallelism (e.g., via Rayon) and is suitable for algorithms
/// where data can be broken down into independent chunks for parallel processing.
/// Requires the `parallel` feature.
///
/// 中文: `SymmetricParallelSystem` 提供了使用数据并行性进行内存中对称加解密的接口。
/// 它适用于可以被分解成独立块进行并行处理的加密算法（例如通过 Rayon）。
/// 需要 `parallel` 特性。
#[cfg(feature = "parallel")]
pub trait SymmetricParallelSystem: SymmetricCryptographicSystem {
    /// Encrypts a plaintext slice in parallel.
    ///
    /// # Arguments
    /// * `key` - The secret key.
    /// * `plaintext` - The data to encrypt.
    /// * `additional_data` - Optional AAD.
    /// * `parallelism_config` - Configuration for parallel execution, like chunk size.
    ///
    /// 中文: [并行] 加密一段明文。
    /// # 参数
    /// * `key` - 密钥。
    /// * `plaintext` - 要加密的明文。
    /// * `additional_data` - 可选的 AAD。
    /// * `parallelism_config` - 并行执行的配置，如块大小。
    fn par_encrypt(
        key: &Self::Key,
        plaintext: &[u8],
        additional_data: Option<&[u8]>,
        parallelism_config: &ParallelismConfig,
    ) -> Result<Vec<u8>, Self::Error>;

    /// Decrypts a ciphertext slice in parallel.
    ///
    /// # Arguments
    /// * `key` - The secret key.
    /// * `ciphertext` - The data to decrypt.
    /// * `additional_data` - Optional AAD.
    /// * `parallelism_config` - Configuration for parallel execution.
    ///
    /// 中文: [并行] 解密一段密文。
    /// # 参数
    /// * `key` - 密钥。
    /// * `ciphertext` - 要解密的密文。
    /// * `additional_data` - 可选的 AAD。
    /// * `parallelism_config` - 并行执行的配置。
    fn par_decrypt(
        key: &Self::Key,
        ciphertext: &[u8],
        additional_data: Option<&[u8]>,
        parallelism_config: &ParallelismConfig,
    ) -> Result<Vec<u8>, Self::Error>;
}

/// `SymmetricParallelStreamingSystem` combines parallel processing with streaming for highly efficient
/// handling of large data streams. The data stream is chunked, and chunks are processed in parallel.
/// Requires the `parallel` feature.
///
/// 中文: `SymmetricParallelStreamingSystem` 结合了并行和流式处理，用于高效处理大型数据流。
/// 数据流被分割成块，这些块被并行地进行加密或解密。
/// 需要 `parallel` 特性。
#[cfg(feature = "parallel")]
pub trait SymmetricParallelStreamingSystem: SymmetricCryptographicSystem {
    /// Encrypts a data stream using parallel streaming.
    ///
    /// 中文: 并行流式加密。
    fn par_encrypt_stream<R: Read + Send, W: Write + Send>(
        key: &Self::Key,
        reader: R,
        writer: W,
        stream_config: &StreamingConfig,
        parallel_config: &ParallelismConfig,
        additional_data: Option<&[u8]>,
    ) -> Result<StreamingResult, SymmetricError>;

    /// Decrypts a data stream using parallel streaming.
    ///
    /// 中文: 并行流式解密。
    fn par_decrypt_stream<R: Read + Send, W: Write + Send>(
        key: &Self::Key,
        reader: R,
        writer: W,
        stream_config: &StreamingConfig,
        parallel_config: &ParallelismConfig,
        additional_data: Option<&[u8]>,
    ) -> Result<StreamingResult, SymmetricError>;
}

/// `SymmetricAsyncParallelStreamingSystem` provides an interface for asynchronous parallel streaming.
/// This is the most advanced trait, combining non-blocking I/O with parallel computation.
/// It's designed for I/O-bound applications that also have heavy CPU-bound cryptographic work.
/// Requires both `parallel` and `async-engine` features.
///
/// 中文: `SymmetricAsyncParallelStreamingSystem` 提供了异步并行流式加密的接口。
/// 这是最高级的 trait，结合了非阻塞I/O和并行计算。
/// 它专为I/O密集型且包含大量CPU密集型加密工作的应用而设计。
/// 需要 `parallel` 和 `async-engine` 两个特性。
#[cfg(all(feature = "parallel", feature = "async-engine"))]
#[async_trait::async_trait]
pub trait SymmetricAsyncParallelStreamingSystem: SymmetricParallelStreamingSystem
where
    Self::Key: Clone + Send + Sync,
{
    /// Encrypts a data stream using asynchronous parallel streaming.
    ///
    /// # Arguments
    /// - `key`: The encryption key.
    /// - `reader`: An asynchronous reader providing the plaintext data.
    /// - `writer`: An asynchronous writer to output the ciphertext.
    /// - `stream_config`: Configuration for the streaming aspects, like buffer size.
    /// - `parallel_config`: Configuration for the parallelism aspects, like number of threads.
    /// - `additional_data`: Optional global AAD for the entire stream.
    ///
    /// 中文: 异步并行流式加密。
    /// # 参数
    /// - `key`: 加密密钥。
    /// - `reader`: 提供明文数据的异步读取器。
    /// - `writer`: 输出密文的异步写入器。
    /// - `stream_config`: 流式处理相关的配置，如缓冲区大小。
    /// - `parallel_config`: 并行化相关的配置，如线程数。
    /// - `additional_data`: 可选的、用于整个流的全局 AAD。
    async fn par_encrypt_stream_async<R, W>(
        key: &Self::Key,
        reader: R,
        writer: W,
        stream_config: &StreamingConfig,
        parallel_config: &ParallelismConfig,
        additional_data: Option<&[u8]>,
    ) -> Result<(StreamingResult, W), SymmetricError>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static;

    /// Decrypts a data stream using asynchronous parallel streaming.
    ///
    /// 中文: 异步并行流式解密。
    async fn par_decrypt_stream_async<R, W>(
        key: &Self::Key,
        reader: R,
        writer: W,
        stream_config: &StreamingConfig,
        parallel_config: &ParallelismConfig,
        additional_data: Option<&[u8]>,
    ) -> Result<(StreamingResult, W), SymmetricError>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static;
}
