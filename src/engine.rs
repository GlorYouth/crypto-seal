mod private;

use crate::common::header::Header;
use crate::rotation::manager::KeyManager;
use crate::{Error, Seal};
use secrecy::SecretString;
use std::sync::Arc;

/// `SealEngine` 是执行实际加密和解密操作的统一接口。
///
/// 它持有密钥管理器的状态，以高效地处理连续的加密操作和自动密钥轮换。
#[derive(Clone)]
pub struct SealEngine {
    pub(crate) key_manager: KeyManager,
    // 我们需要一个对 Seal 的引用来访问配置等信息，但它不参与状态管理
    pub(crate) _seal: Arc<Seal>,
    // 引擎在创建时 "解锁"，存储密码以供内部需要写入的操作（如密钥轮换）使用。
    pub(crate) password: SecretString,

    /// 可选的DEK缓存，用于高性能、低安全性的场景。
    /// An optional DEK cache for high-performance, lower-security scenarios.
    #[cfg(feature = "dek-caching")]
    dek_cache: Option<(Header, Vec<u8>)>,
}

impl SealEngine {
    /// Creates a new `SealEngine`.
    /// This is the correct way to instantiate the engine, as it handles internal state and feature flags.
    /// 创建一个新的 `SealEngine`。
    /// 这是实例化引擎的正确方法，因为它能处理内部状态和功能标志。
    pub(crate) fn new(key_manager: KeyManager, seal: Arc<Seal>, password: SecretString) -> Self {
        Self {
            key_manager,
            _seal: seal,
            password,
            #[cfg(feature = "dek-caching")]
            dek_cache: None,
        }
    }

    /// Clears the cached Data Encryption Key (DEK).
    /// This forces the engine to generate a new DEK on the next `_with_cached_dek` encryption call.
    /// 清除缓存的数据加密密钥（DEK）。
    /// 这将强制引擎在下一次调用 `_with_cached_dek` 加密方法时生成一个新的DEK。
    #[cfg(feature = "dek-caching")]
    pub fn clear_dek_cache(&mut self) {
        self.dek_cache = None;
    }

    /// （内部方法）确保缓存中有一个可用的DEK，如果不存在则生成一个。
    #[cfg(feature = "dek-caching")]
    fn ensure_dek_cached(&mut self) -> Result<(), Error> {
        if self.dek_cache.is_none() {
            if self.key_manager.needs_rotation() {
                self.key_manager.start_rotation(&self.password)?;
            }
            let (header, dek) = self.build_header_and_dek()?;
            self.dek_cache = Some((header, dek));
        }
        Ok(())
    }

    /// [DEK Caching] Encrypts a byte slice using a cached DEK for high performance.
    /// **Warning:** Reusing a DEK for multiple encryption operations is against cryptographic best practices.
    /// [DEK 缓存] 使用缓存的DEK加密字节切片以实现高性能。
    /// **警告：** 对多个加密操作重用DEK违反了密码学的最佳实践。
    #[cfg(feature = "dek-caching")]
    pub fn seal_bytes_with_cached_dek(
        &mut self,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        self.ensure_dek_cached()?;
        let (header, dek) = self.dek_cache.as_ref().unwrap();

        let mut reader = std::io::Cursor::new(plaintext);
        let mut writer = Vec::new();

        let header_bytes = header.encode_to_vec()?;
        writer.write_all(&(header_bytes.len() as u32).to_le_bytes())?;
        writer.write_all(&header_bytes)?;

        use crate::symmetric::systems::aes_gcm::{AesGcmKey, AesGcmSystem};
        use crate::symmetric::traits::SymmetricSyncStreamingSystem;

        let dek_key = AesGcmKey(dek.clone());
        let streaming_config = &self.key_manager.config().streaming;
        AesGcmSystem::encrypt_stream(&dek_key, &mut reader, &mut writer, streaming_config, aad)?;

        self.key_manager.increment_usage_count(&self.password)?;

        Ok(writer)
    }

    /// [DEK Caching] Encrypts a stream using a cached DEK for high performance.
    /// **Warning:** Reusing a DEK for multiple encryption operations is against cryptographic best practices.
    /// [DEK 缓存] 使用缓存的DEK加密流以实现高性能。
    /// **警告：** 对多个加密操作重用DEK违反了密码学的最佳实践。
    #[cfg(feature = "dek-caching")]
    pub fn seal_stream_with_cached_dek<R: Read, W: Write>(
        &mut self,
        source: &mut R,
        destination: &mut W,
        aad: Option<&[u8]>,
    ) -> Result<(), Error> {
        self.ensure_dek_cached()?;
        let (header, dek) = self.dek_cache.as_ref().unwrap();

        let header_bytes = header.encode_to_vec()?;
        destination.write_all(&(header_bytes.len() as u32).to_le_bytes())?;
        destination.write_all(&header_bytes)?;

        use crate::symmetric::systems::aes_gcm::{AesGcmKey, AesGcmSystem};
        use crate::symmetric::traits::SymmetricSyncStreamingSystem;

        let dek_key = AesGcmKey(dek.clone());
        let streaming_config = &self.key_manager.config().streaming;
        AesGcmSystem::encrypt_stream(&dek_key, source, destination, streaming_config, aad)?;

        self.key_manager.increment_usage_count(&self.password)?;

        Ok(())
    }

    /// [DEK Caching] Encrypts a stream in parallel using a cached DEK for high performance.
    /// **Warning:** Reusing a DEK for multiple encryption operations is against cryptographic best practices.
    /// [DEK 缓存] 使用缓存的DEK并行加密流以实现高性能。
    /// **警告：** 对多个加密操作重用DEK违反了密码学的最佳实践。
    #[cfg(feature = "dek-caching")]
    pub fn par_seal_stream_with_cached_dek<R: Read + Send, W: Write + Send>(
        &mut self,
        source: &mut R,
        destination: &mut W,
        aad: Option<&[u8]>,
    ) -> Result<(), Error> {
        self.ensure_dek_cached()?;
        let (header, dek) = self.dek_cache.as_ref().unwrap();

        let header_bytes = header.encode_to_vec()?;
        destination.write_all(&(header_bytes.len() as u32).to_le_bytes())?;
        destination.write_all(&header_bytes)?;

        use crate::symmetric::systems::aes_gcm::{AesGcmKey, AesGcmSystem};
        use crate::symmetric::traits::SymmetricParallelStreamingSystem;

        let dek_key = AesGcmKey(dek.clone());
        let streaming_config = &self.key_manager.config().streaming;
        let parallelism_config = &self.key_manager.config().parallelism;
        AesGcmSystem::par_encrypt_stream(
            &dek_key,
            source,
            destination,
            streaming_config,
            parallelism_config,
            aad,
        )?;

        self.key_manager.increment_usage_count(&self.password)?;

        Ok(())
    }

    /// 使用当前引擎的模式来加密（封印）一个字节切片。
    ///
    /// 这是一个便捷的内存加密方法。
    pub fn seal_bytes(&mut self, plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>, Error> {
        // 为了代码复用，我们可以在内部使用流式加密的实现
        let mut reader = std::io::Cursor::new(plaintext);
        let mut writer = Vec::new();
        self.seal_stream(&mut reader, &mut writer, aad)?;
        Ok(writer)
    }

    /// [并行] 使用当前引擎的模式来加密（封印）一个字节切片。
    pub fn par_seal_bytes(
        &mut self,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        // 1. 检查并执行密钥轮换
        if self.key_manager.needs_rotation() {
            self.key_manager.start_rotation(&self.password)?;
        }

        // 2. 构建 Header 和 DEK
        let (header, dek) = self.build_header_and_dek()?;

        // 3. 序列化
        let header_bytes = header.encode_to_vec()?;

        // 4. 调用底层的并行加密原语
        use crate::symmetric::systems::aes_gcm::{AesGcmKey, AesGcmSystem};
        use crate::symmetric::traits::SymmetricParallelSystem;

        let dek_key = AesGcmKey(dek);
        let parallelism_config = &self.key_manager.config().parallelism;
        let ciphertext_payload =
            AesGcmSystem::par_encrypt(&dek_key, plaintext, aad, parallelism_config)?;

        // 5. 组合 Header 和加密后的载荷
        let mut final_output =
            Vec::with_capacity(4 + header_bytes.len() + ciphertext_payload.len());
        final_output.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
        final_output.extend_from_slice(&header_bytes);
        final_output.extend_from_slice(&ciphertext_payload);

        self.key_manager.increment_usage_count(&self.password)?;

        Ok(final_output)
    }

    /// [并行] 使用当前引擎的模式来流式加密（封印）一个数据流。
    pub fn par_seal_stream<R, W>(
        &mut self,
        reader: R,
        mut writer: W,
        aad: Option<&[u8]>,
    ) -> Result<(), Error>
    where
        R: std::io::Read + Send,
        W: std::io::Write + Send,
    {
        // 1. 检查并执行密钥轮换
        if self.key_manager.needs_rotation() {
            self.key_manager.start_rotation(&self.password)?;
        }

        // 2. 构建 Header 和 DEK
        let (header, dek) = self.build_header_and_dek()?;

        // 3. 序列化并写入 Header
        let header_bytes = header.encode_to_vec()?;
        writer.write_all(&(header_bytes.len() as u32).to_le_bytes())?;
        writer.write_all(&header_bytes)?;

        // 4. 调用底层的并行流式加密原语
        use crate::symmetric::systems::aes_gcm::{AesGcmKey, AesGcmSystem};
        use crate::symmetric::traits::SymmetricParallelStreamingSystem;

        let dek_key = AesGcmKey(dek);
        let streaming_config = &self.key_manager.config().streaming;
        let parallelism_config = &self.key_manager.config().parallelism;

        AesGcmSystem::par_encrypt_stream(
            &dek_key,
            reader,
            writer,
            streaming_config,
            parallelism_config,
            aad,
        )?;

        self.key_manager.increment_usage_count(&self.password)?;

        Ok(())
    }

    /// 使用当前引擎的模式来流式加密（封印）一个数据流。
    ///
    /// 此方法会自动处理密钥轮换、元数据生成和数据加密，
    /// 并将统一格式的密文写入输出流。
    pub fn seal_stream<R, W>(
        &mut self,
        reader: R,
        mut writer: W,
        aad: Option<&[u8]>,
    ) -> Result<(), Error>
    where
        R: std::io::Read,
        W: std::io::Write,
    {
        // 1. 检查并执行密钥轮换
        if self.key_manager.needs_rotation() {
            self.key_manager.start_rotation(&self.password)?;
        }

        // 2. 构建 Header
        let (header, dek) = self.build_header_and_dek()?;

        // 3. 序列化并写入 Header
        let header_bytes = header.encode_to_vec()?;
        writer.write_all(&(header_bytes.len() as u32).to_le_bytes())?;
        writer.write_all(&header_bytes)?;

        // 4. 使用 DEK 加密数据流
        use crate::symmetric::systems::aes_gcm::{AesGcmKey, AesGcmSystem};
        use crate::symmetric::traits::SymmetricSyncStreamingSystem;

        let dek_key = AesGcmKey(dek);
        let streaming_config = &self.key_manager.config().streaming;

        AesGcmSystem::encrypt_stream(&dek_key, reader, writer, streaming_config, aad)?;

        self.key_manager.increment_usage_count(&self.password)?;

        Ok(())
    }

    /// 使用当前引擎的模式解密（解封）一个字节切片。
    ///
    /// 此方法会自动解析密文头部，获取正确的密钥进行解密。
    /// 这是一个便捷的内存解密方法。
    pub fn unseal_bytes(&self, ciphertext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>, Error> {
        let mut reader = std::io::Cursor::new(ciphertext);
        let mut writer = Vec::new();
        self.unseal_stream(&mut reader, &mut writer, aad)?;
        Ok(writer)
    }

    /// [并行] 使用当前引擎的模式解密（解封）一个字节切片。
    pub fn par_unseal_bytes(
        &self,
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        // 1. 解析 Header
        let mut reader = std::io::Cursor::new(ciphertext);
        let header = self.read_and_parse_header(&mut reader)?;

        // 2. 根据 Header 派生/解密 DEK
        let dek = self.derive_dek_from_header(&header)?;

        // 3. 读取剩余的载荷并使用并行原语解密
        let mut payload = Vec::new();
        reader.read_to_end(&mut payload)?;

        use crate::symmetric::systems::aes_gcm::{AesGcmKey, AesGcmSystem};
        use crate::symmetric::traits::SymmetricParallelSystem;
        use std::io::Read;

        let dek_key = AesGcmKey(dek);
        let parallelism_config = &self.key_manager.config().parallelism;
        let decrypted_payload =
            AesGcmSystem::par_decrypt(&dek_key, &payload, aad, parallelism_config)?;

        Ok(decrypted_payload)
    }

    /// [并行] 使用当前引擎的模式来流式解密（解封）一个数据流。
    pub fn par_unseal_stream<R, W>(
        &self,
        mut reader: R,
        writer: W,
        aad: Option<&[u8]>,
    ) -> Result<(), Error>
    where
        R: std::io::Read + Send,
        W: std::io::Write + Send,
    {
        // 1. 解析 Header
        let header = self.read_and_parse_header(&mut reader)?;

        // 2. 根据 Header 派生/解密 DEK
        let dek = self.derive_dek_from_header(&header)?;

        // 3. 调用底层的并行流式解密原语
        use crate::symmetric::systems::aes_gcm::{AesGcmKey, AesGcmSystem};
        use crate::symmetric::traits::SymmetricParallelStreamingSystem;

        let dek_key = AesGcmKey(dek);
        let streaming_config = &self.key_manager.config().streaming;
        let parallelism_config = &self.key_manager.config().parallelism;

        AesGcmSystem::par_decrypt_stream(
            &dek_key,
            reader,
            writer,
            streaming_config,
            parallelism_config,
            aad,
        )?;

        Ok(())
    }

    /// 解密（解封）一个数据流。
    ///
    /// 此方法会自动解析密文头，并用正确的密钥解密后续的数据流。
    pub fn unseal_stream<R, W>(
        &self,
        mut reader: R,
        writer: W,
        aad: Option<&[u8]>,
    ) -> Result<(), Error>
    where
        R: std::io::Read,
        W: std::io::Write,
    {
        // 1. 解析 Header
        let header = self.read_and_parse_header(&mut reader)?;

        // 2. 根据 Header 派生/解密 DEK
        let dek = self.derive_dek_from_header(&header)?;

        use crate::common::header::HeaderPayload;
        use crate::common::traits::SymmetricAlgorithm; // 3. 使用 DEK 解密数据流
        use crate::symmetric::systems::aes_gcm::{AesGcmKey, AesGcmSystem};
        use crate::symmetric::traits::SymmetricSyncStreamingSystem;

        // Dispatch based on DEK algorithm
        match header.payload {
            HeaderPayload::Symmetric { algorithm, .. } => match algorithm {
                SymmetricAlgorithm::Aes256Gcm => {
                    let dek_key = AesGcmKey(dek);
                    let streaming_config = &self.key_manager.config().streaming;
                    AesGcmSystem::decrypt_stream(&dek_key, reader, writer, streaming_config, aad)?;
                }
            },
            HeaderPayload::Hybrid { dek_algorithm, .. } => match dek_algorithm {
                SymmetricAlgorithm::Aes256Gcm => {
                    let dek_key = AesGcmKey(dek);
                    let streaming_config = &self.key_manager.config().streaming;
                    AesGcmSystem::decrypt_stream(&dek_key, reader, writer, streaming_config, aad)?;
                }
            },
        }

        Ok(())
    }
}

#[cfg(feature = "async-engine")]
mod async_engine_impls {
    use super::*;
    use crate::symmetric::traits::{
        SymmetricAsyncParallelStreamingSystem, SymmetricAsyncStreamingSystem,
    };
    use tokio::io::{AsyncRead, AsyncWrite};

    impl SealEngine {
        /// [异步] 使用当前引擎的模式来流式加密（封印）一个数据流。
        pub async fn seal_stream_async<R, W>(
            &mut self,
            reader: R,
            writer: W,
            aad: Option<&[u8]>,
        ) -> Result<W, Error>
        where
            R: AsyncRead + Unpin + Send,
            W: AsyncWrite + Unpin + Send,
        {
            if self.key_manager.needs_rotation() {
                self.key_manager.start_rotation(&self.password)?;
            }
            let (header, dek) = self.build_header_and_dek()?;

            let mut header_bytes = header.encode_to_vec()?;
            let mut final_header = Vec::with_capacity(4 + header_bytes.len());
            final_header.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
            final_header.append(&mut header_bytes);

            let mut async_writer = writer;
            tokio::io::AsyncWriteExt::write_all(&mut async_writer, &final_header).await?;

            use crate::symmetric::systems::aes_gcm::{AesGcmKey, AesGcmSystem};
            let dek_key = AesGcmKey(dek);
            let streaming_config = &self.key_manager.config().streaming;

            let (_, writer) = AesGcmSystem::encrypt_stream_async(
                &dek_key,
                reader,
                async_writer,
                streaming_config,
                aad,
            )
            .await?;

            self.key_manager.increment_usage_count(&self.password)?;
            Ok(writer)
        }

        /// [异步] 使用当前引擎的模式来流式解密（解封）一个数据流。
        pub async fn unseal_stream_async<R, W>(
            &self,
            mut reader: R,
            writer: W,
            aad: Option<&[u8]>,
        ) -> Result<W, Error>
        where
            R: AsyncRead + Unpin + Send,
            W: AsyncWrite + Unpin + Send,
        {
            let header = self.read_and_parse_header_async(&mut reader).await?;
            let dek = self.derive_dek_from_header(&header)?;

            use crate::symmetric::systems::aes_gcm::{AesGcmKey, AesGcmSystem};
            let dek_key = AesGcmKey(dek);
            let streaming_config = &self.key_manager.config().streaming;

            let (_, writer) =
                AesGcmSystem::decrypt_stream_async(&dek_key, reader, writer, streaming_config, aad)
                    .await?;
            Ok(writer)
        }

        /// [异步/并行] 使用当前引擎的模式来流式加密（封印）一个数据流。
        pub async fn par_seal_stream_async<R, W>(
            &mut self,
            reader: R,
            mut writer: W,
            aad: Option<&[u8]>,
        ) -> Result<W, Error>
        where
            R: AsyncRead + Unpin + Send + 'static,
            W: AsyncWrite + Unpin + Send + 'static,
        {
            if self.key_manager.needs_rotation() {
                self.key_manager.start_rotation(&self.password)?;
            }
            let (header, dek) = self.build_header_and_dek()?;

            let mut header_bytes = header.encode_to_vec()?;
            let mut final_header = Vec::with_capacity(4 + header_bytes.len());
            final_header.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
            final_header.append(&mut header_bytes);

            tokio::io::AsyncWriteExt::write_all(&mut writer, &final_header).await?;

            use crate::symmetric::systems::aes_gcm::{AesGcmKey, AesGcmSystem};
            let dek_key = AesGcmKey(dek);
            let streaming_config = &self.key_manager.config().streaming;
            let parallelism_config = &self.key_manager.config().parallelism;

            let (_, writer) = AesGcmSystem::par_encrypt_stream_async(
                &dek_key,
                reader,
                writer,
                streaming_config,
                parallelism_config,
                aad,
            )
            .await?;

            self.key_manager.increment_usage_count(&self.password)?;
            Ok(writer)
        }

        /// [异步/并行] 使用当前引擎的模式来流式解密（解封）一个数据流。
        pub async fn par_unseal_stream_async<R, W>(
            &self,
            mut reader: R,
            writer: W,
            aad: Option<&[u8]>,
        ) -> Result<W, Error>
        where
            R: AsyncRead + Unpin + Send + 'static,
            W: AsyncWrite + Unpin + Send + 'static,
        {
            let header = self.read_and_parse_header_async(&mut reader).await?;
            let dek = self.derive_dek_from_header(&header)?;

            use crate::symmetric::systems::aes_gcm::{AesGcmKey, AesGcmSystem};
            let dek_key = AesGcmKey(dek);
            let streaming_config = &self.key_manager.config().streaming;
            let parallelism_config = &self.key_manager.config().parallelism;

            let (_, writer) = AesGcmSystem::par_decrypt_stream_async(
                &dek_key,
                reader,
                writer,
                streaming_config,
                parallelism_config,
                aad,
            )
            .await?;

            Ok(writer)
        }
    }
}

// In private.rs, or a new async_private.rs, we need an async version of read_and_parse_header
#[cfg(feature = "async-engine")]
impl SealEngine {
    /// [异步] 从输入流中读取并解析出一个 Header。
    pub(crate) async fn read_and_parse_header_async<R: tokio::io::AsyncRead + Unpin + Send>(
        &self,
        mut reader: R,
    ) -> Result<Header, Error> {
        let mut len_buf = [0u8; 4];
        tokio::io::AsyncReadExt::read_exact(&mut reader, &mut len_buf).await?;
        let header_len = u32::from_le_bytes(len_buf) as usize;

        let mut header_bytes = vec![0u8; header_len];
        tokio::io::AsyncReadExt::read_exact(&mut reader, &mut header_bytes).await?;
        let (header, _): (Header, _) = Header::decode_from_vec(&header_bytes)?;

        Ok(header)
    }
}
