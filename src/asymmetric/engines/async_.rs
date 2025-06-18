//! 异步非对称加密引擎
#![cfg(feature = "async-engine")]

use crate::asymmetric::rotation::AsymmetricKeyRotationManager;
use crate::common::errors::Error;
use crate::common::streaming::{StreamingConfig, StreamingResult};
use secrecy::SecretString;
use std::marker::PhantomData;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use crate::asymmetric::traits::AsyncStreamingSystem;

/// `AsymmetricQSealAsyncEngine`：一个支持密钥轮换的用户友好型异步非对称加密引擎。
///
/// 该引擎通过 `Seal` 结构进行实例化，并由 `AsymmetricKeyRotationManager` 在后台管理密钥。
/// 它能够自动使用最新的主密钥进行加密，并能解密由旧密钥加密的数据。
/// 所有涉及 I/O 的操作（如密钥轮换）都是异步的。
pub struct AsymmetricQSealAsyncEngine<T>
where
    T: AsyncStreamingSystem + Send + Sync + 'static,
    T::PublicKey: Send + Sync,
    T::PrivateKey: Send + Sync,
    T::Error: std::error::Error + Send + Sync + 'static,
    Error: From<T::Error>,
{
    key_manager: AsymmetricKeyRotationManager,
    password: SecretString,
    _phantom: PhantomData<T>,
}

impl<T> AsymmetricQSealAsyncEngine<T>
where
    T: AsyncStreamingSystem + Send + Sync + 'static,
    T::PublicKey: Send + Sync,
    T::PrivateKey: Send + Sync,
    T::Error: std::error::Error + Send + Sync + 'static,
    Error: From<T::Error>,
{
    /// 使用密钥管理器创建一个新的引擎实例。
    /// 这个方法是 crate-internal 的，只能通过 `Seal` 结构调用。
    pub(crate) fn new(
        key_manager: AsymmetricKeyRotationManager,
        password: SecretString,
    ) -> Self {
        Self {
            key_manager,
            password,
            _phantom: PhantomData,
        }
    }

    /// 异步加密数据。
    ///
    /// 自动处理密钥选择、使用计数更新和必要的密钥轮换（异步）。
    /// 密文将包含用于加密的密钥ID，格式为 `key_id:ciphertext`。
    pub async fn encrypt(&mut self, data: &[u8]) -> Result<String, Error> {
        // 1. 检查是否需要轮换
        if self.key_manager.needs_rotation() {
            self.key_manager
                .start_rotation_async::<T>(&self.password)
                .await?;
        }

        // 2. 获取主公钥用于加密
        let key_metadata = self
            .key_manager
            .get_primary_key_metadata()
            .ok_or_else(|| Error::KeyManagement("No primary key metadata available.".to_string()))?;
        let public_key = self
            .key_manager
            .get_public_key_by_id::<T>(&key_metadata.id)?
            .ok_or_else(|| Error::Key("Could not find or derive public key.".to_string()))?;

        // 3. 加密数据
        let ciphertext = T::encrypt(&public_key, data, None)?;
        let output = format!("{}:{}", key_metadata.id, ciphertext.to_string());

        // 4. 增加使用计数
        self.key_manager
            .increment_usage_count_async(&self.password)
            .await?;

        Ok(output)
    }

    /// 异步解密数据。
    ///
    /// 期望的密文格式为 `key_id:ciphertext`。
    /// 此操作不涉及I/O，因此在异步上下文中可以阻塞执行，但为保持API一致性，我们返回一个Future。
    pub async fn decrypt(&self, ciphertext: &str) -> Result<Vec<u8>, Error> {
        // 1. 从密文中解析出 key_id
        let parts: Vec<&str> = ciphertext.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(Error::Format(
                "Invalid ciphertext format. Expected 'key_id:ciphertext'".to_string(),
            ));
        }
        let key_id = parts[0];
        let actual_ciphertext = parts[1];

        // 2. 根据 key_id 获取密钥对
        let (_, private_key) = self
            .key_manager
            .get_keypair_by_id::<T>(key_id)?
            .ok_or_else(|| {
                Error::KeyManagement(format!("Could not find or derive key for ID: {}", key_id))
            })?;

        // 3. 解密数据
        T::decrypt(&private_key, actual_ciphertext, None).map_err(Error::from)
    }

    /// 异步流式加密
    pub async fn encrypt_stream<R, W>(
        &mut self,
        mut reader: R,
        mut writer: W,
        config: &StreamingConfig,
    ) -> Result<StreamingResult, Error>
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send,
    {
        // 1. 检查是否需要轮换
        if self.key_manager.needs_rotation() {
            self.key_manager
                .start_rotation_async::<T>(&self.password)
                .await?;
        }

        // 2. 获取主公钥
        let key_metadata = self
            .key_manager
            .get_primary_key_metadata()
            .ok_or_else(|| Error::KeyManagement("No primary key metadata available.".to_string()))?;
        let public_key = self
            .key_manager
            .get_public_key_by_id::<T>(&key_metadata.id)?
            .ok_or_else(|| Error::Key("Could not find or derive public key.".to_string()))?;

        // 3. 将 key_id 写入流的开头
        writer.write_all(key_metadata.id.as_bytes()).await?;
        writer.write_all(b":").await?;

        // 4. 流式加密剩余数据
        let result =
            T::encrypt_stream_async(&public_key, &mut reader, &mut writer, config, None).await?;

        // 5. 增加使用计数
        self.key_manager
            .increment_usage_count_async(&self.password)
            .await?;

        Ok(result)
    }

    /// 异步流式解密
    pub async fn decrypt_stream<R, W>(
        &self,
        mut reader: R,
        mut writer: W,
        config: &StreamingConfig,
    ) -> Result<StreamingResult, Error>
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send,
    {
        // 1. 从流中读取 key_id
        let mut key_id_buf = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            reader.read_exact(&mut byte).await?;
            if byte[0] == b':' {
                break;
            }
            key_id_buf.push(byte[0]);
        }
        let key_id = String::from_utf8(key_id_buf)
            .map_err(|_| Error::Format("Key ID in stream is not valid UTF-8.".to_string()))?;

        // 2. 根据 key_id 获取密钥对
        let (_, private_key) = self
            .key_manager
            .get_keypair_by_id::<T>(&key_id)?
            .ok_or_else(|| {
                Error::KeyManagement(format!("Could not find or derive key for ID: {}", key_id))
            })?;

        // 3. 解密剩余的流数据
        T::decrypt_stream_async(&private_key, &mut reader, &mut writer, config, None).await
    }
}

#[cfg(all(test, feature = "post-quantum", feature = "async-engine"))]
mod tests {
    use super::*;
    use crate::asymmetric::systems::hybrid::rsa_kyber::RsaKyberCryptoSystem;
    use crate::seal::Seal;
    use secrecy::SecretString;
    use std::sync::Arc;
    use tempfile::{tempdir, TempDir};

    type TestEngine = AsymmetricQSealAsyncEngine<RsaKyberCryptoSystem>;

    async fn setup() -> (Arc<Seal>, SecretString, TempDir) {
        let dir = tempdir().unwrap();
        let seal_path = dir.path().join("my.seal");
        let password = SecretString::new("a-very-secret-password".to_string().into_boxed_str());
        let seal = Seal::create(&seal_path, &password).unwrap();
        (seal, password, dir)
    }

    #[tokio::test]
    async fn test_engine_encrypt_decrypt_roundtrip() {
        let (seal, password, _dir) = setup().await;
        let mut engine = seal
            .asymmetric_async_engine::<RsaKyberCryptoSystem>(password)
            .await
            .unwrap();

        let plaintext = b"some very secret data";
        let encrypted = engine.encrypt(plaintext).await.unwrap();
        let decrypted = engine.decrypt(&encrypted).await.unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_engine_streaming_roundtrip() {
        let (seal, password, _dir) = setup().await;
        let mut engine = seal
            .asymmetric_async_engine::<RsaKyberCryptoSystem>(password)
            .await
            .unwrap();

        let plaintext = b"some very long secret data for streaming";
        let mut reader = tokio::io::BufReader::new(plaintext.as_ref());
        let mut encrypted_writer = tokio::io::BufWriter::new(Vec::new());

        let config = StreamingConfig::default();
        engine
            .encrypt_stream(&mut reader, &mut encrypted_writer, &config)
            .await
            .unwrap();
        
        // Use into_inner to get the underlying Vec<u8> from the writer.
        let encrypted_data = encrypted_writer.into_inner();

        let mut encrypted_reader = tokio::io::BufReader::new(encrypted_data.as_slice());
        let mut decrypted_writer = tokio::io::BufWriter::new(Vec::new());
        engine
            .decrypt_stream(&mut encrypted_reader, &mut decrypted_writer, &config)
            .await
            .unwrap();
        
        let decrypted_data = decrypted_writer.into_inner();

        assert_eq!(decrypted_data, plaintext.to_vec());
    }
}