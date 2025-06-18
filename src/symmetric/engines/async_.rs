#![cfg(feature = "async-engine")]

// --- BEGIN Top-level imports ---
// 这里只保留模块本身需要的 `use` 语句
use crate::common::errors::Error;
use crate::common::streaming::{StreamingConfig, StreamingResult};
use crate::symmetric::rotation::SymmetricKeyRotationManager;
use crate::symmetric::traits::{SymmetricAsyncStreamingSystem, SymmetricCryptographicSystem};
use secrecy::SecretString;
use std::marker::PhantomData;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
// --- END Top-level imports ---


/// `SymmetricQSealAsyncEngine`：一个支持密钥轮换的用户友好型异步对称加密引擎。
///
/// 该引擎通过 `Seal` 结构进行实例化，并由 `SymmetricKeyRotationManager` 在后台管理密钥。
/// 它能够自动使用最新的主密钥进行加密，并能解密由旧密钥加密的数据。
pub struct SymmetricQSealAsyncEngine<T>
where
    T: SymmetricCryptographicSystem + SymmetricAsyncStreamingSystem + Send + Sync + 'static,
    T::Key: Send + Sync,
    T::Error: std::error::Error + Send + Sync + 'static,
    Error: From<T::Error>,
{
    key_manager: SymmetricKeyRotationManager,
    password: SecretString,
    _phantom: PhantomData<T>,
}

impl<T> SymmetricQSealAsyncEngine<T>
where
    T: SymmetricCryptographicSystem + SymmetricAsyncStreamingSystem + Send + Sync + 'static,
    T::Key: Clone + Send + Sync,
    T::Error: std::error::Error + Send + Sync + 'static,
    Error: From<T::Error>,
{
    // ... （这里的方法实现保持不变） ...
    pub(crate) fn new(
        key_manager: SymmetricKeyRotationManager,
        password: SecretString,
    ) -> Self {
        Self {
            key_manager,
            password,
            _phantom: PhantomData,
        }
    }

    pub async fn encrypt(
        &mut self,
        plaintext: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<String, Error> {
        let primary_key = self
            .key_manager
            .get_primary_key::<T>()?
            .ok_or_else(|| Error::KeyManagement("No primary key available for encryption.".to_string()))?;
        let key_metadata = self
            .key_manager
            .get_primary_key_metadata()
            .ok_or_else(|| Error::KeyManagement("No primary key metadata available.".to_string()))?;
        let ciphertext_b64 = T::encrypt(&primary_key, plaintext, additional_data)?;
        let output = format!("{}:{}", key_metadata.id, ciphertext_b64);
        self.key_manager
            .increment_usage_count_async(&self.password)
            .await?;
        Ok(output)
    }

    pub async fn decrypt(
        &self,
        ciphertext: &str,
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        let parts: Vec<&str> = ciphertext.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(Error::Format(
                "Invalid ciphertext format. Expected 'key_id:ciphertext'".to_string(),
            ));
        }
        let key_id = parts[0];
        let actual_ciphertext = parts[1];
        let key = self
            .key_manager
            .derive_key_by_id::<T>(key_id)?
            .ok_or_else(|| {
                Error::KeyManagement(format!("Could not find or derive key for ID: {}", key_id))
            })?;
        T::decrypt(&key, actual_ciphertext, additional_data).map_err(Error::from)
    }

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
        let primary_key = self
            .key_manager
            .get_primary_key::<T>()?
            .ok_or_else(|| Error::KeyManagement("No primary key available for encryption.".to_string()))?;
        let key_metadata = self
            .key_manager
            .get_primary_key_metadata()
            .ok_or_else(|| Error::KeyManagement("No primary key metadata available.".to_string()))?;
        writer.write_all(key_metadata.id.as_bytes()).await?;
        writer.write_all(b":").await?;
        let result = T::encrypt_stream_async(&primary_key, &mut reader, &mut writer, config, None).await?;
        self.key_manager
            .increment_usage_count_async(&self.password)
            .await?;
        Ok(result)
    }

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
        let key = self
            .key_manager
            .derive_key_by_id::<T>(&key_id)?
            .ok_or_else(|| {
                Error::KeyManagement(format!("Could not find or derive key for ID: {}", key_id))
            })?;
        T::decrypt_stream_async(&key, &mut reader, &mut writer, config, None).await
    }
}

#[cfg(all(test, feature = "aes-gcm-feature"))]
mod tests {
    // --- BEGIN Test-specific imports ---
    // 这里是只在测试中使用的 `use` 语句
    use super::*;
    use crate::seal::Seal;
    use crate::symmetric::systems::aes_gcm::AesGcmSystem;
    use std::io::Cursor;
    use std::sync::Arc;
    use tempfile::{tempdir, TempDir};
    // --- END Test-specific imports ---


    // 辅助函数：设置一个全新的 Seal 和密码
    async fn setup() -> (Arc<Seal>, SecretString, TempDir) {
        let dir = tempdir().unwrap();
        let seal_path = dir.path().join("my.seal");
        // 注意这里修正了 SecretString 的创建方式
        let password = SecretString::new("a-very-secret-password".to_string().into_boxed_str());
        let seal = Seal::create(&seal_path, &password).unwrap();
        (seal, password, dir)
    }

    #[tokio::test]
    async fn test_engine_encrypt_decrypt_roundtrip() {
        let (seal, password, _dir) = setup().await;
        let mut engine = seal
            .symmetric_async_engine::<AesGcmSystem>(password)
            .await
            .unwrap();

        let plaintext = b"some secret data";
        let encrypted = engine.encrypt(plaintext, None).await.unwrap();
        let decrypted = engine.decrypt(&encrypted, None).await.unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_decryption_after_reopening_seal() {
        let dir = tempdir().unwrap();
        let seal_path = dir.path().join("my.seal");
        // 注意这里修正了 SecretString 的创建方式
        let password = SecretString::new("a-very-secret-password".to_string().into_boxed_str());

        // 1. 创建 Seal，获取引擎，加密数据
        let seal1 = Seal::create(&seal_path, &password).unwrap();
        let mut engine1 = seal1
            .symmetric_async_engine::<AesGcmSystem>(password.clone())
            .await
            .unwrap();
        let plaintext = b"some secret data";
        let encrypted = engine1.encrypt(plaintext, None).await.unwrap();

        // 2. 重新打开同一个 Seal，获取新引擎
        let seal2 = Seal::open(&seal_path, &password).unwrap();
        let engine2 = seal2
            .symmetric_async_engine::<AesGcmSystem>(password)
            .await
            .unwrap();

        // 3. 用新引擎解密旧数据，应该成功
        let decrypted = engine2.decrypt(&encrypted, None).await.unwrap();
        assert_eq!(decrypted, plaintext);
    }
    
    // ... （其他测试保持不变） ...
    #[tokio::test]
    async fn test_engine_streaming_roundtrip() {
        let (seal, password, _dir) = setup().await;
        let mut engine = seal
            .symmetric_async_engine::<AesGcmSystem>(password)
            .await
            .unwrap();

        let plaintext = b"some secret data for streaming";
        let mut reader = Cursor::new(plaintext);
        let mut encrypted_writer = Cursor::new(Vec::new());
        let config = StreamingConfig::default();

        engine
            .encrypt_stream(&mut reader, &mut encrypted_writer, &config)
            .await
            .unwrap();

        let mut encrypted_reader = Cursor::new(encrypted_writer.into_inner());
        let mut decrypted_writer = Cursor::new(Vec::new());
        engine
            .decrypt_stream(&mut encrypted_reader, &mut decrypted_writer, &config)
            .await
            .unwrap();

        assert_eq!(decrypted_writer.into_inner(), plaintext.to_vec());
    }
}