//! Q-Seal核心引擎，提供统一的高级API
use crate::asymmetric::rotation::AsymmetricKeyRotationManager;
use crate::asymmetric::traits::{AsymmetricCryptographicSystem, AsymmetricSyncStreamingSystem};
use crate::common::errors::Error;
use crate::common::streaming::{StreamingConfig, StreamingResult};
use crate::symmetric::traits::SymmetricSyncStreamingSystem;
use secrecy::SecretString;
use std::io::{Read, Write};
use std::marker::PhantomData;

/// `AsymmetricQSealEngine`：一个支持密钥轮换的用户友好型非对称加密引擎。
///
/// 该引擎通过 `Seal` 结构进行实例化，并由 `AsymmetricKeyRotationManager` 在后台管理密钥。
/// 它能够自动使用最新的主密钥进行加密，并能解密由旧密钥加密的数据。
pub struct AsymmetricQSealEngine<T>
where
    T: AsymmetricCryptographicSystem + AsymmetricSyncStreamingSystem,
    T::Error: std::error::Error + 'static,
    Error: From<T::Error>,
{
    key_manager: AsymmetricKeyRotationManager,
    password: SecretString,
    _phantom: PhantomData<T>,
}

impl<T> AsymmetricQSealEngine<T>
where
    T: AsymmetricCryptographicSystem + AsymmetricSyncStreamingSystem,
    T::Error: std::error::Error + 'static,
    Error: From<T::Error>,
{
    /// 使用密钥管理器创建一个新的引擎实例。
    /// 这个方法是 crate-internal 的，只能通过 `Seal` 结构调用。
    pub(crate) fn new(key_manager: AsymmetricKeyRotationManager, password: SecretString) -> Self {
        Self {
            key_manager,
            password,
            _phantom: PhantomData,
        }
    }

    /// 加密数据。
    ///
    /// 自动处理密钥选择、使用计数更新和必要的密钥轮换。
    /// 密文将包含用于加密的密钥ID，格式为 `key_id:ciphertext`。
    pub fn encrypt(&mut self, data: &[u8]) -> Result<String, Error> {
        // 1. 检查是否需要轮换
        if self.key_manager.needs_rotation() {
            self.key_manager.start_rotation::<T>(&self.password)?;
        }

        // 2. 获取主公钥用于加密
        let key_metadata = self.key_manager.get_primary_key_metadata().ok_or_else(|| {
            Error::KeyManagement("No primary key metadata available.".to_string())
        })?;
        let public_key = self
            .key_manager
            .get_public_key_by_id::<T>(&key_metadata.id)?
            .ok_or_else(|| Error::Key("Could not find or derive public key.".to_string()))?;

        // 3. 加密数据
        let ciphertext = T::encrypt(&public_key, data, None)?;
        let output = format!("{}:{}", key_metadata.id, ciphertext.to_string());

        // 4. 增加使用计数
        self.key_manager.increment_usage_count(&self.password)?;

        Ok(output)
    }

    /// 解密数据。
    ///
    /// 期望的密文格式为 `key_id:ciphertext`。
    pub fn decrypt(&self, ciphertext: &str) -> Result<Vec<u8>, Error> {
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

    /// 同步流式加密
    pub fn encrypt_stream<S, R, W>(
        &mut self,
        mut reader: R,
        mut writer: W,
        config: &StreamingConfig,
    ) -> Result<StreamingResult, Error>
    where
        S: SymmetricSyncStreamingSystem,
        Error: From<S::Error>,
        R: Read,
        W: Write,
    {
        // 1. 检查是否需要轮换
        if self.key_manager.needs_rotation() {
            self.key_manager.start_rotation::<T>(&self.password)?;
        }

        // 2. 获取主公钥
        let key_metadata = self.key_manager.get_primary_key_metadata().ok_or_else(|| {
            Error::KeyManagement("No primary key metadata available.".to_string())
        })?;
        let public_key = self
            .key_manager
            .get_public_key_by_id::<T>(&key_metadata.id)?
            .ok_or_else(|| Error::Key("Could not find or derive public key.".to_string()))?;

        // 3. 将 key_id 写入流的开头
        writer.write_all(key_metadata.id.as_bytes())?;
        writer.write_all(b":")?;

        // 4. 流式加密剩余数据
        let result =
            T::encrypt_stream::<S, _, _>(&public_key, &mut reader, &mut writer, config, None)?;

        // 5. 增加使用计数
        self.key_manager.increment_usage_count(&self.password)?;

        Ok(result)
    }

    /// 同步流式解密
    pub fn decrypt_stream<S, R, W>(
        &self,
        mut reader: R,
        mut writer: W,
        config: &StreamingConfig,
    ) -> Result<StreamingResult, Error>
    where
        S: SymmetricSyncStreamingSystem,
        Error: From<S::Error>,
        R: Read,
        W: Write,
    {
        // 1. 从流中读取 key_id
        let mut key_id_buf = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            reader.read_exact(&mut byte)?;
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
        T::decrypt_stream::<S, _, _>(&private_key, &mut reader, &mut writer, config, None)
    }
}
