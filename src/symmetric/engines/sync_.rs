//! 对称加密引擎 `SymmetricQSealEngine`
use std::sync::{Arc, Mutex};
use std::io::{Read, Write};
use crate::common::errors::Error;
use crate::common::utils::CryptoConfig;
use crate::common::streaming::{StreamingConfig, StreamingResult};
use crate::rotation::{KeyStorage, RotationPolicy};
use crate::symmetric::rotation::SymmetricKeyRotationManager;
use crate::symmetric::traits::{SymmetricCryptographicSystem, SymmetricSyncStreamingSystem};
/// `SymmetricQSealEngine`：一个使用对称加密算法并支持密钥自动轮换的用户友好引擎。
///
/// 该引擎泛型于一个 `SymmetricCryptographicSystem`，负责处理所有的密钥管理、
/// 加密和解密操作，为上层应用提供一个简单统一的接口。
pub struct SymmetricQSealEngine<T: SymmetricCryptographicSystem + SymmetricSyncStreamingSystem>
where
    T::Error: std::error::Error + 'static,
    Error: From<T::Error>,
{
    key_manager: Arc<Mutex<SymmetricKeyRotationManager<T>>>,
    config: CryptoConfig,
}

impl<T: SymmetricCryptographicSystem + SymmetricSyncStreamingSystem> SymmetricQSealEngine<T>
where
    T::Error: std::error::Error + 'static,
    Error: From<T::Error>,
{
    /// 创建一个新的 `SymmetricQSealEngine` 实例。
    ///
    /// # 参数
    /// * `config`: 加密配置。
    /// * `rotation_policy`: 密钥轮换策略。
    /// * `key_storage`: 密钥存储的实现。
    /// * `key_prefix`: 用于在存储中标识该引擎密钥的前缀。
    ///
    /// # 返回
    /// 返回一个初始化好的 `SymmetricQSealEngine` 实例。
    pub fn new(
        config: CryptoConfig,
        rotation_policy: RotationPolicy,
        key_storage: Arc<dyn KeyStorage>,
        key_prefix: &str,
    ) -> Result<Self, Error> {
        let mut key_manager = SymmetricKeyRotationManager::new(
            key_storage,
            rotation_policy,
            key_prefix,
        );
        key_manager.initialize(&config)?;

        Ok(Self {
            key_manager: Arc::new(Mutex::new(key_manager)),
            config,
        })
    }

    /// 加密一段明文。
    ///
    /// 该方法会自动处理密钥轮换检查，并使用当前的主密钥进行加密。
    ///
    /// # 参数
    /// * `plaintext`: 要加密的明文数据。
    /// * `additional_data`: （可选）附加数据，将参与认证但不会被加密。
    ///
    /// # 返回
    /// 成功时返回加密后的密文（Base64 编码的字符串），失败时返回错误。
    pub fn encrypt(&self, plaintext: &[u8], additional_data: Option<&[u8]>) -> Result<String, Error> {
        let mut manager = self.key_manager.lock().unwrap();

        // 在加密前检查是否需要轮换
        if manager.needs_rotation() {
            manager.start_rotation(&self.config)?;
        }

        let key = manager.get_primary_key()
            .ok_or_else(|| Error::Operation("没有可用的主密钥进行加密".to_string()))?;

        let ciphertext = T::encrypt(key, plaintext, additional_data)
            .map_err(|e| Error::Operation(format!("加密失败: {}", e)))?;

        // 增加使用计数
        manager.increment_usage_count()?;

        Ok(ciphertext.to_string())
    }

    /// 解密一段密文。
    ///
    /// 该方法会尝试使用引擎中管理的所有密钥（包括主密钥和次要密钥）进行解密，
    /// 直到成功为止。这确保了在密钥轮换后，由旧密钥加密的数据仍然可以被解密。
    ///
    /// # 参数
    /// * `ciphertext`: 要解密的密文（Base64 编码的字符串）。
    /// * `additional_data`: （可选）附加数据。
    ///
    /// # 返回
    /// 成功时返回解密后的明文，如果所有密钥都无法解密，则返回错误。
    pub fn decrypt(&self, ciphertext: &str, additional_data: Option<&[u8]>) -> Result<Vec<u8>, Error> {
        let manager = self.key_manager.lock().unwrap();
        let keys = manager.get_all_keys();

        if keys.is_empty() {
            return Err(Error::Operation("没有可用的密钥进行解密".to_string()));
        }

        for key in keys {
            if let Ok(plaintext) = T::decrypt(key, ciphertext, additional_data) {
                return Ok(plaintext);
            }
        }

        Err(Error::Operation("解密失败，所有可用密钥都无法解密该密文".to_string()))
    }

    /// 同步流式加密
    ///
    /// # 参数
    /// * `reader`: 从中读取明文的输入流。
    /// * `writer`: 将加密数据写入的输出流。
    /// * `config`: 流处理配置。
    ///
    /// # 返回
    /// 成功时返回处理结果，失败时返回错误。
    pub fn encrypt_stream<R: Read, W: Write>(
        &self,
        reader: R,
        writer: W,
        config: &StreamingConfig,
    ) -> Result<StreamingResult, Error> {
        let mut manager = self.key_manager.lock().unwrap();

        if manager.needs_rotation() {
            manager.start_rotation(&self.config)?;
        }

        // 克隆主密钥以释放对 `manager` 的借用
        let key = manager.get_primary_key()
            .map(|k| k.clone())
            .ok_or_else(|| Error::Operation("没有可用的主密钥进行加密".to_string()))?;
        
        // 现在可以安全地可变借用 manager
        manager.increment_usage_count()?;
        
        // 使用克隆的密钥进行流式加密
        T::encrypt_stream(&key, reader, writer, config, None)
    }

    /// 同步流式解密
    ///
    /// 注意：此方法当前只使用主密钥进行解密。对于需要使用旧密钥解密的场景，
    /// 流协议本身需要包含密钥标识符。
    ///
    /// # 参数
    /// * `reader`: 从中读取密文的输入流。
    /// * `writer`: 将解密数据写入的输出流。
    /// * `config`: 流处理配置。
    ///
    /// # 返回
    /// 成功时返回处理结果，失败时返回错误。
    pub fn decrypt_stream<R: Read, W: Write>(
        &self,
        reader: R,
        writer: W,
        config: &StreamingConfig,
    ) -> Result<StreamingResult, Error> {
        let manager = self.key_manager.lock().unwrap();

        // 克隆密钥以释放借用
        let key = manager.get_primary_key()
            .map(|k| k.clone())
            .ok_or_else(|| Error::Operation("没有可用的主密钥进行解密".to_string()))?;
        
        T::decrypt_stream(&key, reader, writer, config, None)
    }
} 