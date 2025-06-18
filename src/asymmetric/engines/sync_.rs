//! Q-Seal核心引擎，提供统一的高级API
//!
//! 该模块封装了密钥管理、轮换、加解密等复杂性，为用户提供一个简洁的入口。

use std::path::Path;
use std::sync::Arc;
use std::io::{Read, Write};
use crate::asymmetric::traits::{AsymmetricCryptographicSystem, AsymmetricSyncStreamingSystem};
use crate::common::config::ConfigManager;
use crate::common::errors::Error;
use crate::asymmetric::rotation::KeyRotationManager;
use crate::storage::KeyFileStorage;
use crate::common::traits::AuthenticatedCryptoSystem;
use crate::common::streaming::{StreamingConfig, StreamingResult};

/// Q-Seal核心引擎
///
/// 这是一个高级API，它封装了所有底层组件，提供了一个简单、统一的接口。
/// `C` 是一个实现了 `CryptographicSystem` 和 `SyncStreamingSystem` 特征的加密系统类型。
pub struct AsymmetricQSealEngine<C: AsymmetricCryptographicSystem + AsymmetricSyncStreamingSystem>
where
    // 确保引擎内可以处理其使用的加密系统的错误
    Error: From<<C as AsymmetricCryptographicSystem>::Error>
{
    /// 配置管理器
    config: Arc<ConfigManager>,
    /// 单线程模式下直接持有轮换管理器
    key_manager: KeyRotationManager<C>,
}

impl<C: AsymmetricCryptographicSystem + AsymmetricSyncStreamingSystem> AsymmetricQSealEngine<C>
where
    Error: From<<C as AsymmetricCryptographicSystem>::Error>,
    <C as AsymmetricCryptographicSystem>::Error: std::error::Error + 'static,
{
    /// 使用指定的配置管理器创建一个新的引擎实例
    ///
    /// # 参数
    ///
    /// * `config_manager` - 一个 `Arc<ConfigManager>`，包含了所有配置信息。
    /// * `key_prefix` - 用于此引擎实例的密钥名称前缀，例如 "user_keys" 或 "document_keys"。
    pub fn new(config_manager: Arc<ConfigManager>, key_prefix: &str) -> Result<Self, Error> {
        // 从配置中获取存储配置
        let storage_config = config_manager.get_storage_config();
        
        // 创建密钥文件存储实例
        let key_storage = Arc::new(KeyFileStorage::new(&storage_config.key_storage_dir)?);
        
        // 从配置中获取轮换策略
        let rotation_policy = config_manager.get_rotation_policy();
        
        // 创建并初始化密钥轮换管理器
        let mut key_manager = KeyRotationManager::<C>::new(
            key_storage,
            rotation_policy,
            key_prefix
        );
        key_manager.initialize(&config_manager.get_crypto_config())?;
        
        Ok(Self {
            config: config_manager,
            key_manager,
        })
    }
    
    /// 从配置文件路径创建一个新的引擎实例
    ///
    /// # 参数
    ///
    /// * `path` - 配置文件的路径。
    /// * `key_prefix` - 用于此引擎实例的密钥名称前缀。
    pub fn from_file<P: AsRef<Path>>(path: P, key_prefix: &str) -> Result<Self, Error> {
        let config_manager = Arc::new(ConfigManager::from_file(path)?);
        Self::new(config_manager, key_prefix)
    }

    /// 使用默认配置创建一个新的引擎实例
    ///
    /// # 参数
    ///
    /// * `key_prefix` - 用于此引擎实例的密钥名称前缀。
    pub fn with_defaults(key_prefix: &str) -> Result<Self, Error> {
        let config_manager = Arc::new(ConfigManager::new());
        Self::new(config_manager, key_prefix)
    }
    
    /// 返回一个构造器以创建引擎
    pub fn builder() -> QSealEngineBuilder<C> {
        QSealEngineBuilder::new()
    }
    
    /// 加密数据
    ///
    /// 自动处理密钥选择、使用计数更新和必要的密钥轮换。
    pub fn encrypt(&mut self, data: &[u8]) -> Result<String, Error> {
        let manager = &mut self.key_manager;
        
        // 检查是否需要轮换
        if manager.needs_rotation() {
            manager.start_rotation(&self.config.get_crypto_config())?;
        }
        
        // 获取主密钥的克隆，从而立即释放对manager的不可变借用
        let public_key = manager.get_primary_key()
            .map(|(pk, _)| pk.clone())
            .ok_or_else(|| Error::Key("没有可用的主加密密钥".to_string()))?;
            
        // 现在可以安全地对manager进行可变借用
        manager.increment_usage_count()?;
        
        // 使用克隆的密钥执行加密
        let ciphertext = C::encrypt(&public_key, data, None)?;
        
        Ok(ciphertext.to_string())
    }
    
    /// 解密数据
    ///
    /// 自动尝试使用主密钥和所有次要密钥进行解密，直到成功为止。
    pub fn decrypt(&mut self, ciphertext: &str) -> Result<Vec<u8>, Error> {
        let manager = &mut self.key_manager;
        
        // 首先尝试使用主密钥解密
        if let Some((_, private_key)) = manager.get_primary_key() {
            if let Ok(plaintext) = C::decrypt(private_key, ciphertext, None) {
                return Ok(plaintext);
            }
        }
        
        // 如果主密钥失败，遍历次要密钥尝试解密
        for (_, private_key, _) in manager.get_secondary_keys() {
            if let Ok(plaintext) = C::decrypt(private_key, ciphertext, None) {
                return Ok(plaintext);
            }
        }
        
        Err(Error::Operation("解密失败：所有可用密钥都无法解密该密文".to_string()))
    }
    
    /// 同步流式加密
    pub fn encrypt_stream<R: Read, W: Write>(
        &mut self,
        reader: R,
        writer: W,
        config: &StreamingConfig,
    ) -> Result<StreamingResult, Error> {
        let manager = &mut self.key_manager;
        if manager.needs_rotation() {
            manager.start_rotation(&self.config.get_crypto_config())?;
        }
        let public_key = manager.get_primary_key()
            .map(|(pk, _)| pk.clone())
            .ok_or_else(|| Error::Key("没有可用的主加密密钥".to_string()))?;
        manager.increment_usage_count()?;
        
        C::encrypt_stream(&public_key, reader, writer, config, None)
            .map_err(Into::into)
    }

    /// 同步流式解密
    pub fn decrypt_stream<R: Read, W: Write>(
        &mut self,
        reader: R,
        writer: W,
        config: &StreamingConfig,
    ) -> Result<StreamingResult, Error> {
        let manager = &mut self.key_manager;

        // 注意：流式解密无法像块解密一样轻易地"尝试"多个密钥。
        // 一个简单的实现是只使用主密钥。
        // 更复杂的实现需要协议层支持，比如在流的开头包含密钥ID。
        // 这里我们选择只用主密钥进行解密。
        let private_key = manager.get_primary_key()
            .map(|(_, sk)| sk.clone())
            .ok_or_else(|| Error::Key("没有可用的主解密密钥".to_string()))?;

        C::decrypt_stream(&private_key, reader, writer, config, None)
            .map_err(Into::into)
    }

    /// 获取当前的配置管理器
    pub fn config(&self) -> Arc<ConfigManager> {
        Arc::clone(&self.config)
    }
}

impl<C: AuthenticatedCryptoSystem> AsymmetricQSealEngine<C>
where
    Error: From<<C as AsymmetricCryptographicSystem>::Error>,
    <C as AsymmetricCryptographicSystem>::Error: std::error::Error + 'static,
{
    /// 带认证的加密: 根据配置执行必要的轮换并可选签名
    pub fn encrypt_authenticated(&mut self, plaintext: &[u8]) -> Result<String, Error> {
        let manager = &mut self.key_manager;
        
        // 检查并执行轮换
        if manager.needs_rotation() {
            manager.start_rotation(&self.config.get_crypto_config())?;
        }
        
        // 克隆公私钥
        let (public_key, private_key) = manager.get_primary_key()
            .map(|(pk, sk)| (pk.clone(), sk.clone()))
            .ok_or_else(|| Error::Key("没有可用的主加密密钥".to_string()))?;
        
        // 更新使用计数
        manager.increment_usage_count()?;
        
        // 根据配置决定是否签名
        let cfg = self.config.get_crypto_config();
        let signer = if cfg.use_authenticated_encryption {
            Some(&private_key)
        } else {
            None
        };
        let auth_output = C::encrypt_authenticated(&public_key, plaintext, None, signer)
            .map_err(Into::into)?;
        Ok(auth_output.to_string())
    }

    /// 带认证的解密: 根据配置执行必要的轮换并可选校验签名
    pub fn decrypt_authenticated(&mut self, ciphertext: &str) -> Result<Vec<u8>, Error> {
        let manager = &mut self.key_manager;
        
        // 获取配置
        let cfg = self.config.get_crypto_config();
        
        // 首先尝试使用主密钥解密并可选验证签名
        if let Some((public_key, private_key)) = manager.get_primary_key() {
            let verifier = if cfg.auto_verify_signatures {
                Some(public_key)
            } else {
                None
            };
            if let Ok(plaintext) = C::decrypt_authenticated(private_key, ciphertext, None, verifier) {
                return Ok(plaintext);
            }
        }
        
        // 如果主密钥失败，遍历次要密钥尝试解密（不验证签名）
        for (_, private_key, _) in manager.get_secondary_keys() {
            if let Ok(plaintext) = C::decrypt_authenticated(private_key, ciphertext, None, None) {
                return Ok(plaintext);
            }
        }
        
        Err(Error::Operation("解密失败：所有可用密钥都无法解密该密文".to_string()))
    }
}

/// `QSealEngine` 的构造器
pub struct QSealEngineBuilder<C: AsymmetricCryptographicSystem + AsymmetricSyncStreamingSystem>
where
    Error: From<<C as AsymmetricCryptographicSystem>::Error>,
    <C as AsymmetricCryptographicSystem>::Error: std::error::Error + 'static,
{
    config_manager: Option<Arc<ConfigManager>>,
    key_prefix: Option<String>,
    _phantom: std::marker::PhantomData<C>,
}

impl<C: AsymmetricCryptographicSystem + AsymmetricSyncStreamingSystem> QSealEngineBuilder<C>
where
    Error: From<<C as AsymmetricCryptographicSystem>::Error>,
    <C as AsymmetricCryptographicSystem>::Error: std::error::Error + 'static,
{
    /// 创建一个新的构造器
    pub fn new() -> Self {
        Self {
            config_manager: None,
            key_prefix: None,
            _phantom: std::marker::PhantomData,
        }
    }

    /// 使用现有的 `ConfigManager`
    pub fn with_config_manager(mut self, config_manager: Arc<ConfigManager>) -> Self {
        self.config_manager = Some(config_manager);
        self
    }

    /// 从配置文件加载配置
    pub fn with_config_file<P: AsRef<Path>>(mut self, path: P) -> Result<Self, Error> {
        let config_manager = Arc::new(ConfigManager::from_file(path)?);
        self.config_manager = Some(config_manager);
        Ok(self)
    }

    /// 设置密钥前缀
    pub fn with_key_prefix(mut self, prefix: &str) -> Self {
        self.key_prefix = Some(prefix.to_string());
        self
    }

    /// 动态设置存储目录
    pub fn with_storage_dir(self, dir: &str) -> Result<Self, Error> {
        let mut cm = self.config_manager.clone().unwrap_or_else(|| Arc::new(ConfigManager::new()));
        let mut storage_config = cm.get_storage_config();
        storage_config.key_storage_dir = dir.to_string();
        Arc::get_mut(&mut cm).unwrap().update_storage_config(storage_config)?;
        Ok(Self {
            config_manager: Some(cm),
            key_prefix: self.key_prefix,
            _phantom: self._phantom,
        })
    }

    /// 动态设置 Argon2 参数
    pub fn with_argon2_params(self, mem_cost: u32, time_cost: u32) -> Result<Self, Error> {
        let mut cm = self.config_manager.clone().unwrap_or_else(|| Arc::new(ConfigManager::new()));
        let mut crypto_config = cm.get_crypto_config();
        crypto_config.argon2_memory_cost = mem_cost;
        crypto_config.argon2_time_cost = time_cost;
        Arc::get_mut(&mut cm).unwrap().update_crypto_config(crypto_config)?;
        Ok(Self {
            config_manager: Some(cm),
            key_prefix: self.key_prefix,
            _phantom: self._phantom,
        })
    }

    /// 构建 `QSealEngine`
    pub fn build(self) -> Result<AsymmetricQSealEngine<C>, Error> {
        let cm = self.config_manager.unwrap_or_else(|| Arc::new(ConfigManager::new()));
        let prefix = self.key_prefix.ok_or_else(|| Error::Operation("Key prefix must be set".to_string()))?;
        AsymmetricQSealEngine::new(cm, &prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asymmetric::systems::hybrid::rsa_kyber::RsaKyberCryptoSystem;
    use crate::common::config::{ConfigFile, StorageConfig};
    use std::io::Cursor;
    use tempfile::tempdir;
    use crate::rotation::RotationPolicy;

    type TestEngine = AsymmetricQSealEngine<RsaKyberCryptoSystem>;

    fn setup_test_engine(dir: &Path, key_prefix: &str) -> TestEngine {
        let storage_config = StorageConfig {
            key_storage_dir: dir.to_path_buf().to_str().unwrap().to_string(),
            ..Default::default()
        };
        let rotation_policy = RotationPolicy {
            max_usage_count: Some(5), // Low count for testing
            ..Default::default()
        };
        let config = ConfigFile {
            storage: storage_config,
            rotation: rotation_policy,
            crypto: Default::default(),
        };
        let config_manager = Arc::new(ConfigManager::from_config_file(config));
        TestEngine::new(config_manager, key_prefix).unwrap()
    }

    #[test]
    fn test_engine_encrypt_decrypt_roundtrip() {
        let dir = tempdir().unwrap();
        let mut engine = setup_test_engine(dir.path(), "roundtrip");
        let plaintext = b"secret data for asymmetric encryption";

        let ciphertext = engine.encrypt(plaintext).unwrap();
        let decrypted = engine.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext.as_ref(), decrypted.as_slice());
    }

    #[test]
    fn test_engine_authenticated_encrypt_decrypt_roundtrip() {
        let dir = tempdir().unwrap();
        let mut engine = setup_test_engine(dir.path(), "auth_roundtrip");
        let plaintext = b"authenticated secret data";

        let ciphertext = engine.encrypt_authenticated(plaintext).unwrap();
        let decrypted = engine.decrypt_authenticated(&ciphertext).unwrap();

        assert_eq!(plaintext.as_ref(), decrypted.as_slice());
    }

    #[test]
    fn test_engine_decrypt_with_rotated_key() {
        let dir = tempdir().unwrap();
        let mut engine = setup_test_engine(dir.path(), "rotation");
        let plaintext1 = b"data with key v1";

        // This will be encrypted with the initial key (v1)
        let ciphertext1 = engine.encrypt(plaintext1).unwrap();

        // Force rotation by exceeding usage count
        for _ in 0..5 {
            engine.encrypt(b"dummy data to increase usage").unwrap();
        }

        // This should be encrypted with the new key (v2)
        let plaintext2 = b"data with key v2";
        let ciphertext2 = engine.encrypt(plaintext2).unwrap();

        // Decryption of old data should still work
        let decrypted1 = engine.decrypt(&ciphertext1).unwrap();
        assert_eq!(plaintext1.as_ref(), decrypted1.as_slice());

        // Decryption of new data should also work
        let decrypted2 = engine.decrypt(&ciphertext2).unwrap();
        assert_eq!(plaintext2.as_ref(), decrypted2.as_slice());
    }
    
    #[test]
    fn test_engine_streaming_roundtrip() {
        let dir = tempdir().unwrap();
        let mut engine = setup_test_engine(dir.path(), "streaming");
        let original_data = b"streaming data for asymmetric engine";
        let streaming_config = StreamingConfig::default();

        let mut source = Cursor::new(original_data);
        let mut encrypted_dest = Cursor::new(Vec::new());
        engine.encrypt_stream(&mut source, &mut encrypted_dest, &streaming_config).unwrap();

        let mut encrypted_source = Cursor::new(encrypted_dest.into_inner());
        let mut decrypted_dest = Cursor::new(Vec::new());
        engine.decrypt_stream(&mut encrypted_source, &mut decrypted_dest, &streaming_config).unwrap();

        assert_eq!(original_data.as_ref(), decrypted_dest.into_inner().as_slice());
    }

    #[test]
    #[should_panic]
    fn test_streaming_decrypt_with_rotated_key_fails() {
        let dir = tempdir().unwrap();
        let mut engine = setup_test_engine(dir.path(), "streaming_rotation_fail");
        let streaming_config = StreamingConfig::default();

        // Encrypt with key v1
        let original_data = b"this stream was encrypted with key v1";
        let mut source = Cursor::new(original_data);
        let mut encrypted_dest = Cursor::new(Vec::new());
        engine.encrypt_stream(&mut source, &mut encrypted_dest, &streaming_config).unwrap();
        
        // Force rotation by exceeding usage count
        for _ in 0..5 {
            engine.encrypt(b"dummy data to increase usage").unwrap();
        }

        // Try to decrypt the stream. This should fail because it only uses the primary key (v2).
        let mut encrypted_source = Cursor::new(encrypted_dest.into_inner());
        let mut decrypted_dest = Cursor::new(Vec::new());
        engine.decrypt_stream(&mut encrypted_source, &mut decrypted_dest, &streaming_config).unwrap();
    }
} 