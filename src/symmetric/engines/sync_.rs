//! 对称加密引擎 `SymmetricQSealEngine`
use std::sync::Arc;
use std::io::{Read, Write};
use std::path::Path;
use crate::common::errors::Error;
use crate::common::config::ConfigManager;
use crate::common::streaming::{StreamingConfig, StreamingResult};
use crate::storage::KeyFileStorage;
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
    config: Arc<ConfigManager>,
    pub(crate) key_manager: SymmetricKeyRotationManager<T>,
}

impl<T: SymmetricCryptographicSystem + SymmetricSyncStreamingSystem> SymmetricQSealEngine<T>
where
    T::Error: std::error::Error + 'static,
    Error: From<T::Error>,
{
    /// 使用指定的配置管理器创建一个新的引擎实例。
    pub fn new(config_manager: Arc<ConfigManager>, key_prefix: &str) -> Result<Self, Error> {
        let storage_config = config_manager.get_storage_config();
        let key_storage = Arc::new(KeyFileStorage::new(&storage_config.key_storage_dir)?);
        let rotation_policy = config_manager.get_rotation_policy();
        
        let mut key_manager = SymmetricKeyRotationManager::<T>::new(
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
    pub fn from_file<P: AsRef<Path>>(path: P, key_prefix: &str) -> Result<Self, Error> {
        let config_manager = Arc::new(ConfigManager::from_file(path)?);
        Self::new(config_manager, key_prefix)
    }

    /// 使用默认配置创建一个新的引擎实例
    pub fn with_defaults(key_prefix: &str) -> Result<Self, Error> {
        let config_manager = Arc::new(ConfigManager::new());
        Self::new(config_manager, key_prefix)
    }
    
    /// 返回一个构造器以创建引擎
    pub fn builder() -> SymmetricQSealEngineBuilder<T> {
        SymmetricQSealEngineBuilder::new()
    }

    /// 加密一段明文。
    pub fn encrypt(&mut self, plaintext: &[u8], additional_data: Option<&[u8]>) -> Result<String, Error> {
        let manager = &mut self.key_manager;
        if manager.needs_rotation() {
            manager.start_rotation(&self.config.get_crypto_config())?;
        }

        let key = manager.get_primary_key()
            .map(|k| k.clone())
            .ok_or_else(|| Error::Key("没有可用的主密钥进行加密".to_string()))?;

        manager.increment_usage_count()?;

        let ciphertext = T::encrypt(&key, plaintext, additional_data)
            .map_err(|e| Error::Operation(format!("加密失败: {}", e)))?;

        Ok(ciphertext.to_string())
    }

    /// 解密一段密文。
    pub fn decrypt(&mut self, ciphertext: &str, additional_data: Option<&[u8]>) -> Result<Vec<u8>, Error> {
        let manager = &mut self.key_manager;
        
        let keys = manager.get_all_keys();
        if keys.is_empty() {
            return Err(Error::Operation("没有可用的密钥进行解密".to_string()));
        }

        for key_ref in keys {
            let key = key_ref.clone(); // 克隆以避免生命周期问题
            if let Ok(plaintext) = T::decrypt(&key, ciphertext, additional_data) {
                return Ok(plaintext);
            }
        }

        Err(Error::Operation("解密失败，所有可用密钥都无法解密该密文".to_string()))
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

        let key = manager.get_primary_key()
            .map(|k| k.clone())
            .ok_or_else(|| Error::Key("没有可用的主密钥进行加密".to_string()))?;
        
        manager.increment_usage_count()?;
        
        T::encrypt_stream(&key, reader, writer, config, None)
    }

    /// 同步流式解密
    pub fn decrypt_stream<R: Read, W: Write>(
        &mut self,
        reader: R,
        writer: W,
        config: &StreamingConfig,
    ) -> Result<StreamingResult, Error> {
        let manager = &mut self.key_manager;

        let key = manager.get_primary_key()
            .map(|k| k.clone())
            .ok_or_else(|| Error::Key("没有可用的主密钥进行解密".to_string()))?;
        
        T::decrypt_stream(&key, reader, writer, config, None)
    }

    /// 获取当前的配置管理器
    pub fn config(&self) -> Arc<ConfigManager> {
        Arc::clone(&self.config)
    }
}

/// `SymmetricQSealEngine` 的构造器
pub struct SymmetricQSealEngineBuilder<T: SymmetricCryptographicSystem + SymmetricSyncStreamingSystem>
where
    T::Error: std::error::Error + 'static,
    Error: From<T::Error>,
{
    config_manager: Option<Arc<ConfigManager>>,
    key_prefix: Option<String>,
    _phantom: std::marker::PhantomData<T>,
}

impl<T: SymmetricCryptographicSystem + SymmetricSyncStreamingSystem> SymmetricQSealEngineBuilder<T>
where
    T::Error: std::error::Error + 'static,
    Error: From<T::Error>,
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
    
    /// 构建 `SymmetricQSealEngine`
    pub fn build(self) -> Result<SymmetricQSealEngine<T>, Error> {
        let cm = self.config_manager.unwrap_or_else(|| Arc::new(ConfigManager::new()));
        let prefix = self.key_prefix.ok_or_else(|| Error::Operation("Key prefix must be set".to_string()))?;
        SymmetricQSealEngine::new(cm, &prefix)
    }
}

#[cfg(all(test, feature = "aes-gcm-feature"))]
mod tests {
    use super::*;
    use crate::common::config::{ConfigFile, StorageConfig};
    use crate::rotation::RotationPolicy;
    use crate::symmetric::systems::aes_gcm::AesGcmSystem;
    use std::io::Cursor;
    use tempfile::tempdir;

    type TestEngine = SymmetricQSealEngine<AesGcmSystem>;

    fn setup_test_engine(dir: &Path, key_prefix: &str) -> TestEngine {
        let storage_config = StorageConfig {
            key_storage_dir: dir.to_path_buf().to_str().unwrap().to_string(),
            ..Default::default()
        };
        let rotation_policy = RotationPolicy {
            max_usage_count: Some(10), // Rotate after 10 operations
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
        let mut engine = setup_test_engine(dir.path(), "test_roundtrip");
        let plaintext = b"top secret data";
        
        let ciphertext = engine.encrypt(plaintext, None).unwrap();
        let decrypted = engine.decrypt(&ciphertext, None).unwrap();
        
        assert_eq!(plaintext.as_ref(), decrypted.as_slice());
    }

    #[test]
    fn test_engine_streaming_roundtrip() {
        let dir = tempdir().unwrap();
        let mut engine = setup_test_engine(dir.path(), "test_streaming");
        let original_data = b"some streaming data to be encrypted";

        let mut source = Cursor::new(original_data);
        let mut encrypted_dest = Cursor::new(Vec::new());
        let streaming_config = StreamingConfig::default();

        engine.encrypt_stream(&mut source, &mut encrypted_dest, &streaming_config).unwrap();

        let mut encrypted_source = Cursor::new(encrypted_dest.into_inner());
        let mut decrypted_dest = Cursor::new(Vec::new());

        engine.decrypt_stream(&mut encrypted_source, &mut decrypted_dest, &streaming_config).unwrap();

        assert_eq!(original_data.as_ref(), decrypted_dest.into_inner().as_slice());
    }

    #[test]
    fn test_decrypt_with_rotated_key() {
        let dir = tempdir().unwrap();
        let mut engine = setup_test_engine(dir.path(), "test_rotation");
        let plaintext1 = b"data encrypted with key v1";

        // Encrypt with the first key
        let ciphertext1 = engine.encrypt(plaintext1, None).unwrap();

        // Force key rotation by exceeding usage count
        engine.key_manager.set_usage_count(11);
        
        // This encryption will trigger rotation, creating key v2
        let plaintext2 = b"data encrypted with key v2";
        let ciphertext2 = engine.encrypt(plaintext2, None).unwrap();
        
        // Now, the primary key is v2. Decrypting data encrypted with v1 should still work.
        let decrypted1 = engine.decrypt(&ciphertext1, None).unwrap();
        assert_eq!(plaintext1.as_ref(), decrypted1.as_slice());

        // And data with v2 should also work.
        let decrypted2 = engine.decrypt(&ciphertext2, None).unwrap();
        assert_eq!(plaintext2.as_ref(), decrypted2.as_slice());
    }

    #[test]
    #[should_panic]
    fn test_streaming_decrypt_with_rotated_key_fails() {
        let dir = tempdir().unwrap();
        let mut engine = setup_test_engine(dir.path(), "test_streaming_rotation_fail");
        let streaming_config = StreamingConfig::default();

        // Encrypt a stream with key v1
        let original_data = b"this stream was encrypted with key v1";
        let mut source = Cursor::new(original_data);
        let mut encrypted_dest = Cursor::new(Vec::new());
        engine.encrypt_stream(&mut source, &mut encrypted_dest, &streaming_config).unwrap();

        // Force rotation to key v2
        engine.key_manager.set_usage_count(11); // Exceed max_operations
        engine.encrypt(b"trigger rotation", None).unwrap(); // This will create v2 and set it as primary

        // Try to decrypt the stream. This should fail because decrypt_stream only uses the primary key (v2).
        let mut encrypted_source = Cursor::new(encrypted_dest.into_inner());
        let mut decrypted_dest = Cursor::new(Vec::new());
        engine.decrypt_stream(&mut encrypted_source, &mut decrypted_dest, &streaming_config).unwrap();
    }
} 