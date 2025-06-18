#![cfg(feature = "async-engine")]

use arc_swap::ArcSwapOption;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use crate::common::config::ConfigManager;
use crate::common::errors::Error;
use crate::common::streaming::StreamingResult;
use crate::rotation::{KeyMetadata, KeyStorage};
use crate::storage::KeyFileStorage;
use crate::common::streaming::StreamingConfig;
use tokio::io::{AsyncRead, AsyncWrite};
use crate::symmetric::traits::{SymmetricAsyncStreamingSystem, SymmetricCryptographicSystem};

/// 并发版对称加密引擎
pub struct SymmetricQSealEngineAsync<C: SymmetricCryptographicSystem + SymmetricAsyncStreamingSystem + Send + Sync + 'static>
where
    Error: From<C::Error>,
    C::Error: Send,
{
    config: Arc<ConfigManager>,
    key_storage: Arc<dyn KeyStorage>,
    key_prefix: String,
    primary: ArcSwapOption<(C::Key, KeyMetadata)>,
    secondary: DashMap<String, (C::Key, KeyMetadata)>,
}

#[derive(Serialize, Deserialize)]
struct KeyData {
    key: String,
}

impl<C> SymmetricQSealEngineAsync<C>
where
    C: SymmetricCryptographicSystem + SymmetricAsyncStreamingSystem + Send + Sync + 'static,
    C::Error: Send,
    C::Key: Send + Sync,
    Error: From<C::Error>,
{
    pub fn new(config: Arc<ConfigManager>, key_prefix: &str) -> Result<Self, Error> {
        let storage_config = config.get_storage_config();
        let key_storage = Arc::new(KeyFileStorage::new(&storage_config.key_storage_dir)?);
        let prefix = key_prefix.to_string();
        
        let engine = Self {
            config: config.clone(),
            key_storage: key_storage.clone(),
            key_prefix: prefix.clone(),
            primary: ArcSwapOption::new(None),
            secondary: DashMap::new(),
        };
        engine.initialize()?;
        Ok(engine)
    }

    fn initialize(&self) -> Result<(), Error> {
        let keys = self.key_storage.list_keys()?;
        for name in keys {
            if name.starts_with(&self.key_prefix) {
                let (meta, data) = self.key_storage.load_key(&name)?;
                let key = Self::deserialize(&data)?;
                match meta.status {
                    crate::common::traits::KeyStatus::Active => {
                        self.primary.store(Some(Arc::new((key, meta))));
                    }
                    crate::common::traits::KeyStatus::Rotating => {
                        self.secondary.insert(name, (key, meta));
                    }
                    crate::common::traits::KeyStatus::Expired => {
                        let _ = self.key_storage.delete_key(&name);
                    }
                }
            }
        }
        if self.primary.load().is_none() {
            self.start_rotation()?;
        }
        Ok(())
    }

    fn deserialize(data: &[u8]) -> Result<C::Key, Error> {
        let kd: KeyData = serde_json::from_slice(data)?;
        C::import_key(&kd.key).map_err(Into::into)
    }

    fn serialize(key: &C::Key) -> Result<Vec<u8>, Error> {
        let key_s = C::export_key(key)?;
        let kd = KeyData { key: key_s };
        serde_json::to_vec(&kd).map_err(Into::into)
    }

    fn needs_rotation(&self) -> bool {
        if let Some(arc) = self.primary.load_full() {
            let (_, metadata) = &*arc;
            let policy = self.config.get_rotation_policy();

            if let Some(expires_at) = &metadata.expires_at {
                if let Ok(expiry_time) = chrono::DateTime::parse_from_rfc3339(expires_at) {
                    let now = chrono::Utc::now();
                    let warning_period = chrono::Duration::days(policy.rotation_start_days as i64);
                    if (now + warning_period) >= expiry_time {
                        return true;
                    }
                }
            }
            
            if let Some(max_count) = policy.max_usage_count {
                if metadata.usage_count >= max_count {
                    return true;
                }
            }
        } else {
            return true; // No primary key, so we need one.
        }
        false
    }
    
    fn start_rotation(&self) -> Result<(), Error> {
        let crypto_config = self.config.get_crypto_config();
        let new_key = C::generate_key(&crypto_config)?;
        let id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();
        
        // This is simplified. A real implementation would get policy from ConfigManager
        let exp = (chrono::Utc::now() + chrono::Duration::days(90)).to_rfc3339();
        
        let mut version = 1;
        if let Some(old) = self.primary.load_full() {
            let (old_key, mut old_meta) = (&*old).clone();
            version = old_meta.version + 1;
            old_meta.status = crate::common::traits::KeyStatus::Rotating;
            let key_name = format!("{}-{}", self.key_prefix, old_meta.id);
            let data = Self::serialize(&old_key)?;
            self.key_storage.save_key(&key_name, &old_meta, &data)?;
            self.secondary.insert(key_name.clone(), (old_key, old_meta));
        }
        
        let metadata = KeyMetadata { id: id.clone(), created_at: now.clone(), expires_at: Some(exp), usage_count: 0, status: crate::common::traits::KeyStatus::Active, version, algorithm: format!("{}", std::any::type_name::<C>()) };
        let key_name = format!("{}-{}", self.key_prefix, id);
        let data = Self::serialize(&new_key)?;
        self.key_storage.save_key(&key_name, &metadata, &data)?;
        self.primary.store(Some(Arc::new((new_key, metadata))));
        Ok(())
    }

    fn increment_usage_count(&self) -> Result<(), Error> {
        if let Some(old) = self.primary.load_full() {
            let (key, mut meta) = (&*old).clone();
            meta.usage_count += 1;
            let key_name = format!("{}-{}", self.key_prefix, meta.id);
            let data = Self::serialize(&key)?;
            self.key_storage.save_key(&key_name, &meta, &data)?;
            self.primary.store(Some(Arc::new((key, meta))));
        }
        Ok(())
    }
    
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<String, Error> {
        if self.needs_rotation() {
            self.start_rotation()?;
        }
        let arc = self.primary.load_full().ok_or_else(|| Error::Key("没有可用主密钥".to_string()))?;
        let (key, _) = &*arc;
        self.increment_usage_count()?;
        let ct = C::encrypt(key, plaintext, None)?;
        Ok(ct.to_string())
    }

    pub fn decrypt(&self, ciphertext: &str) -> Result<Vec<u8>, Error> {
        if let Some(arc) = self.primary.load_full() {
            let (key, _) = &*arc;
            if let Ok(pt) = C::decrypt(key, ciphertext, None) {
                return Ok(pt);
            }
        }
        for entry in self.secondary.iter() {
            let (key, _) = entry.value();
            if let Ok(pt) = C::decrypt(key, ciphertext, None) {
                return Ok(pt);
            }
        }
        Err(Error::Operation("解密失败".to_string()))
    }
    
    pub async fn encrypt_stream<R, W>(&self, reader: R, writer: W, config: &StreamingConfig) -> Result<StreamingResult, Error>
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send,
    {
        if self.needs_rotation() {
            self.start_rotation()?;
        }
        let arc = self.primary.load_full().ok_or_else(|| Error::Key("没有可用主密钥".to_string()))?;
        let (key, _) = &*arc;
        self.increment_usage_count()?;
        C::encrypt_stream_async(key, reader, writer, config, None).await
    }

    pub async fn decrypt_stream<R, W>(&self, reader: R, writer: W, config: &StreamingConfig) -> Result<StreamingResult, Error>
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send,
    {
        let arc = self.primary.load_full().ok_or_else(|| Error::Key("没有可用主密钥".to_string()))?;
        let (key, _) = &*arc;
        C::decrypt_stream_async(key, reader, writer, config, None).await
    }

    #[cfg(test)]
    fn set_usage_count(&self, count: u64) -> Result<(), Error> {
        if let Some(old) = self.primary.load_full() {
            let (key, mut meta) = (&*old).clone();
            meta.usage_count = count;
            self.primary.store(Some(Arc::new((key, meta))));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::config::{ConfigFile, StorageConfig};
    use crate::rotation::RotationPolicy;
    use crate::symmetric::systems::aes_gcm::AesGcmSystem;
    use std::io::Cursor;
    use tempfile::tempdir;
    use tokio::io::BufReader;

    type TestEngine = SymmetricQSealEngineAsync<AesGcmSystem>;

    fn setup_test_engine(dir: &std::path::Path, key_prefix: &str) -> TestEngine {
        let storage_config = StorageConfig {
            key_storage_dir: dir.to_path_buf().to_str().unwrap().to_string(),
            ..Default::default()
        };
        let rotation_policy = RotationPolicy {
            max_usage_count: Some(10),
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

    #[tokio::test]
    async fn test_async_engine_encrypt_decrypt_roundtrip() {
        let dir = tempdir().unwrap();
        let engine = setup_test_engine(dir.path(), "test_async_roundtrip");
        let plaintext = b"async top secret data";

        let ciphertext = engine.encrypt(plaintext).unwrap();
        let decrypted = engine.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext.as_ref(), decrypted.as_slice());
    }

    #[tokio::test]
    async fn test_async_engine_streaming_roundtrip() {
        let dir = tempdir().unwrap();
        let engine = setup_test_engine(dir.path(), "test_async_streaming");
        let original_data = b"some async streaming data".to_vec();

        let source = BufReader::new(Cursor::new(original_data.clone()));
        let mut encrypted_dest = Vec::new();
        let streaming_config = StreamingConfig::default();

        engine
            .encrypt_stream(source, &mut encrypted_dest, &streaming_config)
            .await
            .unwrap();

        let encrypted_source = BufReader::new(Cursor::new(encrypted_dest));
        let mut decrypted_dest = Vec::new();

        engine
            .decrypt_stream(encrypted_source, &mut decrypted_dest, &streaming_config)
            .await
            .unwrap();

        assert_eq!(original_data, decrypted_dest);
    }

    #[tokio::test]
    async fn test_async_decrypt_with_rotated_key() {
        let dir = tempdir().unwrap();
        let engine = setup_test_engine(dir.path(), "test_async_rotation");
        let plaintext1 = b"async data encrypted with key v1";

        let ciphertext1 = engine.encrypt(plaintext1).unwrap();

        engine.set_usage_count(11).unwrap();

        let plaintext2 = b"async data encrypted with key v2";
        let ciphertext2 = engine.encrypt(plaintext2).unwrap();

        let decrypted1 = engine.decrypt(&ciphertext1).unwrap();
        assert_eq!(plaintext1.as_ref(), decrypted1.as_slice());

        let decrypted2 = engine.decrypt(&ciphertext2).unwrap();
        assert_eq!(plaintext2.as_ref(), decrypted2.as_slice());
    }

    #[tokio::test]
    #[should_panic]
    async fn test_async_streaming_decrypt_with_rotated_key_fails() {
        let dir = tempdir().unwrap();
        let engine = setup_test_engine(dir.path(), "test_async_streaming_rotation_fail");
        let streaming_config = StreamingConfig::default();

        let original_data = b"this async stream was encrypted with key v1".to_vec();
        let source = BufReader::new(Cursor::new(original_data.clone()));
        let mut encrypted_dest = Vec::new();
        engine
            .encrypt_stream(source, &mut encrypted_dest, &streaming_config)
            .await
            .unwrap();

        engine.set_usage_count(11).unwrap();
        engine.encrypt(b"trigger rotation").unwrap();

        let encrypted_source = BufReader::new(Cursor::new(encrypted_dest));
        let mut decrypted_dest = Vec::new();
        engine
            .decrypt_stream(encrypted_source, &mut decrypted_dest, &streaming_config)
            .await
            .unwrap();
    }
} 