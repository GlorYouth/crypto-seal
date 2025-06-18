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
        // Simplified compared to asymmetric, as there is no policy yet in ConfigManager for symmetric
        // For now, let's assume it never needs rotation to avoid complexity.
        // In a real scenario, this would check expiration and usage count from policy.
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

    fn complete_rotation(&self) -> Result<(), Error> {
        let to_remove: Vec<_> = self.secondary.iter()
            .filter(|entry| entry.value().1.status == crate::common::traits::KeyStatus::Rotating)
            .map(|entry| entry.key().clone())
            .collect();
        
        for name in to_remove {
            self.secondary.remove(&name);
            let _ = self.key_storage.delete_key(&name);
        }
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
        self.complete_rotation()?;
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
        self.complete_rotation()?;
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
        self.complete_rotation()?;
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
        self.complete_rotation()?;
        let arc = self.primary.load_full().ok_or_else(|| Error::Key("没有可用主密钥".to_string()))?;
        let (key, _) = &*arc;
        C::decrypt_stream_async(key, reader, writer, config, None).await
    }
} 