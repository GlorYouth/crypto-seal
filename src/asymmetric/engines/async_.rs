#![cfg(feature = "async-engine")]

use arc_swap::ArcSwapOption;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::common::utils::CryptoConfig;
use crate::common::config::ConfigManager;
use crate::common::errors::Error;
use crate::rotation::{KeyMetadata, KeyStorage, RotationPolicy};
use crate::storage::KeyFileStorage;
use crate::common::traits::AuthenticatedCryptoSystem;
use crate::common::streaming::StreamingResult;
use crate::common::streaming::StreamingConfig;
use tokio::io::{AsyncRead, AsyncWrite};
use crate::asymmetric::traits::{AsyncStreamingSystem, AsymmetricCryptographicSystem};

/// 并发版 QSeal 引擎，支持多线程同时调用
pub struct AsymmetricQSealEngineAsync<C: AsymmetricCryptographicSystem + AsyncStreamingSystem + Send + Sync + 'static>
where
    Error: From<C::Error>,
    C::Error: Send,
{
    config: Arc<ConfigManager>,
    key_storage: Arc<dyn KeyStorage>,
    rotation_policy: RotationPolicy,
    key_prefix: String,
    /// 主密钥原子存储
    primary: ArcSwapOption<(C::PublicKey, C::PrivateKey, KeyMetadata)>,
    /// 次要密钥并发存储
    secondary: DashMap<String, (C::PublicKey, C::PrivateKey, KeyMetadata)>,
}

/// 密钥序列化结构，用于读取存储的 key_data
#[derive(Serialize, Deserialize)]
struct KeyPairData {
    public_key: String,
    private_key: String,
}

impl<C> AsymmetricQSealEngineAsync<C>
where
    C: AsymmetricCryptographicSystem + AsyncStreamingSystem + Send + Sync + 'static,
    Error: From<C::Error>,
    C::Error: Send,
{
    /// 创建并初始化并发版引擎
    pub fn new(config: Arc<ConfigManager>, key_prefix: &str) -> Result<Self, Error> {
        let storage_config = config.get_storage_config();
        let key_storage = Arc::new(KeyFileStorage::new(&storage_config.key_storage_dir)?);
        let rotation_policy = config.get_rotation_policy();
        let prefix = key_prefix.to_string();
        let engine = AsymmetricQSealEngineAsync {
            config: config.clone(),
            key_storage: key_storage.clone(),
            rotation_policy: rotation_policy.clone(),
            key_prefix: prefix.clone(),
            primary: ArcSwapOption::new(None),
            secondary: DashMap::new(),
        };
        engine.initialize(&config.get_crypto_config())?;
        Ok(engine)
    }

    /// 返回一个构造器以创建引擎
    pub fn builder() -> AsyncQSealEngineBuilder<C> {
        AsyncQSealEngineBuilder::new()
    }

    /// 初始化，加载存储中的主密钥和次要密钥
    fn initialize(&self, config: &CryptoConfig) -> Result<(), Error> {
        let keys = self.key_storage.list_keys()?;
        for name in keys {
            if name.starts_with(&self.key_prefix) {
                let (meta, data) = self.key_storage.load_key(&name)?;
                match meta.status {
                    crate::common::traits::KeyStatus::Active => {
                        let (pubk, privk) = Self::deserialize(&data)?;
                        self.primary.store(Some(Arc::new((pubk, privk, meta))));
                    }
                    crate::common::traits::KeyStatus::Rotating => {
                        let (pubk, privk) = Self::deserialize(&data)?;
                        self.secondary.insert(name, (pubk, privk, meta));
                    }
                    crate::common::traits::KeyStatus::Expired => {
                        let _ = self.key_storage.delete_key(&name);
                    }
                }
            }
        }
        if self.primary.load().is_none() {
            // 没有主密钥，创建新的
            self.start_rotation(config)?;
        }
        Ok(())
    }

    /// 反序列化 key_data
    fn deserialize(data: &[u8]) -> Result<(C::PublicKey, C::PrivateKey), Error> {
        let kp: KeyPairData = serde_json::from_slice(data)
            .map_err(|e| Error::Serialization(format!("反序列化密钥对失败: {}", e)))?;
        let pk = C::import_public_key(&kp.public_key)
            .map_err(|e| Error::Operation(format!("导入公钥失败: {}", e)))?;
        let sk = C::import_private_key(&kp.private_key)
            .map_err(|e| Error::Operation(format!("导入私钥失败: {}", e)))?;
        Ok((pk, sk))
    }

    /// 序列化 key_pair
    fn serialize(pubk: &C::PublicKey, privk: &C::PrivateKey) -> Result<Vec<u8>, Error> {
        let pub_s = C::export_public_key(pubk)
            .map_err(|e| Error::Operation(format!("导出公钥失败: {}", e)))?;
        let priv_s = C::export_private_key(privk)
            .map_err(|e| Error::Operation(format!("导出私钥失败: {}", e)))?;
        let kp = KeyPairData { public_key: pub_s, private_key: priv_s };
        serde_json::to_vec(&kp)
            .map_err(|e| Error::Serialization(format!("序列化密钥对失败: {}", e)))
    }

    /// 检查是否需要轮换
    fn needs_rotation(&self) -> bool {
        if let Some(arc) = self.primary.load_full() {
            let (_, _, meta) = &*arc;
            if let Some(exp) = &meta.expires_at {
                if let Ok(expiry) = chrono::DateTime::parse_from_rfc3339(exp) {
                    let now = chrono::Utc::now();
                    let warn = chrono::Duration::days(self.rotation_policy.rotation_start_days as i64);
                    if (now + warn) >= expiry {
                        return true;
                    }
                }
            }
            if let Some(maxu) = self.rotation_policy.max_usage_count {
                if meta.usage_count >= maxu {
                    return true;
                }
            }
            false
        } else {
            true
        }
    }

    /// 开始轮换：生成新主密钥，旧主标记为 Rotating
    fn start_rotation(&self, config: &CryptoConfig) -> Result<(), Error> {
        let (new_pk, new_sk) = C::generate_keypair(config)
            .map_err(|e| Error::Operation(format!("生成密钥对失败: {}", e)))?;
        let id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();
        let exp = (chrono::Utc::now() + chrono::Duration::days(self.rotation_policy.validity_period_days as i64)).to_rfc3339();
        let mut version = 1;
        // 旧主移到次要
        if let Some(old) = self.primary.load_full() {
            let (_opk, _osk, mut om) = (&*old).clone();
            version = om.version + 1;
            om.status = crate::common::traits::KeyStatus::Rotating;
            let key_name = format!("{}-{}", self.key_prefix, om.id);
            let data = Self::serialize(&_opk, &_osk)?;
            self.key_storage.save_key(&key_name, &om, &data)?;
            self.secondary.insert(key_name.clone(), (_opk, _osk, om));
        }
        let metadata = KeyMetadata { id: id.clone(), created_at: now.clone(), expires_at: Some(exp), usage_count: 0, status: crate::common::traits::KeyStatus::Active, version, algorithm: format!("{}", std::any::type_name::<C>()) };
        let key_name = format!("{}-{}", self.key_prefix, id);
        let data = Self::serialize(&new_pk, &new_sk)?;
        self.key_storage.save_key(&key_name, &metadata, &data)?;
        self.primary.store(Some(Arc::new((new_pk, new_sk, metadata))));
        Ok(())
    }

    /// 增加使用计数
    fn increment_usage_count(&self) -> Result<(), Error> {
        if let Some(old) = self.primary.load_full() {
            let (pk, sk, mut meta) = (&*old).clone();
            meta.usage_count += 1;
            let key_name = format!("{}-{}", self.key_prefix, meta.id);
            let data = Self::serialize(&pk, &sk)?;
            self.key_storage.save_key(&key_name, &meta, &data)?;
            self.primary.store(Some(Arc::new((pk, sk, meta))));
        }
        Ok(())
    }

    /// 加密
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<String, Error> {
        if self.needs_rotation() {
            self.start_rotation(&self.config.get_crypto_config())?;
        }
        let arc = self.primary.load_full().ok_or_else(|| Error::Key("没有可用主密钥".to_string()))?;
        let (pk, _, _) = &*arc;
        self.increment_usage_count()?;
        let ct = C::encrypt(pk, plaintext, None)?;
        Ok(ct.to_string())
    }

    /// 解密
    pub fn decrypt(&self, ciphertext: &str) -> Result<Vec<u8>, Error> {
        if let Some(arc) = self.primary.load_full() {
            let (_, sk, _) = &*arc;
            if let Ok(pt) = C::decrypt(sk, ciphertext, None) {
                return Ok(pt);
            }
        }
        for entry in self.secondary.iter() {
            let (_pk, sk, _) = entry.value();
            if let Ok(pt) = C::decrypt(sk, ciphertext, None) {
                return Ok(pt);
            }
        }
        Err(Error::Operation("解密失败".to_string()))
    }

    /// 带认证加密
    pub fn encrypt_authenticated(&self, plaintext: &[u8]) -> Result<String, Error>
    where C: AuthenticatedCryptoSystem + Send + Sync + 'static
    {
        if self.needs_rotation() {
            self.start_rotation(&self.config.get_crypto_config())?;
        }
        let arc = self.primary.load_full().ok_or_else(|| Error::Key("没有可用主密钥".to_string()))?;
        let (pk, sk, _) = &*arc;
        self.increment_usage_count()?;
        let cfg = self.config.get_crypto_config();
        let signer = if cfg.use_authenticated_encryption { Some(sk) } else { None };
        let auth_ct = C::encrypt_authenticated(pk, plaintext, None, signer)
            .map_err(Into::into)?;
        Ok(auth_ct.to_string())
    }

    /// 带认证解密
    pub fn decrypt_authenticated(&self, ciphertext: &str) -> Result<Vec<u8>, Error>
    where C: AuthenticatedCryptoSystem + Send + Sync + 'static
    {
        let cfg = self.config.get_crypto_config();

        if let Some(arc) = self.primary.load_full() {
            let (pk, sk, _) = &*arc;
            let verifier = if cfg.auto_verify_signatures { Some(pk) } else { None };
            if let Ok(pt) = C::decrypt_authenticated(sk, ciphertext, None, verifier) {
                return Ok(pt);
            }
        }

        for entry in self.secondary.iter() {
            let (_pk, sk, _) = entry.value();
            if let Ok(pt) = C::decrypt_authenticated(sk, ciphertext, None, None) {
                return Ok(pt);
            }
        }

        Err(Error::Operation("认证解密失败".to_string()))
    }

    /// 异步流式加密
    pub async fn encrypt_stream<R, W>(
        &self,
        reader: R,
        writer: W,
        config: &StreamingConfig,
    ) -> Result<StreamingResult, Error>
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send,
        C::PublicKey: Send + Sync,
    {
        if self.needs_rotation() {
            self.start_rotation(&self.config.get_crypto_config())?;
        }
        let arc = self.primary.load_full().ok_or_else(|| Error::Key("没有可用主密钥".to_string()))?;
        let (pk, _, _) = &*arc;
        self.increment_usage_count()?;

        C::encrypt_stream_async(pk, reader, writer, config, None)
            .await
            .map_err(Into::into)
    }

    /// 异步流式解密
    pub async fn decrypt_stream<R, W>(
        &self,
        reader: R,
        writer: W,
        config: &StreamingConfig,
    ) -> Result<StreamingResult, Error>
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send,
        C::PrivateKey: Send + Sync,
    {
        let arc = self.primary.load_full().ok_or_else(|| Error::Key("没有可用主密钥".to_string()))?;
        let (_pk, sk, _) = &*arc;
        C::decrypt_stream_async(sk, reader, writer, config, None).await
    }
}

#[cfg(feature = "parallel")]
impl<C> AsymmetricQSealEngineAsync<C>
where
    C: AsymmetricCryptographicSystem + AsyncStreamingSystem + Send + Sync + 'static,
    Error: From<C::Error>,
    C::Error: Send,
{
    /// 批量加密（并行）。需要公钥和私钥可安全在线程间共享。
    pub fn encrypt_batch<T>(&self, inputs: &[T]) -> Vec<Result<String, Error>>
    where
        Self: Sync,
        T: AsRef<[u8]> + Sync,
        <C as AsymmetricCryptographicSystem>::PublicKey: Send + Sync,
        <C as AsymmetricCryptographicSystem>::PrivateKey: Send + Sync,
    {
        inputs.par_iter().map(|item| self.encrypt(item.as_ref())).collect()
    }
}

#[cfg(not(feature = "parallel"))]
impl<C> AsymmetricQSealEngineAsync<C>
where
    C: AsymmetricCryptographicSystem + AsyncStreamingSystem + Send + Sync + 'static,
    Error: From<C::Error>,
    C::Error: Send,
{
    /// 批量加密（顺序执行）
    pub fn encrypt_batch<T>(&self, inputs: &[T]) -> Vec<Result<String, Error>>
    where
        T: AsRef<[u8]>,
    {
        inputs.iter().map(|item| self.encrypt(item.as_ref())).collect()
    }
}

/// `AsyncQSealEngine` 的构造器
pub struct AsyncQSealEngineBuilder<C: AsymmetricCryptographicSystem + AsyncStreamingSystem + Send + Sync + 'static>
where
    Error: From<C::Error>,
    C::Error: Send,
{
    config_manager: Option<Arc<ConfigManager>>,
    key_prefix: Option<String>,
    _phantom: std::marker::PhantomData<C>,
}

impl<C> AsyncQSealEngineBuilder<C>
where
    C: AsymmetricCryptographicSystem + AsyncStreamingSystem + Send + Sync + 'static,
    Error: From<C::Error>,
    C::Error: Send,
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
    pub fn with_config_file<P: AsRef<std::path::Path>>(mut self, path: P) -> Result<Self, Error> {
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

    /// 构建 `AsyncQSealEngine`
    pub fn build(self) -> Result<AsymmetricQSealEngineAsync<C>, Error> {
        let cm = self.config_manager.unwrap_or_else(|| Arc::new(ConfigManager::new()));
        let prefix = self.key_prefix.ok_or_else(|| Error::Operation("Key prefix must be set".to_string()))?;
        AsymmetricQSealEngineAsync::new(cm, &prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asymmetric::systems::hybrid::rsa_kyber::RsaKyberCryptoSystem;
    use crate::common::config::{ConfigFile, StorageConfig};
    use crate::rotation::RotationPolicy;
    use std::io::Cursor;
    use tempfile::tempdir;
    use tokio::io::BufReader;

    type TestEngine = AsymmetricQSealEngineAsync<RsaKyberCryptoSystem>;

    fn setup_test_engine(dir: &std::path::Path, key_prefix: &str) -> TestEngine {
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

    #[tokio::test]
    async fn test_async_engine_encrypt_decrypt_roundtrip() {
        let dir = tempdir().unwrap();
        let engine = setup_test_engine(dir.path(), "async_roundtrip");
        let plaintext = b"async secret data";

        let ciphertext = engine.encrypt(plaintext).unwrap();
        let decrypted = engine.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext.as_ref(), decrypted.as_slice());
    }

    #[tokio::test]
    async fn test_async_engine_authenticated_encrypt_decrypt_roundtrip() {
        let dir = tempdir().unwrap();
        let engine = setup_test_engine(dir.path(), "async_auth_roundtrip");
        let plaintext = b"async authenticated secret";

        let ciphertext = engine.encrypt_authenticated(plaintext).unwrap();
        let decrypted = engine.decrypt_authenticated(&ciphertext).unwrap();

        assert_eq!(plaintext.as_ref(), decrypted.as_slice());
    }

    #[tokio::test]
    async fn test_async_engine_decrypt_with_rotated_key() {
        let dir = tempdir().unwrap();
        let engine = setup_test_engine(dir.path(), "async_rotation");
        let plaintext1 = b"async data with key v1";

        let ciphertext1 = engine.encrypt(plaintext1).unwrap();

        for _ in 0..5 {
            engine.encrypt(b"dummy").unwrap();
        }

        let plaintext2 = b"async data with key v2";
        let ciphertext2 = engine.encrypt(plaintext2).unwrap();

        let decrypted1 = engine.decrypt(&ciphertext1).unwrap();
        assert_eq!(plaintext1.as_ref(), decrypted1.as_slice());

        let decrypted2 = engine.decrypt(&ciphertext2).unwrap();
        assert_eq!(plaintext2.as_ref(), decrypted2.as_slice());
    }

    #[tokio::test]
    async fn test_async_engine_streaming_roundtrip() {
        let dir = tempdir().unwrap();
        let engine = setup_test_engine(dir.path(), "async_streaming");
        let original_data = b"async streaming data".to_vec();
        let streaming_config = StreamingConfig::default();

        let source = BufReader::new(Cursor::new(original_data.clone()));
        let mut encrypted_dest = Vec::new();
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
    #[should_panic]
    async fn test_async_streaming_decrypt_with_rotated_key_fails() {
        let dir = tempdir().unwrap();
        let engine = setup_test_engine(dir.path(), "async_streaming_rotation_fail");
        let streaming_config = StreamingConfig::default();

        let original_data = b"this async stream was encrypted with key v1".to_vec();
        let source = BufReader::new(Cursor::new(original_data.clone()));
        let mut encrypted_dest = Vec::new();
        engine
            .encrypt_stream(source, &mut encrypted_dest, &streaming_config)
            .await
            .unwrap();

        for _ in 0..5 {
            engine.encrypt(b"dummy").unwrap();
        }

        let encrypted_source = BufReader::new(Cursor::new(encrypted_dest));
        let mut decrypted_dest = Vec::new();
        engine
            .decrypt_stream(encrypted_source, &mut decrypted_dest, &streaming_config)
            .await
            .unwrap();
    }
} 