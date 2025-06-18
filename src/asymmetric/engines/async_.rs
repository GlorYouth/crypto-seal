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
use crate::asymmetric::primitives::async_streaming::AsyncStreamingConfig;
use tokio::io::{AsyncRead, AsyncWrite};
use crate::asymmetric::traits::{AsyncStreamingSystem, CryptographicSystem};

/// 并发版 QSeal 引擎，支持多线程同时调用
pub struct AsyncQSealEngine<C: CryptographicSystem + AsyncStreamingSystem + Send + Sync + 'static>
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

impl<C> AsyncQSealEngine<C>
where
    C: CryptographicSystem + AsyncStreamingSystem + Send + Sync + 'static,
    Error: From<C::Error>,
    C::Error: Send,
{
    /// 创建并初始化并发版引擎
    pub fn new(config: Arc<ConfigManager>, key_prefix: &str) -> Result<Self, Error> {
        let storage_config = config.get_storage_config();
        let key_storage = Arc::new(KeyFileStorage::new(&storage_config.key_storage_dir)?);
        let rotation_policy = config.get_rotation_policy();
        let prefix = key_prefix.to_string();
        let engine = AsyncQSealEngine {
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

    /// 完成轮换：删除 Rotating 的次要密钥
    fn complete_rotation(&self) -> Result<(), Error> {
        let mut to_remove = Vec::new();
        for entry in self.secondary.iter() {
            let (name, (_pk, _sk, meta)) = (entry.key(), entry.value());
            if meta.status == crate::common::traits::KeyStatus::Rotating {
                to_remove.push(name.clone());
            }
        }
        for name in to_remove {
            self.secondary.remove(&name);
            let _ = self.key_storage.delete_key(&name);
        }
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
        self.complete_rotation()?;
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
        self.complete_rotation()?;
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
        self.complete_rotation()?;
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
        self.complete_rotation()?;
        let cfg = self.config.get_crypto_config();

        // 尝试主密钥
        if let Some(arc) = self.primary.load_full() {
            let (pk, sk, _) = &*arc;
            let verifier = if cfg.auto_verify_signatures { Some(pk) } else { None };
            if let Ok(pt) = C::decrypt_authenticated(sk, ciphertext, None, verifier) {
                return Ok(pt);
            }
        }

        // 尝试次要密钥
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
        config: &AsyncStreamingConfig,
    ) -> Result<StreamingResult, Error>
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send,
        C::PublicKey: Send + Sync,
    {
        self.complete_rotation()?;
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
        config: &AsyncStreamingConfig,
    ) -> Result<StreamingResult, Error>
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send,
        C::PrivateKey: Send + Sync,
    {
        self.complete_rotation()?;
        if let Some(arc) = self.primary.load_full() {
            let (_, sk, _) = &*arc;
            // 注意：这里我们只使用主密钥。
            return C::decrypt_stream_async(sk, reader, writer, config, None)
                .await
                .map_err(Into::into);
        }
        Err(Error::Key("没有可用主密钥".to_string()))
    }
}

#[cfg(feature = "parallel")]
impl<C> AsyncQSealEngine<C>
where
    C: CryptographicSystem + AsyncStreamingSystem + Send + Sync + 'static,
    Error: From<C::Error>,
    C::Error: Send,
{
    /// 批量加密（并行）。需要公钥和私钥可安全在线程间共享。
    pub fn encrypt_batch<T>(&self, inputs: &[T]) -> Vec<Result<String, Error>>
    where
        Self: Sync,
        T: AsRef<[u8]> + Sync,
        <C as CryptographicSystem>::PublicKey: Send + Sync,
        <C as CryptographicSystem>::PrivateKey: Send + Sync,
    {
        inputs.par_iter().map(|item| self.encrypt(item.as_ref())).collect()
    }
}

#[cfg(not(feature = "parallel"))]
impl<C> AsyncQSealEngine<C>
where
    C: CryptographicSystem + AsyncStreamingSystem + Send + Sync + 'static,
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
pub struct AsyncQSealEngineBuilder<C: CryptographicSystem + AsyncStreamingSystem + Send + Sync + 'static>
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
    C: CryptographicSystem + AsyncStreamingSystem + Send + Sync + 'static,
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
    pub fn build(self) -> Result<AsyncQSealEngine<C>, Error> {
        let cm = self.config_manager.unwrap_or_else(|| Arc::new(ConfigManager::new()));
        let prefix = self.key_prefix.ok_or_else(|| Error::Operation("Key prefix must be set".to_string()))?;
        AsyncQSealEngine::new(cm, &prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tokio::io::{copy, AsyncWriteExt};
    use crate::common::streaming::StreamingResult;
    use crate::common::utils::{from_base64, Base64String, CryptoConfig};

    // A dummy crypto system for testing
    struct DummyCryptoSystem;

    impl CryptographicSystem for DummyCryptoSystem {
        type PublicKey = String;
        type PrivateKey = String;
        type CiphertextOutput = Base64String;
        type Error = Error;

        fn generate_keypair(_config: &CryptoConfig) -> Result<(Self::PublicKey, Self::PrivateKey), Self::Error> {
            let key = "dummy_key".to_string();
            Ok((key.clone(), key))
        }

        fn encrypt(_public_key: &Self::PublicKey, plaintext: &[u8], _additional_data: Option<&[u8]>) -> Result<Self::CiphertextOutput, Self::Error> {
            Ok(Base64String::from(plaintext.to_vec()))
        }

        fn decrypt(_private_key: &Self::PrivateKey, ciphertext: &str, _additional_data: Option<&[u8]>) -> Result<Vec<u8>, Self::Error> {
            from_base64(ciphertext).map_err(|e| Error::Operation(format!("base64 error: {}", e)))
        }

        fn export_public_key(pk: &Self::PublicKey) -> Result<String, Self::Error> { Ok(pk.clone()) }
        fn export_private_key(sk: &Self::PrivateKey) -> Result<String, Self::Error> { Ok(sk.clone()) }
        fn import_public_key(pk: &str) -> Result<Self::PublicKey, Self::Error> { Ok(pk.to_string()) }
        fn import_private_key(sk: &str) -> Result<Self::PrivateKey, Self::Error> { Ok(sk.to_string()) }
    }

    #[async_trait::async_trait]
    impl AsyncStreamingSystem for DummyCryptoSystem {
        async fn encrypt_stream_async<R, W>(
            _public_key: &Self::PublicKey,
            mut reader: R,
            mut writer: W,
            _config: &AsyncStreamingConfig,
            _additional_data: Option<&[u8]>,
        ) -> Result<StreamingResult, Error>
        where
            R: AsyncRead + Unpin + Send,
            W: AsyncWrite + Unpin + Send,
        {
            let mut buffer = Vec::new();
            let bytes_read = copy(&mut reader, &mut buffer).await.unwrap();
            writer.write_all(&buffer).await.unwrap();
            Ok(StreamingResult { bytes_processed: bytes_read, buffer: Some(buffer) })
        }

        async fn decrypt_stream_async<R, W>(
            _private_key: &Self::PrivateKey,
            mut reader: R,
            mut writer: W,
            _config: &AsyncStreamingConfig,
            _additional_data: Option<&[u8]>,
        ) -> Result<StreamingResult, Error>
        where
            R: AsyncRead + Unpin + Send,
            W: AsyncWrite + Unpin + Send,
        {
            let mut buffer = Vec::new();
            let bytes_read = copy(&mut reader, &mut buffer).await.unwrap();
            writer.write_all(&buffer).await.unwrap();
            Ok(StreamingResult { bytes_processed: bytes_read, buffer: Some(buffer) })
        }
    }

    // A dummy authenticated crypto system for testing
    struct DummyAuthSystem;

    impl CryptographicSystem for DummyAuthSystem {
        type PublicKey = String;
        type PrivateKey = String;
        type CiphertextOutput = Base64String;
        type Error = Error;

        fn generate_keypair(_config: &CryptoConfig) -> Result<(Self::PublicKey, Self::PrivateKey), Self::Error> {
            let key = "dummy_auth_key".to_string();
            Ok((key.clone(), key))
        }
        fn encrypt(_public_key: &Self::PublicKey, plaintext: &[u8], _additional_data: Option<&[u8]>) -> Result<Self::CiphertextOutput, Self::Error> {
            Ok(Base64String::from(plaintext.to_vec()))
        }
        fn decrypt(_private_key: &Self::PrivateKey, ciphertext: &str, _additional_data: Option<&[u8]>) -> Result<Vec<u8>, Self::Error> {
            from_base64(ciphertext).map_err(|e| Error::Operation(format!("base64 error: {}", e)))
        }
        fn export_public_key(pk: &Self::PublicKey) -> Result<String, Self::Error> { Ok(pk.clone()) }
        fn export_private_key(sk: &Self::PrivateKey) -> Result<String, Self::Error> { Ok(sk.clone()) }
        fn import_public_key(pk: &str) -> Result<Self::PublicKey, Self::Error> { Ok(pk.to_string()) }
        fn import_private_key(sk: &str) -> Result<Self::PrivateKey, Self::Error> { Ok(sk.to_string()) }
    }

    impl AuthenticatedCryptoSystem for DummyAuthSystem {
        type AuthenticatedOutput = Base64String;

        fn sign(_private_key: &Self::PrivateKey, _data: &[u8]) -> Result<Vec<u8>, Self::Error> {
            Ok(b"_signed".to_vec())
        }

        fn verify(_public_key: &Self::PublicKey, _data: &[u8], _signature: &[u8]) -> Result<bool, Self::Error> { Ok(true) }

        fn encrypt_authenticated(
            _public_key: &Self::PublicKey,
            plaintext: &[u8],
            _additional_data: Option<&[u8]>,
            signer_key: Option<&Self::PrivateKey>
        ) -> Result<Self::AuthenticatedOutput, Self::Error> {
            if let Some(sk) = signer_key {
                let sig = Self::sign(sk, plaintext)?;
                let mut output = plaintext.to_vec();
                output.extend_from_slice(&sig);
                return Ok(Base64String::from(output));
            }
            Ok(Base64String::from(plaintext.to_vec()))
        }

        fn decrypt_authenticated(
            _private_key: &Self::PrivateKey,
            ciphertext: &str,
            _additional_data: Option<&[u8]>,
            verifier_key: Option<&Self::PublicKey>
        ) -> Result<Vec<u8>, Self::Error> {
             let data = from_base64(ciphertext).map_err(|e| Error::Operation(format!("base64 error: {}", e)))?;
             if let Some(_pk) = verifier_key {
                 // Simplified verification for test
                 if data.ends_with(b"_signed") {
                     return Ok(data[..data.len() - b"_signed".len()].to_vec())
                 }
             }
             Ok(data)
        }
    }

    #[async_trait::async_trait]
    impl AsyncStreamingSystem for DummyAuthSystem {
        async fn encrypt_stream_async<R, W>(
            _public_key: &Self::PublicKey,
            _reader: R,
            _writer: W,
            _config: &AsyncStreamingConfig,
            _additional_data: Option<&[u8]>,
        ) -> Result<StreamingResult, Error>
        where
            R: AsyncRead + Unpin + Send,
            W: AsyncWrite + Unpin + Send,
        {
            unimplemented!()
        }

        async fn decrypt_stream_async<R, W>(
            _private_key: &Self::PrivateKey,
            _reader: R,
            _writer: W,
            _config: &AsyncStreamingConfig,
            _additional_data: Option<&[u8]>,
        ) -> Result<StreamingResult, Error>
        where
            R: AsyncRead + Unpin + Send,
            W: AsyncWrite + Unpin + Send,
        {
            unimplemented!()
        }
    }

    fn setup_test_engine<C>(key_prefix: &str) -> (tempfile::TempDir, AsyncQSealEngine<C>)
    where
        C: CryptographicSystem + AsyncStreamingSystem + Send + Sync + 'static,
        Error: From<C::Error>,
        C::Error: Send,
    {
        let dir = tempfile::tempdir().unwrap();
        let engine = AsyncQSealEngine::<C>::builder()
            .with_storage_dir(dir.path().to_str().unwrap())
            .unwrap()
            .with_key_prefix(key_prefix)
            .build()
            .unwrap();

        (dir, engine)
    }

    #[tokio::test]
    async fn test_async_basic_encrypt_decrypt() {
        let (_dir, engine) = setup_test_engine::<DummyCryptoSystem>("test");
        
        let plaintext = b"some secret data";
        let ciphertext = engine.encrypt(plaintext).unwrap();
        let decrypted = engine.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_async_streaming_encrypt_decrypt() {
        let (_dir, engine) = setup_test_engine::<DummyCryptoSystem>("test_stream");

        let plaintext = b"some very long secret data that should be streamed";
        let mut source = Cursor::new(plaintext);
        let mut sink = Vec::new();
        
        let config = AsyncStreamingConfig::default();

        engine.encrypt_stream(&mut source, &mut sink, &config).await.unwrap();

        let ciphertext = sink;
        let mut encrypted_source = Cursor::new(ciphertext);
        let mut decrypted_sink = Vec::new();

        engine.decrypt_stream(&mut encrypted_source, &mut decrypted_sink, &config).await.unwrap();

        assert_eq!(decrypted_sink, plaintext);
    }

    #[tokio::test]
    async fn test_async_encrypt_authenticated_with_signature() {
        let (_dir, engine) = setup_test_engine::<DummyAuthSystem>("test_auth");
        let plaintext = b"authenticated data";
        let ciphertext = engine.encrypt_authenticated(plaintext).unwrap();
        let decrypted = engine.decrypt_authenticated(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_async_encrypt_without_signature() {
        let dir = tempfile::tempdir().unwrap();
        let engine = AsyncQSealEngine::<DummyAuthSystem>::builder()
            .with_storage_dir(dir.path().to_str().unwrap())
            .unwrap()
            .with_key_prefix("test_auth_no_sign")
            .build()
            .unwrap();
        
        let mut crypto_config = engine.config.get_crypto_config();
        crypto_config.use_authenticated_encryption = false;
        engine.config.update_crypto_config(crypto_config).unwrap();

        let plaintext = b"authenticated data";
        let ciphertext = engine.encrypt_authenticated(plaintext).unwrap();
        let decrypted = engine.decrypt_authenticated(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }
} 