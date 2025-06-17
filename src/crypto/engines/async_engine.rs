#![cfg(feature = "async-engine")]

use arc_swap::ArcSwapOption;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::crypto::common::CryptoConfig;
use crate::crypto::config::ConfigManager;
use crate::crypto::errors::Error;
use crate::crypto::key_rotation::{KeyMetadata, KeyStorage, RotationPolicy};
use crate::crypto::storage::KeyFileStorage;
use crate::crypto::traits::{AuthenticatedCryptoSystem, CryptographicSystem};

/// 并发版 QSeal 引擎，支持多线程同时调用
pub struct AsyncQSealEngine<C: CryptographicSystem + Send + Sync + 'static>
where
    Error: From<<C as CryptographicSystem>::Error>
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
    C: CryptographicSystem + Send + Sync + 'static,
    Error: From<<C as CryptographicSystem>::Error>,
    <C as CryptographicSystem>::Error: std::error::Error + 'static,
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

    /// 初始化，加载存储中的主密钥和次要密钥
    fn initialize(&self, config: &CryptoConfig) -> Result<(), Error> {
        let keys = self.key_storage.list_keys()?;
        for name in keys {
            if name.starts_with(&self.key_prefix) {
                let (meta, data) = self.key_storage.load_key(&name)?;
                match meta.status {
                    crate::crypto::traits::KeyStatus::Active => {
                        let (pubk, privk) = Self::deserialize(&data)?;
                        self.primary.store(Some(Arc::new((pubk, privk, meta))));
                    }
                    crate::crypto::traits::KeyStatus::Rotating => {
                        let (pubk, privk) = Self::deserialize(&data)?;
                        self.secondary.insert(name, (pubk, privk, meta));
                    }
                    crate::crypto::traits::KeyStatus::Expired => {
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
            om.status = crate::crypto::traits::KeyStatus::Rotating;
            let key_name = format!("{}-{}", self.key_prefix, om.id);
            let data = Self::serialize(&_opk, &_osk)?;
            self.key_storage.save_key(&key_name, &om, &data)?;
            self.secondary.insert(key_name.clone(), (_opk, _osk, om));
        }
        let metadata = KeyMetadata { id: id.clone(), created_at: now.clone(), expires_at: Some(exp), usage_count: 0, status: crate::crypto::traits::KeyStatus::Active, version, algorithm: format!("{}", std::any::type_name::<C>()) };
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
            if meta.status == crate::crypto::traits::KeyStatus::Rotating {
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
        // 完成上次轮换并删除过期密钥
        self.complete_rotation()?;
        // 获取配置
        let cfg = self.config.get_crypto_config();
        // 首先尝试使用主密钥解密并可选验证签名
        if let Some(arc) = self.primary.load_full() {
            let (pubk, sk, _) = &*arc;
            let verifier = if cfg.auto_verify_signatures { Some(pubk) } else { None };
            if let Ok(pt) = C::decrypt_authenticated(sk, ciphertext, None, verifier) {
                return Ok(pt);
            }
        }
        // 主密钥失败后尝试次要密钥（不验证签名）
        for entry in self.secondary.iter() {
            let (_pubk, sk, _) = entry.value();
            if let Ok(pt) = C::decrypt_authenticated(sk, ciphertext, None, None) {
                return Ok(pt);
            }
        }
        Err(Error::Operation("解密失败：所有可用密钥都无法解密该密文".to_string()))
    }
}

// 为并发引擎添加单元测试
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::common::{Base64String, CryptoConfig, from_base64};
    use crate::crypto::config::ConfigManager;
    use crate::crypto::errors::Error;
    use crate::crypto::traits::{AuthenticatedCryptoSystem, CryptographicSystem};
    use std::sync::Arc;
    use tempfile::TempDir;

    /// 仅支持基础加解密的测试系统
    #[derive(Clone)]
    struct DummyCryptoSystem;
    impl CryptographicSystem for DummyCryptoSystem {
        type PublicKey = String;
        type PrivateKey = String;
        type CiphertextOutput = Base64String;
        type Error = Error;

        fn generate_keypair(_config: &CryptoConfig) -> Result<(Self::PublicKey, Self::PrivateKey), Self::Error> {
            Ok(("PUB".to_string(), "PRIV".to_string()))
        }
        fn encrypt(_public_key: &Self::PublicKey, plaintext: &[u8], _additional_data: Option<&[u8]>) -> Result<Self::CiphertextOutput, Self::Error> {
            Ok(Base64String::from(plaintext.to_vec()))
        }
        fn decrypt(_private_key: &Self::PrivateKey, ciphertext: &str, _additional_data: Option<&[u8]>) -> Result<Vec<u8>, Self::Error> {
            from_base64(ciphertext).map_err(|e| Error::Operation(format!("Base64解码失败: {}", e)))
        }
        fn export_public_key(pk: &Self::PublicKey) -> Result<String, Self::Error> { Ok(pk.clone()) }
        fn export_private_key(sk: &Self::PrivateKey) -> Result<String, Self::Error> { Ok(sk.clone()) }
        fn import_public_key(pk: &str) -> Result<Self::PublicKey, Self::Error> { Ok(pk.to_string()) }
        fn import_private_key(sk: &str) -> Result<Self::PrivateKey, Self::Error> { Ok(sk.to_string()) }
    }

    /// 支持认证加解密的测试系统
    #[derive(Clone)]
    struct DummyAuthSystem;
    impl CryptographicSystem for DummyAuthSystem {
        type PublicKey = String;
        type PrivateKey = String;
        type CiphertextOutput = Base64String;
        type Error = Error;

        fn generate_keypair(_config: &CryptoConfig) -> Result<(Self::PublicKey, Self::PrivateKey), Self::Error> {
            Ok(("PUB".to_string(), "PRIV".to_string()))
        }
        fn encrypt(_public_key: &Self::PublicKey, plaintext: &[u8], _additional_data: Option<&[u8]>) -> Result<Self::CiphertextOutput, Self::Error> {
            Ok(Base64String::from(plaintext.to_vec()))
        }
        fn decrypt(_private_key: &Self::PrivateKey, ciphertext: &str, _additional_data: Option<&[u8]>) -> Result<Vec<u8>, Self::Error> {
            from_base64(ciphertext).map_err(|e| Error::Operation(format!("Base64解码失败: {}", e)))
        }
        fn export_public_key(pk: &Self::PublicKey) -> Result<String, Self::Error> { Ok(pk.clone()) }
        fn export_private_key(sk: &Self::PrivateKey) -> Result<String, Self::Error> { Ok(sk.clone()) }
        fn import_public_key(pk: &str) -> Result<Self::PublicKey, Self::Error> { Ok(pk.to_string()) }
        fn import_private_key(sk: &str) -> Result<Self::PrivateKey, Self::Error> { Ok(sk.to_string()) }
    }
    impl AuthenticatedCryptoSystem for DummyAuthSystem {
        type AuthenticatedOutput = Base64String;

        fn sign(_private_key: &Self::PrivateKey, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
            let mut v = data.to_vec(); v.extend_from_slice(b"::SIG"); Ok(v)
        }
        fn verify(_public_key: &Self::PublicKey, _data: &[u8], _signature: &[u8]) -> Result<bool, Self::Error> { Ok(true) }
        fn encrypt_authenticated(
            public_key: &Self::PublicKey,
            plaintext: &[u8],
            additional_data: Option<&[u8]>,
            signer_key: Option<&Self::PrivateKey>
        ) -> Result<Self::AuthenticatedOutput, Self::Error> {
            let mut v = plaintext.to_vec();
            if signer_key.is_some() {
                let sig = Self::sign(signer_key.unwrap(), plaintext)?;
                v = sig;
            }
            Ok(Base64String::from(v))
        }
        fn decrypt_authenticated(
            private_key: &Self::PrivateKey,
            ciphertext: &str,
            additional_data: Option<&[u8]>,
            verifier_key: Option<&Self::PublicKey>
        ) -> Result<Vec<u8>, Self::Error> {
            // 先进行 Base64 解码
            let mut data = from_base64(ciphertext).map_err(|e| Error::Operation(format!("Base64解码失败: {}", e)))?;
            if verifier_key.is_some() && !data.ends_with(b"::SIG") {
                return Err(Error::Operation("签名验证失败".to_string()));
            }
            if data.ends_with(b"::SIG") {
                data.truncate(data.len() - 5);
            }
            Ok(data)
        }
    }

    #[test]
    fn test_async_basic_encrypt_decrypt() {
        let temp = TempDir::new().unwrap();
        let dir = temp.path().to_str().unwrap().to_string();
        let config = Arc::new(ConfigManager::new());
        let mut sc = config.get_storage_config(); sc.key_storage_dir = dir.clone();
        config.update_storage_config(sc).unwrap();
        let engine = AsyncQSealEngine::<DummyCryptoSystem>::new(Arc::clone(&config), "test").unwrap();
        let plaintext = b"async world";
        let ct = engine.encrypt(plaintext).unwrap();
        let pt = engine.decrypt(&ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_async_encrypt_authenticated_with_signature() {
        let temp = TempDir::new().unwrap();
        let dir = temp.path().to_str().unwrap().to_string();
        let config = Arc::new(ConfigManager::new());
        let mut sc = config.get_storage_config(); sc.key_storage_dir = dir.clone();
        config.update_storage_config(sc).unwrap();
        let engine = AsyncQSealEngine::<DummyAuthSystem>::new(Arc::clone(&config), "auth").unwrap();
        let plaintext = b"async protect";
        let ct = engine.encrypt_authenticated(plaintext).unwrap();
        let pt = engine.decrypt_authenticated(&ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_async_encrypt_without_signature() {
        let temp = TempDir::new().unwrap();
        let dir = temp.path().to_str().unwrap().to_string();
        let config = Arc::new(ConfigManager::new());
        let mut cc = config.get_crypto_config();
        cc.use_authenticated_encryption = false;
        cc.auto_verify_signatures = false;
        config.update_crypto_config(cc).unwrap();
        let mut sc = config.get_storage_config(); sc.key_storage_dir = dir.clone();
        config.update_storage_config(sc).unwrap();
        let engine = AsyncQSealEngine::<DummyAuthSystem>::new(Arc::clone(&config), "auth2").unwrap();
        let plaintext = b"async no sign";
        let ct = engine.encrypt_authenticated(plaintext).unwrap();
        assert_eq!(ct, Base64String::from(plaintext.to_vec()).to_string());
        let pt = engine.decrypt_authenticated(&ct).unwrap();
        assert_eq!(pt, plaintext);
    }
} 