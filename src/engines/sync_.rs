//! Q-Seal核心引擎，提供统一的高级API
//!
//! 该模块封装了密钥管理、轮换、加解密等复杂性，为用户提供一个简洁的入口。

use std::path::Path;
use std::sync::Arc;

use crate::config::ConfigManager;
use crate::errors::Error;
use crate::rotation::KeyRotationManager;
use crate::storage::KeyFileStorage;
use crate::traits::{AuthenticatedCryptoSystem, CryptographicSystem};
use crate::primitives::{from_base64, Base64String, CryptoConfig};

/// Q-Seal核心引擎
///
/// 这是一个高级API，它封装了所有底层组件，提供了一个简单、统一的接口。
/// `C` 是一个实现了 `CryptographicSystem` 特征的加密系统类型。
pub struct QSealEngine<C: CryptographicSystem>
where
    // 确保引擎内可以处理其使用的加密系统的错误
    Error: From<<C as CryptographicSystem>::Error>
{
    /// 配置管理器
    config: Arc<ConfigManager>,
    /// 单线程模式下直接持有轮换管理器
    key_manager: KeyRotationManager<C>,
}

impl<C: CryptographicSystem> QSealEngine<C>
where
    Error: From<<C as CryptographicSystem>::Error>,
    <C as CryptographicSystem>::Error: std::error::Error + 'static,
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
    
    /// 加密数据
    ///
    /// 自动处理密钥选择、使用计数更新和必要的密钥轮换。
    pub fn encrypt(&mut self, data: &[u8]) -> Result<String, Error> {
        let manager = &mut self.key_manager;
        
        // 完成上次轮换并删除过期密钥
        manager.complete_rotation()?;
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
        
        // 完成上次轮换并删除过期密钥
        manager.complete_rotation()?;
        
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
    
    /// 获取当前的配置管理器
    pub fn config(&self) -> Arc<ConfigManager> {
        Arc::clone(&self.config)
    }
}

impl<C: AuthenticatedCryptoSystem> QSealEngine<C>
where
    Error: From<<C as CryptographicSystem>::Error>,
    <C as CryptographicSystem>::Error: std::error::Error + 'static,
{
    /// 带认证的加密: 根据配置执行必要的轮换并可选签名
    pub fn encrypt_authenticated(&mut self, plaintext: &[u8]) -> Result<String, Error> {
        let manager = &mut self.key_manager;
        
        // 完成上次轮换并删除过期密钥
        manager.complete_rotation()?;
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
        
        // 完成上次轮换并删除过期密钥
        manager.complete_rotation()?;
        
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::{from_base64, Base64String, CryptoConfig};
    use crate::config::ConfigManager;
    use std::sync::Arc;
    use tempfile::TempDir;

    /// 简单的测试用系统，仅实现基础加密/解密
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

    /// 支持认证加解密的测试用系统
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
            // 模拟签名，将 "::SIG" 附加到数据
            let mut v = data.to_vec(); v.extend_from_slice(b"::SIG"); Ok(v)
        }
        fn verify(_public_key: &Self::PublicKey, data: &[u8], _signature: &[u8]) -> Result<bool, Self::Error> {
            // 总是验证通过
            let _ = data; Ok(true)
        }
        fn encrypt_authenticated(
            _public_key: &Self::PublicKey,
            plaintext: &[u8],
            _additional_data: Option<&[u8]>,
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
            _private_key: &Self::PrivateKey,
            ciphertext: &str,
            _additional_data: Option<&[u8]>,
            verifier_key: Option<&Self::PublicKey>
        ) -> Result<Vec<u8>, Self::Error> {
            let mut data = from_base64(ciphertext)
                .map_err(|e| Error::Operation(format!("Base64解码失败: {}", e)))?;
            // 模拟验签：如果提供了 verifier_key，必须已附加 ::SIG
            if let Some(_pk) = verifier_key {
                if !data.ends_with(b"::SIG") {
                    return Err(Error::Operation("签名验证失败".to_string()));
                }
            }
            // 去除签名部分
            if data.ends_with(b"::SIG") {
                data.truncate(data.len() - 5);
            }
            Ok(data)
        }
    }

    fn make_engine<C: CryptographicSystem>(config: Arc<ConfigManager>, prefix: &str) -> QSealEngine<C>
    where Error: From<<C as CryptographicSystem>::Error>, <C as CryptographicSystem>::Error: std::error::Error + 'static {
        QSealEngine::new(config, prefix).unwrap()
    }

    #[test]
    fn test_engine_basic_encrypt_decrypt() {
        let temp = TempDir::new().unwrap();
        let dir = temp.path().to_str().unwrap().to_string();
        let config = Arc::new(ConfigManager::new());
        let mut sc = config.get_storage_config(); sc.key_storage_dir = dir.clone();
        config.update_storage_config(sc).unwrap();
        let mut engine = make_engine::<DummyCryptoSystem>(Arc::clone(&config), "test");
        let plaintext = b"hello world";
        let ct = engine.encrypt(plaintext).unwrap();
        let pt = engine.decrypt(&ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_engine_encrypt_authenticated_with_signature_and_verify() {
        let temp = TempDir::new().unwrap();
        let dir = temp.path().to_str().unwrap().to_string();
        let config = Arc::new(ConfigManager::new());
        let mut sc = config.get_storage_config(); sc.key_storage_dir = dir.clone();
        config.update_storage_config(sc).unwrap();
        // 默认配置下 use_authenticated_encryption=true, auto_verify_signatures=true
        let mut engine = make_engine::<DummyAuthSystem>(Arc::clone(&config), "auth");
        let plaintext = b"data to protect";
        let ct = engine.encrypt_authenticated(plaintext).unwrap();
        let pt = engine.decrypt_authenticated(&ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_engine_encrypt_authenticated_without_signature() {
        let temp = TempDir::new().unwrap();
        let dir = temp.path().to_str().unwrap().to_string();
        let config = Arc::new(ConfigManager::new());
        // 关闭签名和验证
        let mut cc = config.get_crypto_config();
        cc.use_authenticated_encryption = false;
        cc.auto_verify_signatures = false;
        config.update_crypto_config(cc).unwrap();
        let mut sc = config.get_storage_config(); sc.key_storage_dir = dir.clone();
        config.update_storage_config(sc).unwrap();
        let mut engine = make_engine::<DummyAuthSystem>(Arc::clone(&config), "auth2");
        let plaintext = b"no sign data";
        let ct = engine.encrypt_authenticated(plaintext).unwrap();
        // ciphertext 应该是 plaintext 的 Base64
        assert_eq!(from_base64(&ct).unwrap(), plaintext);
        // decrypt 不需校验签名
        let pt = engine.decrypt_authenticated(&ct).unwrap();
        assert_eq!(pt, plaintext);
    }
} 