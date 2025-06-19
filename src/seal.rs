use arc_swap::ArcSwap;
use secrecy::{CloneableSecret, ExposeSecret, SecretBox, SecretString, SerializableSecret};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs as tokio_fs;

use crate::asymmetric::engines::AsymmetricQSealAsyncEngine;
use crate::asymmetric::engines::AsymmetricQSealEngine;
use crate::asymmetric::rotation::AsymmetricKeyRotationManager;
use crate::asymmetric::traits::{AsymmetricCryptographicSystem, AsymmetricSyncStreamingSystem};
use crate::common::ConfigFile;
use crate::common::config::ConfigManager;
use crate::common::errors::Error;
use crate::common::traits::{KeyMetadata, SecureKeyStorage};
use crate::storage::EncryptedKeyContainer;
use crate::symmetric::engines::SymmetricQSealAsyncEngine;
use crate::symmetric::engines::SymmetricQSealEngine;
use crate::symmetric::rotation::SymmetricKeyRotationManager;
use crate::symmetric::traits::{
    SymmetricAsyncStreamingSystem, SymmetricCryptographicSystem, SymmetricSyncStreamingSystem,
};
use hkdf::Hkdf;
use rand_core::{OsRng, TryRngCore};
use sha2::Sha256;
use zeroize::Zeroize;

const MASTER_SEED_SIZE: usize = 32; // 256-bit master seed
const SEAL_ALGORITHM_ID: &str = "seal-kit-v1-vault";
// const SYMMETRIC_ENGINE_CONTEXT: &[u8] = b"seal-kit/symmetric-engine/v1";

/// 用于主种子的 Newtype 包装，以实现 `SerializableSecret`。
#[derive(Clone, Serialize, Deserialize, Zeroize)]
pub struct MasterSeed(#[serde(with = "serde_bytes")] pub Vec<u8>);

// 为我们的 newtype 选择加入秘密序列化。
impl SerializableSecret for MasterSeed {}
// 允许包含此 newtype 的 SecretBox 被克隆。
impl CloneableSecret for MasterSeed {}

/// Seal 文件中加密存储的核心载荷 (Payload)。
///
/// 这个结构体包含了维持保险库运作所需的所有状态，包括用于派生所有密钥的根种子、
/// 密钥元数据注册表以及完整的配置。
/// 它被序列化为 JSON，然后使用主密码通过 `EncryptedKeyContainer` 进行加密。
#[derive(Clone, Serialize, Deserialize)]
pub struct VaultPayload {
    /// 用于确定性地派生所有子密钥的根种子。
    pub master_seed: SecretBox<MasterSeed>,
    /// 密钥元数据注册表，键是密钥的唯一ID。
    pub key_registry: HashMap<String, KeyMetadata>,
    /// 存储在保险库内的配置信息。
    pub config: ConfigFile,
}

/// `Seal` 是 seal-kit 库的主入口点。
///
/// 它以无锁方式管理一个由主密码加密的保险库（Vault）。
/// 保险库文件是自包含的，安全地存储了根密钥种子、所有密钥的元数据以及配置。
/// 成功打开后，`Seal` 可以作为工厂，按需创建用于对称和非对称加解密的引擎。
pub struct Seal {
    /// 指向保险库文件的路径，用于持久化。
    path: PathBuf,
    /// 使用 ArcSwap 实现对核心载荷的原子化、无锁读写。
    payload: Arc<ArcSwap<VaultPayload>>,
}

impl Seal {
    /// 创建一个新的保险库，并将其加密保存到指定的路径。
    pub fn create<P: AsRef<Path>>(path: P, password: &SecretString) -> Result<Arc<Self>, Error> {
        let path = path.as_ref();
        if path.exists() {
            return Err(Error::KeyStorage(format!(
                "Seal file already exists at: {}",
                path.display()
            )));
        }

        // 1. 生成一个新的、高熵的根种子。
        let mut seed_bytes = vec![0u8; MASTER_SEED_SIZE];
        OsRng
            .try_fill_bytes(&mut seed_bytes)
            .map_err(|e| Error::Key(e.to_string()))?;
        let master_seed = SecretBox::new(Box::from(MasterSeed(seed_bytes)));

        // 2. 创建一个默认的 VaultPayload。
        let initial_payload = VaultPayload {
            master_seed,
            key_registry: HashMap::new(),
            config: ConfigManager::new()?,
        };

        // 3. 将初始载荷写入加密文件。
        Self::write_payload(path, &initial_payload, password)?;

        // 4. 返回一个新的 Seal 实例，包裹在 Arc 中。
        Ok(Arc::new(Self {
            path: path.to_path_buf(),
            payload: Arc::new(ArcSwap::new(Arc::new(initial_payload))),
        }))
    }

    /// 从指定路径打开一个现有的保险库。
    pub fn open<P: AsRef<Path>>(path: P, password: &SecretString) -> Result<Arc<Self>, Error> {
        let path = path.as_ref();

        // 1. 从文件读取并解密核心载荷。
        let payload_json = Self::read_and_decrypt_payload(path, password)?;
        let payload: VaultPayload = serde_json::from_str(&payload_json).map_err(|e| {
            Error::Serialization(format!("Failed to deserialize vault payload: {}", e))
        })?;

        // 2. 返回一个新的 Seal 实例，包裹在 Arc 中。
        Ok(Arc::new(Self {
            path: path.to_path_buf(),
            payload: Arc::new(ArcSwap::new(Arc::new(payload))),
        }))
    }

    /// 将给定的载荷加密并原子地写入文件。
    fn write_payload(
        path: &Path,
        payload: &VaultPayload,
        password: &SecretString,
    ) -> Result<(), Error> {
        let payload_json = serde_json::to_string(payload)?;

        let container = EncryptedKeyContainer::encrypt_key(
            password,
            payload_json.as_bytes(),
            SEAL_ALGORITHM_ID,
        )?;

        let container_json = container.to_json()?;

        // 原子写入：先写入临时文件，成功后再重命名。
        let temp_path = path.with_extension("tmp");
        fs::write(&temp_path, container_json).map_err(|e| Error::Io(e))?;
        fs::rename(&temp_path, path).map_err(|e| Error::Io(e))?;

        Ok(())
    }

    /// (Async) 将给定的载荷加密并原子地写入文件。
    async fn write_payload_async(
        path: &Path,
        payload: &VaultPayload,
        password: &SecretString,
    ) -> Result<(), Error> {
        let payload_json = serde_json::to_string(payload)?;

        let container = EncryptedKeyContainer::encrypt_key(
            password,
            payload_json.as_bytes(),
            SEAL_ALGORITHM_ID,
        )?;

        let container_json = container.to_json()?;

        // 原子写入：先写入临时文件，成功后再重命名。
        let temp_path = path.with_extension("tmp");
        tokio_fs::write(&temp_path, container_json).await?;
        tokio_fs::rename(&temp_path, path).await?;

        Ok(())
    }

    /// 从文件读取保险库，解密并返回其JSON字符串形式的内容。
    fn read_and_decrypt_payload(path: &Path, password: &SecretString) -> Result<String, Error> {
        let container_json = fs::read_to_string(path)
            .map_err(|e| Error::KeyStorage(format!("Failed to read seal file: {}", e)))?;
        let container = EncryptedKeyContainer::from_json(&container_json)?;

        let decrypted_bytes = container.decrypt_key(password)?;
        String::from_utf8(decrypted_bytes)
            .map_err(|e| Error::Format(format!("Vault payload is not valid UTF-8: {}", e)))
    }

    /// 创建一个同步对称加密引擎。
    ///
    /// 此方法从主密钥派生出一个专用于对称加密的密钥，并用它来实例化一个
    /// `SymmetricQSealEngine`。返回的引擎可以安全地用于加密和解密数据。
    pub fn symmetric_sync_engine<T>(
        self: &Arc<Self>,
        password: SecretString,
    ) -> Result<SymmetricQSealEngine<T>, Error>
    where
        T: SymmetricCryptographicSystem + SymmetricSyncStreamingSystem,
        T::Error: std::error::Error + 'static,
        Error: From<T::Error>,
        T::Key: Clone,
    {
        // 1. 创建并初始化密钥管理器。
        let mut key_manager =
            SymmetricKeyRotationManager::new(Arc::clone(self), "symmetric-default");
        key_manager.initialize()?;

        // 2. 如果需要，执行首次密钥轮换（即创建第一个密钥）。
        if key_manager.needs_rotation() {
            let algorithm_name = std::any::type_name::<T>().to_string();
            key_manager.start_rotation(&password, &algorithm_name)?;
        }

        // 3. 创建并返回引擎实例。
        Ok(SymmetricQSealEngine::new(key_manager, password))
    }

    /// 创建一个异步对称加密引擎。
    pub async fn symmetric_async_engine<T>(
        self: &Arc<Self>,
        password: SecretString,
    ) -> Result<SymmetricQSealAsyncEngine<T>, Error>
    where
        T: SymmetricCryptographicSystem + SymmetricAsyncStreamingSystem + Send + Sync + 'static,
        T::Key: Send + Sync,
        T::Error: std::error::Error + Send + Sync + 'static,
        Error: From<T::Error>,
    {
        // 1. 创建并初始化密钥管理器。
        let mut key_manager =
            SymmetricKeyRotationManager::new(Arc::clone(self), "symmetric-default-async");
        key_manager.initialize()?;

        // 2. 如果需要，执行首次密钥轮换（即创建第一个密钥）。
        if key_manager.needs_rotation() {
            let algorithm_name = std::any::type_name::<T>().to_string();
            key_manager
                .start_rotation_async(&password, &algorithm_name)
                .await?;
        }

        // 3. 创建并返回引擎实例。
        Ok(SymmetricQSealAsyncEngine::new(key_manager, password))
    }

    /// 创建一个同步非对称加密引擎。
    pub fn asymmetric_sync_engine<T>(
        self: &Arc<Self>,
        password: SecretString,
    ) -> Result<AsymmetricQSealEngine<T>, Error>
    where
        T: AsymmetricCryptographicSystem + AsymmetricSyncStreamingSystem,
        T::Error: std::error::Error + 'static,
        Error: From<T::Error>,
    {
        // 1. 创建并初始化密钥管理器。
        let mut key_manager =
            AsymmetricKeyRotationManager::new(Arc::clone(self), "asymmetric-default");
        key_manager.initialize()?;

        // 2. 如果需要，执行首次密钥轮换（即创建第一个密钥）。
        if key_manager.needs_rotation() {
            key_manager.start_rotation::<T>(&password)?;
        }

        // 3. 创建并返回引擎实例。
        Ok(AsymmetricQSealEngine::new(key_manager, password))
    }

    /// 创建一个异步非对称加密引擎。
    pub async fn asymmetric_async_engine<T>(
        self: &Arc<Self>,
        password: SecretString,
    ) -> Result<AsymmetricQSealAsyncEngine<T>, Error>
    where
        T: crate::asymmetric::traits::AsyncStreamingSystem + Send + Sync + 'static,
        T::PublicKey: Send + Sync,
        T::PrivateKey: Send + Sync,
        T::Error: std::error::Error + Send + Sync + 'static,
        Error: From<T::Error>,
    {
        // 1. 创建并初始化密钥管理器。
        let mut key_manager =
            AsymmetricKeyRotationManager::new(Arc::clone(self), "asymmetric-default-async");
        key_manager.initialize()?;

        // 2. 如果需要，执行首次密钥轮换（即创建第一个密钥）。
        if key_manager.needs_rotation() {
            key_manager.start_rotation_async::<T>(&password).await?;
        }

        // 3. 创建并返回引擎实例。
        Ok(AsymmetricQSealAsyncEngine::new(key_manager, password))
    }

    /// 使用HKDF从主密钥派生出一个新的密钥。
    pub(crate) fn derive_key(
        &self,
        master_seed: &SecretBox<MasterSeed>,
        context: &[u8],
        output_len: usize,
    ) -> Result<Vec<u8>, Error> {
        let hk = Hkdf::<Sha256>::new(None, &master_seed.expose_secret().0);
        let mut okm = vec![0u8; output_len];
        hk.expand(context, &mut okm)
            .map_err(|e| Error::Key(format!("Failed to derive key using HKDF: {}", e)))?;
        Ok(okm)
    }

    /// 获取当前保险库内的配置。
    pub fn config(&self) -> ConfigFile {
        self.payload.load().config.clone()
    }

    /// (crate-internal) 获取对内部载荷的只读访问。
    pub(crate) fn payload(&self) -> Arc<VaultPayload> {
        self.payload.load_full()
    }

    /// 使用新的密码重新加密保险库。
    ///
    /// 这个操作是原子的。它会读取当前的载荷，用新密码重新加密，并替换旧文件。
    pub fn change_password(&self, new_password: &SecretString) -> Result<(), Error> {
        // "读取-克隆-保存" 模式
        // 在此场景下，我们无需修改载荷，只需用新密码重新加密即可。
        let current_payload = self.payload.load();
        Self::write_payload(&self.path, &current_payload, new_password)?;
        Ok(())
    }

    /// 以原子方式提交对保险库载荷的修改。
    ///
    /// 此方法是实现对保险库状态（如密钥轮换、配置更改）进行安全并发修改的核心。
    /// 它加载当前的载荷，克隆它，然后将可变引用传递给 `update_fn` 闭包。
    /// 闭包执行完毕后，新的载荷将被加密并原子地写入文件，然后更新内存中的 `ArcSwap`。
    ///
    /// # Arguments
    /// * `password` - 用于加密新载荷的主密码。
    /// * `update_fn` - 一个接收 `&mut VaultPayload` 的闭包，用于执行修改。
    pub(crate) fn commit_payload<F>(
        &self,
        password: &SecretString,
        update_fn: F,
    ) -> Result<(), Error>
    where
        F: FnOnce(&mut VaultPayload),
    {
        // 1. 加载当前载荷的 Arc 指针。
        let old_payload_arc = self.payload.load();

        // 2. 克隆载荷以进行修改。
        //    我们克隆 Arc 内部的数据，而不是 Arc 本身。
        let mut new_payload = (**old_payload_arc).clone();

        // 3. 将可变引用传递给闭包以执行更新。
        update_fn(&mut new_payload);

        // 4. 将更新后的载荷原子地写入文件。
        Self::write_payload(&self.path, &new_payload, password)?;

        // 5. 用新的载荷原子地替换内存中的旧载荷。
        self.payload.store(Arc::new(new_payload));

        Ok(())
    }

    /// (Async) 以原子方式提交对保险库载荷的修改。
    pub(crate) async fn commit_payload_async<F>(
        &self,
        password: &SecretString,
        update_fn: F,
    ) -> Result<(), Error>
    where
        F: FnOnce(&mut VaultPayload),
    {
        // 1. 加载当前载荷的 Arc 指针。
        let old_payload_arc = self.payload.load();

        // 2. 克隆载荷以进行修改。
        let mut new_payload = (**old_payload_arc).clone();

        // 3. 将可变引用传递给闭包以执行更新。
        update_fn(&mut new_payload);

        // 4. 将更新后的载荷原子地写入文件。
        Self::write_payload_async(&self.path, &new_payload, password).await?;

        // 5. 用新的载荷原子地替换内存中的旧载荷。
        self.payload.store(Arc::new(new_payload));

        Ok(())
    }
}
