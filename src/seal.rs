use arc_swap::ArcSwap;
use secrecy::{ExposeSecret, SecretBox, SecretString};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs as tokio_fs;

use crate::common::ConfigFile;
use crate::common::config::ConfigManager;
use crate::common::errors::Error;
use crate::common::header::SealMode;
use crate::common::traits::{AsymmetricAlgorithm, SecureKeyStorage};
use crate::engine::SealEngine;
use crate::rotation::manager::KeyManager;
use crate::storage::EncryptedKeyContainer;
use crate::vault::{MasterSeed, VaultPayload};
use hkdf::Hkdf;
use rand_core::{OsRng, TryRngCore};
use sha2::Sha256;

const MASTER_SEED_SIZE: usize = 32; // 256-bit master seed
const SEAL_ALGORITHM_ID: &str = "seal-kit-v1-vault";
// const SYMMETRIC_ENGINE_CONTEXT: &[u8] = b"seal-kit/symmetric-engine/v1";

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
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("Seal file already exists at: {}", path.display()),
            )));
        }

        // 1. 生成一个新的、高熵的根种子。
        let mut seed_bytes = vec![0u8; MASTER_SEED_SIZE];
        OsRng
            .try_fill_bytes(&mut seed_bytes)
            .map_err(|e| Error::Cryptography(e.to_string()))?;
        let master_seed = SecretBox::new(Box::from(MasterSeed(seed_bytes)));

        // 2. 创建一个默认的 VaultPayload。
        let initial_payload = VaultPayload {
            master_seed,
            key_registry: HashMap::new(),
            config: ConfigManager::new(path.parent())?,
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
        let payload: VaultPayload = serde_json::from_str(&payload_json)?;

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
            &payload.config.crypto,
        )?;

        let container_json = container.to_json()?;

        // 原子写入：先写入临时文件，成功后再重命名。
        let temp_path = path.with_extension("tmp");
        fs::write(&temp_path, container_json)?;
        fs::rename(&temp_path, path)?;

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
            &payload.config.crypto,
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
        let container_json = fs::read_to_string(path)?;
        let container = EncryptedKeyContainer::from_json(&container_json)?;

        let decrypted_bytes = container.decrypt_key(password)?;
        String::from_utf8(decrypted_bytes).map_err(Into::into)
    }

    /// 创建一个统一的、有状态的加密引擎实例。
    ///
    /// 这个方法会初始化一个密钥管理器，执行首次必要的密钥轮换，
    /// 然后返回一个持有该管理器状态的引擎。
    pub fn engine(
        self: &Arc<Self>,
        mode: SealMode,
        password: &SecretString,
    ) -> Result<SealEngine, Error> {
        let mut key_manager = KeyManager::new(Arc::clone(self), "seal-engine", mode);
        key_manager.initialize();

        // 如果没有主密钥，则根据当前配置自动轮换
        if key_manager.get_primary_key_metadata().is_none() {
            key_manager.start_rotation(password)?;
        }

        // 2. 初始化对应模式的 KeyManager
        let mut key_manager = KeyManager::new(self.clone(), "seal-engine", mode);
        key_manager.initialize();

        // 3. 如果是 Hybrid 模式，但没有主密钥，需要先创建一个
        if mode == SealMode::Hybrid && key_manager.get_primary_key_metadata().is_none() {
            // 在 engine() 调用中不应自动轮换，这应该是一个明确的用户操作。
            // 我们返回一个错误，提示用户需要先轮换/设置密钥。
            // Throwing an error here to guide the user.
            return Err(Error::KeyManagement(
                "Hybrid mode requires an initial asymmetric key. Please call `rotate_asymmetric_key` first.".to_string(),
            ));
        }

        // 4. 创建并返回引擎
        Ok(SealEngine::new(key_manager, self.clone(), password.clone()))
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
            .map_err(|e| Error::Cryptography(format!("Failed to derive key using HKDF: {}", e)))?;
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
        let current_payload = self.payload.load();
        let mut new_payload = (**current_payload).clone();

        update_fn(&mut new_payload);

        // 首先，将修改后的载荷原子地写入磁盘。
        Self::write_payload(&self.path, &new_payload, password)?;

        // 写入成功后，才更新内存中的状态。
        self.payload.store(Arc::new(new_payload));

        Ok(())
    }

    /// 手动轮换到指定的主非对称密钥。
    ///
    /// 这个方法会首先更新保险库中的主非对称算法配置，
    /// 然后立即生成一个该类型的新密钥对，并将其设为活动状态。
    ///
    /// # Arguments
    ///
    /// * `algorithm` - 要轮换到的目标非对称算法。
    /// * `password` - 用于解锁保险库的密码。
    pub fn rotate_asymmetric_key(
        self: &Arc<Self>,
        algorithm: AsymmetricAlgorithm,
        password: &SecretString,
    ) -> Result<(), Error> {
        // 1. 原子地更新配置
        self.commit_payload(password, |payload| {
            payload.config.crypto.primary_asymmetric_algorithm = algorithm;
        })?;

        // 2. 创建一个 KeyManager 来执行轮换
        //    我们总是为非对称密钥使用 Hybrid 模式
        let mut key_manager = KeyManager::new(Arc::clone(self), "seal-engine", SealMode::Hybrid);
        key_manager.initialize();

        // 3. 强制开始轮换，这将根据新的配置生成密钥
        key_manager.start_rotation(password)?;

        Ok(())
    }
}
