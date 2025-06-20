//! The main entry point for the `seal-kit` library.
// English: The main entry point for the `seal-kit` library.

use arc_swap::ArcSwap;
use secrecy::{ExposeSecret, SecretBox, SecretString};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs as tokio_fs;

use crate::common::ConfigFile;
use crate::common::config::ConfigManager;
use crate::common::errors::CryptographyError;
use crate::common::errors::Error;
use crate::common::errors::KeyManagementError;
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

/// `Seal` is the main entry point for the `seal-kit` library.
///
/// It provides lock-free management of a "vault" encrypted with a master password.
/// The vault file is self-contained, securely storing the root key seed, metadata for all keys, and configuration.
/// Once opened, `Seal` acts as a factory to create engines for symmetric and asymmetric cryptography on demand.
///
/// 中文: `Seal` 是 seal-kit 库的主入口点。
///
/// 它以无锁方式管理一个由主密码加密的保险库（Vault）。
/// 保险库文件是自包含的，安全地存储了根密钥种子、所有密钥的元数据以及配置。
/// 成功打开后，`Seal` 可以作为工厂，按需创建用于对称和非对称加解密的引擎。
pub struct Seal {
    /// The path to the vault file for persistence.
    /// 中文: 指向保险库文件的路径，用于持久化。
    path: PathBuf,
    /// Uses `ArcSwap` for atomic, lock-free read/write access to the core payload.
    /// This allows the vault's in-memory state (like keys and configuration) to be updated safely
    /// across multiple threads without blocking read operations.
    /// 中文: 使用 `ArcSwap` 实现对核心载荷的原子化、无锁读写。
    /// 这允许保险库的内存状态（如密钥和配置）在多个线程之间安全地更新，而不会阻塞读取操作。
    payload: Arc<ArcSwap<VaultPayload>>,
}

impl Seal {
    /// Creates a new vault and saves it encrypted to the specified path.
    ///
    /// # Arguments
    /// * `path` - The file path where the new vault will be stored.
    /// * `password` - The master password used to encrypt the entire vault.
    ///
    /// 中文: 创建一个新的保险库，并将其加密保存到指定的路径。
    /// # 参数
    /// * `path` - 用于存储新保险库的文件路径。
    /// * `password` - 用于加密整个保险库的主密码。
    pub fn create<P: AsRef<Path>>(path: P, password: &SecretString) -> Result<Arc<Self>, Error> {
        let path = path.as_ref();
        if path.exists() {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("Seal file already exists at: {}", path.display()),
            )));
        }

        // 1. Generate a new, high-entropy root seed.
        let mut seed_bytes = vec![0u8; MASTER_SEED_SIZE];
        OsRng
            .try_fill_bytes(&mut seed_bytes)
            .map_err(|e| Error::Cryptography(CryptographyError::RandomnessError(e.to_string())))?;
        let master_seed = SecretBox::new(Box::from(MasterSeed(seed_bytes)));

        // 2. Create a default VaultPayload.
        // 中文: 2. 创建一个默认的 VaultPayload。
        let initial_payload = VaultPayload {
            master_seed,
            key_registry: HashMap::new(),
            config: ConfigManager::new(path.parent())?,
        };

        // 3. Write the initial payload to the encrypted file.
        Self::write_payload(path, &initial_payload, password)?;

        // 4. Return a new Seal instance, wrapped in an Arc.
        Ok(Arc::new(Self {
            path: path.to_path_buf(),
            payload: Arc::new(ArcSwap::new(Arc::new(initial_payload))),
        }))
    }

    /// Opens an existing vault from the specified path.
    ///
    /// # Arguments
    /// * `path` - The file path of the vault to open.
    /// * `password` - The master password required to decrypt the vault.
    ///
    /// 中文: 从指定路径打开一个现有的保险库。
    /// # 参数
    /// * `path` - 要打开的保险库的文件路径。
    /// * `password` - 解密保险库所需的主密码。
    pub fn open<P: AsRef<Path>>(path: P, password: &SecretString) -> Result<Arc<Self>, Error> {
        let path = path.as_ref();

        // 1. Read and decrypt the core payload from the file.
        // 中文: 1. 从文件读取并解密核心载荷。
        let payload_json = Self::read_and_decrypt_payload(path, password)?;
        let payload: VaultPayload = serde_json::from_str(&payload_json)?;

        // 2. Return a new Seal instance, wrapped in an Arc.
        // 中文: 2. 返回一个新的 Seal 实例，包裹在 Arc 中。
        Ok(Arc::new(Self {
            path: path.to_path_buf(),
            payload: Arc::new(ArcSwap::new(Arc::new(payload))),
        }))
    }

    /// Encrypts and atomically writes the given payload to a file.
    ///
    /// The atomic write is achieved by writing to a temporary file first,
    /// and then renaming it to the final destination upon successful completion.
    /// This prevents data corruption if the write operation is interrupted.
    ///
    /// 中文: 将给定的载荷加密并原子地写入文件。
    ///
    /// 原子写入通过先写入临时文件，成功后再将其重命名为最终目标来实现。
    /// 这可以防止在写入操作被中断时发生数据损坏。
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

        // Atomic write: write to a temporary file first, then rename on success.
        // 中文: 原子写入：先写入临时文件，成功后再重命名。
        let temp_path = path.with_extension("tmp");
        fs::write(&temp_path, container_json)?;
        fs::rename(&temp_path, path)?;

        Ok(())
    }

    /// (Async) Encrypts and atomically writes the given payload to a file.
    ///
    /// 中文: (Async) 将给定的载荷加密并原子地写入文件。
    #[allow(dead_code)]
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

        // Atomic write: write to a temporary file first, then rename on success.
        // 中文: 原子写入：先写入临时文件，成功后再重命名。
        let temp_path = path.with_extension("tmp");
        tokio_fs::write(&temp_path, container_json).await?;
        tokio_fs::rename(&temp_path, path).await?;

        Ok(())
    }

    /// Reads the vault from a file, decrypts it, and returns its content as a JSON string.
    ///
    /// 中文: 从文件读取保险库，解密并返回其JSON字符串形式的内容。
    fn read_and_decrypt_payload(path: &Path, password: &SecretString) -> Result<String, Error> {
        let container_json = fs::read_to_string(path)?;
        let container = EncryptedKeyContainer::from_json(&container_json)?;

        let decrypted_bytes = container.decrypt_key(password)?;
        String::from_utf8(decrypted_bytes).map_err(Into::into)
    }

    /// Creates a unified, stateful encryption engine instance.
    ///
    /// This method initializes a `KeyManager` for the specified mode, performs an initial key rotation
    /// if necessary, and then returns an engine that holds the state of the manager.
    /// The engine is the primary tool for performing cryptographic operations.
    ///
    /// 中文: 创建一个统一的、有状态的加密引擎实例。
    ///
    /// 这个方法会初始化一个指定模式的密钥管理器，执行首次必要的密钥轮换，
    /// 然后返回一个持有该管理器状态的引擎。该引擎是执行加密操作的主要工具。
    pub fn engine(
        self: &Arc<Self>,
        mode: SealMode,
        password: &SecretString,
    ) -> Result<SealEngine, Error> {
        let mut key_manager = KeyManager::new(Arc::clone(self), "seal-engine", mode);
        key_manager.initialize();

        // If there is no primary key, rotate automatically based on the current configuration.
        // 中文: 如果没有主密钥，则根据当前配置自动轮换。
        if key_manager.get_primary_key_metadata().is_none() {
            key_manager.start_rotation(password)?;
        }

        // 2. Initialize a KeyManager for the corresponding mode.
        // 中文: 2. 初始化对应模式的 KeyManager。
        let mut key_manager = KeyManager::new(self.clone(), "seal-engine", mode);
        key_manager.initialize();

        // 3. If in Hybrid mode but there's no primary key, one needs to be created first.
        //    Automatic rotation should not occur in the engine() call; this should be an explicit user action.
        //    We return an error to guide the user to rotate/set a key first.
        // 中文: 3. 如果是 Hybrid 模式，但没有主密钥，需要先创建一个。
        //    在 engine() 调用中不应自动轮换，这应该是一个明确的用户操作。
        //    我们返回一个错误，提示用户需要先轮换/设置密钥。
        if mode == SealMode::Hybrid && key_manager.get_primary_key_metadata().is_none() {
            // In the engine() call, automatic rotation should not happen. This should be an explicit user action.
            // We return an error to guide the user to rotate/set the key first.
            // 中文: 在 engine() 调用中不应自动轮换，这应该是一个明确的用户操作。
            // 我们返回一个错误，提示用户需要先轮换/设置密钥。
            return Err(Error::KeyManagement(KeyManagementError::NoPrimaryKey));
        }

        // 4. Create and return the engine.
        // 中文: 4. 创建并返回引擎。
        Ok(SealEngine::new(key_manager, self.clone(), password.clone()))
    }

    /// Derives a new key from the master seed using HKDF.
    ///
    /// # Arguments
    /// * `master_seed` - The root seed from the vault.
    /// * `context` - A context string to ensure derived keys are domain-separated.
    /// * `output_len` - The desired length of the derived key in bytes.
    ///
    /// 中文: 使用HKDF从主密钥派生出一个新的密钥。
    /// # 参数
    /// * `master_seed` - 来自保险库的根种子。
    /// * `context` - 用于确保派生密钥在不同域中分离的上下文信息。
    /// * `output_len` - 派生密钥的期望长度（字节）。
    pub(crate) fn derive_key(
        &self,
        master_seed: &SecretBox<MasterSeed>,
        context: &[u8],
        output_len: usize,
    ) -> Result<Vec<u8>, Error> {
        let hk = Hkdf::<Sha256>::new(None, &master_seed.expose_secret().0);
        let mut okm = vec![0u8; output_len];
        hk.expand(context, &mut okm).map_err(|e| {
            Error::Cryptography(CryptographyError::KeyDerivationError(e.to_string()))
        })?;
        Ok(okm)
    }

    /// Gets the current configuration from within the vault.
    ///
    /// 中文: 获取当前保险库内的配置。
    pub fn config(&self) -> ConfigFile {
        self.payload.load().config.clone()
    }

    /// (crate-internal) Gets read-only access to the internal payload.
    ///
    /// 中文: (crate-internal) 获取对内部载荷的只读访问。
    pub(crate) fn payload(&self) -> Arc<VaultPayload> {
        self.payload.load_full()
    }

    /// Re-encrypts the vault with a new password.
    ///
    /// This operation is atomic. It reads the current payload, re-encrypts it with the new password,
    /// and replaces the old file.
    ///
    /// 中文: 使用新的密码重新加密保险库。
    ///
    /// 这个操作是原子的。它会读取当前的载荷，用新密码重新加密，并替换旧文件。
    pub fn change_password(&self, new_password: &SecretString) -> Result<(), Error> {
        // "Read-Clone-Save" pattern.
        // In this scenario, we don't need to modify the payload, just re-encrypt it with the new password.
        // 中文: "读取-克隆-保存" 模式。
        // 在此场景下，我们无需修改载荷，只需用新密码重新加密即可。
        let current_payload = self.payload.load();
        Self::write_payload(&self.path, &current_payload, new_password)?;
        Ok(())
    }

    /// Atomically commits modifications to the vault payload.
    ///
    /// This method is central to making safe, concurrent modifications to the vault's state (e.g., key rotation, config changes).
    /// It loads the current payload, clones it, and then passes a mutable reference to the `update_fn` closure.
    /// After the closure finishes, the new payload is encrypted and atomically written to the file,
    /// and then the in-memory `ArcSwap` is updated.
    ///
    /// # Arguments
    /// * `password` - The master password used to encrypt the new payload.
    /// * `update_fn` - A closure that receives a `&mut VaultPayload` to perform modifications.
    ///
    /// 中文: 以原子方式提交对保险库载荷的修改。
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

        // First, atomically write the modified payload to disk.
        // 中文: 首先，将修改后的载荷原子地写入磁盘。
        Self::write_payload(&self.path, &new_payload, password)?;

        // Only after the write is successful, update the in-memory state.
        // 中文: 写入成功后，才更新内存中的状态。
        self.payload.store(Arc::new(new_payload));

        Ok(())
    }

    /// Manually rotates to a specified primary asymmetric key algorithm.
    ///
    /// This method first updates the primary asymmetric algorithm configuration in the vault,
    /// then immediately generates a new key pair of that type and sets it as active.
    ///
    /// # Arguments
    /// * `algorithm` - The target asymmetric algorithm to rotate to.
    /// * `password` - The password to unlock the vault.
    ///
    /// 中文: 手动轮换到指定的主非对称密钥。
    ///
    /// 这个方法会首先更新保险库中的主非对称算法配置，
    /// 然后立即生成一个该类型的新密钥对，并将其设为活动状态。
    ///
    /// # Arguments
    /// * `algorithm` - 要轮换到的目标非对称算法。
    /// * `password` - 用于解锁保险库的密码。
    pub fn rotate_asymmetric_key(
        self: &Arc<Self>,
        algorithm: AsymmetricAlgorithm,
        password: &SecretString,
    ) -> Result<(), Error> {
        // 1. Atomically update the configuration.
        // 中文: 1. 原子地更新配置。
        self.commit_payload(password, |payload| {
            payload.config.crypto.primary_asymmetric_algorithm = algorithm;
        })?;

        // 2. Create a KeyManager to perform the rotation.
        //    We always use Hybrid mode for asymmetric keys.
        // 中文: 2. 创建一个 KeyManager 来执行轮换。
        //    我们总是为非对称密钥使用 Hybrid 模式。
        let mut key_manager = KeyManager::new(Arc::clone(self), "seal-engine", SealMode::Hybrid);
        key_manager.initialize();

        // 3. Force a rotation, which will generate a key based on the new configuration.
        // 中文: 3. 强制开始轮换，这将根据新的配置生成密钥。
        key_manager.start_rotation(password)?;

        Ok(())
    }
}
