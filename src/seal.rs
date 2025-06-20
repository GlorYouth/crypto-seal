//! The main entry point for the `seal-kit` library.
// English: The main entry point for the `seal-kit` library.

use arc_swap::ArcSwap;
use secrecy::{ExposeSecret, SecretBox, SecretString};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::common::config::{ConfigManager, ConfigFile};
use crate::common::errors::{CryptographyError, Error, KeyManagementError};
use crate::common::header::SealMode;
use crate::common::traits::AsymmetricAlgorithm;
use crate::engine::SealEngine;
use crate::rotation::manager::KeyManager;
#[cfg(feature = "secure-storage")]
use crate::storage::encrypted_store::EncryptedVaultStore;
use crate::storage::plaintext_store::PlaintextVaultStore;
use crate::storage::traits::VaultPersistence;
use crate::vault::{MasterSeed, VaultPayload};
use hkdf::Hkdf;
use rand_core::{OsRng, TryRngCore};
use sha2::Sha256;

const MASTER_SEED_SIZE: usize = 32; // 256-bit master seed
const SEAL_ALGORITHM_ID: &str = "seal-kit-v1-vault";
// const SYMMETRIC_ENGINE_CONTEXT: &[u8] = b"seal-kit/symmetric-engine/v1";

/// `Seal` is the main, thread-safe entry point for the `seal-kit` library.
///
/// It represents an entire cryptographic context, often called a "vault".
/// This vault is a single, self-contained entity (typically a file) that securely stores:
/// - A master seed from which all cryptographic keys are derived.
/// - A registry of all generated keys (both symmetric and asymmetric) and their metadata.
/// - Configuration for cryptographic operations.
///
/// `Seal` uses different persistence strategies (`VaultPersistence`) to handle storage,
/// allowing it to operate in either a password-encrypted mode (`secure-storage` feature)
/// or a plaintext JSON mode. Once initialized, `Seal` acts as a factory for creating
/// stateful `SealEngine` instances that perform the actual encryption and decryption.
///
/// Due to its use of `Arc` and `ArcSwap`, a `Seal` instance can be safely shared across threads.
///
/// 中文: `Seal` 是 `seal-kit` 库主要的、线程安全的入口点。
///
/// 它代表一个完整的加密上下文，通常称为"保险库"（Vault）。
/// 这个保险库是一个独立的、自包含的实体（通常是一个文件），安全地存储了：
/// - 一个主种子，所有加密密钥都由它派生而来。
/// - 一个包含所有已生成密钥（对称和非对称）及其元数据的注册表。
/// - 用于加密操作的配置。
///
/// `Seal` 使用不同的持久化策略 (`VaultPersistence`) 来处理存储，
/// 使其既可以在密码加密模式下工作（`secure-storage` 特性），也可以在明文 JSON 模式下工作。
/// 初始化后，`Seal` 充当工厂，用于创建执行实际加密和解密的状态化 `SealEngine` 实例。
///
/// 由于其内部使用了 `Arc` 和 `ArcSwap`，`Seal` 实例可以在多个线程之间安全地共享。
pub struct Seal {
    /// The file path to the vault, used for loading and saving.
    /// 中文: 指向保险库文件的路径，用于加载和保存。
    path: PathBuf,
    /// Uses `ArcSwap` for atomic, lock-free read/write access to the core `VaultPayload`.
    /// This allows the vault's in-memory state (like keys and configuration) to be updated
    /// safely across multiple threads without blocking read operations.
    /// 中文: 使用 `ArcSwap` 实现对核心 `VaultPayload` 的原子化、无锁读写。
    /// 这允许保险库的内存状态（如密钥和配置）在多个线程之间安全地更新，而不会阻塞读取操作。
    payload: Arc<ArcSwap<VaultPayload>>,
    /// The persistence strategy (`EncryptedVaultStore` or `PlaintextVaultStore`) for loading and saving the vault.
    /// 中文: 用于加载和保存保险库的持久化策略（`EncryptedVaultStore` 或 `PlaintextVaultStore`）。
    persistence: Arc<dyn VaultPersistence>,
}

impl Seal {
    /// The generic, internal constructor for creating a new vault.
    ///
    /// This function handles the core logic of generating a master seed, creating a default payload,
    /// and performing the initial save using the provided persistence strategy.
    ///
    /// For external use, the convenience methods `create_encrypted` and `create_plaintext` are preferred.
    ///
    /// 中文: 用于创建新保险库的通用内部构造函数。
    ///
    /// 此函数处理生成主种子、创建默认载荷以及使用所提供的持久化策略执行初始保存的核心逻辑。
    ///
    /// 对于外部使用，推荐使用更便捷的 `create_encrypted` 和 `create_plaintext` 方法。
    pub fn create<P: AsRef<Path>>(
        path: P,
        password: Option<&SecretString>,
        persistence: Arc<dyn VaultPersistence>,
    ) -> Result<Arc<Self>, Error> {
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
        let initial_payload = VaultPayload {
            master_seed,
            key_registry: HashMap::new(),
            config: ConfigManager::new(path.parent())?,
        };

        // 3. Write the initial payload using the persistence strategy.
        persistence.save(path, &initial_payload, password)?;

        // 4. Return a new Seal instance, wrapped in an Arc.
        // 中文: 返回一个新的 Seal 实例，包装在 Arc 中。
        Ok(Arc::new(Self {
            path: path.to_path_buf(),
            payload: Arc::new(ArcSwap::new(Arc::new(initial_payload))),
            persistence,
        }))
    }

    /// Creates a new, password-encrypted vault and saves it to the specified path.
    ///
    /// This is the standard, secure way to create a vault. It uses the `EncryptedVaultStore`
    /// persistence strategy, which encrypts the entire vault file with a key derived from the provided password.
    ///
    /// **This method is only available when the `secure-storage` feature is enabled.**
    ///
    /// 中文: 创建一个新的、由密码加密的保险库，并将其保存到指定路径。
    ///
    /// 这是创建保险库的标准、安全方式。它使用 `EncryptedVaultStore` 持久化策略，
    /// 该策略使用从所提供密码派生的密钥来加密整个保险库文件。
    ///
    /// **此方法仅在 `secure-storage` 功能启用时可用。**
    #[cfg(feature = "secure-storage")]
    pub fn create_encrypted<P: AsRef<Path>>(
        path: P,
        password: &SecretString,
    ) -> Result<Arc<Self>, Error> {
        Self::create(path, Some(password), Arc::new(EncryptedVaultStore::new()))
    }

    /// Creates a new, plaintext vault and saves it to the specified path.
    ///
    /// The resulting vault is a human-readable JSON file. This is useful for environments where the
    /// vault file is stored on an already-encrypted filesystem or for local tools where at-rest encryption is not needed.
    ///
    /// This method uses the `PlaintextVaultStore` and ignores any password.
    ///
    /// 中文: 创建一个新的明文保险库，并将其保存到指定的路径。
    ///
    /// 生成的保险库是一个人类可读的 JSON 文件。这对于保险库文件存储在已加密文件系统上，
    /// 或静态加密非必需的本地工具等场景很有用。
    ///
    /// 此方法使用 `PlaintextVaultStore` 并忽略任何密码。
    pub fn create_plaintext<P: AsRef<Path>>(path: P) -> Result<Arc<Self>, Error> {
        Self::create(path, None, Arc::new(PlaintextVaultStore::new()))
    }

    /// The generic, internal constructor for opening an existing vault.
    ///
    /// This function loads the vault from the given path using the specified persistence strategy.
    ///
    /// For external use, the convenience methods `open_encrypted` and `open_plaintext` are preferred.
    ///
    /// 中文: 用于打开现有保险库的通用内部构造函数。
    ///
    /// 此函数使用指定的持久化策略从给定路径加载保险库。
    ///
    /// 对于外部使用，推荐使用更便捷的 `open_encrypted` 和 `open_plaintext` 方法。
    pub fn open<P: AsRef<Path>>(
        path: P,
        password: Option<&SecretString>,
        persistence: Arc<dyn VaultPersistence>,
    ) -> Result<Arc<Self>, Error> {
        let path = path.as_ref();

        // 1. Read and decrypt the core payload from the file.
        let payload = persistence.load(path, password)?;

        // 2. Return a new Seal instance, wrapped in an Arc.
        // 中文: 返回一个新的 Seal 实例，包装在 Arc 中。
        Ok(Arc::new(Self {
            path: path.to_path_buf(),
            payload: Arc::new(ArcSwap::new(Arc::new(payload))),
            persistence,
        }))
    }

    /// Opens an existing encrypted vault from the specified path.
    ///
    /// A correct password must be provided to successfully decrypt and load the vault.
    /// This method uses the `EncryptedVaultStore`.
    ///
    /// **This method is only available when the `secure-storage` feature is enabled.**
    ///
    /// 中文: 从指定路径打开一个现有的加密保险库。
    ///
    /// 必须提供正确的密码才能成功解密和加载保险库。
    /// 此方法使用 `EncryptedVaultStore`。
    ///
    /// **此方法仅在 `secure-storage` 功能启用时可用。**
    #[cfg(feature = "secure-storage")]
    pub fn open_encrypted<P: AsRef<Path>>(
        path: P,
        password: &SecretString,
    ) -> Result<Arc<Self>, Error> {
        Self::open(path, Some(password), Arc::new(EncryptedVaultStore::new()))
    }

    /// Opens an existing plaintext vault from the specified path.
    ///
    /// This method uses the `PlaintextVaultStore` and does not require a password for the load operation.
    ///
    /// 中文: 从指定路径打开一个现有的明文保险库。
    ///
    /// 此方法使用 `PlaintextVaultStore`，加载操作不需要密码。
    pub fn open_plaintext<P: AsRef<Path>>(path: P) -> Result<Arc<Self>, Error> {
        Self::open(path, None, Arc::new(PlaintextVaultStore::new()))
    }

    /// Creates and initializes a `SealEngine` for cryptographic operations.
    ///
    /// The engine is the stateful workhorse that performs encryption and decryption.
    /// It is initialized for a specific `SealMode` (`Symmetric` or `Hybrid`).
    ///
    /// # Arguments
    /// * `self` - An `Arc` reference to `Seal`, allowing the engine to access the shared vault state.
    /// * `mode` - The desired operational mode for the engine.
    /// * `password` - The password for the vault. This is required to derive keys for cryptographic
    ///   operations within the engine, such as decrypting private keys from the payload, even if
    ///   the vault itself is stored in plaintext.
    ///
    /// 中文: 创建并初始化一个用于加密操作的 `SealEngine`。
    ///
    /// 引擎是执行加密和解密的状态化主力。
    /// 它为特定的 `SealMode`（`Symmetric` 或 `Hybrid`）进行初始化。
    ///
    /// # 参数
    /// * `self` - 对 `Seal` 的 `Arc` 引用，允许引擎访问共享的保险库状态。
    /// * `mode` - 引擎期望的操作模式。
    /// * `password` - 保险库的密码。即使保险库本身是以明文形式存储的，引擎内部的加密操作
    ///   （例如从载荷中解密私钥）也需要此密码来派生密钥。
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

    /// Derives a key from the master seed using HKDF-SHA256.
    ///
    /// This is an internal cryptographic primitive used throughout the library to generate specific keys
    /// from the single master seed. It should not be called directly for application-level encryption.
    ///
    /// 中文: 使用 HKDF-SHA256 从主种子派生一个密钥。
    ///
    /// 这是库中广泛使用的内部加密原语，用于从单一的主种子生成特定的密钥。
    /// 不应为应用级加密直接调用它。
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

    /// Provides access to the vault's configuration manager.
    ///
    /// This returns a snapshot of the current configuration. To modify the configuration,
    /// you must use methods on the `ConfigManager` and then commit the changes.
    ///
    /// 中文: 提供对保险库配置管理器的访问。
    ///
    /// 这会返回当前配置的快照。要修改配置，您必须使用 `ConfigManager` 上的方法，然后提交更改。
    pub fn config(&self) -> ConfigFile {
        self.payload.load().config.clone()
    }

    /// Returns a snapshot of the current `VaultPayload`.
    ///
    /// This provides read-only, thread-safe access to the entire in-memory state of the vault.
    ///
    /// 中文: 返回当前 `VaultPayload` 的一个快照。
    ///
    /// 这提供了对整个保险库内存状态的只读、线程安全的访问。
    pub(crate) fn payload(&self) -> Arc<VaultPayload> {
        self.payload.load_full()
    }

    /// Atomically updates the `VaultPayload` and persists the changes to disk.
    ///
    /// This is the central method for modifying the vault's state (e.g., adding a new key, changing config).
    /// It takes a closure that receives a mutable draft of the payload. After the closure runs,
    /// this function atomically swaps the old payload with the new one in memory and then saves it
    /// to disk using the configured persistence strategy.
    ///
    /// # Arguments
    /// * `password` - The vault password, which may be required by the persistence strategy to save the changes.
    /// * `update_fn` - A closure that modifies the `VaultPayload`.
    ///
    /// 中文: 原子地更新 `VaultPayload` 并将更改持久化到磁盘。
    ///
    /// 这是修改保险库状态（例如，添加新密钥、更改配置）的核心方法。
    /// 它接受一个闭包，该闭包接收一个可变的载荷草稿。闭包运行后，
    /// 此函数会在内存中原子地将旧载荷替换为新载荷，然后使用配置的持久化策略将其保存到磁盘。
    ///
    /// # 参数
    /// * `password` - 保险库密码，持久化策略可能需要它来保存更改。
    /// * `update_fn` - 一个修改 `VaultPayload` 的闭包。
    pub(crate) fn commit_payload<F>(
        &self,
        password: Option<&SecretString>,
        update_fn: F,
    ) -> Result<(), Error>
    where
        F: FnOnce(&mut VaultPayload),
    {
        // 1. Clone the *inner data* of the Arc to create a mutable working copy.
        let mut new_payload = (**self.payload.load()).clone();

        // 2. Apply the update function to the mutable clone.
        update_fn(&mut new_payload);

        // 3. Persist the updated payload to disk using the vault's strategy.
        // The password might be ignored by plaintext strategies.
        self.persistence
            .save(&self.path, &new_payload, password)?;

        // 4. If persistence is successful, atomically swap the in-memory payload.
        self.payload.store(Arc::new(new_payload));

        Ok(())
    }

    /// Changes the master password for an encrypted vault.
    ///
    /// This function re-encrypts the vault file with the new password. It does not affect
    /// the master seed or any cryptographic keys within the vault.
    ///
    /// **This operation is only meaningful for encrypted vaults.**
    ///
    /// 中文: 更改加密保险库的主密码。
    ///
    /// 此函数使用新密码重新加密保险库文件。它不会影响保险库内的主种子或任何加密密钥。
    ///
    /// **此操作仅对加密保险库有意义。**
    #[cfg(feature = "secure-storage")]
    pub fn change_password(
        &self,
        old_password: &SecretString,
        new_password: &SecretString,
    ) -> Result<(), Error> {
        // This operation first verifies the old password before re-encrypting with the new one.
        // 中文: 此操作会先验证旧密码，然后再用新密码重新加密。
        if !self.persistence.is_encrypted() {
            return Err(Error::Config(
                "Password changes are only supported for encrypted vaults.".to_string(),
            ));
        }

        // 1. Verify the old password by attempting to load (and decrypt) the vault from disk.
        // This confirms the user knows the current password before allowing a change.
        // We discard the resulting payload; this is purely for verification.
        // 中文: 1. 通过尝试从磁盘加载（并解密）保险库来验证旧密码。
        // 这能确保用户在允许更改密码之前知道当前密码。
        // 我们会丢弃加载结果，此步骤纯粹用于验证。
        self.persistence.load(&self.path, Some(old_password))?;

        // 2. If verification is successful, save the current in-memory payload with the new password.
        // The persistence layer handles the re-encryption.
        // 中文: 2. 如果验证成功，则使用新密码保存当前的内存中载荷。
        // 持久化层会处理重新加密。
        self.persistence
            .save(&self.path, &self.payload(), Some(new_password))
    }

    /// Rotates the primary asymmetric key for the vault.
    ///
    /// This is a high-level convenience method that:
    /// 1. Sets the specified algorithm as the default in the configuration.
    /// 2. Creates a new `KeyManager` for the `Hybrid` mode.
    /// 3. Triggers the key rotation process within the manager, which generates a new key pair
    ///    and commits it to the vault.
    ///
    /// # Arguments
    /// * `algorithm` - The asymmetric algorithm to generate a new key for.
    /// * `password` - The vault password, required to commit the changes.
    ///
    /// 中文: 轮换保险库的主非对称密钥。
    ///
    /// 这是一个高级便利方法，它会：
    /// 1. 在配置中将指定的算法设置为默认值。
    /// 2. 为 `Hybrid` 模式创建一个新的 `KeyManager`。
    /// 3. 在管理器内部触发密钥轮换过程，该过程会生成一个新的密钥对并将其提交到保险库。
    ///
    /// # 参数
    /// * `algorithm` - 要为其生成新密钥的非对称算法。
    /// * `password` - 保险库密码，提交更改时需要。
    pub fn rotate_asymmetric_key(
        self: &Arc<Self>,
        algorithm: AsymmetricAlgorithm,
        password: &SecretString,
    ) -> Result<(), Error> {
        // First, atomically update the configuration to set the new primary algorithm.
        // 中文: 首先，原子地更新配置以设置新的主算法。
        self.commit_payload(Some(password), |payload| {
            payload.config.crypto.primary_asymmetric_algorithm = algorithm;
        })?;

        // After the config is committed, create a manager and start the rotation.
        // The manager will read the updated configuration.
        // 中文: 配置提交后，创建一个管理器并开始轮换。
        // 管理器将读取更新后的配置。
        let mut manager = KeyManager::new(self.clone(), "default", SealMode::Hybrid);
        manager.initialize();
        manager.start_rotation(password)?;
        Ok(())
    }
}
