use arc_swap::ArcSwap;
use secrecy::{CloneableSecret, ExposeSecret, SecretBox, SecretString, SerializableSecret};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs as tokio_fs;
use bincode;

use crate::asymmetric::traits::{AsymmetricCryptographicSystem};
use crate::common::ConfigFile;
use crate::common::config::ConfigManager;
use crate::common::errors::Error;
use crate::common::header::{Header, HeaderPayload, SealMode};
use crate::common::traits::{
    Algorithm, AsymmetricAlgorithm, KeyMetadata, SecString, SecureKeyStorage, SymmetricAlgorithm,
};
use crate::rotation::manager::KeyManager;
use crate::storage::EncryptedKeyContainer;
use crate::symmetric::traits::{
     SymmetricCryptographicSystem,
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
        key_manager.initialize()?;

        // 创建引擎时，确保至少有一个可用的主密钥
        if key_manager.needs_rotation() {
            key_manager.start_rotation(password)?;
        }

        Ok(SealEngine {
            key_manager,
            _seal: Arc::clone(self),
            password: password.clone(),
        })
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
        let current_payload = self.payload.load();
        let mut new_payload = (**current_payload).clone();
        update_fn(&mut new_payload);
        self.payload.store(Arc::new(new_payload));
        Ok(())
    }
}

// ===================================================================================
// UNIFIED SEAL ENGINE
// ===================================================================================

/// `SealEngine` 是执行实际加密和解密操作的统一接口。
///
/// 它持有密钥管理器的状态，以高效地处理连续的加密操作和自动密钥轮换。
pub struct SealEngine {
    key_manager: KeyManager,
    // 我们需要一个对 Seal 的引用来访问配置等信息，但它不参与状态管理
    _seal: Arc<Seal>,
    // 引擎在创建时 "解锁"，存储密码以供内部需要写入的操作（如密钥轮换）使用。
    password: SecretString,
}

impl SealEngine {
    /// 使用当前引擎的模式来加密（封印）一个字节切片。
    ///
    /// 这是一个便捷的内存加密方法。
    pub fn seal_bytes(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        // 为了代码复用，我们可以在内部使用流式加密的实现
        let mut reader = std::io::Cursor::new(plaintext);
        let mut writer = Vec::new();
        self.seal_stream(&mut reader, &mut writer)?;
        Ok(writer)
    }

    /// [并行] 使用当前引擎的模式来加密（封印）一个字节切片。
    pub fn par_seal_bytes(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        // 1. 检查并执行密钥轮换
        if self.key_manager.needs_rotation() {
            self.key_manager.start_rotation(&self.password)?;
        }

        // 2. 构建 Header 和 DEK
        let (header, dek) = self.build_header_and_dek()?;

        // 3. 序列化 Header
        let header_bytes = bincode::serialize(&header)?;

        // 4. 调用底层的并行加密原语
        use crate::symmetric::systems::aes_gcm::{AesGcmKey, AesGcmSystem};
        use crate::symmetric::traits::SymmetricParallelSystem;

        let dek_key = AesGcmKey(dek);
        let parallelism_config = &self.key_manager.config().parallelism;
        let ciphertext_payload =
            AesGcmSystem::par_encrypt(&dek_key, plaintext, None, parallelism_config)?;

        // 5. 组合 Header 和加密后的载荷
        let mut final_output =
            Vec::with_capacity(4 + header_bytes.len() + ciphertext_payload.len());
        final_output.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
        final_output.extend_from_slice(&header_bytes);
        final_output.extend_from_slice(&ciphertext_payload);

        self.key_manager.increment_usage_count(&self.password)?;

        Ok(final_output)
    }

    /// [并行] 使用当前引擎的模式来流式加密（封印）一个数据流。
    pub fn par_seal_stream<R, W>(&mut self, reader: R, mut writer: W) -> Result<(), Error>
    where
        R: std::io::Read + Send,
        W: std::io::Write + Send,
    {
        // 1. 检查并执行密钥轮换
        if self.key_manager.needs_rotation() {
            self.key_manager.start_rotation(&self.password)?;
        }

        // 2. 构建 Header 和 DEK
        let (header, dek) = self.build_header_and_dek()?;

        // 3. 序列化并写入 Header
        let header_bytes = bincode::serialize(&header)?;
        writer.write_all(&(header_bytes.len() as u32).to_le_bytes())?;
        writer.write_all(&header_bytes)?;

        // 4. 调用底层的并行流式加密原语
        use crate::symmetric::systems::aes_gcm::{AesGcmKey, AesGcmSystem};
        use crate::symmetric::traits::SymmetricParallelStreamingSystem;

        let dek_key = AesGcmKey(dek);
        let streaming_config = &self.key_manager.config().streaming;
        let parallelism_config = &self.key_manager.config().parallelism;

        AesGcmSystem::par_encrypt_stream(
            &dek_key,
            reader,
            writer,
            streaming_config,
            parallelism_config,
            None,
        )?;

        self.key_manager.increment_usage_count(&self.password)?;

        Ok(())
    }

    /// 使用当前引擎的模式来流式加密（封印）一个数据流。
    ///
    /// 此方法会自动处理密钥轮换、元数据生成和数据加密，
    /// 并将统一格式的密文写入输出流。
    pub fn seal_stream<R, W>(&mut self, reader: R, mut writer: W) -> Result<(), Error>
    where
        R: std::io::Read,
        W: std::io::Write,
    {
        // 1. 检查并执行密钥轮换
        if self.key_manager.needs_rotation() {
            self.key_manager.start_rotation(&self.password)?;
        }

        // 2. 构建 Header
        let (header, dek) = self.build_header_and_dek()?;

        // 3. 序列化并写入 Header
        let header_bytes = bincode::serialize(&header)?; // 使用 bincode 以获得更紧凑的输出
        writer.write_all(&(header_bytes.len() as u32).to_le_bytes())?;
        writer.write_all(&header_bytes)?;

        // 4. 使用 DEK 加密数据流
        use crate::symmetric::systems::aes_gcm::{AesGcmKey, AesGcmSystem};
        use crate::symmetric::traits::SymmetricSyncStreamingSystem;

        let dek_key = AesGcmKey(dek);
        let streaming_config = &self.key_manager.config().streaming;

        AesGcmSystem::encrypt_stream(&dek_key, reader, writer, streaming_config, None)?;

        self.key_manager.increment_usage_count(&self.password)?;

        Ok(())
    }

    /// 使用当前引擎的模式解密（解封）一个字节切片。
    ///
    /// 此方法会自动解析密文头部，获取正确的密钥进行解密。
    /// 这是一个便捷的内存解密方法。
    pub fn unseal_bytes(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let mut reader = std::io::Cursor::new(ciphertext);
        let mut writer = Vec::new();
        self.unseal_stream(&mut reader, &mut writer)?;
        Ok(writer)
    }

    /// [并行] 使用当前引擎的模式解密（解封）一个字节切片。
    pub fn par_unseal_bytes(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        // 1. 解析 Header
        let mut reader = std::io::Cursor::new(ciphertext);
        let header = self.read_and_parse_header(&mut reader)?;

        // 2. 根据 Header 派生/解密 DEK
        let dek = self.derive_dek_from_header(&header)?;

        // 3. 读取剩余的载荷并使用并行原语解密
        let mut payload = Vec::new();
        reader.read_to_end(&mut payload)?;

        use crate::symmetric::systems::aes_gcm::{AesGcmKey, AesGcmSystem};
        use crate::symmetric::traits::SymmetricParallelSystem;

        let dek_key = AesGcmKey(dek);
        let parallelism_config = &self.key_manager.config().parallelism;
        let decrypted_payload =
            AesGcmSystem::par_decrypt(&dek_key, &payload, None, parallelism_config)?;

        Ok(decrypted_payload)
    }

    /// [并行] 使用当前引擎的模式来流式解密（解封）一个数据流。
    pub fn par_unseal_stream<R, W>(&self, mut reader: R, writer: W) -> Result<(), Error>
    where
        R: std::io::Read + Send,
        W: std::io::Write + Send,
    {
        // 1. 解析 Header
        let header = self.read_and_parse_header(&mut reader)?;

        // 2. 根据 Header 派生/解密 DEK
        let dek = self.derive_dek_from_header(&header)?;

        // 3. 调用底层的并行流式解密原语
        use crate::symmetric::systems::aes_gcm::{AesGcmKey, AesGcmSystem};
        use crate::symmetric::traits::SymmetricParallelStreamingSystem;

        let dek_key = AesGcmKey(dek);
        let streaming_config = &self.key_manager.config().streaming;
        let parallelism_config = &self.key_manager.config().parallelism;

        AesGcmSystem::par_decrypt_stream(
            &dek_key,
            reader,
            writer,
            streaming_config,
            parallelism_config,
            None,
        )?;

        Ok(())
    }

    /// 解密（解封）一个数据流。
    ///
    /// 此方法会自动解析密文头，并用正确的密钥解密后续的数据流。
    pub fn unseal_stream<R, W>(&self, mut reader: R, writer: W) -> Result<(), Error>
    where
        R: std::io::Read,
        W: std::io::Write,
    {
        // 1. 解析 Header
        let header = self.read_and_parse_header(&mut reader)?;

        // 2. 根据 Header 派生/解密 DEK
        let dek = self.derive_dek_from_header(&header)?;

        // 3. 使用 DEK 解密数据流
        use crate::symmetric::systems::aes_gcm::{AesGcmKey, AesGcmSystem};
        use crate::symmetric::traits::SymmetricSyncStreamingSystem;

        // Dispatch based on DEK algorithm
        match header.payload {
            HeaderPayload::Symmetric { algorithm, .. } => match algorithm {
                SymmetricAlgorithm::Aes256Gcm => {
                    let dek_key = AesGcmKey(dek);
                    let streaming_config = &self.key_manager.config().streaming;
                    AesGcmSystem::decrypt_stream(
                        &dek_key,
                        reader,
                        writer,
                        streaming_config,
                        None,
                    )?;
                }
            },
            HeaderPayload::Hybrid { dek_algorithm, .. } => match dek_algorithm {
                SymmetricAlgorithm::Aes256Gcm => {
                    let dek_key = AesGcmKey(dek);
                    let streaming_config = &self.key_manager.config().streaming;
                    AesGcmSystem::decrypt_stream(
                        &dek_key,
                        reader,
                        writer,
                        streaming_config,
                        None,
                    )?;
                }
            },
        }

        Ok(())
    }

    /// 从输入流中读取并解析出一个 Header。
    fn read_and_parse_header<R: std::io::Read>(&self, mut reader: R) -> Result<Header, Error> {
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf)?;
        let header_len = u32::from_le_bytes(len_buf) as usize;

        let mut header_bytes = vec![0u8; header_len];
        reader.read_exact(&mut header_bytes)?;
        let header: Header = bincode::deserialize(&header_bytes)?;

        Ok(header)
    }

    /// 根据 Header 和当前引擎模式，派生或解密出数据加密密钥 (DEK)。
    fn derive_dek_from_header(&self, header: &Header) -> Result<Vec<u8>, Error> {
        // 解密时，我们创建一个临时的、只读的 KeyManager
        let mut key_manager =
            KeyManager::new(Arc::clone(&self._seal), "seal-engine-readonly", header.mode);
        key_manager.initialize()?;

        match &header.payload {
            HeaderPayload::Symmetric { key_id, algorithm } => {
                // Dispatch based on symmetric algorithm
                match algorithm {
                    SymmetricAlgorithm::Aes256Gcm => {
                        use crate::symmetric::systems::aes_gcm::AesGcmSystem;
                        let key = key_manager
                            .derive_symmetric_key::<AesGcmSystem>(key_id)?
                            .ok_or_else(|| {
                                Error::Key(format!(
                                    "Failed to derive symmetric key for id: {}",
                                    key_id
                                ))
                            })?;
                        Ok(key.0)
                    }
                }
            }
            HeaderPayload::Hybrid {
                kek_id,
                encrypted_dek,
                kek_algorithm,
                ..
            } => {
                // Dispatch based on KEK algorithm
                match kek_algorithm {
                    AsymmetricAlgorithm::Rsa2048 => {
                        use crate::asymmetric::systems::traditional::rsa::RsaCryptoSystem;
                        use crate::asymmetric::traits::AsymmetricCryptographicSystem;

                        let (_, kek_priv) = key_manager
                            .get_asymmetric_keypair::<RsaCryptoSystem>(kek_id)?
                            .ok_or_else(|| {
                                Error::Key(format!("Failed to get KEK keypair for id: {}", kek_id))
                            })?;

                        let dek = RsaCryptoSystem::decrypt(&kek_priv, encrypted_dek, None)?;
                        Ok(dek)
                    }
                }
            }
        }
    }

    /// 根据当前模式构建 Header 和数据加密密钥 (DEK)。
    fn build_header_and_dek(&mut self) -> Result<(Header, Vec<u8>), Error> {
        let primary_meta = self
            .key_manager
            .get_primary_key_metadata()
            .ok_or_else(|| Error::KeyManagement("No primary key available.".to_string()))?
            .clone(); // Clone to avoid borrow checker issues

        let (header_payload, dek) = match self.key_manager.mode() {
            SealMode::Symmetric => {
                // 在对称模式下，DEK 就是从主种子派生出的密钥本身。
                match primary_meta.algorithm {
                    Algorithm::Symmetric(sym_alg) => {
                        use crate::symmetric::systems::aes_gcm::AesGcmSystem; // TODO: make configurable

                        let key = self
                            .key_manager
                            .derive_symmetric_key::<AesGcmSystem>(&primary_meta.id)?
                            .ok_or_else(|| {
                                Error::Key("Failed to derive symmetric key.".to_string())
                            })?;

                        let payload = HeaderPayload::Symmetric {
                            key_id: primary_meta.id.clone(),
                            algorithm: sym_alg,
                        };
                        Ok((payload, key.0))
                    }
                    _ => Err(Error::KeyManagement(
                        "Mismatched key type in metadata for symmetric mode.".to_string(),
                    )),
                }?
            }
            SealMode::Hybrid => {
                // 在混合模式下，生成一个新的DEK，并用主非对称公钥加密它。
                match primary_meta.algorithm {
                    Algorithm::Asymmetric(asym_alg) => {
                        use crate::asymmetric::systems::traditional::rsa::RsaCryptoSystem;
                        use crate::symmetric::systems::aes_gcm::AesGcmSystem;

                        // 1. 获取KEK
                        let (kek_pub, _) = self
                            .key_manager
                            .get_asymmetric_keypair::<RsaCryptoSystem>(&primary_meta.id)?
                            .ok_or_else(|| Error::Key("Failed to get KEK keypair.".to_string()))?;

                        // 2. 生成一次性DEK (TODO: algorithm should be configurable)
                        let dek =
                            AesGcmSystem::generate_key(&self.key_manager.config().crypto)?;

                        // 3. 加密DEK
                        let encrypted_dek = RsaCryptoSystem::encrypt(&kek_pub, &dek.0, None)?;

                        let payload = HeaderPayload::Hybrid {
                            kek_id: primary_meta.id.clone(),
                            kek_algorithm: asym_alg,
                            dek_algorithm: SymmetricAlgorithm::Aes256Gcm, // TODO: Configurable
                            encrypted_dek,
                        };
                        Ok((payload, dek.0))
                    }
                    _ => Err(Error::KeyManagement(
                        "Mismatched key type in metadata for hybrid mode.".to_string(),
                    )),
                }?
            }
        };

        let header = Header {
            version: 1,
            mode: self.key_manager.mode(),
            payload: header_payload,
        };

        Ok((header, dek))
    }
}
