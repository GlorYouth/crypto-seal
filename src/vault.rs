use crate::common::{ConfigFile, KeyMetadata};
use secrecy::{CloneableSecret, SecretBox, SerializableSecret};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::Zeroize;

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
