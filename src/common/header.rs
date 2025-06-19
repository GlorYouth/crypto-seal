//! 定义 seal-kit 的统一头部格式，用于支持对称和混合加密模式。

use crate::asymmetric::systems::traditional::rsa::RsaSignature;
use crate::common::traits::{AsymmetricAlgorithm, SymmetricAlgorithm};
use bincode::config::Configuration;
use bincode::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// 定义加密操作的模式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Decode, Encode)]
pub enum SealMode {
    /// 纯对称加密模式，使用预共享或管理的对称密钥。
    Symmetric,
    /// 混合加密模式，使用非对称密钥加密一个一次性的数据加密密钥 (DEK)。
    Hybrid,
}

/// `Header` 是所有加密数据流的元数据信封。
/// 它位于加密数据的前面，提供了足够的信息来解密后续的载荷。
#[derive(Debug, Serialize, Deserialize, Decode, Encode)]
pub struct Header {
    /// 协议版本号，用于未来的兼容性升级。
    pub version: u16,
    /// 加密模式，指示载荷是使用对称密钥还是混合加密。
    pub mode: SealMode,
    /// 根据加密模式包含不同的载荷。
    #[serde(flatten)]
    pub payload: HeaderPayload,
}

impl Header {
    pub fn encode_to_vec(&self) -> Result<Vec<u8>, crate::Error> {
        static CONFIG: Configuration = bincode::config::standard();
        Ok(bincode::encode_to_vec(self, CONFIG)?)
    }

    pub fn decode_from_vec(data: &[u8]) -> Result<(Self, usize), crate::Error> {
        static CONFIG: Configuration = bincode::config::standard();
        Ok(bincode::decode_from_slice(data, CONFIG)?)
    }
}

/// `HeaderPayload` 包含了特定于加密模式的元数据。
#[derive(Debug, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "kebab-case")]
pub enum HeaderPayload {
    /// 对称加密模式的元数据。
    Symmetric {
        /// 用于查找解密密钥的ID。
        key_id: String,
        /// 使用的对称加密算法，例如 "aes-256-gcm"。
        algorithm: SymmetricAlgorithm,
    },
    /// 混合加密模式的元数据。
    Hybrid {
        /// 密钥加密密钥 (KEK) 的ID，用于查找解密的非对称私钥。
        kek_id: String,
        /// 用于加密DEK的非对称算法，例如 "rsa-oaep-sha256"。
        kek_algorithm: AsymmetricAlgorithm,
        /// 用于加密数据的对称算法 (DEK的算法)，例如 "aes-256-gcm"。
        dek_algorithm: SymmetricAlgorithm,
        /// 被KEK加密后的数据加密密钥 (DEK)。
        encrypted_dek: Vec<u8>,
        /// (可选) 对 `encrypted_dek` 的签名，用于认证加密。
        #[serde(skip_serializing_if = "Option::is_none")]
        signature: Option<RsaSignature>,
    },
}
