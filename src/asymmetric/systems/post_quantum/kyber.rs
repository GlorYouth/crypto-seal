//! # Kyber Post-Quantum Crypto System Implementation
//!
//! This module provides an implementation of the `AsymmetricCryptographicSystem` trait using Kyber,
//! a post-quantum Key Encapsulation Mechanism (KEM) chosen by NIST for standardization.
//!
//! ## KEM Functionality
//! Kyber is not a general-purpose encryption algorithm but a KEM. Its primary role is to securely
//! establish a shared secret between two parties. In the `seal-kit` framework, this shared secret
//! is used as the Data Encryption Key (DEK) for a symmetric cipher.
//!
//! The process is as follows:
//! 1.  **Encapsulation (Encrypt)**: The sender uses the recipient's public key to generate a
//!     ciphertext and a shared secret. The `encrypt` function in this module takes the DEK
//!     (as plaintext), encapsulates it using the shared secret, and returns a combined payload.
//! 2.  **Decapsulation (Decrypt)**: The recipient uses their private key and the received
//!     ciphertext to derive the exact same shared secret, which they can then use to
//!     recover the original DEK.
//!
//! ## Signing
//! Kyber is a KEM and **does not support digital signatures**. The `sign` and `verify` methods
//! are implemented to return an `UnsupportedOperation` error. For signatures, Kyber should be

//! combined with a digital signature algorithm (like Dilithium) in a hybrid scheme.
//!
//! ---
//!
//! # Kyber 后量子加密系统实现
//!
//! 本模块使用 Kyber 提供了 `AsymmetricCryptographicSystem` 特征的实现。Kyber 是一个
//! 后量子密钥封装机制（KEM），被NIST选择用于标准化。
//!
//! ## KEM 功能
//! Kyber 不是一个通用的加密算法，而是一个KEM。其主要作用是在两方之间安全地
//! 建立一个共享密钥。在 `seal-kit` 框架中，这个共享密钥被用作对称密码的
//! 数据加密密钥（DEK）。
//!
//! 过程如下：
//! 1.  **封装 (加密)**: 发送方使用接收方的公钥生成一个密文和一个共享密钥。
//!     本模块中的 `encrypt` 函数接收DEK（作为明文），使用共享密钥对其进行封装，
//!     并返回一个组合的载荷。
//! 2.  **解封装 (解密)**: 接收方使用他们的私钥和接收到的密文来派生出完全相同
//!     的共享密钥，然后用它来恢复原始的DEK。
//!
//! ## 签名
//! Kyber 是一个 KEM，**不支持数字签名**。`sign` 和 `verify` 方法被实现为
//! 返回一个 `UnsupportedOperation` 错误。如果需要签名，Kyber 应与一个
//! 数字签名算法（如Dilithium）在混合方案中结合使用。
use crate::asymmetric::traits::AsymmetricCryptographicSystem;
use crate::common::config::CryptoConfig;
use crate::common::utils::ZeroizingVec;
use base64::{Engine, engine::general_purpose::STANDARD};
use pqcrypto_kyber::{kyber512, kyber768, kyber1024};
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Dedicated error types for the Kyber system.
///
/// ---
///
/// Kyber 系统专用的错误类型。
#[derive(Error, Debug)]
pub enum KyberSystemError {
    /// The specified security level (e.g., 512, 768, 1024) is not supported.
    /// ---
    /// 指定的安全级别（例如 512, 768, 1024）不受支持。
    #[error("Unsupported Kyber security level: {0}")]
    UnsupportedSecurityLevel(usize),

    /// The provided public key data is malformed or has an incorrect size.
    /// ---
    /// 提供的公钥数据格式错误或大小不正确。
    #[error("Invalid public key format or size")]
    InvalidPublicKey,

    /// The provided private key data is malformed or has an incorrect size.
    /// ---
    /// 提供的私钥数据格式错误或大小不正确。
    #[error("Invalid private key format or size")]
    InvalidPrivateKey,

    /// The provided ciphertext is malformed, truncated, or has an incorrect size.
    /// ---
    /// 提供的密文格式错误、被截断或大小不正确。
    #[error("Invalid ciphertext format or size")]
    InvalidCiphertext,

    /// Error when importing a key from Base64, because its raw size is not one of the valid sizes.
    /// ---
    /// 从 Base64 导入密钥时出错，因为其原始大小不是有效的尺寸之一。
    #[error("Invalid key size for import: expected one of {expected:?}, got {actual}")]
    InvalidKeySize { expected: Vec<usize>, actual: usize },

    /// The plaintext (DEK) length does not match the required shared secret length for the security level.
    /// ---
    /// 明文（DEK）长度与该安全级别要求的共享密钥长度不匹配。
    #[error("Mismatched plaintext length: expected {expected}, got {actual}")]
    MismatchedPlaintextLength { expected: usize, actual: usize },

    /// The private key's security level does not match the security level indicated by the ciphertext.
    /// ---
    /// 私钥的安全级别与密文所指示的安全级别不匹配。
    #[error("Private key does not match the security level of the ciphertext")]
    KeyMismatch,

    /// Decryption failed, typically because the ciphertext is invalid or has been tampered with.
    /// ---
    /// 解密失败，通常是因为密文无效或已被篡改。
    #[error("Decryption failed: ciphertext verification failed")]
    DecryptionFailed,

    /// The requested operation (e.g., signing) is not supported by Kyber.
    /// ---
    /// Kyber 不支持请求的操作（例如签名）。
    #[error("This operation is not supported by Kyber: {0}")]
    UnsupportedOperation(String),

    /// Failed to decode a key from a Base64 string.
    /// ---
    /// 从 Base64 字符串解码密钥失败。
    #[error("Base64 decoding failed: {0}")]
    Base64Decode(#[from] base64::DecodeError),
}

/// A wrapper for a Kyber public key to provide serialization support.
///
/// ---
///
/// Kyber 公钥包装器，提供序列化支持。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KyberPublicKeyWrapper(pub Vec<u8>);

/// A wrapper for a Kyber private key. It uses `ZeroizingVec`
/// to ensure the key material is securely wiped from memory when dropped.
///
/// ---
///
/// Kyber 私钥包装器。它使用 `ZeroizingVec`
/// 确保密钥材料在被丢弃时能从内存中安全擦除。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KyberPrivateKeyWrapper(pub ZeroizingVec);

/// Placeholder for a Kyber signature. As Kyber does not support signing,
/// this is an empty struct used to satisfy the trait requirements.
///
/// ---
///
/// Kyber 签名的占位符。由于 Kyber 不支持签名，
/// 这是一个空结构体，用于满足 trait 的要求。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KyberSignature(Vec<u8>);

impl AsRef<[u8]> for KyberSignature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// An implementation of `AsymmetricCryptographicSystem` for the Kyber KEM.
/// Supports Kyber-512, Kyber-768, and Kyber-1024 security levels.
///
/// ---
///
/// Kyber KEM 的 `AsymmetricCryptographicSystem` 实现。
/// 支持 Kyber-512, Kyber-768, 和 Kyber-1024 安全级别。
pub struct KyberCryptoSystem;

// Kyber constants for key and ciphertext sizes across different security levels.
// ---
// 不同安全级别下 Kyber 密钥和密文大小的常量。
const KYBER512_PUBLICKEYBYTES: usize = kyber512::public_key_bytes();
const KYBER512_SECRETKEYBYTES: usize = kyber512::secret_key_bytes();
const KYBER512_CIPHERTEXTBYTES: usize = kyber512::ciphertext_bytes();
const KYBER512_SHAREDKEYBYTES: usize = kyber512::shared_secret_bytes();

const KYBER768_PUBLICKEYBYTES: usize = kyber768::public_key_bytes();
const KYBER768_SECRETKEYBYTES: usize = kyber768::secret_key_bytes();
const KYBER768_CIPHERTEXTBYTES: usize = kyber768::ciphertext_bytes();
const KYBER768_SHAREDKEYBYTES: usize = kyber768::shared_secret_bytes();

const KYBER1024_PUBLICKEYBYTES: usize = kyber1024::public_key_bytes();
const KYBER1024_SECRETKEYBYTES: usize = kyber1024::secret_key_bytes();
const KYBER1024_CIPHERTEXTBYTES: usize = kyber1024::ciphertext_bytes();
const KYBER1024_SHAREDKEYBYTES: usize = kyber1024::shared_secret_bytes();

impl AsymmetricCryptographicSystem for KyberCryptoSystem {
    type PublicKey = KyberPublicKeyWrapper;
    type PrivateKey = KyberPrivateKeyWrapper;
    type Signature = KyberSignature;
    type Error = KyberSystemError;

    /// Generates a Kyber key pair for the security level specified in the configuration.
    ///
    /// ---
    ///
    /// 根据配置中指定的安全级别生成 Kyber 密钥对。
    fn generate_keypair(
        config: &CryptoConfig,
    ) -> Result<(Self::PublicKey, Self::PrivateKey), Self::Error> {
        // Generate a keypair based on the security level (`k` parameter) from the config.
        // ---
        // 根据配置中的安全级别（`k` 参数）生成密钥对。
        let (public_key_vec, private_key_vec) = match config.kyber_parameter_k {
            512 => {
                let (pk, sk) = kyber512::keypair();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
            768 => {
                let (pk, sk) = kyber768::keypair();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
            1024 => {
                let (pk, sk) = kyber1024::keypair();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
            k => return Err(KyberSystemError::UnsupportedSecurityLevel(k)),
        };

        Ok((
            KyberPublicKeyWrapper(public_key_vec),
            KyberPrivateKeyWrapper(ZeroizingVec(private_key_vec)),
        ))
    }

    /// Encrypts (encapsulates) a plaintext (DEK) using the Kyber public key.
    ///
    /// This function performs the following steps:
    /// 1. Uses the public key to generate a Kyber ciphertext and a shared secret.
    /// 2. Hashes the shared secret to create a keystream.
    /// 3. XORs the plaintext (DEK) with the keystream to produce an encrypted DEK.
    /// 4. Appends the original shared secret to the output for later verification during decryption.
    ///
    /// The final output format is: `[variant_id(1)][Kyber_ciphertext][encrypted_DEK][original_shared_secret]`
    ///
    /// Note: `additional_data` is not used here, as it's intended to be handled by the symmetric cipher.
    ///
    /// ---
    ///
    /// 使用 Kyber 公钥加密（封装）明文（DEK）。
    ///
    /// 此函数执行以下步骤：
    /// 1. 使用公钥生成 Kyber 密文和共享密钥。
    /// 2. 哈希共享密钥以创建密钥流。
    /// 3. 将明文（DEK）与密钥流进行异或（XOR）操作，生成加密后的DEK。
    /// 4. 将原始共享密钥附加到输出中，以便在解密时进行验证。
    ///
    /// 最终输出格式为：`[变体ID(1)][Kyber密文][加密后的DEK][原始共享密钥]`
    ///
    /// 注意：此处不使用 `additional_data`，因为它应由对称密码处理。
    fn encrypt(
        public_key: &Self::PublicKey,
        plaintext: &[u8],
        _additional_data: Option<&[u8]>, // AAD is handled by the symmetric cipher in SealEngine. / AAD由SealEngine中的对称密码处理。
    ) -> Result<Vec<u8>, Self::Error> {
        let pk_bytes = &public_key.0;
        // Determine the Kyber variant and perform encapsulation based on the public key size.
        // This returns a variant ID, the KEM ciphertext, and the generated shared secret.
        // ---
        // 根据公钥大小确定 Kyber 变体并执行封装操作。
        // 这会返回一个变体ID、KEM密文和生成的共享密钥。
        let (variant_id, kyber_ciphertext_bytes, shared_secret_bytes) = match pk_bytes.len() {
            KYBER512_PUBLICKEYBYTES => {
                // Ensure the plaintext (DEK) length matches the shared secret length for this level.
                // ---
                // 确保明文（DEK）的长度与此级别的共享密钥长度相匹配。
                if plaintext.len() != KYBER512_SHAREDKEYBYTES {
                    return Err(KyberSystemError::MismatchedPlaintextLength {
                        expected: KYBER512_SHAREDKEYBYTES,
                        actual: plaintext.len(),
                    });
                }
                let pk = kyber512::PublicKey::from_bytes(pk_bytes)
                    .map_err(|_| KyberSystemError::InvalidPublicKey)?;
                // `encapsulate` generates a shared secret and a ciphertext that allows the
                // corresponding private key holder to derive the same shared secret.
                // ---
                // `encapsulate` 生成一个共享密钥和一个密文，允许对应的私钥持有者
                // 派生出相同的共享密钥。
                let (ss, ct) = kyber512::encapsulate(&pk);
                (1u8, ct.as_bytes().to_vec(), ss.as_bytes().to_vec())
            }
            KYBER768_PUBLICKEYBYTES => {
                if plaintext.len() != KYBER768_SHAREDKEYBYTES {
                    return Err(KyberSystemError::MismatchedPlaintextLength {
                        expected: KYBER768_SHAREDKEYBYTES,
                        actual: plaintext.len(),
                    });
                }
                let pk = kyber768::PublicKey::from_bytes(pk_bytes)
                    .map_err(|_| KyberSystemError::InvalidPublicKey)?;
                let (ss, ct) = kyber768::encapsulate(&pk);
                (2u8, ct.as_bytes().to_vec(), ss.as_bytes().to_vec())
            }
            KYBER1024_PUBLICKEYBYTES => {
                if plaintext.len() != KYBER1024_SHAREDKEYBYTES {
                    return Err(KyberSystemError::MismatchedPlaintextLength {
                        expected: KYBER1024_SHAREDKEYBYTES,
                        actual: plaintext.len(),
                    });
                }
                let pk = kyber1024::PublicKey::from_bytes(pk_bytes)
                    .map_err(|_| KyberSystemError::InvalidPublicKey)?;
                let (ss, ct) = kyber1024::encapsulate(&pk);
                (3u8, ct.as_bytes().to_vec(), ss.as_bytes().to_vec())
            }
            _ => return Err(KyberSystemError::InvalidPublicKey),
        };

        // Instead of using the shared secret directly, we use its hash to create a keystream.
        // This provides a layer of key derivation.
        // ---
        // 我们不直接使用共享密钥，而是使用其哈希创建一个密钥流。
        // 这提供了一个密钥派生层。
        let mut hasher = Sha256::new();
        hasher.update(&shared_secret_bytes);
        let key_hash = hasher.finalize();

        // XOR the plaintext (DEK) with the keystream to encrypt it.
        // ---
        // 将明文（DEK）与密钥流进行异或操作以对其进行加密。
        let mut encrypted_dek = plaintext.to_vec();
        for (i, byte) in key_hash.iter().take(encrypted_dek.len()).enumerate() {
            encrypted_dek[i] ^= byte;
        }

        // The final output is a custom format combining all necessary parts.
        // The original shared secret is appended to allow for verification during decryption.
        // ---
        // 最终的输出是一个自定义格式，组合了所有必要的部分。
        // 附加原始共享密钥是为了在解密时进行验证。
        // Format: [variant_id(1)][Kyber_ciphertext][XORed_DEK][original_shared_secret]
        let mut combined = vec![variant_id];
        combined.extend_from_slice(&kyber_ciphertext_bytes);
        combined.extend_from_slice(&encrypted_dek);
        combined.extend_from_slice(&shared_secret_bytes);

        Ok(combined)
    }

    /// Decrypts (decapsulates) a ciphertext to retrieve the original plaintext (DEK).
    ///
    /// This function performs the following steps:
    /// 1. Parses the input to extract the variant ID, Kyber ciphertext, encrypted DEK, and original shared secret.
    /// 2. Uses the private key to decapsulate the Kyber ciphertext, yielding a decapsulated shared secret.
    /// 3. Verifies that the decapsulated shared secret matches the original shared secret from the payload. This confirms the ciphertext's integrity.
    /// 4. Hashes the verified shared secret to recreate the keystream.
    /// 5. XORs the encrypted DEK with the keystream to recover the original plaintext DEK.
    ///
    /// ---
    ///
    /// 解密（解封装）密文以恢复原始明文（DEK）。
    ///
    /// 此函数执行以下步骤：
    /// 1. 解析输入以提取变体ID、Kyber密文、加密的DEK和原始共享密钥。
    /// 2. 使用私钥解封装Kyber密文，得到一个解封装后的共享密钥。
    /// 3. 验证解封装后的共享密钥与载荷中的原始共享密钥是否匹配。这可以确认密文的完整性。
    /// 4. 哈希已验证的共享密钥以重新创建密钥流。
    /// 5. 将加密的DEK与密钥流进行异或（XOR）操作，以恢复原始的明文DEK。
    fn decrypt(
        private_key: &Self::PrivateKey,
        ciphertext: &[u8],
        _additional_data: Option<&[u8]>, // AAD is handled by the symmetric cipher in SealEngine. / AAD由SealEngine中的对称密码处理。
    ) -> Result<Vec<u8>, Self::Error> {
        if ciphertext.len() < 2 {
            // Must have at least a variant ID and some data.
            // ---
            // 必须至少包含一个变体ID和一些数据。
            return Err(KyberSystemError::InvalidCiphertext);
        }

        // Extract the variant ID to determine the Kyber security level.
        // ---
        // 提取变体ID以确定Kyber安全级别。
        let variant_id = ciphertext[0];
        let rest = &ciphertext[1..];

        // Based on the variant, perform decapsulation to derive the shared secret from the ciphertext.
        // ---
        // 根据变体，执行解封装操作以从密文中派生共享密钥。
        let (kyber_ct_len, decapsulated_ss_bytes, shared_key_len) = match variant_id {
            1 => {
                // Kyber512
                // Check if the provided private key matches the security level.
                // ---
                // 检查提供的私钥是否与安全级别匹配。
                if private_key.0.len() != KYBER512_SECRETKEYBYTES {
                    return Err(KyberSystemError::KeyMismatch);
                }
                if rest.len() < KYBER512_CIPHERTEXTBYTES + KYBER512_SHAREDKEYBYTES {
                    return Err(KyberSystemError::InvalidCiphertext);
                }
                // Extract the actual Kyber ciphertext part from the payload.
                // ---
                // 从载荷中提取实际的Kyber密文部分。
                let ct_bytes = &rest[..KYBER512_CIPHERTEXTBYTES];
                let sk = kyber512::SecretKey::from_bytes(private_key.0.as_ref())
                    .map_err(|_| KyberSystemError::InvalidPrivateKey)?;
                let ct = kyber512::Ciphertext::from_bytes(ct_bytes)
                    .map_err(|_| KyberSystemError::InvalidCiphertext)?;
                // `decapsulate` derives the shared secret.
                // ---
                // `decapsulate` 派生出共享密钥。
                let ss = kyber512::decapsulate(&ct, &sk);
                (
                    KYBER512_CIPHERTEXTBYTES,
                    ss.as_bytes().to_vec(),
                    KYBER512_SHAREDKEYBYTES,
                )
            }
            2 => {
                // Kyber768
                if private_key.0.len() != KYBER768_SECRETKEYBYTES {
                    return Err(KyberSystemError::KeyMismatch);
                }
                if rest.len() < KYBER768_CIPHERTEXTBYTES + KYBER768_SHAREDKEYBYTES {
                    return Err(KyberSystemError::InvalidCiphertext);
                }
                let ct_bytes = &rest[..KYBER768_CIPHERTEXTBYTES];
                let sk = kyber768::SecretKey::from_bytes(private_key.0.as_ref())
                    .map_err(|_| KyberSystemError::InvalidPrivateKey)?;
                let ct = kyber768::Ciphertext::from_bytes(ct_bytes)
                    .map_err(|_| KyberSystemError::InvalidCiphertext)?;
                let ss = kyber768::decapsulate(&ct, &sk);
                (
                    KYBER768_CIPHERTEXTBYTES,
                    ss.as_bytes().to_vec(),
                    KYBER768_SHAREDKEYBYTES,
                )
            }
            3 => {
                // Kyber1024
                if private_key.0.len() != KYBER1024_SECRETKEYBYTES {
                    return Err(KyberSystemError::KeyMismatch);
                }
                if rest.len() < KYBER1024_CIPHERTEXTBYTES + KYBER1024_SHAREDKEYBYTES {
                    return Err(KyberSystemError::InvalidCiphertext);
                }
                let ct_bytes = &rest[..KYBER1024_CIPHERTEXTBYTES];
                let sk = kyber1024::SecretKey::from_bytes(private_key.0.as_ref())
                    .map_err(|_| KyberSystemError::InvalidPrivateKey)?;
                let ct = kyber1024::Ciphertext::from_bytes(ct_bytes)
                    .map_err(|_| KyberSystemError::InvalidCiphertext)?;
                let ss = kyber1024::decapsulate(&ct, &sk);
                (
                    KYBER1024_CIPHERTEXTBYTES,
                    ss.as_bytes().to_vec(),
                    KYBER1024_SHAREDKEYBYTES,
                )
            }
            _ => return Err(KyberSystemError::InvalidCiphertext),
        };

        // This is a critical verification step. We check if the shared secret derived from
        // decapsulation matches the one that was appended to the ciphertext.
        // A mismatch indicates a tampered ciphertext or incorrect key.
        // ---
        // 这是一个关键的验证步骤。我们检查从解封装派生的共享密钥是否
        // 与附加到密文的共享密钥匹配。
        // 不匹配表示密文被篡改或密钥不正确。
        let expected_ss_start = kyber_ct_len + shared_key_len;
        if rest.len() < expected_ss_start {
            return Err(KyberSystemError::InvalidCiphertext);
        }
        let original_ss_bytes = &rest[expected_ss_start..];

        if original_ss_bytes != decapsulated_ss_bytes.as_slice() {
            return Err(KyberSystemError::DecryptionFailed);
        }

        // Extract the part of the payload that contains the XOR-encrypted DEK.
        // ---
        // 提取载荷中包含经异或加密的DEK的部分。
        let encrypted_dek_part = &rest[kyber_ct_len..expected_ss_start];
        if encrypted_dek_part.len() != shared_key_len {
            return Err(KyberSystemError::InvalidCiphertext);
        }
        let mut dek = encrypted_dek_part.to_vec();

        // Recreate the same keystream by hashing the (now verified) shared secret.
        // ---
        // 通过哈希（现已验证的）共享密钥来重新创建相同的密钥流。
        let mut hasher = Sha256::new();
        hasher.update(&decapsulated_ss_bytes);
        let key_hash = hasher.finalize();

        // XOR the encrypted DEK with the keystream to recover the original DEK.
        // ---
        // 将加密的DEK与密钥流进行异或，以恢复原始DEK。
        for (i, byte) in key_hash.iter().take(dek.len()).enumerate() {
            dek[i] ^= byte;
        }

        Ok(dek)
    }

    /// Not supported. Kyber is a KEM and does not provide a signing mechanism.
    ///
    /// ---
    ///
    /// 不支持。Kyber 是一个 KEM，不提供签名机制。
    fn sign(
        _private_key: &Self::PrivateKey,
        _message: &[u8],
    ) -> Result<Self::Signature, Self::Error> {
        Err(KyberSystemError::UnsupportedOperation(
            "Kyber is a Key Encapsulation Mechanism and does not support signing.".to_string(),
        ))
    }

    /// Not supported. Kyber is a KEM and does not provide a verification mechanism.
    ///
    /// ---
    ///
    /// 不支持。Kyber 是一个 KEM，不提供验证机制。
    fn verify(
        _public_key: &Self::PublicKey,
        _message: &[u8],
        _signature: &Self::Signature,
    ) -> Result<(), Self::Error> {
        Err(KyberSystemError::UnsupportedOperation(
            "Kyber is a Key Encapsulation Mechanism and does not support verification.".to_string(),
        ))
    }

    /// Exports the public key to a Base64 encoded string.
    ///
    /// ---
    ///
    /// 将公钥导出为 Base64 编码的字符串。
    fn export_public_key(public_key: &Self::PublicKey) -> Result<String, Self::Error> {
        Ok(STANDARD.encode(&public_key.0))
    }

    /// Exports the private key to a Base64 encoded string.
    ///
    /// ---
    ///
    /// 将私钥导出为 Base64 编码的字符串。
    fn export_private_key(private_key: &Self::PrivateKey) -> Result<String, Self::Error> {
        Ok(STANDARD.encode(private_key.0.as_ref()))
    }

    /// Imports a public key from a Base64 encoded string.
    ///
    /// ---
    ///
    /// 从 Base64 编码的字符串导入公钥。
    fn import_public_key(key_data: &str) -> Result<Self::PublicKey, Self::Error> {
        // Decode from Base64 and then validate the length against known Kyber public key sizes.
        // ---
        // 从 Base64 解码，然后根据已知的 Kyber 公钥大小验证其长度。
        let decoded = STANDARD.decode(key_data)?;
        let valid_lens = vec![
            KYBER512_PUBLICKEYBYTES,
            KYBER768_PUBLICKEYBYTES,
            KYBER1024_PUBLICKEYBYTES,
        ];

        if !valid_lens.contains(&decoded.len()) {
            return Err(KyberSystemError::InvalidKeySize {
                expected: valid_lens,
                actual: decoded.len(),
            });
        }

        Ok(KyberPublicKeyWrapper(decoded))
    }

    /// Imports a private key from a Base64 encoded string.
    ///
    /// ---
    ///
    /// 从 Base64 编码的字符串导入私钥。
    fn import_private_key(key_data: &str) -> Result<Self::PrivateKey, Self::Error> {
        // Decode from Base64 and then validate the length against known Kyber private key sizes.
        // ---
        // 从 Base64 解码，然后根据已知的 Kyber 私钥大小验证其长度。
        let decoded = STANDARD.decode(key_data)?;
        let valid_lens = vec![
            KYBER512_SECRETKEYBYTES,
            KYBER768_SECRETKEYBYTES,
            KYBER1024_SECRETKEYBYTES,
        ];

        if !valid_lens.contains(&decoded.len()) {
            return Err(KyberSystemError::InvalidKeySize {
                expected: valid_lens,
                actual: decoded.len(),
            });
        }

        Ok(KyberPrivateKeyWrapper(ZeroizingVec(decoded)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::config::CryptoConfig;

    fn setup_keys(k: usize) -> (KyberPublicKeyWrapper, KyberPrivateKeyWrapper) {
        let config = CryptoConfig {
            kyber_parameter_k: k,
            ..Default::default()
        };
        KyberCryptoSystem::generate_keypair(&config).unwrap()
    }

    // All Kyber shared secrets are 32 bytes long
    const DEK_SIZE: usize = 32;

    #[test]
    fn test_kyber_roundtrip_all_levels() {
        for &k in &[512, 768, 1024] {
            let (public_key, private_key) = setup_keys(k);
            let dek = vec![42u8; DEK_SIZE];

            let ciphertext = KyberCryptoSystem::encrypt(&public_key, &dek, None).unwrap();
            let decrypted = KyberCryptoSystem::decrypt(&private_key, &ciphertext, None).unwrap();

            assert_eq!(dek, decrypted);
        }
    }

    #[test]
    fn test_kyber_tampered_ciphertext_fails() {
        let (public_key, private_key) = setup_keys(768);
        let dek = vec![42u8; DEK_SIZE];

        let mut ciphertext = KyberCryptoSystem::encrypt(&public_key, &dek, None).unwrap();

        // Tamper
        let len = ciphertext.len();
        if len > 0 {
            ciphertext[len / 2] ^= 0xff;
        }

        let result = KyberCryptoSystem::decrypt(&private_key, &ciphertext, None);
        assert!(matches!(result, Err(KyberSystemError::DecryptionFailed)));
    }

    #[test]
    fn test_kyber_decrypt_wrong_key_fails() {
        let (public_key, _) = setup_keys(768);
        let (_, wrong_private_key) = setup_keys(768);
        let dek = vec![42u8; DEK_SIZE];

        let ciphertext = KyberCryptoSystem::encrypt(&public_key, &dek, None).unwrap();
        let result = KyberCryptoSystem::decrypt(&wrong_private_key, &ciphertext, None);

        assert!(matches!(result, Err(KyberSystemError::DecryptionFailed)));
    }

    #[test]
    fn test_ciphertext_uniqueness() {
        let (public_key, _) = setup_keys(768);
        let dek = vec![42u8; DEK_SIZE];
        let ciphertext1 = KyberCryptoSystem::encrypt(&public_key, &dek, None).unwrap();
        let ciphertext2 = KyberCryptoSystem::encrypt(&public_key, &dek, None).unwrap();
        assert_ne!(
            ciphertext1, ciphertext2,
            "Two encryptions of the same plaintext should not be identical due to KEM randomization"
        );
    }

    #[test]
    fn test_kyber_signing_is_not_supported() {
        let (public_key, private_key) = setup_keys(768);
        let message = b"test message";

        let sign_result = KyberCryptoSystem::sign(&private_key, message);
        assert!(matches!(
            sign_result,
            Err(KyberSystemError::UnsupportedOperation(_))
        ));

        // 即使签名从未被创建，也测试验证函数
        let dummy_signature = KyberSignature(vec![]);
        let verify_result = KyberCryptoSystem::verify(&public_key, message, &dummy_signature);
        assert!(matches!(
            verify_result,
            Err(KyberSystemError::UnsupportedOperation(_))
        ));
    }

    #[test]
    fn test_import_invalid_key_size() {
        let bad_key_data = STANDARD.encode([0u8; 100]);
        let pub_result = KyberCryptoSystem::import_public_key(&bad_key_data);
        assert!(matches!(
            pub_result,
            Err(KyberSystemError::InvalidKeySize { .. })
        ));

        let priv_result = KyberCryptoSystem::import_private_key(&bad_key_data);
        assert!(matches!(
            priv_result,
            Err(KyberSystemError::InvalidKeySize { .. })
        ));
    }

    #[test]
    fn test_mismatched_plaintext_length() {
        let (public_key, _) = setup_keys(512);
        let dek = vec![42u8; 16]; // Incorrect length
        let result = KyberCryptoSystem::encrypt(&public_key, &dek, None);
        assert!(matches!(
            result,
            Err(KyberSystemError::MismatchedPlaintextLength { .. })
        ));
    }
}
