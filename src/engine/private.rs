//! `private.rs` 封装了 SealEngine 的核心私有辅助方法，主要负责密文头部的读取解析、密钥派生与解密、加密头部构建等底层细节。
//!
//! English: `private.rs` encapsulates the core private helper methods for SealEngine, mainly responsible for reading/parsing ciphertext headers, key derivation/decryption, and header construction.

use crate::asymmetric::errors::AsymmetricError;
use crate::common::errors::KeyManagementError;
use crate::common::header::{Header, HeaderPayload, SealMode};
use crate::common::traits::{Algorithm, AsymmetricAlgorithm, SymmetricAlgorithm};
use crate::engine::SealEngine;
use crate::symmetric::errors::SymmetricError;
use crate::symmetric::traits::SymmetricCryptographicSystem;
use crate::{AsymmetricCryptographicSystem, Error};

impl SealEngine {
    /// 从输入流中读取并解析出一个 Header。
    ///
    /// 该方法首先读取前4字节，解析出Header的长度，然后读取Header本体并反序列化。
    /// 这是解密流程的第一步，决定后续密钥派生与算法分发。
    ///
    /// English: Read and parse a Header from the input stream.
    /// This method first reads 4 bytes to get the header length, then reads and deserializes the header itself.
    /// This is the first step in the decryption process, determining subsequent key derivation and algorithm dispatch.
    pub(crate) fn read_and_parse_header<R: std::io::Read>(
        &self,
        mut reader: R,
    ) -> Result<Header, Error> {
        // 1. 读取前4字节，获取Header长度
        // English: Read the first 4 bytes to get the header length
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf)?;
        let header_len = u32::from_le_bytes(len_buf) as usize;

        // 2. 读取Header本体
        // English: Read the header body
        let mut header_bytes = vec![0u8; header_len];
        reader.read_exact(&mut header_bytes)?;
        let (header, _): (Header, _) = Header::decode_from_vec(&header_bytes)?;

        Ok(header)
    }

    /// 根据 Header 和当前引擎模式，派生或解密出数据加密密钥 (DEK)。
    ///
    /// 该方法根据Header中的payload类型（对称/混合）和算法分支，
    /// 调用密钥管理器派生对称密钥或解密混合加密下的DEK。
    /// 包含详细的错误处理和算法分发。
    ///
    /// English: Derive or decrypt the Data Encryption Key (DEK) based on the Header and current engine mode.
    /// This method dispatches by payload type (symmetric/hybrid) and algorithm, calling the key manager to derive symmetric keys or decrypt hybrid-encrypted DEKs.
    /// Includes detailed error handling and algorithm dispatch.
    pub(crate) fn derive_dek_from_header(&self, header: &Header) -> Result<Vec<u8>, Error> {
        // 使用引擎自身的密钥管理器来查找和解密密钥。
        // English: Use the engine's key manager to look up and decrypt the key.
        let key_manager = &self.key_manager;

        // 检查模式是否匹配，防止解密模式与密文头部不一致。
        // English: Check mode match to prevent mismatched decryption.
        if key_manager.mode() != header.mode {
            return Err(Error::KeyManagement(KeyManagementError::ModeMismatch(
                format!(
                    "Engine mode ({:?}) does not match header mode ({:?}).",
                    key_manager.mode(),
                    header.mode
                ),
            )));
        }

        match &header.payload {
            HeaderPayload::Symmetric { key_id, algorithm } => {
                // 对称加密分支：根据算法类型派生密钥
                // English: Symmetric branch: derive key by algorithm type
                match algorithm {
                    SymmetricAlgorithm::Aes256Gcm => {
                        use crate::symmetric::systems::aes_gcm::AesGcmSystem;
                        let key = key_manager
                            .derive_symmetric_key::<AesGcmSystem>(key_id)?
                            .ok_or_else(|| {
                                Error::KeyNotFound(format!(
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
                kek_algorithm,
                encrypted_dek,
                signature,
                ..
            } => {
                // 混合加密分支：根据KEK算法类型解密DEK
                // English: Hybrid branch: decrypt DEK by KEK algorithm type
                match kek_algorithm {
                    AsymmetricAlgorithm::Rsa2048 => {
                        use crate::asymmetric::systems::traditional::rsa::RsaCryptoSystem;
                        let (_, kek_priv) = key_manager
                            .get_asymmetric_keypair::<RsaCryptoSystem>(kek_id)?
                            .ok_or_else(|| {
                                Error::KeyNotFound(format!(
                                    "Failed to get KEK keypair for id: {}",
                                    kek_id
                                ))
                            })?;
                        // 使用RSA私钥解密DEK
                        // English: Decrypt DEK with RSA private key
                        let dek = RsaCryptoSystem::decrypt(&kek_priv, encrypted_dek, None)
                            .map_err(AsymmetricError::from)?;
                        Ok(dek)
                    }
                    AsymmetricAlgorithm::Kyber768 => {
                        use crate::asymmetric::systems::post_quantum::kyber::KyberCryptoSystem;
                        let (_, kek_priv) = key_manager
                            .get_asymmetric_keypair::<KyberCryptoSystem>(kek_id)?
                            .ok_or_else(|| {
                                Error::KeyNotFound(format!(
                                    "Failed to get KEK keypair for id: {}",
                                    kek_id
                                ))
                            })?;
                        // 使用Kyber私钥解密DEK
                        // English: Decrypt DEK with Kyber private key
                        let dek = KyberCryptoSystem::decrypt(&kek_priv, encrypted_dek, None)
                            .map_err(AsymmetricError::from)?;
                        Ok(dek)
                    }
                    AsymmetricAlgorithm::RsaKyber768 => {
                        use crate::AsymmetricCryptographicSystem;
                        use crate::asymmetric::systems::hybrid::rsa_kyber::RsaKyberCryptoSystem;

                        // 先校验签名，防止密文被篡改
                        // English: Verify signature before decryption to prevent tampering
                        let sig_to_verify = signature
                            .as_ref()
                            .ok_or(Error::Asymmetric(AsymmetricError::SignatureMissing))?;

                        let (kek_pub, kek_priv) = key_manager
                            .get_asymmetric_keypair::<RsaKyberCryptoSystem>(kek_id)?
                            .ok_or_else(|| {
                                Error::KeyNotFound(format!(
                                    "Failed to get KEK keypair for id: {}",
                                    kek_id
                                ))
                            })?;

                        RsaKyberCryptoSystem::verify(&kek_pub, encrypted_dek, sig_to_verify)
                            .map_err(AsymmetricError::from)?;

                        // 校验通过后解密DEK
                        // English: Decrypt DEK after signature verification
                        let dek = RsaKyberCryptoSystem::decrypt(&kek_priv, encrypted_dek, None)
                            .map_err(AsymmetricError::from)?;
                        Ok(dek)
                    }
                }
            }
        }
    }

    /// 根据当前模式构建 Header 和数据加密密钥 (DEK)。
    ///
    /// 该方法用于加密流程，自动根据密钥管理器的主密钥元数据和模式，
    /// 构建密文头部（Header）和实际用于数据加密的DEK。
    /// 对称模式下直接派生DEK，混合模式下生成新DEK并用主公钥加密，必要时签名。
    ///
    /// English: Build the Header and Data Encryption Key (DEK) according to the current mode.
    /// This method is used in the encryption process, automatically constructing the ciphertext header and the actual DEK based on the key manager's primary key metadata and mode.
    /// In symmetric mode, the DEK is derived directly; in hybrid mode, a new DEK is generated and encrypted with the primary public key, with signature if needed.
    pub(crate) fn build_header_and_dek(&mut self) -> Result<(Header, Vec<u8>), Error> {
        // 1. 获取主密钥元数据，若无则报错
        // English: Get primary key metadata, error if missing
        let primary_meta = self
            .key_manager
            .get_primary_key_metadata()
            .ok_or(Error::KeyManagement(KeyManagementError::NoPrimaryKey))?
            .clone(); // Clone to avoid borrow checker issues

        // 2. 根据模式分支构建HeaderPayload和DEK
        // English: Build HeaderPayload and DEK by mode branch
        let (header_payload, dek) = match self.key_manager.mode() {
            SealMode::Symmetric => {
                // 对称模式：直接派生DEK，Header记录密钥ID和算法
                // English: Symmetric mode: derive DEK, header records key ID and algorithm
                match primary_meta.algorithm {
                    Algorithm::Symmetric(sym_alg) => {
                        use crate::symmetric::systems::aes_gcm::AesGcmSystem;

                        let key = self
                            .key_manager
                            .derive_symmetric_key::<AesGcmSystem>(&primary_meta.id)?
                            .ok_or_else(|| {
                                Error::KeyNotFound("Failed to derive symmetric key.".to_string())
                            })?;

                        let payload = HeaderPayload::Symmetric {
                            key_id: primary_meta.id.clone(),
                            algorithm: sym_alg,
                        };
                        Ok((payload, key.0))
                    }
                    _ => Err(Error::KeyManagement(KeyManagementError::KeyTypeMismatch)),
                }?
            }
            SealMode::Hybrid => {
                // 混合模式：生成新DEK，用主公钥加密，必要时签名
                // English: Hybrid mode: generate new DEK, encrypt with primary public key, sign if needed
                use crate::symmetric::systems::aes_gcm::AesGcmSystem;
                match &primary_meta.algorithm {
                    Algorithm::Asymmetric(asym_alg) => match asym_alg {
                        AsymmetricAlgorithm::Rsa2048 => {
                            use crate::asymmetric::systems::traditional::rsa::RsaCryptoSystem;

                            let (kek_pub, _) = self
                                .key_manager
                                .get_asymmetric_keypair::<RsaCryptoSystem>(&primary_meta.id)?
                                .ok_or_else(|| {
                                    Error::KeyNotFound("Failed to get KEK keypair.".to_string())
                                })?;

                            // 生成新DEK
                            // English: Generate new DEK
                            let dek = AesGcmSystem::generate_key(&self.key_manager.config().crypto)
                                .map_err(SymmetricError::from)?;

                            // 用RSA公钥加密DEK
                            // English: Encrypt DEK with RSA public key
                            let encrypted_dek = RsaCryptoSystem::encrypt(&kek_pub, &dek.0, None)
                                .map_err(AsymmetricError::from)?;

                            let payload = HeaderPayload::Hybrid {
                                kek_id: primary_meta.id.clone(),
                                kek_algorithm: asym_alg.clone(),
                                dek_algorithm: SymmetricAlgorithm::Aes256Gcm,
                                encrypted_dek,
                                signature: None, // 无签名
                            };
                            Ok((payload, dek.0))
                        }
                        AsymmetricAlgorithm::Kyber768 => {
                            use crate::asymmetric::systems::post_quantum::kyber::KyberCryptoSystem;

                            let (kek_pub, _) = self
                                .key_manager
                                .get_asymmetric_keypair::<KyberCryptoSystem>(&primary_meta.id)?
                                .ok_or_else(|| {
                                    Error::KeyNotFound("Failed to get KEK keypair.".to_string())
                                })?;

                            let dek = AesGcmSystem::generate_key(&self.key_manager.config().crypto)
                                .map_err(SymmetricError::from)?;

                            // 用Kyber公钥加密DEK
                            // English: Encrypt DEK with Kyber public key
                            let encrypted_dek = KyberCryptoSystem::encrypt(&kek_pub, &dek.0, None)
                                .map_err(AsymmetricError::from)?;

                            let payload = HeaderPayload::Hybrid {
                                kek_id: primary_meta.id.clone(),
                                kek_algorithm: asym_alg.clone(),
                                dek_algorithm: SymmetricAlgorithm::Aes256Gcm,
                                encrypted_dek,
                                signature: None, // 无签名
                            };
                            Ok((payload, dek.0))
                        }
                        AsymmetricAlgorithm::RsaKyber768 => {
                            use crate::AsymmetricCryptographicSystem;
                            use crate::asymmetric::systems::hybrid::rsa_kyber::RsaKyberCryptoSystem;

                            let (kek_pub, kek_priv) = self
                                .key_manager
                                .get_asymmetric_keypair::<RsaKyberCryptoSystem>(&primary_meta.id)?
                                .ok_or_else(|| {
                                    Error::KeyNotFound("Failed to get KEK keypair.".to_string())
                                })?;

                            let dek = AesGcmSystem::generate_key(&self.key_manager.config().crypto)
                                .map_err(SymmetricError::from)?;

                            // 用混合公钥加密DEK
                            // English: Encrypt DEK with hybrid public key
                            let encrypted_dek =
                                RsaKyberCryptoSystem::encrypt(&kek_pub, &dek.0, None)
                                    .map_err(AsymmetricError::from)?;

                            // 用混合私钥签名密文DEK
                            // English: Sign encrypted DEK with hybrid private key
                            let signature = RsaKyberCryptoSystem::sign(&kek_priv, &encrypted_dek)
                                .map_err(AsymmetricError::from)?;

                            let payload = HeaderPayload::Hybrid {
                                kek_id: primary_meta.id.clone(),
                                kek_algorithm: asym_alg.clone(),
                                dek_algorithm: SymmetricAlgorithm::Aes256Gcm,
                                encrypted_dek,
                                signature: Some(signature),
                            };
                            Ok((payload, dek.0))
                        }
                    },
                    _ => Err(Error::KeyManagement(KeyManagementError::KeyTypeMismatch)),
                }?
            }
        };

        // 3. 构建Header结构体，包含版本、模式和payload
        // English: Build Header struct with version, mode, and payload
        let header = Header {
            version: 1,
            mode: self.key_manager.mode(),
            payload: header_payload,
        };

        Ok((header, dek))
    }
}
