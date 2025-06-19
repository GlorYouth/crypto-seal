use crate::common::header::{Header, HeaderPayload, SealMode};
use crate::common::traits::{Algorithm, AsymmetricAlgorithm, SymmetricAlgorithm};
use crate::engine::SealEngine;
use crate::rotation::manager::KeyManager;
use crate::symmetric::traits::SymmetricCryptographicSystem;
use crate::{AsymmetricCryptographicSystem, Error};
use rsa::signature::SignatureEncoding;
use std::sync::Arc;

impl SealEngine {
    /// 从输入流中读取并解析出一个 Header。
    pub(crate) fn read_and_parse_header<R: std::io::Read>(
        &self,
        mut reader: R,
    ) -> Result<Header, Error> {
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf)?;
        let header_len = u32::from_le_bytes(len_buf) as usize;

        let mut header_bytes = vec![0u8; header_len];
        reader.read_exact(&mut header_bytes)?;
        let header: Header = bincode::deserialize(&header_bytes)?;

        Ok(header)
    }

    /// 根据 Header 和当前引擎模式，派生或解密出数据加密密钥 (DEK)。
    pub(crate) fn derive_dek_from_header(&self, header: &Header) -> Result<Vec<u8>, Error> {
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
                signature,
                ..
            } => {
                // Dispatch based on KEK algorithm
                match kek_algorithm {
                    AsymmetricAlgorithm::Rsa2048 => {
                        if signature.is_some() {
                            return Err(Error::Verification(
                                "Unexpected signature found for non-authenticated algorithm."
                                    .to_string(),
                            ));
                        }
                        use crate::asymmetric::systems::traditional::rsa::RsaCryptoSystem;

                        let (_, kek_priv) = key_manager
                            .get_asymmetric_keypair::<RsaCryptoSystem>(kek_id)?
                            .ok_or_else(|| {
                                Error::Key(format!("Failed to get KEK keypair for id: {}", kek_id))
                            })?;

                        let dek = RsaCryptoSystem::decrypt(&kek_priv, encrypted_dek, None)?;
                        Ok(dek)
                    }
                    AsymmetricAlgorithm::Kyber768 => {
                        if signature.is_some() {
                            return Err(Error::Verification(
                                "Unexpected signature found for non-authenticated algorithm."
                                    .to_string(),
                            ));
                        }
                        use crate::asymmetric::systems::post_quantum::kyber::KyberCryptoSystem;

                        let (_, kek_priv) = key_manager
                            .get_asymmetric_keypair::<KyberCryptoSystem>(kek_id)?
                            .ok_or_else(|| {
                                Error::Key(format!("Failed to get KEK keypair for id: {}", kek_id))
                            })?;

                        let dek = KyberCryptoSystem::decrypt(&kek_priv, encrypted_dek, None)?;
                        Ok(dek)
                    }
                    AsymmetricAlgorithm::RsaKyber768 => {
                        use crate::asymmetric::systems::hybrid::rsa_kyber::RsaKyberCryptoSystem;

                        let sig_to_verify = signature.as_ref().ok_or_else(|| {
                            Error::Signature("Signature missing for RsaKyber768.".to_string())
                        })?;

                        let (kek_pub, kek_priv) = key_manager
                            .get_asymmetric_keypair::<RsaKyberCryptoSystem>(kek_id)?
                            .ok_or_else(|| {
                                Error::Key(format!("Failed to get KEK keypair for id: {}", kek_id))
                            })?;

                        // 使用 trait 方法进行验证
                        RsaKyberCryptoSystem::verify(&kek_pub, encrypted_dek, sig_to_verify)
                            .map_err(|e| {
                                Error::Verification(format!("Signature verification failed: {}", e))
                            })?;

                        let dek = RsaKyberCryptoSystem::decrypt(&kek_priv, encrypted_dek, None)?;
                        Ok(dek)
                    }
                }
            }
        }
    }

    /// 根据当前模式构建 Header 和数据加密密钥 (DEK)。
    pub(crate) fn build_header_and_dek(&mut self) -> Result<(Header, Vec<u8>), Error> {
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
                        use crate::symmetric::systems::aes_gcm::AesGcmSystem;

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
                use crate::symmetric::systems::aes_gcm::AesGcmSystem;
                match &primary_meta.algorithm {
                    Algorithm::Asymmetric(asym_alg) => match asym_alg {
                        AsymmetricAlgorithm::Rsa2048 => {
                            use crate::asymmetric::systems::traditional::rsa::RsaCryptoSystem;

                            let (kek_pub, _) = self
                                .key_manager
                                .get_asymmetric_keypair::<RsaCryptoSystem>(&primary_meta.id)?
                                .ok_or_else(|| {
                                    Error::Key("Failed to get KEK keypair.".to_string())
                                })?;

                            let dek =
                                AesGcmSystem::generate_key(&self.key_manager.config().crypto)?;

                            let encrypted_dek = RsaCryptoSystem::encrypt(&kek_pub, &dek.0, None)?;

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
                                    Error::Key("Failed to get KEK keypair.".to_string())
                                })?;

                            let dek =
                                AesGcmSystem::generate_key(&self.key_manager.config().crypto)?;

                            let encrypted_dek = KyberCryptoSystem::encrypt(&kek_pub, &dek.0, None)?;

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
                            use crate::asymmetric::systems::hybrid::rsa_kyber::RsaKyberCryptoSystem;

                            let (kek_pub, kek_priv) = self
                                .key_manager
                                .get_asymmetric_keypair::<RsaKyberCryptoSystem>(&primary_meta.id)?
                                .ok_or_else(|| {
                                    Error::Key("Failed to get KEK keypair.".to_string())
                                })?;

                            let dek =
                                AesGcmSystem::generate_key(&self.key_manager.config().crypto)?;

                            let encrypted_dek =
                                RsaKyberCryptoSystem::encrypt(&kek_pub, &dek.0, None)?;

                            // 使用 trait 方法进行签名
                            let signature = RsaKyberCryptoSystem::sign(&kek_priv, &encrypted_dek)?;

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
