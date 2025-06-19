use crate::asymmetric::traits::AsymmetricCryptographicSystem;
use crate::common::config::StreamingConfig;
use crate::common::errors::Error;
use crate::common::streaming::StreamingResult;
use crate::symmetric::primitives::streaming::{
    SymmetricStreamingDecryptor, SymmetricStreamingEncryptor,
};
use crate::symmetric::traits::SymmetricCryptographicSystem;
use std::io::{Read, Write};
use std::marker::PhantomData;

/// 使用混合加密实现流式加密器
pub struct StreamingEncryptor<'a, C, R, W>
where
    C: AsymmetricCryptographicSystem,
    R: Read,
    W: Write,
    Error: From<C::Error>,
{
    reader: R,
    writer: W,
    public_key: &'a C::PublicKey,
    config: StreamingConfig,
    additional_data: Option<Vec<u8>>,
    _phantom: PhantomData<C>,
}

impl<'a, C, R, W> StreamingEncryptor<'a, C, R, W>
where
    C: AsymmetricCryptographicSystem,
    R: Read,
    W: Write,
    Error: From<C::Error>,
{
    /// 创建新的流式加密器
    pub fn new(
        reader: R,
        writer: W,
        public_key: &'a C::PublicKey,
        config: StreamingConfig,
        additional_data: Option<&[u8]>,
    ) -> Self {
        Self {
            reader,
            writer,
            public_key,
            config,
            additional_data: additional_data.map(|d| d.to_vec()),
            _phantom: PhantomData,
        }
    }

    /// 执行混合流式加密操作
    pub fn process<S>(mut self) -> Result<StreamingResult, Error>
    where
        S: SymmetricCryptographicSystem,
        Error: From<S::Error>,
    {
        // 1. 生成一次性对称密钥
        let symmetric_key = S::generate_key(&Default::default())?;

        // 2. 使用非对称公钥加密对称密钥 (密钥封装)
        let exported_key = S::export_key(&symmetric_key)?;
        let encrypted_symmetric_key = C::encrypt(
            self.public_key,
            exported_key.as_bytes(),
            None, // AAD不用于密钥封装
        )?;

        // 3. 写入头部: [封装密钥的长度 (u32)][封装的密钥]
        let encrypted_key_bytes = encrypted_symmetric_key.to_string().into_bytes();
        let key_len = encrypted_key_bytes.len() as u32;
        self.writer.write_all(&key_len.to_le_bytes())?;
        self.writer.write_all(&encrypted_key_bytes)?;

        // 4. 使用对称流加密器处理剩余的数据流
        let symmetric_encryptor = SymmetricStreamingEncryptor::<S, _, _>::new(
            self.reader,
            self.writer,
            &symmetric_key,
            &self.config,
            self.additional_data.as_deref(),
        );

        symmetric_encryptor.process()
    }
}

/// 使用混合加密实现流式解密器
pub struct StreamingDecryptor<'a, C, R, W>
where
    C: AsymmetricCryptographicSystem,
    R: Read,
    W: Write,
    Error: From<C::Error>,
{
    reader: R,
    writer: W,
    private_key: &'a C::PrivateKey,
    config: StreamingConfig,
    additional_data: Option<Vec<u8>>,
    _phantom: PhantomData<C>,
}

impl<'a, C, R, W> StreamingDecryptor<'a, C, R, W>
where
    C: AsymmetricCryptographicSystem,
    R: Read,
    W: Write,
    Error: From<C::Error>,
{
    /// 创建新的流式解密器
    pub fn new(
        reader: R,
        writer: W,
        private_key: &'a C::PrivateKey,
        config: StreamingConfig,
        additional_data: Option<&[u8]>,
    ) -> Self {
        Self {
            reader,
            writer,
            private_key,
            config,
            additional_data: additional_data.map(|d| d.to_vec()),
            _phantom: PhantomData,
        }
    }

    /// 执行混合流式解密操作
    pub fn process<S>(mut self) -> Result<StreamingResult, Error>
    where
        S: SymmetricCryptographicSystem,
        Error: From<S::Error>,
    {
        // 1. 读取头部: [封装密钥的长度 (u32)][封装的密钥]
        let mut key_len_buf = [0u8; 4];
        self.reader.read_exact(&mut key_len_buf)?;
        let key_len = u32::from_le_bytes(key_len_buf) as usize;

        let mut encrypted_key_buf = vec![0u8; key_len];
        self.reader.read_exact(&mut encrypted_key_buf)?;

        let encrypted_key_str = String::from_utf8(encrypted_key_buf)
            .map_err(|e| Error::Format(format!("无效的UTF-8密钥: {}", e)))?;

        // 2. 使用非对称私钥解密对称密钥 (密钥恢复)
        let decrypted_key_bytes = C::decrypt(self.private_key, &encrypted_key_str, None)?;

        let key_str = String::from_utf8(decrypted_key_bytes)
            .map_err(|e| Error::Format(format!("无效的UTF-8密钥: {}", e)))?;
        let symmetric_key = S::import_key(&key_str)?;

        // 3. 使用对称流解密器处理剩余的数据流
        let symmetric_decryptor = SymmetricStreamingDecryptor::<S, _, _>::new(
            self.reader,
            self.writer,
            &symmetric_key,
            &self.config,
            self.additional_data.as_deref(),
        );

        symmetric_decryptor.process()
    }
}

impl<T> crate::asymmetric::traits::AsymmetricSyncStreamingSystem for T
where
    T: AsymmetricCryptographicSystem,
    Error: From<T::Error>,
{
    fn encrypt_stream<S, R, W>(
        public_key: &Self::PublicKey,
        reader: R,
        writer: W,
        config: &StreamingConfig,
        additional_data: Option<&[u8]>,
    ) -> Result<StreamingResult, Error>
    where
        S: SymmetricCryptographicSystem,
        Error: From<S::Error>,
        R: Read,
        W: Write,
    {
        StreamingEncryptor::<Self, R, W>::new(
            reader,
            writer,
            public_key,
            config.clone(),
            additional_data,
        )
        .process::<S>()
    }

    fn decrypt_stream<S, R, W>(
        private_key: &Self::PrivateKey,
        reader: R,
        writer: W,
        config: &StreamingConfig,
        additional_data: Option<&[u8]>,
    ) -> Result<StreamingResult, Error>
    where
        S: SymmetricCryptographicSystem,
        Error: From<S::Error>,
        R: Read,
        W: Write,
    {
        StreamingDecryptor::<Self, R, W>::new(
            reader,
            writer,
            private_key,
            config.clone(),
            additional_data,
        )
        .process::<S>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asymmetric::systems::hybrid::rsa_kyber::RsaKyberCryptoSystem;
    use crate::asymmetric::traits::{AsymmetricCryptographicSystem, AsymmetricSyncStreamingSystem};
    use crate::common::config::CryptoConfig;
    use crate::symmetric::systems::aes_gcm::AesGcmSystem;
    use std::io::Cursor;

    #[test]
    fn test_hybrid_streaming_encrypt_decrypt_roundtrip() {
        let (pk, sk) = RsaKyberCryptoSystem::generate_keypair(&CryptoConfig::default()).unwrap();
        let config = StreamingConfig {
            buffer_size: 256,
            ..Default::default()
        };
        let original_data = b"This is a long test string for hybrid streaming encryption. It should be handled efficiently.";

        // Encrypt
        let mut source = Cursor::new(original_data.as_ref());
        let mut encrypted_dest = Cursor::new(Vec::new());
        RsaKyberCryptoSystem::encrypt_stream::<AesGcmSystem, _, _>(
            &pk,
            &mut source,
            &mut encrypted_dest,
            &config,
            None,
        )
        .unwrap();

        // Decrypt
        let mut encrypted_source = Cursor::new(encrypted_dest.into_inner());
        let mut decrypted_dest = Cursor::new(Vec::new());
        RsaKyberCryptoSystem::decrypt_stream::<AesGcmSystem, _, _>(
            &sk,
            &mut encrypted_source,
            &mut decrypted_dest,
            &config,
            None,
        )
        .unwrap();

        assert_eq!(
            original_data.as_ref(),
            decrypted_dest.into_inner().as_slice()
        );
    }

    #[test]
    fn test_hybrid_streaming_with_aad() {
        let (pk, sk) = RsaKyberCryptoSystem::generate_keypair(&CryptoConfig::default()).unwrap();
        let config = StreamingConfig {
            buffer_size: 256,
            ..Default::default()
        };
        let original_data = b"Some data to be protected by streaming with AAD.";
        let aad = b"additional authenticated data for the stream";

        // Encrypt
        let mut source = Cursor::new(original_data.as_ref());
        let mut encrypted_dest = Cursor::new(Vec::new());
        RsaKyberCryptoSystem::encrypt_stream::<AesGcmSystem, _, _>(
            &pk,
            &mut source,
            &mut encrypted_dest,
            &config,
            Some(aad),
        )
        .unwrap();

        // Decrypt
        let mut encrypted_source = Cursor::new(encrypted_dest.into_inner());
        let mut decrypted_dest = Cursor::new(Vec::new());
        RsaKyberCryptoSystem::decrypt_stream::<AesGcmSystem, _, _>(
            &sk,
            &mut encrypted_source,
            &mut decrypted_dest,
            &config,
            Some(aad),
        )
        .unwrap();

        assert_eq!(
            original_data.as_ref(),
            decrypted_dest.into_inner().as_slice()
        );
    }

    #[test]
    fn test_hybrid_streaming_wrong_aad_fails() {
        let (pk, sk) = RsaKyberCryptoSystem::generate_keypair(&CryptoConfig::default()).unwrap();
        let config = StreamingConfig {
            buffer_size: 256,
            ..Default::default()
        };
        let original_data = b"Some data that must fail with wrong AAD.";
        let aad1 = b"correct_aad";
        let aad2 = b"wrong_aad";

        // Encrypt with aad1
        let mut source = Cursor::new(original_data.as_ref());
        let mut encrypted_dest = Cursor::new(Vec::new());
        RsaKyberCryptoSystem::encrypt_stream::<AesGcmSystem, _, _>(
            &pk,
            &mut source,
            &mut encrypted_dest,
            &config,
            Some(aad1),
        )
        .unwrap();

        // Decrypt with aad2 should fail
        let mut encrypted_source = Cursor::new(encrypted_dest.into_inner());
        let mut decrypted_dest = Cursor::new(Vec::new());
        let result = RsaKyberCryptoSystem::decrypt_stream::<AesGcmSystem, _, _>(
            &sk,
            &mut encrypted_source,
            &mut decrypted_dest,
            &config,
            Some(aad2),
        );

        assert!(
            result.is_err(),
            "Decryption with wrong AAD should have failed"
        );
    }

    #[test]
    fn test_hybrid_streaming_tampered_header_fails() {
        let (pk, sk) = RsaKyberCryptoSystem::generate_keypair(&CryptoConfig::default()).unwrap();
        let config = StreamingConfig {
            buffer_size: 256,
            ..Default::default()
        };
        let original_data = b"Tampering the header must lead to failure.";

        // Encrypt
        let mut source = Cursor::new(original_data.as_ref());
        let mut encrypted_dest = Cursor::new(Vec::new());
        RsaKyberCryptoSystem::encrypt_stream::<AesGcmSystem, _, _>(
            &pk,
            &mut source,
            &mut encrypted_dest,
            &config,
            None,
        )
        .unwrap();

        // Tamper with the header (encrypted symmetric key)
        let mut tampered_data = encrypted_dest.into_inner();
        if tampered_data.len() > 10 {
            tampered_data[10] ^= 0xff; // Flip a bit in the encrypted key part
        }

        // Decrypt should fail
        let mut tampered_source = Cursor::new(tampered_data);
        let mut decrypted_dest = Cursor::new(Vec::new());
        let result = RsaKyberCryptoSystem::decrypt_stream::<AesGcmSystem, _, _>(
            &sk,
            &mut tampered_source,
            &mut decrypted_dest,
            &config,
            None,
        );

        assert!(
            result.is_err(),
            "Decryption with tampered header should have failed"
        );
    }

    #[test]
    fn test_hybrid_streaming_tampered_body_fails() {
        let (pk, sk) = RsaKyberCryptoSystem::generate_keypair(&CryptoConfig::default()).unwrap();
        let config = StreamingConfig {
            buffer_size: 256,
            ..Default::default()
        };
        let original_data = b"Tampering the body must lead to failure.";

        // Encrypt
        let mut source = Cursor::new(original_data.as_ref());
        let mut encrypted_dest = Cursor::new(Vec::new());
        RsaKyberCryptoSystem::encrypt_stream::<AesGcmSystem, _, _>(
            &pk,
            &mut source,
            &mut encrypted_dest,
            &config,
            None,
        )
        .unwrap();

        // Tamper with the body
        let mut tampered_data = encrypted_dest.into_inner();
        let data_len = tampered_data.len();
        if data_len > 0 {
            tampered_data[data_len - 10] ^= 0xff; // Flip a bit towards the end of the stream
        }

        // Decrypt should fail
        let mut tampered_source = Cursor::new(tampered_data);
        let mut decrypted_dest = Cursor::new(Vec::new());
        let result = RsaKyberCryptoSystem::decrypt_stream::<AesGcmSystem, _, _>(
            &sk,
            &mut tampered_source,
            &mut decrypted_dest,
            &config,
            None,
        );

        assert!(
            result.is_err(),
            "Decryption with tampered body should have failed"
        );
    }
}
