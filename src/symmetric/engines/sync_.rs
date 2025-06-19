//! 对称加密引擎 `SymmetricQSealEngine`
use crate::common::errors::Error;
use crate::common::streaming::StreamingResult;
use crate::symmetric::rotation::SymmetricKeyRotationManager;
use crate::symmetric::traits::{SymmetricCryptographicSystem, SymmetricSyncStreamingSystem};
use memchr::memchr;
use secrecy::SecretString;
use std::io::{Read, Write};
use std::marker::PhantomData;

/// `SymmetricQSealEngine`：一个支持密钥轮换的用户友好对称加密引擎。
///
/// 该引擎通过 `Seal` 结构进行实例化，并由 `SymmetricKeyRotationManager` 在后台管理密钥。
/// 它能够自动使用最新的主密钥进行加密，并能解密由旧密钥加密的数据。
pub struct SymmetricQSealEngine<T: SymmetricCryptographicSystem + SymmetricSyncStreamingSystem>
where
    T::Error: std::error::Error + 'static,
    Error: From<T::Error>,
{
    key_manager: SymmetricKeyRotationManager,
    password: SecretString, // 需要密码来提交密钥轮换或使用计数更新
    _phantom: PhantomData<T>,
}

impl<T: SymmetricCryptographicSystem + SymmetricSyncStreamingSystem> SymmetricQSealEngine<T>
where
    T::Error: std::error::Error + 'static,
    Error: From<T::Error>,
    T::Key: Clone,
{
    /// 使用密钥管理器创建一个新的引擎实例。
    /// 这个方法是 crate-internal 的，只能通过 `Seal` 结构调用。
    pub(crate) fn new(key_manager: SymmetricKeyRotationManager, password: SecretString) -> Self {
        Self {
            key_manager,
            password,
            _phantom: PhantomData,
        }
    }

    /// 加密一段明文。
    ///
    /// 密文格式为 `key_id:ciphertext_bytes`。
    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        // 1. 获取主密钥进行加密
        let primary_key = self.key_manager.get_primary_key::<T>()?.ok_or_else(|| {
            Error::KeyManagement("No primary key available for encryption.".to_string())
        })?;
        let key_metadata = self.key_manager.get_primary_key_metadata().ok_or_else(|| {
            Error::KeyManagement("No primary key metadata available.".to_string())
        })?;

        // 2. 加密数据
        let ciphertext_bytes =
            T::encrypt(&primary_key, plaintext, additional_data).map_err(Error::from)?;

        // 3. 构造输出: key_id:ciphertext
        let mut output = key_metadata.id.as_bytes().to_vec();
        output.push(b':');
        output.extend_from_slice(&ciphertext_bytes);

        // 4. 增加使用计数
        self.key_manager.increment_usage_count(&self.password)?;

        Ok(output)
    }

    /// 解密一段密文。
    ///
    /// 期望的密文格式为 `key_id:ciphertext_bytes`。
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        // 1. 从密文中解析出 key_id
        let separator_pos = memchr(b':', ciphertext).ok_or_else(|| {
            Error::Format("Invalid ciphertext format. Missing ':' separator.".to_string())
        })?;

        let key_id_bytes = &ciphertext[..separator_pos];
        let actual_ciphertext = &ciphertext[separator_pos + 1..];

        let key_id = std::str::from_utf8(key_id_bytes)
            .map_err(|_| Error::Format("Key ID is not valid UTF-8.".to_string()))?;

        // 2. 根据 key_id 派生解密密钥
        let key = self
            .key_manager
            .derive_key_by_id::<T>(key_id)?
            .ok_or_else(|| {
                Error::KeyManagement(format!("Could not find or derive key for ID: {}", key_id))
            })?;

        // 3. 解密数据
        T::decrypt(&key, actual_ciphertext, additional_data).map_err(Error::from)
    }

    /// 同步流式加密
    pub fn encrypt_stream<R: Read, W: Write>(
        &mut self,
        mut reader: R,
        mut writer: W,
    ) -> Result<StreamingResult, Error> {
        // 1. 获取主密钥
        let primary_key = self.key_manager.get_primary_key::<T>()?.ok_or_else(|| {
            Error::KeyManagement("No primary key available for encryption.".to_string())
        })?;
        let key_metadata = self.key_manager.get_primary_key_metadata().ok_or_else(|| {
            Error::KeyManagement("No primary key metadata available.".to_string())
        })?;

        // 2. 将 key_id 写入流的开头
        writer.write_all(key_metadata.id.as_bytes())?;
        writer.write_all(b":")?;

        // 3. 流式加密剩余数据
        let config = self.key_manager.config().streaming;
        let result = T::encrypt_stream(&primary_key, &mut reader, &mut writer, &config, None)?;

        // 4. 增加使用计数
        self.key_manager.increment_usage_count(&self.password)?;

        Ok(result)
    }

    /// 同步流式解密
    pub fn decrypt_stream<R: Read, W: Write>(
        &self,
        mut reader: R,
        mut writer: W,
    ) -> Result<StreamingResult, Error> {
        // 1. 从流中读取 key_id
        let mut key_id_buf = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            reader.read_exact(&mut byte)?;
            if byte[0] == b':' {
                break;
            }
            key_id_buf.push(byte[0]);
        }
        let key_id = String::from_utf8(key_id_buf)
            .map_err(|_| Error::Format("Key ID in stream is not valid UTF-8.".to_string()))?;

        // 2. 根据 key_id 派生密钥
        let key = self
            .key_manager
            .derive_key_by_id::<T>(&key_id)?
            .ok_or_else(|| {
                Error::KeyManagement(format!("Could not find or derive key for ID: {}", key_id))
            })?;

        // 3. 解密剩余的流数据
        let config = self.key_manager.config().streaming;
        T::decrypt_stream(&key, &mut reader, &mut writer, &config, None)
    }

    #[cfg(feature = "parallel")]
    /// [并行] 加密一段明文。
    ///
    /// 底层使用 `SymmetricParallelSystem` trait。
    /// 密文格式与非并行版本相同: `key_id:ciphertext_bytes`。
    pub fn par_encrypt(
        &mut self,
        plaintext: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error>
    where
        T: crate::symmetric::traits::SymmetricParallelSystem,
    {
        let primary_key = self.key_manager.get_primary_key::<T>()?.ok_or_else(|| {
            Error::KeyManagement("No primary key available for encryption.".to_string())
        })?;
        let key_metadata = self.key_manager.get_primary_key_metadata().ok_or_else(|| {
            Error::KeyManagement("No primary key metadata available.".to_string())
        })?;

        let ciphertext_bytes =
            T::par_encrypt(&primary_key, plaintext, additional_data).map_err(Error::from)?;

        let mut output = key_metadata.id.as_bytes().to_vec();
        output.push(b':');
        output.extend_from_slice(&ciphertext_bytes);

        self.key_manager.increment_usage_count(&self.password)?;

        Ok(output)
    }

    #[cfg(feature = "parallel")]
    /// [并行] 解密一段密文。
    ///
    /// 底层使用 `SymmetricParallelSystem` trait。
    /// 期望的密文格式与非并行版本相同: `key_id:ciphertext_bytes`。
    pub fn par_decrypt(
        &self,
        ciphertext: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error>
    where
        T: crate::symmetric::traits::SymmetricParallelSystem,
    {
        let separator_pos = memchr(b':', ciphertext).ok_or_else(|| {
            Error::Format("Invalid ciphertext format. Missing ':' separator.".to_string())
        })?;
        let key_id_bytes = &ciphertext[..separator_pos];
        let actual_ciphertext = &ciphertext[separator_pos + 1..];
        let key_id = std::str::from_utf8(key_id_bytes)
            .map_err(|_| Error::Format("Key ID is not valid UTF-8.".to_string()))?;

        let key = self
            .key_manager
            .derive_key_by_id::<T>(key_id)?
            .ok_or_else(|| {
                Error::KeyManagement(format!("Could not find or derive key for ID: {}", key_id))
            })?;

        T::par_decrypt(&key, actual_ciphertext, additional_data).map_err(Error::from)
    }

    #[cfg(feature = "parallel")]
    /// [并行] 同步流式加密。
    ///
    /// 底层使用 `SymmetricParallelStreamingSystem` trait。
    pub fn par_encrypt_stream<R: Read + Send, W: Write + Send>(
        &mut self,
        mut reader: R,
        mut writer: W,
    ) -> Result<StreamingResult, Error>
    where
        T: crate::symmetric::traits::SymmetricParallelStreamingSystem,
    {
        let primary_key = self.key_manager.get_primary_key::<T>()?.ok_or_else(|| {
            Error::KeyManagement("No primary key available for encryption.".to_string())
        })?;
        let key_metadata = self.key_manager.get_primary_key_metadata().ok_or_else(|| {
            Error::KeyManagement("No primary key metadata available.".to_string())
        })?;

        writer.write_all(key_metadata.id.as_bytes())?;
        writer.write_all(b":")?;

        let result = T::par_encrypt_stream(
            &primary_key,
            &mut reader,
            &mut writer,
            &self.key_manager.config().streaming,
            &self.key_manager.config().parallelism,
            None,
        )?;

        self.key_manager.increment_usage_count(&self.password)?;

        Ok(result)
    }

    #[cfg(feature = "parallel")]
    /// [并行] 同步流式解密。
    ///
    /// 底层使用 `SymmetricParallelStreamingSystem` trait。
    pub fn par_decrypt_stream<R: Read + Send, W: Write + Send>(
        &self,
        mut reader: R,
        mut writer: W,
    ) -> Result<StreamingResult, Error>
    where
        T: crate::symmetric::traits::SymmetricParallelStreamingSystem,
    {
        let mut key_id_buf = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            reader.read_exact(&mut byte)?;
            if byte[0] == b':' {
                break;
            }
            key_id_buf.push(byte[0]);
        }
        let key_id = String::from_utf8(key_id_buf)
            .map_err(|_| Error::Format("Key ID in stream is not valid UTF-8.".to_string()))?;

        let key = self
            .key_manager
            .derive_key_by_id::<T>(&key_id)?
            .ok_or_else(|| {
                Error::KeyManagement(format!("Could not find or derive key for ID: {}", key_id))
            })?;

        let streaming_config = self.key_manager.config().streaming;
        T::par_decrypt_stream(
            &key,
            &mut reader,
            &mut writer,
            &streaming_config,
            &self.key_manager.config().parallelism,
            None,
        )
    }
}

#[cfg(all(test, feature = "aes-gcm-feature"))]
mod tests {
    use crate::seal::Seal;
    use crate::symmetric::systems::aes_gcm::AesGcmSystem;
    use secrecy::SecretString;
    use std::io::Cursor;
    use std::sync::Arc;
    use tempfile::{TempDir, tempdir};

    // 辅助函数：设置一个全新的 Seal 和密码
    fn setup() -> (Arc<Seal>, SecretString, TempDir) {
        let dir = tempdir().unwrap();
        let seal_path = dir.path().join("my.seal");
        let password = SecretString::new("a-very-secret-password".into());
        let seal = Seal::create(seal_path, &password).unwrap();
        (seal, password, dir)
    }

    #[test]
    fn test_engine_encrypt_decrypt_roundtrip() {
        let (seal, password, _dir) = setup();
        let mut engine = seal
            .symmetric_sync_engine::<AesGcmSystem>(password)
            .unwrap();

        let plaintext = b"some secret data";
        let encrypted = engine.encrypt(plaintext, None).unwrap();
        let decrypted = engine.decrypt(&encrypted, None).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decryption_after_reopening_seal() {
        let dir = tempdir().unwrap();
        let seal_path = dir.path().join("my.seal");
        let password = SecretString::new("a-very-secret-password".into());

        // 1. 创建 Seal，获取引擎，加密数据
        let seal1 = Seal::create(&seal_path, &password).unwrap();
        let mut engine1 = seal1
            .symmetric_sync_engine::<AesGcmSystem>(password.clone())
            .unwrap();
        let plaintext = b"some secret data";
        let encrypted = engine1.encrypt(plaintext, None).unwrap();

        // 2. 重新打开同一个 Seal，获取新引擎
        let seal2 = Seal::open(&seal_path, &password).unwrap();
        let engine2 = seal2
            .symmetric_sync_engine::<AesGcmSystem>(password)
            .unwrap();

        // 3. 用新引擎解密旧数据，应该成功
        let decrypted = engine2.decrypt(&encrypted, None).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decryption_with_rotated_key() {
        let (seal, password, _dir) = setup();
        let mut engine = seal
            .symmetric_sync_engine::<AesGcmSystem>(password.clone())
            .unwrap();

        // 1. 使用初始密钥加密数据
        let plaintext1 = b"data before rotation";
        let encrypted1 = engine.encrypt(plaintext1, None).unwrap();

        // 2. 手动触发密钥轮换
        let algorithm_name = std::any::type_name::<AesGcmSystem>().to_string();
        engine
            .key_manager
            .start_rotation(&password, &algorithm_name)
            .unwrap();

        // 3. 使用新的主密钥加密数据
        let plaintext2 = b"data after rotation";
        let encrypted2 = engine.encrypt(plaintext2, None).unwrap();

        // 确保两个密文不同 (因为密钥不同)
        assert_ne!(encrypted1, encrypted2);

        // 4. 引擎应该能解密两个密文
        let decrypted1 = engine.decrypt(&encrypted1, None).unwrap();
        let decrypted2 = engine.decrypt(&encrypted2, None).unwrap();

        assert_eq!(decrypted1, plaintext1);
        assert_eq!(decrypted2, plaintext2);
    }

    #[test]
    fn test_engine_streaming_roundtrip() {
        let (seal, password, _dir) = setup();
        let mut engine = seal
            .symmetric_sync_engine::<AesGcmSystem>(password)
            .unwrap();

        let source_data = b"This is a test for streaming encryption and decryption.";
        let mut reader = Cursor::new(source_data);
        let mut encrypted_writer = Cursor::new(Vec::new());

        // 加密
        engine
            .encrypt_stream(&mut reader, &mut encrypted_writer)
            .unwrap();

        // 解密
        let mut encrypted_reader = Cursor::new(encrypted_writer.into_inner());
        let mut decrypted_writer = Cursor::new(Vec::new());
        engine
            .decrypt_stream(&mut encrypted_reader, &mut decrypted_writer)
            .unwrap();

        assert_eq!(decrypted_writer.into_inner(), source_data);
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn test_engine_parallel_encrypt_decrypt_roundtrip() {
        let (seal, password, _dir) = setup();
        let mut engine = seal
            .symmetric_sync_engine::<AesGcmSystem>(password)
            .unwrap();

        // Use a large plaintext to trigger parallel logic
        let plaintext = vec![1u8; 1024 * 1024 * 3]; // 3MB
        let encrypted = engine.par_encrypt(&plaintext, None).unwrap();
        let decrypted = engine.par_decrypt(&encrypted, None).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn test_engine_parallel_streaming_roundtrip() {
        let (seal, password, _dir) = setup();
        let mut engine = seal
            .symmetric_sync_engine::<AesGcmSystem>(password.clone())
            .unwrap();

        let source_data = b"This is a longer test for parallel streaming encryption and decryption which needs to be larger than a single chunk size to be effective.";
        let mut source = Cursor::new(source_data);
        let mut encrypted_dest = Cursor::new(Vec::new());

        // 并行加密
        engine
            .par_encrypt_stream(&mut source, &mut encrypted_dest)
            .unwrap();

        // 并行解密
        let mut encrypted_source = Cursor::new(encrypted_dest.into_inner());
        let mut decrypted_dest = Cursor::new(Vec::new());

        engine
            .par_decrypt_stream(&mut encrypted_source, &mut decrypted_dest)
            .unwrap();

        assert_eq!(decrypted_dest.into_inner(), source_data);
    }
}
