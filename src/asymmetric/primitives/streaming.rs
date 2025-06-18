use std::io::{Read, Write};
use std::marker::PhantomData;
use crate::asymmetric::traits::AsymmetricCryptographicSystem;
use crate::common::errors::Error;
use std::sync::Arc;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use crate::common::streaming::{StreamingConfig, StreamingResult};

/// 流式加密器，将输入流数据加密并写入输出流
pub struct StreamingEncryptor<'a, C: AsymmetricCryptographicSystem, R: Read, W: Write> 
where
    Error: From<<C as AsymmetricCryptographicSystem>::Error>
{
    reader: R,
    writer: W,
    public_key: &'a C::PublicKey,
    buffer_size: usize,
    additional_data: Option<Vec<u8>>,
    bytes_processed: u64,
    total_bytes: Option<u64>,
    /// 是否在控制台输出进度
    show_progress: bool,
    _phantom: PhantomData<C>,
    progress_callback: Option<Arc<dyn Fn(u64, Option<u64>) + Send + Sync>>,
    buffer: Option<Vec<u8>>,
}

impl<'a, C: AsymmetricCryptographicSystem, R: Read, W: Write> StreamingEncryptor<'a, C, R, W>
where
    Error: From<<C as AsymmetricCryptographicSystem>::Error>
{
    /// 创建新的流式加密器
    pub fn new(reader: R, writer: W, public_key: &'a C::PublicKey, config: &StreamingConfig) -> Self {
        Self {
            reader,
            writer,
            public_key,
            buffer_size: config.buffer_size,
            additional_data: None,
            bytes_processed: 0,
            total_bytes: config.total_bytes,
            show_progress: config.show_progress,
            _phantom: PhantomData,
            progress_callback: config.progress_callback.clone(),
            buffer: if config.keep_in_memory { Some(Vec::new()) } else { None },
        }
    }
    
    /// 设置用于认证的附加数据
    pub fn with_additional_data(mut self, data: &[u8]) -> Self {
        self.additional_data = Some(data.to_vec());
        self
    }
    
    /// 设置总字节大小（用于进度显示）
    pub fn with_total_size(mut self, size: u64) -> Self {
        self.total_bytes = Some(size);
        self
    }
    
    /// 执行流式加密操作
    pub fn process(mut self) -> Result<StreamingResult, Error> {
        let mut buffer = vec![0u8; self.buffer_size];
        let mut encrypted_size = 0;
        
        loop {
            // 读取输入数据块
            let read_bytes = self.reader.read(&mut buffer)
                .map_err(Error::Io)?;
                
            if read_bytes == 0 {
                break; // 读取完成
            }
            
            // 加密数据块
            let plaintext = &buffer[..read_bytes];
            let ciphertext = C::encrypt(
                self.public_key, 
                plaintext, 
                self.additional_data.as_deref()
            )?;
            
            // 写入加密数据长度和数据本身
            let ciphertext_str = ciphertext.to_string();
            let ciphertext_bytes = ciphertext_str.as_bytes();
            let length = ciphertext_bytes.len() as u32;
            
            // 写入长度前缀（4字节）
            self.writer.write_all(&length.to_le_bytes())
                .map_err(Error::Io)?;
                
            // 写入密文数据块
            self.writer.write_all(ciphertext_bytes)
                .map_err(Error::Io)?;
            // 如果配置了内存保留，则累积数据
            if let Some(buf) = self.buffer.as_mut() {
                buf.extend_from_slice(ciphertext_bytes);
            }
            
            // 更新统计
            self.bytes_processed += read_bytes as u64;
            encrypted_size += read_bytes as u64;
            
            // 进度回调
            if let Some(cb) = &self.progress_callback {
                cb(self.bytes_processed, self.total_bytes);
            }
            // 控制台显示进度
            if self.show_progress {
                if let Some(total) = self.total_bytes {
                    println!("Encrypted {}/{} bytes", self.bytes_processed, total);
                } else {
                    println!("Encrypted {} bytes", self.bytes_processed);
                }
            }
        }
        
        // 完成时刷新输出流
        self.writer.flush().map_err(Error::Io)?;
        
        Ok(StreamingResult {
            bytes_processed: encrypted_size,
            buffer: self.buffer,
        })
    }
}

/// 流式解密器，将加密的输入流解密并写入输出流
pub struct StreamingDecryptor<'a, C: AsymmetricCryptographicSystem, R: Read, W: Write>
where
    Error: From<<C as AsymmetricCryptographicSystem>::Error>
{
    reader: R,
    writer: W,
    private_key: &'a C::PrivateKey,
    additional_data: Option<Vec<u8>>,
    bytes_processed: u64,
    total_bytes: Option<u64>,
    /// 是否在控制台输出进度
    show_progress: bool,
    _phantom: PhantomData<C>,
    progress_callback: Option<Arc<dyn Fn(u64, Option<u64>) + Send + Sync>>,
    buffer: Option<Vec<u8>>,
}

impl<'a, C: AsymmetricCryptographicSystem, R: Read, W: Write> StreamingDecryptor<'a, C, R, W>
where
    Error: From<<C as AsymmetricCryptographicSystem>::Error>
{
    /// 创建新的流式解密器
    pub fn new(reader: R, writer: W, private_key: &'a C::PrivateKey, config: &StreamingConfig) -> Self {
        Self {
            reader,
            writer,
            private_key,
            additional_data: None,
            bytes_processed: 0,
            total_bytes: config.total_bytes,
            show_progress: config.show_progress,
            _phantom: PhantomData,
            progress_callback: config.progress_callback.clone(),
            buffer: if config.keep_in_memory { Some(Vec::new()) } else { None },
        }
    }
    
    /// 设置用于认证的附加数据
    pub fn with_additional_data(mut self, data: &[u8]) -> Self {
        self.additional_data = Some(data.to_vec());
        self
    }
    
    /// 设置总字节大小（用于进度显示）
    pub fn with_total_size(mut self, size: u64) -> Self {
        self.total_bytes = Some(size);
        self
    }
    
    /// 执行流式解密操作
    pub fn process(mut self) -> Result<StreamingResult, Error> {
        let mut decrypted_size = 0;
        let mut length_buffer = [0u8; 4];
        
        loop {
            // 读取长度前缀
            match self.reader.read_exact(&mut length_buffer) {
                Ok(_) => {},
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(Error::Io(e)),
            }
            
            // 解析块大小
            let block_size = u32::from_le_bytes(length_buffer) as usize;
            
            // 读取密文块
            let mut ciphertext_buffer = vec![0u8; block_size];
            self.reader.read_exact(&mut ciphertext_buffer)
                .map_err(Error::Io)?;
                
            // 将字节解析为字符串
            let ciphertext = String::from_utf8(ciphertext_buffer)
                .map_err(|e| Error::Format(format!("无效的UTF-8密文: {}", e)))?;
                
            // 解密数据块
            let plaintext = C::decrypt(
                self.private_key, 
                &ciphertext, 
                self.additional_data.as_deref()
            )?;
            
            // 写入解密数据
            self.writer.write_all(&plaintext)
                .map_err(Error::Io)?;
            // 如果配置了内存保留，则累积数据
            if let Some(buf) = self.buffer.as_mut() {
                buf.extend_from_slice(&plaintext);
            }
            
            // 更新统计
            self.bytes_processed += plaintext.len() as u64;
            decrypted_size += plaintext.len() as u64;
            
            // 进度回调
            if let Some(cb) = &self.progress_callback {
                cb(self.bytes_processed, self.total_bytes);
            }
            // 控制台显示进度
            if self.show_progress {
                if let Some(total) = self.total_bytes {
                    println!("Decrypted {}/{} bytes", self.bytes_processed, total);
                } else {
                    println!("Decrypted {} bytes", self.bytes_processed);
                }
            }
        }
        
        // 完成时刷新输出流
        self.writer.flush().map_err(Error::Io)?;
        
        Ok(StreamingResult {
            bytes_processed: decrypted_size,
            buffer: self.buffer,
        })
    }
}

impl<T> crate::asymmetric::traits::AsymmetricSyncStreamingSystem for T
where
    T: AsymmetricCryptographicSystem,
    Error: From<T::Error>,
{
    fn encrypt_stream<R: Read, W: Write>(
        public_key: &Self::PublicKey,
        reader: R,
        writer: W,
        config: &StreamingConfig,
        additional_data: Option<&[u8]>,
    ) -> Result<StreamingResult, Error> {
        let mut encryptor = StreamingEncryptor::<Self, R, W>::new(reader, writer, public_key, config);
        if let Some(data) = additional_data {
            encryptor = encryptor.with_additional_data(data);
        }
        encryptor.process()
    }

    fn decrypt_stream<R: Read, W: Write>(
        private_key: &Self::PrivateKey,
        reader: R,
        writer: W,
        config: &StreamingConfig,
        additional_data: Option<&[u8]>,
    ) -> Result<StreamingResult, Error> {
        let mut decryptor = StreamingDecryptor::<Self, R, W>::new(reader, writer, private_key, config);
        if let Some(data) = additional_data {
            decryptor = decryptor.with_additional_data(data);
        }
        decryptor.process()
    }
}

/// 并行流式加密
///
/// 使用Rayon在多个线程上并行处理数据块的加密。
#[cfg(feature = "parallel")]
/// 并行流式加密：先读取所有数据块并行加密，然后按顺序写出
pub fn encrypt_stream_parallel<C, R, W>(
    public_key: &C::PublicKey,
    mut reader: R,
    mut writer: W,
    config: &StreamingConfig,
    additional_data: Option<&[u8]>,
) -> Result<StreamingResult, Error>
where
    C: AsymmetricCryptographicSystem,
    C::PublicKey: Sync + Send,
    <C as AsymmetricCryptographicSystem>::Error: Send + 'static,
    Error: From<<C as AsymmetricCryptographicSystem>::Error>,
    R: Read + Send,
    W: Write + Send,
{
    // 读取所有数据块
    let mut chunks = Vec::new();
    let mut buf = vec![0u8; config.buffer_size];
    while let Ok(n) = reader.read(&mut buf) {
        if n == 0 { break; }
        chunks.push(buf[..n].to_vec());
    }
    // 统计原始明文字节总数
    let plaintext_total: u64 = chunks.iter().map(|c| c.len() as u64).sum();
    // 并行执行加密并收集结果
    let cipher_results: Vec<Result<Vec<u8>, <C as AsymmetricCryptographicSystem>::Error>> =
        chunks.into_par_iter()
            .map(|plaintext| {
                C::encrypt(public_key, &plaintext, additional_data)
                    .map(|ct| ct.to_string().into_bytes())
            })
            .collect();
    // 序列化处理错误或提取加密块
    let cipher_chunks: Vec<Vec<u8>> = cipher_results
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .map_err(Error::from)?;
    // 顺序写出
    let mut mem_buf = if config.keep_in_memory { Some(Vec::new()) } else { None };
    for ciphertext_bytes in cipher_chunks {
        let len = ciphertext_bytes.len() as u32;
        writer.write_all(&len.to_le_bytes()).map_err(Error::Io)?;
        writer.write_all(&ciphertext_bytes).map_err(Error::Io)?;
        if let Some(buf) = mem_buf.as_mut() {
            buf.extend_from_slice(&ciphertext_bytes);
        }
    }
    writer.flush().map_err(Error::Io)?;
    Ok(StreamingResult { bytes_processed: plaintext_total, buffer: mem_buf })
}

#[cfg(feature = "parallel")]
/// 并行流式解密：先读取所有密文块并行解密，然后按顺序写出
pub fn decrypt_stream_parallel<C, R, W>(
    private_key: &C::PrivateKey,
    mut reader: R,
    mut writer: W,
    config: &StreamingConfig,
    additional_data: Option<&[u8]>,
) -> Result<StreamingResult, Error>
where
    C: AsymmetricCryptographicSystem,
    C::PrivateKey: Sync + Send,
    <C as AsymmetricCryptographicSystem>::Error: Send + 'static,
    Error: From<<C as AsymmetricCryptographicSystem>::Error>,
    R: Read + Send,
    W: Write + Send,
{
    // 读取所有密文块
    let mut chunks = Vec::new();
    loop {
        let mut len_buf = [0u8; 4];
        match reader.read_exact(&mut len_buf) {
            Ok(_) => {},
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(Error::Io(e)),
        }
        let size = u32::from_le_bytes(len_buf) as usize;
        let mut cipher_buf = vec![0u8; size];
        reader.read_exact(&mut cipher_buf).map_err(Error::Io)?;
        let ciphertext = String::from_utf8(cipher_buf)
            .map_err(|e| Error::Format(format!("无效的UTF-8密文: {}", e)))?;
        chunks.push(ciphertext);
    }
    // 并行执行解密并收集结果
    let plain_results: Vec<Result<Vec<u8>, <C as AsymmetricCryptographicSystem>::Error>> =
        chunks.into_par_iter()
            .map(|ciphertext| C::decrypt(private_key, &ciphertext, additional_data))
            .collect();
    // 序列化处理错误或提取明文块
    let plain_chunks: Vec<Vec<u8>> = plain_results
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .map_err(Error::from)?;
    // 顺序写出
    let mut total = 0u64;
    let mut mem_buf = if config.keep_in_memory { Some(Vec::new()) } else { None };
    for plaintext in plain_chunks {
        writer.write_all(&plaintext).map_err(Error::Io)?;
        if let Some(buf) = mem_buf.as_mut() {
            buf.extend_from_slice(&plaintext);
        }
        total += plaintext.len() as u64;
    }
    writer.flush().map_err(Error::Io)?;
    Ok(StreamingResult { bytes_processed: total, buffer: mem_buf })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asymmetric::systems::hybrid::rsa_kyber::RsaKyberCryptoSystem;
    use crate::asymmetric::traits::{AsymmetricCryptographicSystem, AsymmetricSyncStreamingSystem};
    use crate::common::utils::CryptoConfig;
    use std::io::Cursor;

    fn get_test_keys_and_config() -> (
        <RsaKyberCryptoSystem as AsymmetricCryptographicSystem>::PublicKey,
        <RsaKyberCryptoSystem as AsymmetricCryptographicSystem>::PrivateKey,
        StreamingConfig,
    ) {
        let (pk, sk) = RsaKyberCryptoSystem::generate_keypair(&CryptoConfig::default()).unwrap();
        let config = StreamingConfig {
            buffer_size: 128, // Smaller buffer for testing smaller data chunks
            ..Default::default()
        };
        (pk, sk, config)
    }

    #[test]
    fn test_streaming_encrypt_decrypt_roundtrip() {
        let (pk, sk, config) = get_test_keys_and_config();
        let original_data = b"This is a test for asymmetric streaming roundtrip.";

        // Encrypt
        let mut source = Cursor::new(original_data);
        let mut encrypted_dest = Cursor::new(Vec::new());
        RsaKyberCryptoSystem::encrypt_stream(&pk, &mut source, &mut encrypted_dest, &config, None).unwrap();

        // Decrypt
        let mut encrypted_source = Cursor::new(encrypted_dest.into_inner());
        let mut decrypted_dest = Cursor::new(Vec::new());
        RsaKyberCryptoSystem::decrypt_stream(&sk, &mut encrypted_source, &mut decrypted_dest, &config, None)
            .unwrap();

        assert_eq!(original_data.as_ref(), decrypted_dest.into_inner().as_slice());
    }

    #[test]
    fn test_streaming_with_aad() {
        let (pk, sk, config) = get_test_keys_and_config();
        let original_data = b"Some data to be protected by streaming with AAD.";
        let aad = b"additional authenticated data";

        // Encrypt
        let mut source = Cursor::new(original_data);
        let mut encrypted_dest = Cursor::new(Vec::new());
        RsaKyberCryptoSystem::encrypt_stream(&pk, &mut source, &mut encrypted_dest, &config, Some(aad))
            .unwrap();

        // Decrypt
        let mut encrypted_source = Cursor::new(encrypted_dest.into_inner());
        let mut decrypted_dest = Cursor::new(Vec::new());
        RsaKyberCryptoSystem::decrypt_stream(&sk, &mut encrypted_source, &mut decrypted_dest, &config, Some(aad))
            .unwrap();

        assert_eq!(original_data.as_ref(), decrypted_dest.into_inner().as_slice());
    }

    #[test]
    fn test_streaming_tampered_data_fails() {
        let (pk, sk, config) = get_test_keys_and_config();
        let original_data = b"This data should not be decryptable if tampered.";
        let aad = b"some aad";

        // Encrypt
        let mut source = Cursor::new(original_data);
        let mut encrypted_dest = Cursor::new(Vec::new());
        RsaKyberCryptoSystem::encrypt_stream(&pk, &mut source, &mut encrypted_dest, &config, Some(aad))
            .unwrap();

        // Tamper data
        let mut tampered_data = encrypted_dest.into_inner();
        let len = tampered_data.len();
        if len > 0 {
            tampered_data[len / 2] ^= 0xff; // Flip a byte in the middle
        }
        
        // Decrypt
        let mut encrypted_source = Cursor::new(tampered_data);
        let mut decrypted_dest = Cursor::new(Vec::new());
        let result = RsaKyberCryptoSystem::decrypt_stream(
            &sk,
            &mut encrypted_source,
            &mut decrypted_dest,
            &config,
            Some(aad),
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_streaming_wrong_aad_fails() {
        let (pk, sk, config) = get_test_keys_and_config();
        let original_data = b"This data should not be decryptable with wrong AAD.";
        let aad = b"correct aad";
        let wrong_aad = b"wrong aad";

        // Encrypt
        let mut source = Cursor::new(original_data);
        let mut encrypted_dest = Cursor::new(Vec::new());
        RsaKyberCryptoSystem::encrypt_stream(&pk, &mut source, &mut encrypted_dest, &config, Some(aad))
            .unwrap();

        // Decrypt with wrong AAD
        let mut encrypted_source = Cursor::new(encrypted_dest.into_inner());
        let mut decrypted_dest = Cursor::new(Vec::new());
        let result = RsaKyberCryptoSystem::decrypt_stream(
            &sk,
            &mut encrypted_source,
            &mut decrypted_dest,
            &config,
            Some(wrong_aad),
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_streaming_empty_input() {
        let (pk, sk, config) = get_test_keys_and_config();
        let original_data = b"";

        // Encrypt
        let mut source = Cursor::new(original_data);
        let mut encrypted_dest = Cursor::new(Vec::new());
        let enc_result = RsaKyberCryptoSystem::encrypt_stream(&pk, &mut source, &mut encrypted_dest, &config, None).unwrap();
        assert_eq!(enc_result.bytes_processed, 0);
        
        // Decrypt
        let mut encrypted_source = Cursor::new(encrypted_dest.into_inner());
        let mut decrypted_dest = Cursor::new(Vec::new());
        let dec_result = RsaKyberCryptoSystem::decrypt_stream(&sk, &mut encrypted_source, &mut decrypted_dest, &config, None)
            .unwrap();

        assert_eq!(dec_result.bytes_processed, 0);
        assert_eq!(decrypted_dest.into_inner().as_slice(), b"");
    }
} 