use std::io::{Read, Write};
use std::marker::PhantomData;
use crate::traits::CryptographicSystem;
use crate::errors::Error;
use std::sync::Arc;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// 流式处理返回结果
#[derive(Debug)]
pub struct StreamingResult {
    /// 已处理的字节数（原始字节数）
    pub bytes_processed: u64,
    /// 如果配置了 keep_in_memory，则包含完整数据，否则为 None
    pub buffer: Option<Vec<u8>>,
}

/// 默认缓冲区大小（64KB）
const DEFAULT_BUFFER_SIZE: usize = 65536;

/// 流式加密配置
pub struct StreamingConfig {
    /// 缓冲区大小
    pub buffer_size: usize,
    
    /// 是否在处理过程中显示进度
    pub show_progress: bool,
    
    /// 是否在内存中保留完整密文/明文
    pub keep_in_memory: bool,
    
    /// 可选的进度回调
    pub progress_callback: Option<Arc<dyn Fn(u64, Option<u64>) + Send + Sync>>,
    
    /// 可选的总字节数，用于进度计算
    pub total_bytes: Option<u64>,
}

impl Default for StreamingConfig {
    fn default() -> Self {
        Self {
            buffer_size: DEFAULT_BUFFER_SIZE,
            show_progress: false,
            keep_in_memory: false,
            progress_callback: None,
            total_bytes: None,
        }
    }
}

/// 为 StreamingConfig 添加 builder 方法：设置总字节数
impl StreamingConfig {
    /// 设置总字节大小（用于进度回调）
    pub fn with_total_bytes(mut self, total: u64) -> Self {
        self.total_bytes = Some(total);
        self
    }
    /// 设置缓冲区大小
    pub fn with_buffer_size(mut self, size: usize) -> Self {
        self.buffer_size = size;
        self
    }
    /// 设置是否在控制台显示进度
    pub fn with_show_progress(mut self, show: bool) -> Self {
        self.show_progress = show;
        self
    }
    /// 设置是否在内存保留完整数据
    pub fn with_keep_in_memory(mut self, keep: bool) -> Self {
        self.keep_in_memory = keep;
        self
    }
    /// 设置进度回调
    pub fn with_progress_callback(mut self, callback: Arc<dyn Fn(u64, Option<u64>) + Send + Sync>) -> Self {
        self.progress_callback = Some(callback);
        self
    }
}

/// 流式加密器，将输入流数据加密并写入输出流
pub struct StreamingEncryptor<'a, C: CryptographicSystem, R: Read, W: Write> 
where
    Error: From<<C as CryptographicSystem>::Error>
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

impl<'a, C: CryptographicSystem, R: Read, W: Write> StreamingEncryptor<'a, C, R, W>
where
    Error: From<<C as CryptographicSystem>::Error>
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
pub struct StreamingDecryptor<'a, C: CryptographicSystem, R: Read, W: Write>
where
    Error: From<<C as CryptographicSystem>::Error>
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

impl<'a, C: CryptographicSystem, R: Read, W: Write> StreamingDecryptor<'a, C, R, W>
where
    Error: From<<C as CryptographicSystem>::Error>
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

impl<T> crate::traits::SyncStreamingSystem for T
where
    T: CryptographicSystem,
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
    C: CryptographicSystem,
    C::PublicKey: Sync + Send,
    <C as CryptographicSystem>::Error: Send + 'static,
    Error: From<<C as CryptographicSystem>::Error>,
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
    let cipher_results: Vec<Result<Vec<u8>, <C as CryptographicSystem>::Error>> =
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
    C: CryptographicSystem,
    C::PrivateKey: Sync + Send,
    <C as CryptographicSystem>::Error: Send + 'static,
    Error: From<<C as CryptographicSystem>::Error>,
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
    let plain_results: Vec<Result<Vec<u8>, <C as CryptographicSystem>::Error>> =
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
    use std::io::Cursor;
    use crate::primitives::{constant_time_eq, Base64String, CryptoConfig, from_base64};
    use crate::traits::CryptographicSystem;
    use std::sync::Mutex;
    #[cfg(feature = "post-quantum")]
    use crate::systems::post_quantum::KyberCryptoSystem;
    use crate::traits::SyncStreamingSystem;

    #[cfg(feature = "post-quantum")]
    #[test]
    fn test_streaming_encryption_decryption() {
        use crate::systems::post_quantum::KyberCryptoSystem;
        // 生成测试数据（100KB）
        let data_size = 100 * 1024;
        let mut test_data = Vec::with_capacity(data_size);
        for i in 0..data_size {
            test_data.push((i % 256) as u8);
        }
        
        // 生成密钥对 - 使用Kyber而非RSA-Kyber，因为Kyber支持任意大小的消息
        let config = CryptoConfig::default();
        let (public_key, private_key) = KyberCryptoSystem::generate_keypair(&config).unwrap();
        
        // 准备输入输出缓冲区
        let input = Cursor::new(test_data.clone());
        let mut encrypted = Vec::new();
        let stream_config = StreamingConfig {
            buffer_size: 1024, // 使用一个合理的缓冲区大小
            show_progress: false,
            keep_in_memory: true,
            progress_callback: None,
            total_bytes: None,
        };
        
        // 流式加密
        let encrypt_result = KyberCryptoSystem::encrypt_stream(
            &public_key,
            input,
            Cursor::new(&mut encrypted),
            &stream_config,
            None
        ).unwrap();
        let _encrypted_size = encrypt_result.bytes_processed;
        
        // 准备解密
        let mut decrypted = Vec::new();
        
        // 流式解密
        let decrypt_result = KyberCryptoSystem::decrypt_stream(
            &private_key,
            Cursor::new(&encrypted),
            Cursor::new(&mut decrypted),
            &stream_config,
            None
        ).unwrap();
        let decrypted_size = decrypt_result.bytes_processed;
        
        // 验证
        assert_eq!(decrypted_size, test_data.len() as u64);
        assert!(constant_time_eq(&decrypted, &test_data));
    }

    #[test]
    fn test_streaming_progress_and_buffer() {
        // 使用DummySystem测试进度回调和内存缓冲
        #[derive(Clone)]
        struct DummySystem;
        impl CryptographicSystem for DummySystem {
            type PublicKey = ();
            type PrivateKey = ();
            type CiphertextOutput = Base64String;
            type Error = Error;
            fn generate_keypair(_config: &CryptoConfig) -> Result<(Self::PublicKey, Self::PrivateKey), Self::Error> {
                Ok(((), ()))
            }
            fn encrypt(_pk: &Self::PublicKey, plaintext: &[u8], _aad: Option<&[u8]>) -> Result<Self::CiphertextOutput, Self::Error> {
                Ok(Base64String::from(plaintext.to_vec()))
            }
            fn decrypt(_sk: &Self::PrivateKey, ciphertext: &str, _aad: Option<&[u8]>) -> Result<Vec<u8>, Self::Error> {
                from_base64(ciphertext).map_err(Error::from)
            }
            fn export_public_key(_pk: &Self::PublicKey) -> Result<String, Self::Error> { Ok(String::new()) }
            fn export_private_key(_sk: &Self::PrivateKey) -> Result<String, Self::Error> { Ok(String::new()) }
            fn import_public_key(_data: &str) -> Result<Self::PublicKey, Self::Error> { Ok(()) }
            fn import_private_key(_data: &str) -> Result<Self::PrivateKey, Self::Error> { Ok(()) }
        }
        // 构造测试数据
        let data = (0u8..12u8).collect::<Vec<u8>>();
        let total = data.len() as u64;
        // 收集进度记录
        let records = std::sync::Arc::new(Mutex::new(Vec::new()));
        let callback_records = std::sync::Arc::clone(&records);
        let callback = std::sync::Arc::new(move |processed: u64, total_opt: Option<u64>| {
            callback_records.lock().unwrap().push((processed, total_opt));
        });
        let mut sc = StreamingConfig::default();
        sc.buffer_size = 5;
        sc.keep_in_memory = true;
        sc.progress_callback = Some(callback.clone());
        sc.total_bytes = Some(total);
        // 执行流式加密
        let (pk, _sk) = DummySystem::generate_keypair(&CryptoConfig::default()).unwrap();
        let res = DummySystem::encrypt_stream(&pk, Cursor::new(data.clone()), Cursor::new(Vec::new()), &sc, None).unwrap();
        assert_eq!(res.bytes_processed, total);
        // 验证回调
        let recs = records.lock().unwrap().clone();
        assert_eq!(recs, vec![(5, Some(total)), (10, Some(total)), (12, Some(total))]);
        // 验证缓冲区
        assert!(res.buffer.is_some());
    }

    #[cfg(all(feature = "parallel", feature = "post-quantum"))]
    #[test]
    fn test_streaming_parallel_matches_sequential() {
        use crate::systems::post_quantum::KyberCryptoSystem;
        // 验证并行与顺序流式加解密结果一致 (使用Kyber)
        let data = (0u8..100u8).collect::<Vec<u8>>();
        let config = CryptoConfig::default();
        let (public_key, private_key) = KyberCryptoSystem::generate_keypair(&config).unwrap();
        let mut seq_encrypted = Vec::new();
        let mut par_encrypted = Vec::new();
        let mut seq_decrypted = Vec::new();
        let mut par_decrypted = Vec::new();
        let stream_config = StreamingConfig::default().with_buffer_size(16).with_keep_in_memory(true);
        // 顺序流式加密并解密
        KyberCryptoSystem::encrypt_stream(
            &public_key,
            Cursor::new(&data),
            Cursor::new(&mut seq_encrypted),
            &stream_config,
            None
        ).unwrap();
        KyberCryptoSystem::decrypt_stream(
            &private_key,
            Cursor::new(&seq_encrypted),
            Cursor::new(&mut seq_decrypted),
            &stream_config,
            None
        ).unwrap();
        // 并行流式加密并解密
        encrypt_stream_parallel::<KyberCryptoSystem, _, _>(
            &public_key,
            Cursor::new(&data),
            Cursor::new(&mut par_encrypted),
            &stream_config,
            None
        ).unwrap();
        decrypt_stream_parallel::<KyberCryptoSystem, _, _>(
            &private_key,
            Cursor::new(&par_encrypted),
            Cursor::new(&mut par_decrypted),
            &stream_config,
            None
        ).unwrap();
        // 比较解密结果
        assert_eq!(par_decrypted, seq_decrypted);
        assert!(constant_time_eq(&par_decrypted, &data));
    }

    #[test]
    fn test_streaming_without_memory_buffer() {
        // 使用 DummySystem 测试 keep_in_memory = false 时 buffer = None
        #[derive(Clone)]
        struct DummySystem;
        impl CryptographicSystem for DummySystem {
            type PublicKey = ();
            type PrivateKey = ();
            type CiphertextOutput = Base64String;
            type Error = Error;
            fn generate_keypair(_config: &CryptoConfig) -> Result<(Self::PublicKey, Self::PrivateKey), Self::Error> {
                Ok(((), ()))
            }
            fn encrypt(_pk: &Self::PublicKey, plaintext: &[u8], _aad: Option<&[u8]>) -> Result<Self::CiphertextOutput, Self::Error> {
                Ok(Base64String::from(plaintext.to_vec()))
            }
            fn decrypt(_sk: &Self::PrivateKey, ciphertext: &str, _aad: Option<&[u8]>) -> Result<Vec<u8>, Self::Error> {
                from_base64(ciphertext).map_err(Error::from)
            }
            fn export_public_key(_pk: &Self::PublicKey) -> Result<String, Self::Error> { Ok(String::new()) }
            fn export_private_key(_sk: &Self::PrivateKey) -> Result<String, Self::Error> { Ok(String::new()) }
            fn import_public_key(_data: &str) -> Result<Self::PublicKey, Self::Error> { Ok(()) }
            fn import_private_key(_data: &str) -> Result<Self::PrivateKey, Self::Error> { Ok(()) }
        }
        let data = b"hello world".to_vec();
        let mut encrypted = Vec::new();
        let mut sc = StreamingConfig::default();
        sc.buffer_size = 4;
        sc.keep_in_memory = false;
        let (pk, _sk) = DummySystem::generate_keypair(&CryptoConfig::default()).unwrap();
        let enc_res = DummySystem::encrypt_stream(&pk, Cursor::new(&data), Cursor::new(&mut encrypted), &sc, None).unwrap();
        assert_eq!(enc_res.bytes_processed, data.len() as u64);
        assert!(enc_res.buffer.is_none());
        let mut decrypted = Vec::new();
        let dec_res = DummySystem::decrypt_stream(&_sk, Cursor::new(&encrypted), Cursor::new(&mut decrypted), &sc, None).unwrap();
        assert_eq!(dec_res.bytes_processed, data.len() as u64);
        assert!(dec_res.buffer.is_none());
        assert!(constant_time_eq(&decrypted, &data));
    }
} 