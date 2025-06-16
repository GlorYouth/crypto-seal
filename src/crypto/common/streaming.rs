use std::io::{Read, Write};
use std::marker::PhantomData;
use crate::crypto::traits::CryptographicSystem;
use crate::crypto::errors::Error;
use crate::crypto::systems::post_quantum::kyber::KyberCryptoSystem;

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
}

impl Default for StreamingConfig {
    fn default() -> Self {
        Self {
            buffer_size: DEFAULT_BUFFER_SIZE,
            show_progress: false,
            keep_in_memory: false,
        }
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
    _phantom: PhantomData<C>,
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
            total_bytes: None,
            _phantom: PhantomData,
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
    pub fn process(mut self) -> Result<u64, Error> {
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
                
            // 更新统计
            self.bytes_processed += read_bytes as u64;
            encrypted_size += read_bytes as u64;
            
            // 可以在这里添加进度显示
            if let Some(total) = self.total_bytes {
                let progress = (self.bytes_processed * 100) / total;
                // 可以基于show_progress配置决定是否输出
            }
        }
        
        // 完成时刷新输出流
        self.writer.flush().map_err(Error::Io)?;
        
        Ok(encrypted_size)
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
    _phantom: PhantomData<C>,
}

impl<'a, C: CryptographicSystem, R: Read, W: Write> StreamingDecryptor<'a, C, R, W>
where
    Error: From<<C as CryptographicSystem>::Error>
{
    /// 创建新的流式解密器
    pub fn new(reader: R, writer: W, private_key: &'a C::PrivateKey, _config: &StreamingConfig) -> Self {
        Self {
            reader,
            writer,
            private_key,
            additional_data: None,
            bytes_processed: 0,
            total_bytes: None,
            _phantom: PhantomData,
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
    pub fn process(mut self) -> Result<u64, Error> {
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
                
            // 更新统计
            self.bytes_processed += plaintext.len() as u64;
            decrypted_size += plaintext.len() as u64;
            
            // 可以在这里添加进度显示
            if let Some(total) = self.total_bytes {
                let progress = (self.bytes_processed * 100) / total;
                // 可以基于show_progress配置决定是否输出
            }
        }
        
        // 完成时刷新输出流
        self.writer.flush().map_err(Error::Io)?;
        
        Ok(decrypted_size)
    }
}

/// 流式处理扩展特征，为加密系统添加流式处理能力
pub trait StreamingCryptoExt: CryptographicSystem
where
    Error: From<<Self as CryptographicSystem>::Error>
{
    /// 流式加密方法
    /// 
    /// # 参数
    /// 
    /// * `reader` - 读取明文的输入流
    /// * `writer` - 写入密文的输出流
    /// * `public_key` - 加密公钥
    /// * `config` - 流式处理配置
    /// * `additional_data` - 可选的附加认证数据
    fn encrypt_stream<R: Read, W: Write>(
        public_key: &Self::PublicKey, 
        reader: R, 
        writer: W, 
        config: &StreamingConfig,
        additional_data: Option<&[u8]>
    ) -> Result<u64, Error> {
        let mut encryptor = StreamingEncryptor::<Self, R, W>::new(reader, writer, public_key, config);
        
        if let Some(data) = additional_data {
            encryptor = encryptor.with_additional_data(data);
        }
        
        encryptor.process()
    }
    
    /// 流式解密方法
    /// 
    /// # 参数
    /// 
    /// * `reader` - 读取密文的输入流
    /// * `writer` - 写入明文的输出流
    /// * `private_key` - 解密私钥
    /// * `config` - 流式处理配置
    /// * `additional_data` - 可选的附加认证数据
    fn decrypt_stream<R: Read, W: Write>(
        private_key: &Self::PrivateKey, 
        reader: R, 
        writer: W, 
        config: &StreamingConfig,
        additional_data: Option<&[u8]>
    ) -> Result<u64, Error> {
        let mut decryptor = StreamingDecryptor::<Self, R, W>::new(reader, writer, private_key, config);
        
        if let Some(data) = additional_data {
            decryptor = decryptor.with_additional_data(data);
        }
        
        decryptor.process()
    }
}

// 自动为所有实现CryptographicSystem的类型实现流式处理扩展
impl<T: CryptographicSystem> StreamingCryptoExt for T 
where
    Error: From<<T as CryptographicSystem>::Error>
{}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use crate::crypto::common::constant_time_eq;
    use crate::crypto::common;

    #[test]
    fn test_streaming_encryption_decryption() {
        // 生成测试数据（100KB）
        let data_size = 100 * 1024;
        let mut test_data = Vec::with_capacity(data_size);
        for i in 0..data_size {
            test_data.push((i % 256) as u8);
        }
        
        // 生成密钥对 - 使用Kyber而非RSA-Kyber，因为Kyber支持任意大小的消息
        let config = common::CryptoConfig::default();
        let (public_key, private_key) = KyberCryptoSystem::generate_keypair(&config).unwrap();
        
        // 准备输入输出缓冲区
        let input = Cursor::new(test_data.clone());
        let mut encrypted = Vec::new();
        let stream_config = StreamingConfig {
            buffer_size: 1024, // 使用一个合理的缓冲区大小
            show_progress: false,
            keep_in_memory: true,
        };
        
        // 流式加密
        let _encrypted_size = KyberCryptoSystem::encrypt_stream(
            &public_key,
            input,
            Cursor::new(&mut encrypted),
            &stream_config,
            None
        ).unwrap();
        
        // 准备解密
        let mut decrypted = Vec::new();
        
        // 流式解密
        let decrypted_size = KyberCryptoSystem::decrypt_stream(
            &private_key,
            Cursor::new(&encrypted),
            Cursor::new(&mut decrypted),
            &stream_config,
            None
        ).unwrap();
        
        // 验证
        assert_eq!(decrypted_size, test_data.len() as u64);
        assert!(constant_time_eq(&decrypted, &test_data));
    }
} 