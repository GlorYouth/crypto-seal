//! 对称加密流式API使用示例
//!
//! 运行: `cargo run --example symmetric_streaming`

use std::io::Cursor;
use std::sync::Arc;
use seal_kit::{SymmetricQSealEngine, ConfigManager};
use seal_kit::common::streaming::StreamingConfig;
use seal_kit::symmetric::systems::aes_gcm::AesGcmSystem;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 准备用于加解密的数据
    let data = (0u8..100).collect::<Vec<u8>>();

    // 1. 使用默认配置初始化同步引擎
    // QSealEngine 会自动处理密钥的生成、加载和轮换
    let config = Arc::new(ConfigManager::new());
    let mut engine = SymmetricQSealEngine::<AesGcmSystem>::new(config, "symmetric_streaming_example_keys")?;

    // 2. 构建流式配置
    let sc = StreamingConfig::default()
        .with_buffer_size(16)
        .with_keep_in_memory(true) // 在内存中保留结果以便验证
        .with_show_progress(true)
        .with_total_bytes(data.len() as u64);

    // 3. 流式加密到内存缓冲区
    let mut encrypted_buf = Vec::new();
    let encrypt_result = engine.encrypt_stream(
        Cursor::new(&data),
        &mut encrypted_buf, // 直接写入 Vec
        &sc,
    )?;
    println!("\nEncryption complete. Processed {} original bytes.", encrypt_result.bytes_processed);

    // 4. 流式解密回内存缓冲区
    let mut decrypted_buf = Vec::new();
    let decrypt_result = engine.decrypt_stream(
        Cursor::new(&encrypted_buf),
        &mut decrypted_buf,
        &sc,
    )?;
    println!("\nDecryption complete. Processed {} encrypted bytes.", decrypt_result.bytes_processed);

    // 5. 验证数据一致性
    assert_eq!(decrypted_buf, data);
    println!("\nSymmetric streaming example success: Original data and decrypted data match.");
    
    Ok(())
} 