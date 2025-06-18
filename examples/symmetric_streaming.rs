//! 对称加密流式API使用示例
//!
//! 运行: `cargo run --example symmetric_streaming`

use std::io::Cursor;
use std::sync::Arc;
use tempfile::tempdir;

use seal_kit::asymmetric::primitives::streaming::StreamingConfig;
use seal_kit::primitives::CryptoConfig;
use seal_kit::rotation::RotationPolicy;
use seal_kit::storage::KeyFileStorage;
use seal_kit::symmetric::systems::aes_gcm::AesGcmSystem;
use seal_kit::SymmetricQSealEngine;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- 对称加密流式 API 示例 ---");

    // 1. 创建临时目录用于密钥存储
    let temp_dir = tempdir()?;
    let key_storage_path = temp_dir.path();
    println!("密钥将存储在临时目录: {:?}", key_storage_path);

    // 2. 初始化密钥存储和引擎
    let key_storage = Arc::new(KeyFileStorage::new(key_storage_path)?);
    let engine = SymmetricQSealEngine::<AesGcmSystem>::new(
        CryptoConfig::default(),
        RotationPolicy::default(),
        key_storage,
        "symmetric-stream-example",
    )?;

    // 3. 准备测试数据 (例如: 256KB 的数据)
    let data_size = 256 * 1024;
    let original_data: Vec<u8> = (0..data_size).map(|i| (i % 256) as u8).collect();
    println!("\n准备了 {} 字节的测试数据。", data_size);

    // 4. 配置流式处理
    let progress_records = Arc::new(std::sync::Mutex::new(0));
    let progress_callback_records = Arc::clone(&progress_records);
    let streaming_config = StreamingConfig::default()
        .with_buffer_size(16 * 1024) // 16KB 缓冲区
        .with_total_bytes(data_size as u64)
        .with_progress_callback(Arc::new(move |processed, total| {
            let mut num = progress_callback_records.lock().unwrap();
            *num += 1;
            let percentage = (processed as f64 / total.unwrap_or(1) as f64) * 100.0;
            print!("\r处理中... {:.2}% (回调触发 {} 次)", percentage, *num);
        }));

    // 5. 流式加密
    println!("\n--- 开始流式加密 ---");
    let input_stream = Cursor::new(original_data.clone());
    let mut encrypted_data = Vec::new();
    let encrypted_stream = Cursor::new(&mut encrypted_data);
    
    let encryption_result = engine.encrypt_stream(input_stream, encrypted_stream, &streaming_config)?;
    println!("\n加密完成。原始字节数: {}, 加密后总大小: {}", 
        encryption_result.bytes_processed, 
        encrypted_data.len()
    );

    // 6. 流式解密
    println!("\n--- 开始流式解密 ---");
    // 重置进度回调计数器
    *progress_records.lock().unwrap() = 0; 
    let encrypted_input_stream = Cursor::new(encrypted_data);
    let mut decrypted_data = Vec::new();
    let decrypted_stream = Cursor::new(&mut decrypted_data);

    let decryption_result = engine.decrypt_stream(encrypted_input_stream, decrypted_stream, &streaming_config)?;
    println!("\n解密完成。处理字节数: {}", decryption_result.bytes_processed);

    // 7. 验证结果
    println!("\n--- 验证结果 ---");
    assert_eq!(original_data, decrypted_data, "解密后的数据与原始数据不匹配！");
    println!("成功！解密后的数据与原始数据完全一致。");

    // 清理临时目录
    temp_dir.close()?;
    Ok(())
} 