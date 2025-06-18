//! 对称加密流式API使用示例
//!
//! 运行: `cargo run --example symmetric_streaming --features="aes-gcm-feature"`

use seal_kit::Seal;
use seal_kit::common::streaming::StreamingConfig;
use seal_kit::symmetric::systems::aes_gcm::AesGcmSystem;
use secrecy::SecretString;
use std::io::Cursor;
use tempfile::tempdir;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 准备用于加解密的数据
    let data = (0u8..100).collect::<Vec<u8>>();

    // 1. 使用 Seal API 初始化引擎
    let dir = tempdir()?;
    let seal_path = dir.path().join("symmetric_streaming.seal");
    let password = SecretString::new("symmetric-streaming-password".to_string().into_boxed_str());
    let seal = Seal::create(&seal_path, &password)?;
    let mut engine = seal.symmetric_sync_engine::<AesGcmSystem>(password)?;

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
    println!(
        "\nEncryption complete. Processed {} original bytes.",
        encrypt_result.bytes_processed
    );

    // 4. 流式解密回内存缓冲区
    let mut decrypted_buf = Vec::new();
    let decrypt_result =
        engine.decrypt_stream(Cursor::new(&encrypted_buf), &mut decrypted_buf, &sc)?;
    println!(
        "\nDecryption complete. Processed {} encrypted bytes.",
        decrypt_result.bytes_processed
    );

    // 5. 验证数据一致性
    assert_eq!(decrypted_buf, data);
    println!("\nSymmetric streaming example success: Original data and decrypted data match.");

    Ok(())
}
