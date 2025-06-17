use std::io::Cursor;
use crypto_seal::TraditionalRsa;
use crypto_seal::crypto::common::{CryptoConfig, streaming::{StreamingConfig, StreamingCryptoExt}};
use crypto_seal::CryptographicSystem;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 准备用于加解密的数据
    let data = (0u8..100).collect::<Vec<u8>>();

    // 生成 RSA 密钥对
    let config = CryptoConfig::default();
    let (pub_key, priv_key) = TraditionalRsa::generate_keypair(&config)?;

    // 构建流式配置
    let sc = StreamingConfig::default()
        .with_buffer_size(16)
        .with_keep_in_memory(true)
        .with_show_progress(false)
        .with_total_bytes(data.len() as u64);

    // 流式加密到内存
    let mut encrypted_buf = Vec::new();
    let encrypt_result = TraditionalRsa::encrypt_stream(
        &pub_key,
        Cursor::new(&data),
        Cursor::new(&mut encrypted_buf),
        &sc,
        None,
    )?;
    println!("Encrypted {} bytes", encrypt_result.bytes_processed);

    // 流式解密到内存
    let mut decrypted_buf = Vec::new();
    let decrypt_result = TraditionalRsa::decrypt_stream(
        &priv_key,
        Cursor::new(&encrypted_buf),
        Cursor::new(&mut decrypted_buf),
        &sc,
        None,
    )?;
    println!("Decrypted {} bytes", decrypt_result.bytes_processed);

    // 验证数据一致性
    assert_eq!(decrypted_buf, data);
    println!("Streaming example success");
    Ok(())
} 