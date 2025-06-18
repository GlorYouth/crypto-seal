#![cfg(all(feature = "traditional", feature = "post-quantum"))]
use seal_kit::{AsymmetricQSealEngine, HybridRsaKyber};
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 在使用 JSON 存储前删除旧目录，确保干净
    let _ = fs::remove_dir_all("keys");
    // 使用默认配置（混合 RSA+Kyber）
    let mut engine = AsymmetricQSealEngine::<HybridRsaKyber>::with_defaults("example_keys")?;
    let data = b"Hello, Seal-Kit!";

    // 加密
    let cipher = engine.encrypt(data)?;
    println!("Ciphertext: {}", cipher);

    // 解密
    let plaintext = engine.decrypt(&cipher)?;
    println!("Decrypted: {}", String::from_utf8(plaintext)?);

    // 清理生成的密钥目录
    let _ = fs::remove_dir_all("keys");

    Ok(())
} 