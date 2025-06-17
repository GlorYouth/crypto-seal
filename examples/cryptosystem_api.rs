use crypto_seal::TraditionalRsa;
use crypto_seal::crypto::common::CryptoConfig;
use crypto_seal::CryptographicSystem;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 使用底层 CryptographicSystem 特性
    let config = CryptoConfig::default();
    let (pub_key, priv_key) = TraditionalRsa::generate_keypair(&config)?;
    let plaintext = "底层 API 示例".as_bytes();

    // 加密
    let ciphertext = TraditionalRsa::encrypt(&pub_key, plaintext, None)?;
    println!("Ciphertext (Base64): {}", ciphertext.to_string());

    // 解密
    let decrypted = TraditionalRsa::decrypt(&priv_key, &ciphertext.to_string(), None)?;
    println!("Decrypted: {}", String::from_utf8(decrypted)?);

    Ok(())
} 