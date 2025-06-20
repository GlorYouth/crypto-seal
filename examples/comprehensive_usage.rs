use seal_kit::{
    Seal,
    common::{header::SealMode, traits::AsymmetricAlgorithm},
};
use secrecy::SecretString;
use std::fs;
use std::io::Cursor;

/// A helper function to demonstrate in-memory encryption and decryption.
/// It handles vault creation, configuration, encryption, decryption, and cleanup.
/// 一个用于演示内存加解密的辅助函数。
/// 它负责处理保险库的创建、配置、加密、解密和清理工作。
fn run_in_memory_encryption_example(
    vault_path: &str,
    password_str: &str,
    algorithm: AsymmetricAlgorithm,
    plaintext: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let password = SecretString::new(password_str.to_string().into_boxed_str());

    // --- VAULT CREATION / 创建保险库 ---
    // Seal::create returns an Arc<Seal>.
    // Seal::create 返回一个 Arc<Seal>。
    let seal = Seal::create(vault_path, &password)?;
    println!(
        "[Vault: {}] Successfully created vault. / 成功创建保险库。",
        vault_path
    );

    // --- CONFIGURATION & KEY ROTATION / 配置与密钥轮换 ---
    // The correct way to set the primary algorithm is to rotate to it.
    // This updates the config and generates the first key pair.
    // 设置主算法的正确方法是"轮换"到该算法。
    // 这会更新配置并生成第一对密钥。
    println!(
        "[Vault: {}] Rotating to primary algorithm: {:?}. / 正在轮换到主算法: {:?}。",
        vault_path, algorithm, algorithm
    );
    seal.rotate_asymmetric_key(algorithm, &password)?;

    // --- ENGINE CREATION / 创建引擎 ---
    // The engine method is called on the Arc<Seal>.
    // engine 方法在 Arc<Seal> 上调用。
    let mut engine = seal.engine(SealMode::Hybrid, &password)?;

    // --- IN-MEMORY ENCRYPTION / 内存加密 ---
    // All seal/unseal methods take an optional `aad` (Additional Associated Data) argument. We pass `None`.
    // 所有 seal/unseal 方法都接受一个可选的 `aad` (关联附加数据) 参数。我们传入 `None`。
    println!(
        "[Vault: {}] Encrypting data in-memory... / 正在进行内存加密...",
        vault_path
    );
    let ciphertext = engine.seal_bytes(plaintext, None)?;
    println!(
        "[Vault: {}] Original data length: {}. / 原始数据长度: {}。",
        vault_path,
        plaintext.len(),
        plaintext.len()
    );
    println!(
        "[Vault: {}] Encrypted data length: {}. / 加密后数据长度: {}。",
        vault_path,
        ciphertext.len(),
        ciphertext.len()
    );

    // --- IN-MEMORY DECRYPTION / 内存解密 ---
    println!(
        "[Vault: {}] Decrypting data in-memory... / 正在进行内存解密...",
        vault_path
    );
    // The engine can be borrowed immutably for decryption.
    // 解密时可以非可变地借用引擎。
    let decrypted_text = engine.unseal_bytes(&ciphertext, None)?;

    // --- VERIFICATION / 验证 ---
    assert_eq!(plaintext, decrypted_text.as_slice());
    println!(
        "[Vault: {}] Success! Decrypted data matches original. / 成功！解密后的数据与原始数据匹配。",
        vault_path
    );

    // --- CLEANUP / 清理 ---
    fs::remove_file(vault_path)?;
    println!(
        "[Vault: {}] Cleaned up vault file. / 已清理保险库文件。",
        vault_path
    );

    Ok(())
}

/// A helper function to demonstrate stream-based encryption and decryption.
/// This is ideal for large files as it keeps memory usage low and constant.
/// 一个用于演示流式加解密的辅助函数。
/// 这是处理大文件的理想方式，因为它能保持内存使用量稳定且低下。
fn run_streaming_encryption_example() -> Result<(), Box<dyn std::error::Error>> {
    let vault_path = "streaming_vault.seal";
    let password = SecretString::new(
        "a-different-streaming-password"
            .to_string()
            .into_boxed_str(),
    );

    // --- VAULT CREATION & CONFIGURATION / 创建并配置保险库 ---
    let seal = Seal::create(vault_path, &password)?;
    // We'll use Rsa2048 for this streaming example.
    // 在这个流式示例中，我们将使用 Rsa2048 算法。
    seal.rotate_asymmetric_key(AsymmetricAlgorithm::Rsa2048, &password)?;
    let mut engine = seal.engine(SealMode::Hybrid, &password)?;
    println!("\n--- Starting Stream Encryption Example (RSA-2048) ---");
    println!("--- 开始流式加密示例 (RSA-2048) ---");

    // --- STREAM ENCRYPTION / 流式加密 ---
    let source_data =
        "This is a large dataset that we want to process as a stream to keep memory usage low."
            .repeat(5000);
    let mut source_reader = Cursor::new(source_data.as_bytes());
    let mut encrypted_writer = Vec::new();

    println!("Encrypting stream... / 正在加密流...");
    engine.seal_stream(&mut source_reader, &mut encrypted_writer, None)?;
    println!(
        "Stream encryption complete. Encrypted size: {} bytes. / 流加密完成。加密后大小: {} 字节。",
        encrypted_writer.len(),
        encrypted_writer.len()
    );

    // --- STREAM DECRYPTION / 流式解密 ---
    let mut encrypted_reader = Cursor::new(encrypted_writer);
    let mut decrypted_writer = Vec::new();

    println!("Decrypting stream... / 正在解密流...");
    engine.unseal_stream(&mut encrypted_reader, &mut decrypted_writer, None)?;
    println!("Stream decryption complete. / 流解密完成。");

    // --- VERIFICATION / 验证 ---
    assert_eq!(source_data.as_bytes(), decrypted_writer.as_slice());
    println!("Success! Decrypted stream matches original source. / 成功！解密后的流与原始源匹配。");

    // --- CLEANUP / 清理 ---
    fs::remove_file(vault_path)?;
    println!("Cleaned up streaming vault file. / 已清理流式加密的保险库文件。");

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // --- EXAMPLE 1: HYBRID (RSA + KYBER) ENCRYPTION ---
    // --- 示例 1: 混合 (RSA + KYBER) 加密 ---
    println!("--- Starting Hybrid Encryption Example (RSA+Kyber) ---");
    println!("--- 开始混合加密示例 (RSA+Kyber) ---");
    run_in_memory_encryption_example(
        "hybrid_vault.seal",
        "my-hybrid-password-123",
        AsymmetricAlgorithm::RsaKyber768,
        b"This message is protected by both RSA and Kyber for dual-layer security.",
    )?;
    println!("--------------------------------------------------\n");

    // --- EXAMPLE 2: POST-QUANTUM (KYBER) ENCRYPTION ---
    // --- 示例 2: 后量子 (KYBER) 加密 ---
    println!("--- Starting Post-Quantum Encryption Example (Kyber) ---");
    println!("--- 开始后量子加密示例 (Kyber) ---");
    run_in_memory_encryption_example(
        "kyber_vault.seal",
        "my-kyber-password-456",
        AsymmetricAlgorithm::Kyber768,
        b"This is a quantum-resistant message, secured with Kyber.",
    )?;
    println!("--------------------------------------------------\n");

    // --- EXAMPLE 3: TRADITIONAL (RSA) ENCRYPTION ---
    // --- 示例 3: 传统 (RSA) 加密 ---
    println!("--- Starting Traditional Encryption Example (RSA) ---");
    println!("--- 开始传统加密示例 (RSA) ---");
    run_in_memory_encryption_example(
        "rsa_vault.seal",
        "my-rsa-password-789",
        AsymmetricAlgorithm::Rsa2048,
        b"A classic, traditionally encrypted message using RSA.",
    )?;
    println!("--------------------------------------------------\n");

    // --- EXAMPLE 4: STREAMING ENCRYPTION ---
    // --- 示例 4: 流式加密 ---
    run_streaming_encryption_example()?;
    println!("--------------------------------------------------\n");

    println!("All examples completed successfully! / 所有示例均已成功完成！");

    Ok(())
}
