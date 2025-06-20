//! An executable example demonstrating the comprehensive usage of the `seal-kit` library.
//!
//! This example covers:
//! 1. Creating and using an ENCRYPTED vault (`Seal::create_encrypted`).
//! 2. Creating and using a PLAINTEXT vault (`Seal::create_plaintext`).
//! 3. Key rotation for different asymmetric algorithms.
//! 4. In-memory encryption and decryption (`seal_bytes`/`unseal_bytes`).
//! 5. Stream-based encryption for large data (`seal_stream`/`unseal_stream`).
//! 6. The concept of Additional Associated Data (AAD) is mentioned but not used for simplicity.
//!
//! To run this example: `cargo run --example comprehensive_usage --all-features`

use seal_kit::{
    common::{header::SealMode, traits::AsymmetricAlgorithm},
    Seal,
};
use secrecy::SecretString;
use std::fs;
use std::io::Cursor;

/// Demonstrates creating an encrypted vault and performing in-memory operations.
/// This function showcases the standard, secure way of using `seal-kit`, where the vault
/// itself is protected by a user-provided password.
///
/// 中文: 演示如何创建加密保险库并执行内存中的操作。
/// 此函数展示了使用 `seal-kit` 的标准、安全方式，其中保险库本身受用户提供的密码保护。
fn demonstrate_encrypted_mode(
    vault_path: &str,
    password_str: &str,
    algorithm: AsymmetricAlgorithm,
    plaintext: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let password = SecretString::new(password_str.to_string().into_boxed_str());

    // --- VAULT CREATION (ENCRYPTED) ---
    // Use `create_encrypted` for a password-protected vault. This encrypts the entire vault file
    // using a key derived from the provided password.
    // 中文: 使用 `create_encrypted` 创建一个密码保护的保险库。这会使用从所提供密码派生的密钥
    // 来加密整个保险库文件。
    let seal = Seal::create_encrypted(vault_path, &password)?;
    println!(
        "[Encrypted Vault: {}] Successfully created vault.",
        vault_path
    );

    // --- KEY ROTATION ---
    // Before encrypting, we must have an active key. `rotate_asymmetric_key` generates a new
    // key pair for the given algorithm, sets it as the primary key, and saves the changes to the vault.
    // A password is required to unlock the vault before committing changes.
    // 中文: 在加密之前，我们必须有一个活动密钥。`rotate_asymmetric_key` 为给定算法生成一个新的
    // 密钥对，将其设置为主密钥，并将更改保存到保险库。
    // 在提交更改之前，需要密码来解锁保险库。
    println!(
        "[Encrypted Vault: {}] Rotating to primary algorithm: {:?}",
        vault_path, algorithm
    );
    seal.rotate_asymmetric_key(algorithm, &password)?;

    // --- ENGINE CREATION ---
    // The `SealEngine` is the stateful workhorse for encryption and decryption.
    // It is initialized for a specific mode (e.g., `Hybrid`) and requires the password to access
    // key material from the vault.
    // 中文: `SealEngine` 是用于加密和解密的状态化主力。
    // 它针对特定模式（例如 `Hybrid`）进行初始化，并需要密码才能从保险库访问密钥材料。
    let mut engine = seal.engine(SealMode::Hybrid, &password)?;

    // --- IN-MEMORY ENCRYPTION ---
    // `seal_bytes` performs "in-memory" encryption. It's suitable for smaller chunks of data.
    // The second argument is for Additional Associated Data (AAD), which is not used here.
    // 中文: `seal_bytes` 执行"内存中"加密。它适用于较小的数据块。
    // 第二个参数是附加关联数据（AAD），此处未使用。
    println!(
        "[Encrypted Vault: {}] Encrypting data in-memory...",
        vault_path
    );
    let ciphertext = engine.seal_bytes(plaintext, None)?;
    println!(
        "[Encrypted Vault: {}] Original data length: {}.",
        vault_path,
        plaintext.len()
    );
    println!(
        "[Encrypted Vault: {}] Encrypted data length: {}.",
        vault_path,
        ciphertext.len()
    );

    // --- IN-MEMORY DECRYPTION ---
    // `unseal_bytes` decrypts the data. It automatically reads the header from the ciphertext
    // to determine which key and algorithm were used.
    // 中文: `unseal_bytes` 解密数据。它会自动从密文中读取头部，以确定使用了哪个密钥和算法。
    println!(
        "[Encrypted Vault: {}] Decrypting data in-memory...",
        vault_path
    );
    let decrypted_text = engine.unseal_bytes(&ciphertext, None)?;

    // --- VERIFICATION ---
    // Always verify that the decrypted data matches the original plaintext.
    // 中文: 务必验证解密后的数据与原始明文是否匹配。
    assert_eq!(plaintext, decrypted_text.as_slice());
    println!(
        "[Encrypted Vault: {}] Success! Decrypted data matches original.",
        vault_path
    );

    // --- CLEANUP ---
    fs::remove_file(vault_path)?;
    println!(
        "[Encrypted Vault: {}] Cleaned up vault file.",
        vault_path
    );

    Ok(())
}

/// Demonstrates stream-based encryption with an encrypted vault.
/// This is the most memory-efficient way to handle large files or network streams,
/// as data is processed in chunks rather than being loaded entirely into memory.
///
/// 中文: 演示如何使用加密保险库进行流式加密。
/// 这是处理大文件或网络流的最高效内存方式，因为数据是分块处理的，
/// 而不是完全加载到内存中。
fn demonstrate_streaming_with_encrypted_vault() -> Result<(), Box<dyn std::error::Error>> {
    let vault_path = "streaming_vault.seal";
    let password = SecretString::new(
        "a-different-streaming-password"
            .to_string()
            .into_boxed_str(),
    );

    // --- VAULT CREATION & CONFIGURATION (ENCRYPTED) ---
    // Setup is the same as the in-memory example: create a vault and rotate a key.
    // 中文: 设置与内存示例相同：创建一个保险库并轮换一个密钥。
    let seal = Seal::create_encrypted(vault_path, &password)?;
    seal.rotate_asymmetric_key(AsymmetricAlgorithm::Rsa2048, &password)?;
    let mut engine = seal.engine(SealMode::Hybrid, &password)?;
    println!("\n--- Starting Stream Encryption Example (Encrypted Vault) ---");

    // --- STREAM ENCRYPTION ---
    // We use `Read` and `Write` traits to perform streaming encryption.
    // `seal_stream` reads from the source, encrypts chunk by chunk, and writes to the destination.
    // 中文: 我们使用 `Read` 和 `Write` trait 来执行流式加密。
    // `seal_stream` 从源读取，逐块加密，然后写入目的地。
    let source_data =
        "This is a large dataset that we want to process as a stream to keep memory usage low."
            .repeat(5000);
    let mut source_reader = Cursor::new(source_data.as_bytes());
    let mut encrypted_writer = Vec::new();

    println!("Encrypting stream...");
    engine.seal_stream(&mut source_reader, &mut encrypted_writer, None)?;
    println!(
        "Stream encryption complete. Encrypted size: {} bytes.",
        encrypted_writer.len()
    );

    // --- STREAM DECRYPTION ---
    // Decryption works similarly. `unseal_stream` reads the encrypted source, decrypts, and writes.
    // It handles the header transparently.
    // 中文: 解密工作方式类似。`unseal_stream` 读取加密的源，解密并写入。
    // 它透明地处理头部信息。
    let mut encrypted_reader = Cursor::new(encrypted_writer);
    let mut decrypted_writer = Vec::new();

    println!("Decrypting stream...");
    engine.unseal_stream(&mut encrypted_reader, &mut decrypted_writer, None)?;
    println!("Stream decryption complete.");

    // --- VERIFICATION ---
    assert_eq!(source_data.as_bytes(), decrypted_writer.as_slice());
    println!("Success! Decrypted stream matches original source.");

    // --- CLEANUP ---
    fs::remove_file(vault_path)?;
    println!("Cleaned up streaming vault file.");

    Ok(())
}

/// Demonstrates creating and using a PLAINTEXT vault.
/// This mode is useful for scenarios where the storage medium is already secure (e.g., an encrypted disk),
/// or for local tools where password management is not required. The vault is a human-readable JSON file.
///
/// 中文: 演示如何创建和使用明文保险库。
/// 此模式适用于存储介质已安全（例如加密磁盘）或不需要密码管理的本地工具等场景。
/// 保险库是一个人类可读的 JSON 文件。
fn demonstrate_plaintext_mode() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n--- Starting Plaintext Mode Example ---");
    let vault_path = "plaintext_vault.json";
    // This password is required for engine operations but is NOT used to encrypt the vault file itself.
    // For example, it's used to decrypt private keys stored inside the vault payload.
    // 中文: 引擎操作需要此密码，但它不用于加密保险库文件本身。
    // 例如，它被用来解密存储在保险库载荷内部的私钥。
    let dummy_password = SecretString::new("this-password-is-for-engine-only".to_string().into_boxed_str());

    // --- VAULT CREATION (PLAINTEXT) ---
    // Use `create_plaintext`. No password is required for creation, as the file is stored unencrypted.
    // 中文: 使用 `create_plaintext`。创建时不需要密码，因为文件以未加密方式存储。
    let seal = Seal::create_plaintext(vault_path)?;
    println!("[Plaintext Vault] Successfully created plaintext vault.");

    // --- CHECK FILE CONTENT ---
    // We can inspect the vault file; it's just JSON.
    // NOTE: While the vault is plaintext, the asymmetric private keys within it are still encrypted.
    // 中文: 我们可以检查保险库文件；它只是一个 JSON。
    // 注意：虽然保险库是明文的，但其中的非对称私钥仍然是加密的。
    let content = fs::read_to_string(vault_path)?;
    println!("[Plaintext Vault] Vault file content is readable JSON: {}...", &content[..80]);
    assert!(serde_json::from_str::<serde_json::Value>(&content).is_ok());

    // --- KEY ROTATION & USAGE ---
    // Key management still works the same way. A password is required for the *engine's* internal
    // cryptographic operations, even if the vault itself isn't encrypted at rest.
    // For example, decrypting the private key from its container inside the vault payload.
    // 中文: 密钥管理仍然以相同方式工作。即使保险库本身不是静态加密的，引擎的内部
    // 加密操作仍需要密码。例如，从保险库载荷内的容器中解密私钥。
    seal.rotate_asymmetric_key(AsymmetricAlgorithm::Kyber768, &dummy_password)?;
    let mut engine = seal.engine(SealMode::Hybrid, &dummy_password)?;
    
    let plaintext = b"Data protected by a plaintext vault's keys.";
    let ciphertext = engine.seal_bytes(plaintext, None)?;
    let decrypted = engine.unseal_bytes(&ciphertext, None)?;

    assert_eq!(plaintext, decrypted.as_slice());
    println!("[Plaintext Vault] Encryption/Decryption roundtrip successful.");

    // --- RE-OPENING A PLAINTEXT VAULT ---
    // Opening a plaintext vault is also simple and requires no password.
    // 中文: 打开一个明文保险库同样简单，且无需密码。
    let reopened_seal = Seal::open_plaintext(vault_path)?;
    println!("[Plaintext Vault] Successfully re-opened plaintext vault.");
    // We still need the same password to initialize an engine that can work with the keys.
    // 中文: 我们仍然需要相同的密码来初始化可以处理密钥的引擎。
    let mut reopened_engine = reopened_seal.engine(SealMode::Hybrid, &dummy_password)?;
    let decrypted_again = reopened_engine.unseal_bytes(&ciphertext, None)?;
    assert_eq!(plaintext, decrypted_again.as_slice());
    println!("[Plaintext Vault] Decryption successful with re-opened vault.");

    // --- CLEANUP ---
    fs::remove_file(vault_path)?;
    println!("[Plaintext Vault] Cleaned up vault file.");
    
    Ok(())
}


fn main() -> Result<(), Box<dyn std::error::Error>> {
    // This main function orchestrates the different demonstration scenarios.
    // 中文: 这个 main 函数协调了不同的演示场景。

    // --- EXAMPLE 1: HYBRID (RSA + KYBER) ENCRYPTION ---
    // Demonstrates the dual-layer security mode.
    // 中文: 演示双层安全模式。
    println!("--- Starting Encrypted Mode Example (RSA+Kyber) ---");
    demonstrate_encrypted_mode(
        "hybrid_vault.seal",
        "my-hybrid-password-123",
        AsymmetricAlgorithm::RsaKyber768,
        b"This message is protected by both RSA and Kyber for dual-layer security.",
    )?;
    println!("--------------------------------------------------\n");

    // --- EXAMPLE 2: POST-QUANTUM (KYBER) ENCRYPTION ---
    // Demonstrates pure post-quantum encryption.
    // 中文: 演示纯粹的后量子加密。
    println!("--- Starting Encrypted Mode Example (Kyber) ---");
    demonstrate_encrypted_mode(
        "kyber_vault.seal",
        "my-kyber-password-456",
        AsymmetricAlgorithm::Kyber768,
        b"This is a quantum-resistant message, secured with Kyber.",
    )?;
    println!("--------------------------------------------------\n");

    // --- EXAMPLE 3: STREAMING ENCRYPTION (with an encrypted vault) ---
    // Shows how to handle large data efficiently.
    // 中文: 展示如何高效处理大数据。
    demonstrate_streaming_with_encrypted_vault()?;
    println!("--------------------------------------------------\n");

    // --- EXAMPLE 4: PLAINTEXT MODE ---
    // Shows the alternative storage mode for specific use cases.
    // 中文: 展示用于特定用例的备用存储模式。
    demonstrate_plaintext_mode()?;
    println!("--------------------------------------------------\n");

    println!("All examples completed successfully!");

    Ok(())
}
