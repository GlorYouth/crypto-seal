# seal-kit: Modern & Unified Hybrid Cryptography Framework

[中文版本 (Chinese Version)](./README_CN.md)

[![crates.io](https://img.shields.io/crates/v/seal-kit.svg)](https://crates.io/crates/seal-kit)
[![docs.rs](https://docs.rs/seal-kit/badge.svg)](https://docs.rs/seal-kit)

`seal-kit` is a modern, robust, and extensible cryptographic library for Rust, designed to provide a seamless and unified interface for both traditional (RSA) and post-quantum (Kyber) cryptography. It abstracts away the complexities of underlying cryptographic primitives, offering a simple, stateful engine that handles various encryption modes, automated key rotation, and a unified ciphertext format.

This library is ideal for applications requiring forward-thinking security, providing an easy migration path to post-quantum cryptography while maintaining compatibility with established standards.

## Core Features

- **Unified Stateful Engine**: A single `SealEngine` handles all cryptographic operations, maintaining state for efficiency and enabling features like automated key rotation.
- **Hybrid Cryptography**: Natively supports **RSA-2048**, **Kyber-768**, and a hybrid **RSA+Kyber** mode for dual-layer security. The hybrid mode with RSA signatures provides robust authenticated encryption.
- **Multiple Operation Modes**:
    - **In-Memory**: Simple encryption/decryption of byte slices.
    - **Streaming**: Efficiently handle large files and data streams without high memory consumption.
    - **Parallel Streaming**: High-throughput stream encryption leveraging multiple CPU cores.
    - **Parallel In-Memory**: High-throughput in-memory encryption using data parallelism.
- **Automated Key Rotation**: The engine automatically manages the lifecycle of encryption keys based on usage or time, transparently ensuring cryptographic hygiene.
- **Type-Safe Algorithm Selection**: Utilizes enums (`SymmetricAlgorithm`, `AsymmetricAlgorithm`) instead of strings to specify cryptographic algorithms, preventing runtime errors from typos.
- **Unified Ciphertext Format**: All encryption modes and algorithms produce a single, interoperable ciphertext format (`[Header Length][Serialized Header][Encrypted Payload]`), ensuring that data encrypted with one mode can be decrypted with another.

## Architecture Overview

The library is designed with a clean, modular architecture:

- `Seal`: The main entry point. It manages a secure vault which contains the master seed, key metadata, and configuration. It acts as a factory for creating `SealEngine` instances.
- `SealEngine`: A stateful engine that performs the actual encryption and decryption. It is instantiated for a specific `SealMode` (Symmetric or Hybrid) and holds the necessary key management state.
- `KeyManager`: A unified manager responsible for the entire lifecycle of both symmetric and asymmetric keys, including generation, derivation, rotation, and retrieval.
- `Asymmetric` & `Symmetric` Systems: Pluggable cryptographic algorithm implementations. `seal-kit` uses the asymmetric systems as Key Encapsulation Mechanisms (KEMs) to encrypt a Data Encryption Key (DEK), which is then used by a symmetric system (e.g., AES-GCM) for the actual data encryption.

## Quick Start

Here's a simple example of how to create a vault, get an engine, and perform in-memory encryption and decryption.

First, add `seal-kit` to your `Cargo.toml`:
```toml
[dependencies]
seal-kit = { version = "0.1.0", features = ["traditional", "post-quantum"] }
# You'll also need a password management library like `secrecy`
secrecy = { version = "0.8", features = ["serde"] }
```

Now, you can use it in your code:

```rust
use seal_kit::{Seal, common::header::SealMode, common::traits::AsymmetricAlgorithm};
use secrecy::SecretString;
use std::sync::Arc;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let vault_path = "my_secure_vault.seal";
    let password = SecretString::new("my-super-secret-password".to_string());

    // 1. Create a new Seal vault.
    // This will generate a master seed and store it securely.
    let seal = Seal::create(vault_path, &password)?;

    // You can also open an existing vault with:
    // let seal = Seal::open(vault_path, &password)?;

    // 2. Create a key for the hybrid mode using a specific algorithm.
    // The key manager will automatically handle key creation on first use.
    seal.config().set_primary_asymmetric_algorithm(AsymmetricAlgorithm::RsaKyber768)?;

    // 3. Get a stateful engine for hybrid encryption.
    let mut engine = seal.engine(SealMode::Hybrid, &password)?;

    // 4. Encrypt some data.
    let plaintext = b"This is a highly confidential message.";
    let ciphertext = engine.seal_bytes(plaintext)?;

    println!("Plaintext: {:?}", plaintext);
    println!("Ciphertext: {:?}", ciphertext);

    // 5. Decrypt the data.
    // Note that `unseal_bytes` can be called on an immutable engine reference.
    let decrypted_text = engine.unseal_bytes(&ciphertext)?;

    assert_eq!(plaintext, decrypted_text.as_slice());
    println!("Successfully decrypted!");

    // Clean up the vault file
    fs::remove_file(vault_path)?;

    Ok(())
}
```

## Usage Examples

### Streaming Encryption for Large Files

`seal-kit` excels at handling large files by streaming data, which keeps memory usage low and constant.

```rust
# use seal_kit::{Seal, common::header::SealMode, common::traits::AsymmetricAlgorithm};
# use secrecy::SecretString;
# use std::sync::Arc;
# use std::fs::{self, File};
# use std::io::{Cursor, Read, Write};
#
# fn run() -> Result<(), Box<dyn std::error::Error>> {
#     let vault_path = "my_secure_vault.seal";
#     let password = SecretString::new("my-super-secret-password".to_string());
#     let seal = Seal::create(vault_path, &password)?;
#     seal.config().set_primary_asymmetric_algorithm(AsymmetricAlgorithm::Rsa2048)?;
#     let mut engine = seal.engine(SealMode::Hybrid, &password)?;
#
let source_data = "This is a very large amount of data that should be streamed.".repeat(1000);
let mut source_reader = Cursor::new(source_data.as_bytes());
let mut encrypted_writer = Vec::new();

// Encrypt a stream
engine.seal_stream(&mut source_reader, &mut encrypted_writer)?;

println!("Encrypted stream size: {} bytes", encrypted_writer.len());

let mut encrypted_reader = Cursor::new(encrypted_writer);
let mut decrypted_writer = Vec::new();

// Decrypt a stream
engine.unseal_stream(&mut encrypted_reader, &mut decrypted_writer)?;

assert_eq!(source_data.as_bytes(), decrypted_writer.as_slice());
println!("Stream decrypted successfully!");
#
#     fs::remove_file(vault_path)?;
#     Ok(())
# }
# run().unwrap();
```

## Crate Features

`seal-kit` uses feature flags to keep the compiled library small and relevant to your needs.

- `traditional`: Enables **RSA-2048** support.
- `post-quantum`: Enables **Kyber-768** support.

To use the hybrid `RsaKyber768` algorithm, both features must be enabled.

## Contributing

Contributions are welcome! If you find a bug or have a feature request, please open an issue on our GitHub repository.

---

_This README was generated based on the modernized, refactored `seal-kit` architecture._ 