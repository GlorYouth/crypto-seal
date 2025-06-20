# seal-kit: 现代统一的混合加密框架

[![crates.io](https://img.shields.io/crates/v/seal-kit.svg)](https://crates.io/crates/seal-kit)
[![docs.rs](https://docs.rs/seal-kit/badge.svg)](https://docs.rs/seal-kit)

`seal-kit` 是一个为 Rust 设计的现代化、健壮且可扩展的加密库，旨在为传统密码学 (RSA) 和后量子密码学 (Kyber) 提供无缝、统一的接口。它抽象了底层加密原语的复杂性，提供了一个简单的、有状态的引擎，可处理各种加密模式、自动密钥轮换和统一的密文格式。

对于需要前瞻性安全性的应用程序来说，该库是理想的选择，它在保持与既定标准兼容的同时，为向后量子密码学的迁移提供了简单的路径。

## 核心特性

- **双存储模式**:
  - **加密保险库 (默认)**: 一个由密码保护的安全容器，用于存放密钥和配置，通过 `secure-storage` 特性启用。
  - **明文保险库**: 一个人类可读的 JSON 文件，适用于存储介质本身已加密，或在无需密码管理的工具化场景。
- **统一的状态化引擎**: 单一的 `SealEngine` 处理所有加密操作，为提高效率而维护状态，并支持自动密钥轮换等功能。
- **混合加密**: 原生支持 **RSA-2048**、**Kyber-768** 以及用于双层安全保障的混合模式 **RSA+Kyber**。带有 RSA 签名的混合模式提供了强大的认证加密功能。
- **多种操作模式**:
    - **内存模式**: 简单地加密/解密字节切片。
    - **流式模式**: 高效处理大文件和数据流，无高内存消耗。
    - **并行流式模式**: 利用多 CPU 核心实现高吞吐量的流加密。
- **自动密钥轮换**: 引擎根据使用情况或时间自动管理加密密钥的生命周期，透明地确保密码学的卫生。
- **统一的密文格式**: 所有加密模式和算法都产生单一、可互操作的密文格式，确保用一种模式加密的数据可以用另一种模式解密。

## 架构概览

- `Seal`: 主入口点。它管理一个包含主种子、密钥元数据和配置的保险库。它充当创建 `SealEngine` 实例的工厂，并同时支持加密和明文两种存储后端。
- `SealEngine`: 执行实际加密和解密的有状态引擎。
- `KeyManager`: 统一的管理器，负责密钥的整个生命周期。
- `VaultPersistence`: 一个抽象了存储层的 Trait，允许 `Seal` 与不同的后端协同工作。`EncryptedVaultStore` 和 `PlaintextVaultStore` 是库提供的两个具体实现。

## 快速上手：加密保险库

这是大多数应用场景下的推荐模式，它为你的密钥和配置提供基于密码的静态加密保护。

首先，将 `seal-kit` 添加到你的 `Cargo.toml` 中：
```toml
[dependencies]
# `secure-storage` 特性是默认启用的
seal-kit = { version = "0.1.0", features = ["traditional", "post-quantum"] }
secrecy = { version = "0.8", features = ["serde"] }
```

现在，你可以在代码中使用它：

```rust
use seal_kit::{Seal, common::header::SealMode, common::traits::AsymmetricAlgorithm};
use secrecy::SecretString;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let vault_path = "my_secure_vault.seal";
    let password = SecretString::new("my-super-secret-password".to_string());

    // 1. 创建一个新的、加密的 Seal 保险库。
    let seal = Seal::create_encrypted(vault_path, &password)?;
    
    // 你也可以用以下方式打开一个现有的加密保险库：
    // let seal = Seal::open_encrypted(vault_path, &password)?;

    // 2. 轮换到期望的主算法。
    // 这会生成第一对密钥并将其设为活动状态。
    seal.rotate_asymmetric_key(AsymmetricAlgorithm::RsaKyber768, &password)?;

    // 3. 获取一个用于混合加密的状态化引擎。
    let mut engine = seal.engine(SealMode::Hybrid, &password)?;

    // 4. 加密一些数据。
    let plaintext = b"This is a highly confidential message.";
    let ciphertext = engine.seal_bytes(plaintext, None)?;

    println!("密文长度: {}", ciphertext.len());

    // 5. 解密数据。
    let decrypted_text = engine.unseal_bytes(&ciphertext, None)?;

    assert_eq!(plaintext, decrypted_text.as_slice());
    println!("成功解密!");

    // 清理保险库文件
    fs::remove_file(vault_path)?;

    Ok(())
}
```

## 明文保险库模式

对于保险库文件存储在已加密文件系统上，或用于无需密码保护的本地工具等场景，你可以使用明文模式。

如果你*只*需要明文模式，可以在 `Cargo.toml` 中禁用默认特性（这将减小编译后二进制文件的大小）：
```toml
[dependencies]
seal-kit = { version = "0.1.0", default-features = false, features = ["traditional", "post-quantum"] }
# 即使存储时不用，引擎操作仍然需要 `secrecy`
secrecy = "0.8"
```

保险库文件将以人类可读的 JSON 格式存储。

```rust
use seal_kit::{Seal, common::header::SealMode, common::traits::AsymmetricAlgorithm};
use secrecy::SecretString;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let vault_path = "plaintext_vault.json";
    
    // 1. 创建一个明文保险库，存储时无需密码。
    let seal = Seal::create_plaintext(vault_path)?;

    // 保险库内容是可读的 JSON
    let content = fs::read_to_string(vault_path)?;
    println!("明文保险库内容开头: {}", &content[..50]);

    // 2. 密钥管理和引擎操作仍然以相同方式工作。
    // 引擎的内部操作仍需要密码，即使它不用于静态存储加密。
    let dummy_password = SecretString::new("a-password-for-the-engine".to_string());
    seal.rotate_asymmetric_key(AsymmetricAlgorithm::Rsa2048, &dummy_password)?;
    
    let mut engine = seal.engine(SealMode::Hybrid, &dummy_password)?;
    
    let plaintext = b"由明文保险库中的密钥保护的数据。";
    let ciphertext = engine.seal_bytes(plaintext, None)?;
    let decrypted = engine.unseal_bytes(&ciphertext, None)?;

    assert_eq!(plaintext, decrypted.as_slice());
    println!("使用明文保险库的加解密成功!");

    fs::remove_file("plaintext_vault.json")?;
    Ok(())
}
```


## Crate 特性

`seal-kit` 使用特性标志来保持编译后的库体积小巧，并与你的需求相关。

- `secure-storage` (默认启用): 启用由密码加密的保险库存储。如果禁用，则只有明文保险库可用。
- `traditional`: 启用 **RSA-2048** 支持。
- `post-quantum`: 启用 **Kyber-768** 支持。

要使用混合算法 `RsaKyber768`，必须同时启用 `traditional` 和 `post-quantum` 特性。

## 贡献

欢迎贡献！如果你发现 bug 或有功能请求，请在我们的 GitHub 仓库中开启一个 issue。

---

_这份 README 是根据现代化、重构后的 `seal-kit` 架构生成的。_ 