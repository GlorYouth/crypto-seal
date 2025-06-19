# seal-kit: 现代统一的混合加密框架

[![crates.io](https://img.shields.io/crates/v/seal-kit.svg)](https://crates.io/crates/seal-kit)
[![docs.rs](https://docs.rs/seal-kit/badge.svg)](https://docs.rs/seal-kit)

`seal-kit` 是一个为 Rust 设计的现代化、健壮且可扩展的加密库，旨在为传统密码学 (RSA) 和后量子密码学 (Kyber) 提供无缝、统一的接口。它抽象了底层加密原语的复杂性，提供了一个简单的、有状态的引擎，可处理各种加密模式、自动密钥轮换和统一的密文格式。

对于需要前瞻性安全性的应用程序来说，该库是理想的选择，它在保持与既定标准兼容的同时，为向后量子密码学的迁移提供了简单的路径。

## 核心特性

- **统一的状态化引擎**: 单一的 `SealEngine` 处理所有加密操作，为提高效率而维护状态，并支持自动密钥轮换等功能。
- **混合加密**: 原生支持 **RSA-2048**、**Kyber-768** 以及用于双层安全保障的混合模式 **RSA+Kyber**。带有 RSA 签名的混合模式提供了强大的认证加密功能。
- **多种操作模式**:
    - **内存模式**: 简单地加密/解密字节切片。
    - **流式模式**: 高效处理大文件和数据流，无高内存消耗。
    - **并行流式模式**: 利用多 CPU 核心实现高吞吐量的流加密。
    - **并行内存模式**: 使用数据并行实现高吞吐量的内存加密。
- **自动密钥轮换**: 引擎根据使用情况或时间自动管理加密密钥的生命周期，透明地确保密码学的卫生。
- **类型安全的算法选择**: 使用枚举 (`SymmetricAlgorithm`, `AsymmetricAlgorithm`) 而非字符串来指定加密算法，防止因拼写错误导致的运行时错误。
- **统一的密文格式**: 所有加密模式和算法都产生单一、可互操作的密文格式 (`[头部长度][序列化头部][加密负载]`)，确保用一种模式加密的数据可以用另一种模式解密。

## 架构概览

该库采用清晰、模块化的架构设计：

- `Seal`: 主入口点。它管理一个安全的保险库（Vault），其中包含主种子、密钥元数据和配置。它充当创建 `SealEngine` 实例的工厂。
- `SealEngine`: 执行实际加密和解密的有状态引擎。它针对特定的 `SealMode`（对称或混合）进行实例化，并持有必要的密钥管理状态。
- `KeyManager`: 统一的管理器，负责对称和非对称密钥的整个生命周期，包括生成、派生、轮换和检索。
- `Asymmetric` & `Symmetric` Systems: 可插拔的加密算法实现。`seal-kit` 使用非对称系统作为密钥封装机制 (KEM) 来加密数据加密密钥 (DEK)，然后由对称系统（如 AES-GCM）使用该 DEK 进行实际的数据加密。

## 快速上手

下面是一个简单的示例，演示如何创建保险库、获取引擎并执行内存中的加密和解密。

首先，将 `seal-kit` 添加到你的 `Cargo.toml` 中：
```toml
[dependencies]
seal-kit = { version = "0.1.0", features = ["traditional", "post-quantum"] }
# 你还需要一个像 `secrecy` 这样的密码管理库
secrecy = { version = "0.8", features = ["serde"] }
```

现在，你可以在代码中使用它：

```rust
use seal_kit::{Seal, common::header::SealMode, common::traits::AsymmetricAlgorithm};
use secrecy::SecretString;
use std::sync::Arc;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let vault_path = "my_secure_vault.seal";
    let password = SecretString::new("my-super-secret-password".to_string());

    // 1. 创建一个新的 Seal 保险库。
    // 这将生成一个主种子并安全地存储它。
    let seal = Seal::create(vault_path, &password)?;

    // 你也可以用以下方式打开一个现有的保险库：
    // let seal = Seal::open(vault_path, &password)?;

    // 2. 使用特定算法为混合模式创建一个密钥。
    // 密钥管理器将在首次使用时自动处理密钥创建。
    seal.config().set_primary_asymmetric_algorithm(AsymmetricAlgorithm::RsaKyber768)?;

    // 3. 获取一个用于混合加密的状态化引擎。
    let mut engine = seal.engine(SealMode::Hybrid, &password)?;

    // 4. 加密一些数据。
    let plaintext = b"This is a highly confidential message.";
    let ciphertext = engine.seal_bytes(plaintext)?;

    println!("明文: {:?}", plaintext);
    println!("密文: {:?}", ciphertext);

    // 5. 解密数据。
    // 注意 `unseal_bytes` 可以在一个不可变的引擎引用上调用。
    let decrypted_text = engine.unseal_bytes(&ciphertext)?;

    assert_eq!(plaintext, decrypted_text.as_slice());
    println!("成功解密!");

    // 清理保险库文件
    fs::remove_file(vault_path)?;

    Ok(())
}
```

## 使用示例

### 针对大文件的流式加密

`seal-kit` 通过流式处理数据来出色地处理大文件，这使得内存使用量保持在较低且恒定的水平。

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
let source_data = "这是一段非常大的数据，应该以流的方式处理。".repeat(1000);
let mut source_reader = Cursor::new(source_data.as_bytes());
let mut encrypted_writer = Vec::new();

// 加密流
engine.seal_stream(&mut source_reader, &mut encrypted_writer)?;

println!("加密流大小: {} 字节", encrypted_writer.len());

let mut encrypted_reader = Cursor::new(encrypted_writer);
let mut decrypted_writer = Vec::new();

// 解密流
engine.unseal_stream(&mut encrypted_reader, &mut decrypted_writer)?;

assert_eq!(source_data.as_bytes(), decrypted_writer.as_slice());
println!("流成功解密!");
#
#     fs::remove_file(vault_path)?;
#     Ok(())
# }
# run().unwrap();
```

## Crate 特性

`seal-kit` 使用特性标志来保持编译后的库体积小巧，并与你的需求相关。

- `traditional`: 启用 **RSA-2048** 支持。
- `post-quantum`: 启用 **Kyber-768** 支持。

要使用混合算法 `RsaKyber768`，必须同时启用这两个特性。

## 贡献

欢迎贡献！如果你发现 bug 或有功能请求，请在我们的 GitHub 仓库中开启一个 issue。

---

_这份 README 是根据现代化、重构后的 `seal-kit` 架构生成的。_ 