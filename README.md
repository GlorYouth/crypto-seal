# Q-Seal Core: 核心加密库

`q-seal-core` 是一个功能强大且灵活的Rust加密库，旨在提供一个统一的框架来处理传统加密（RSA）、后量子加密（Kyber）以及两者的混合模式。本库通过高级API简化了复杂的密钥管理和加密流程，同时也为需要精细控制的开发者保留了底层API。

## 主要特性

- **统一的加密接口**: 通过 `CryptographicSystem` 特征（trait），为所有加密算法（RSA, Kyber, 混合加密）提供了一致的调用接口。
- **高级API (`QSealEngine`)**: 封装了密钥管理、自动密钥轮换、加解密等复杂操作，提供极其简洁的API，是推荐的入门方式。
- **自动密钥管理**: 内置密钥轮换管理器 (`KeyRotationManager`)，可根据配置的策略（如时间、使用次数）自动生成和轮换密钥。
- **灵活的配置**: 支持通过JSON文件或环境变量进行中心化配置，可轻松调整加密参数、密钥存储位置和轮换策略。
- **混合加密安全**: 提供了RSA和Kyber的混合加密方案 (`RsaKyberCryptoSystem`)，确保即使其中一种算法被破解，数据依然安全。
- **认证加密**: 支持对密文进行签名和验证，确保数据的完整性和来源可信。
- **安全的密钥存储**: 提供了基于密码的密钥加密容器 (`EncryptedKeyContainer`)，使用Argon2和AES-GCM保护存储在磁盘上的密钥。

## 核心概念

1.  **`QSealEngine` (高级引擎)**
    这是与库交互的推荐入口。它处理了所有复杂性，包括：
    -   根据配置自动初始化密钥存储。
    -   管理一个或多个密钥集（通过 `key_prefix` 区分）。
    -   在加密时自动执行密钥轮换。
    -   在解密时自动尝试所有可用密钥。

2.  **`CryptographicSystem` (底层接口)**
    这是一个特征（trait），定义了所有加密系统的通用行为（密钥生成、加解密、导入/导出）。如果你需要绕过 `QSealEngine` 进行更底层的操作，可以直接使用它。

3.  **`ConfigManager` (配置管理器)**
    这是所有配置的中心。它从 `config.json` 或环境变量加载配置，并将其提供给库的其他部分。

## 安装

将以下内容添加到您的 `Cargo.toml` 文件中：

```toml
[dependencies]
q-seal-core = { path = "path/to/q-seal/core" } # 或使用crates.io版本
```

## 使用方法

### 推荐方式：使用 `QSealEngine`

这是最简单、最安全的使用方式。

**1. 准备配置文件 `config.json` (可选)**

您可以创建一个 `config.json` 文件来定制化所有行为。如果省略，将使用默认配置。

```json
{
  "crypto": {
    "use_traditional": true,
    "use_post_quantum": true,
    "rsa_key_bits": 3072,
    "kyber_parameter_k": 768,
    "use_authenticated_encryption": true,
    "auto_verify_signatures": true,
    "default_signature_algorithm": "RSA-PSS-SHA256",
    "argon2_memory_cost": 19456,
    "argon2_time_cost": 2
  },
  "rotation": {
    "enabled": true,
    "validity_period_days": 90,
    "max_usage_count": 1000000
  },
  "storage": {
    "key_storage_dir": "./q_seal_keys",
    "use_metadata_cache": true,
    "secure_delete": true,
    "file_permissions": 384
  }
}
```

**2. 初始化引擎并进行加解密**

```rust
use q_seal_core::{QSealEngine, RsaKyberCryptoSystem}; // 使用混合加密系统

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 方法一：从配置文件创建引擎
    // let engine = QSealEngine::<RsaKyberCryptoSystem>::from_file("config.json", "user_auth_keys")?;

    // 方法二：使用默认配置创建引擎
    // 这将在 "./q_seal_keys" 目录下自动创建和管理密钥
    let engine = QSealEngine::<RsaKyberCryptoSystem>::with_defaults("user_auth_keys")?;

    let plaintext = b"这是一条需要被安全加密的绝密信息！";

    // 加密
    // 引擎会自动处理密钥生成、轮换和使用计数
    let ciphertext = engine.encrypt(plaintext)?;
    println!("加密后的密文: {}", ciphertext);

    // 解密
    // 引擎会自动尝试所有可用密钥（主密钥、次要密钥）
    let decrypted = engine.decrypt(&ciphertext)?;
    println!("解密后的明文: {:?}", String::from_utf8_lossy(&decrypted));
    
    assert_eq!(plaintext.as_ref(), decrypted.as_slice());
    
    Ok(())
}
```
*   `key_prefix` ("user_auth_keys") 用于创建独立的密钥集。您可以为不同的业务场景（如用户认证、文档加密）使用不同的前缀。

### 进阶方式：直接使用 `CryptographicSystem`

如果您需要对密钥对进行更精细的控制，可以不通过 `QSealEngine`，直接使用 `CryptographicSystem`。

```rust
use q_seal_core::{
    CryptographicSystem, 
    RsaKyberCryptoSystem, // 混合加密系统
    ConfigManager,
    CryptoConfig,
};
use std::sync::Arc;

fn main() {
    // 1. 创建配置
    let config = CryptoConfig::default();

    // 2. 生成密钥对
    let (public_key, private_key) = RsaKyberCryptoSystem::generate_keypair(&config).unwrap();
    
    // 3. 加密
    let plaintext = b"底层API测试";
    let ciphertext = RsaKyberCryptoSystem::encrypt(&public_key, plaintext, None).unwrap();

    // 4. 解密
    let decrypted = RsaKyberCryptoSystem::decrypt(&private_key, &ciphertext.to_string(), None).unwrap();

    assert_eq!(decrypted, plaintext);
    println!("底层API加解密成功！");
}
```

## 可用的加密系统

-   `q_seal_core::TraditionalRsa` (别名): `RsaCryptoSystem`
-   `q_seal_core::PostQuantumKyber` (别名): `KyberCryptoSystem`
-   `q_seal_core::HybridRsaKyber` (别名): `RsaKyberCryptoSystem` (推荐)
-   `q_seal_core::AuthenticatedRsaKyber` (别名): 提供带签名的认证加密版本

## 贡献

欢迎提交问题、功能请求和合并请求（Pull Requests）。
