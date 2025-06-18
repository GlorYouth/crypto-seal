# seal-kit

[![Crates.io](https://img.shields.io/crates/v/seal-kit.svg)](https://crates.io/crates/seal-kit)  [![Docs.rs](https://docs.rs/seal-kit/badge.svg)](https://docs.rs/seal-kit)  ![License: MPL-2.0](https://img.shields.io/badge/license-MPL--2.0-brightgreen)

`seal-kit` 是一个功能齐全且灵活的 Rust 加密库，提供统一的框架来处理非对称和对称加密。

- **非对称加密**:
  - 传统加密 (RSA)
  - 后量子加密 (Kyber)
  - 混合加密 (RSA + Kyber)
- **对称加密**:
  - AES-256-GCM
  - ChaCha20-Poly1305 (通过 `chacha` 特性)
- **核心功能**:
  - 自动密钥管理与轮换
  - 安全的密钥存储 (基于 Argon2 & AES-GCM)
  - 统一的同步/异步引擎 API
  - 高效的流式加解密
  - 灵活的配置 (JSON 文件或环境变量)

---

## 主要特性

- **统一接口**: 通过 `AsymmetricCryptographicSystem` 和 `SymmetricCryptographicSystem` 特征，支持多种加密系统。
- **高级引擎**:
  - `AsymmetricQSealEngine`: 用于非对称加密，自动处理密钥对管理、轮换、签名和验证。
  - `SymmetricQSealEngine`: 用于对称加密，简化密钥管理和数据保护。
  - 异步版本 (`AsymmetricQSealEngineAsync` / `SymmetricQSealEngineAsync`) 支持高并发场景。
- **混合加密**: `HybridRsaKyber` 结合了 RSA 和 Kyber 的优点，提供双重安全保障。
- **流式处理**: 支持对大文件或数据流进行分块加解密，内存占用低，并可报告进度。
- **安全密钥存储**: 使用 `EncryptedKeyContainer` 和 `KeyFileStorage`，通过强密码派生函数 Argon2 和 AES-GCM 加密来保护磁盘上的密钥。
- **自动密钥轮换**: 可根据使用次数或时间有效期自动轮换密钥，提高安全性。
- **内存安全**: 使用 `secrecy` 和 `zeroize` crate 在敏感数据（如私钥）离开作用域时自动从内存中清除。
- **高度可配置**: 通过 `ConfigManager` 从 JSON 文件或环境变量加载配置。
- **模块化特性**: 通过 Cargo features 可以按需启用功能，减小最终二进制文件大小。

---

## 安装

在 `Cargo.toml` 中添加依赖：

```toml
[dependencies]
seal-kit = { version = "0.1.0", features = ["asymmetric", "symmetric", "secure-storage", "async-engine"] }
```

默认情况下，`asymmetric` 和 `symmetric` 都被启用。您可以根据需要选择特性。

---

## 示例

### 非对称加密引擎 (`AsymmetricQSealEngine`)

本示例展示了如何使用 `AsymmetricQSealEngine` 进行混合加密。

```rust
use std::sync::Arc;
use seal_kit::{AsymmetricQSealEngine, HybridRsaKyber, ConfigManager};

fn main() -> anyhow::Result<()> {
    // 使用默认配置初始化引擎
    let config = Arc::new(ConfigManager::new());
    let mut engine = AsymmetricQSealEngine::<HybridRsaKyber>::new(config, "my_asymmetric_keys")?;

    let data = b"这是一条需要非对称加密的机密信息";
    
    // 加密
    let cipher = engine.encrypt(data)?;
    println!("加密后的数据: {}", cipher);
    
    // 解密
    let plain = engine.decrypt(&cipher)?;
    println!("解密后的数据: {}", String::from_utf8_lossy(&plain));

    assert_eq!(plain, data);

    Ok(())
}
```

### 对称加密引擎 (`SymmetricQSealEngine`)

本示例展示了如何使用 `SymmetricQSealEngine` 和 `AesGcmSystem` 进行流式加密。

```rust
use std::io::Cursor;
use std::sync::Arc;
use seal_kit::{SymmetricQSealEngine, ConfigManager};
use seal_kit::common::streaming::StreamingConfig;
use seal_kit::symmetric::systems::aes_gcm::AesGcmSystem;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 准备数据
    let data = b"这是一长段需要通过对称加密流式处理的数据...".repeat(100);

    // 1. 初始化引擎
    let config = Arc::new(ConfigManager::new());
    let mut engine = SymmetricQSealEngine::<AesGcmSystem>::new(config, "my_symmetric_keys")?;

    // 2. 配置流式处理
    let sc = StreamingConfig::default()
        .with_buffer_size(1024) // 1KB 缓冲区
        .with_show_progress(true);

    // 3. 流式加密到内存
    let mut encrypted_buf = Vec::new();
    engine.encrypt_stream(Cursor::new(&data), &mut encrypted_buf, &sc)?;
    println!("\n加密完成!");

    // 4. 流式解密
    let mut decrypted_buf = Vec::new();
    engine.decrypt_stream(Cursor::new(&encrypted_buf), &mut decrypted_buf, &sc)?;
    println!("\n解密完成!");

    // 5. 验证数据
    assert_eq!(decrypted_buf, data);
    println!("\n数据验证成功！");
    
    Ok(())
}
```

### 底层接口 (`AsymmetricCryptographicSystem`)

直接使用加密系统接口，绕过引擎层。

```rust
use seal_kit::{AsymmetricCryptographicSystem, TraditionalRsa, common::utils::CryptoConfig};

fn main() {
    let config = CryptoConfig::default();
    let (pk, sk) = TraditionalRsa::generate_keypair(&config).unwrap();
    let cipher = TraditionalRsa::encrypt(&pk, b"raw data", None).unwrap();
    let plain = TraditionalRsa::decrypt(&sk, &cipher.to_string(), None).unwrap();
    assert_eq!(plain, b"raw data");
}
```

---

## 特性标志 (Features)

`seal-kit` 被设计为模块化的，您可以通过特性标志来选择需要的功能。

### 默认特性

`default = ["asymmetric", "symmetric", "secure-storage", "async-engine", "parallel"]`

### 功能类别

- **`asymmetric`**: 启用所有非对称加密功能。
  - **`traditional`**: 启用 RSA 加密 (`RsaCryptoSystem`)。
  - **`post-quantum`**: 启用 Kyber 加密 (`KyberCryptoSystem`)。

- **`symmetric`**: 启用所有对称加密功能。
  - **`aes-gcm-feature`**: 启用 AES-256-GCM (`AesGcmSystem`)。
  - **`chacha`**: 启用 ChaCha20-Poly1305。

- **`secure-storage`**: 启用安全的密钥磁盘存储功能 (`EncryptedKeyContainer`)。
- **`async-engine`**: 启用所有异步 API (`...Async`)。
- **`parallel`**: 在异步引擎中启用批量操作的并行处理。

---

## 配置

### JSON 配置文件

`seal-kit` 的行为可以通过 `config.json` 文件进行配置。对称加密目前不需要特定配置。

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
    "validity_period_days": 90,
    "max_usage_count": 1000000,
    "rotation_start_days": 7
  },
  "storage": {
    "key_storage_dir": "./seal_keys",
    "use_metadata_cache": true,
    "secure_delete": true,
    "file_permissions": 384
  }
}
```

### 环境变量

您可以使用环境变量来覆盖 JSON 配置。

- `Q_SEAL_USE_TRADITIONAL` (true/false)
- `Q_SEAL_USE_PQ` (true/false)
- `Q_SEAL_RSA_BITS` (整数)
- `Q_SEAL_KEYBER_PARAMETER_K` (整数)
- ...等等。

---

## 性能基准测试 (Benchmarks)

本库集成了基于 `criterion` 的性能基准测试。

执行基准测试：
```sh
cargo bench
```

---

## 文档与支持

- 文档：https://docs.rs/seal-kit
- 源码：https://github.com/GlorYouth/seal-kit
- 许可证：MPL-2.0

---

## 贡献

欢迎提交 Issue 和 Pull Request！ 