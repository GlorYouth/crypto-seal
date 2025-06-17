# crypto-seal

[![Crates.io](https://img.shields.io/crates/v/crypto-seal.svg)](https://crates.io/crates/crypto-seal)  [![Docs.rs](https://docs.rs/crypto-seal/badge.svg)](https://docs.rs/crypto-seal)  ![License: MPL-2.0](https://img.shields.io/badge/license-MPL--2.0-brightgreen)

`crypto-seal` 是一个功能齐全且灵活的 Rust 加密库，提供：

- 传统加密（RSA）
- 后量子加密（Kyber）
- 混合加密（RSA + Kyber）
- 自动密钥管理与轮换
- 安全的密钥存储（基于 Argon2 & AES-GCM）
- 高级同步/异步引擎 API
- 流式加解密支持
- 配置灵活，支持 JSON 文件和环境变量

---

## 主要特性

- **统一接口**：通过 `CryptographicSystem` 特征，兼容多种加密系统。
- **自动敏感数据零化**：使用 `ZeroizingVec` 自动清除私钥等敏感数据在内存中的残留。
- **AEAD 算法多样化**：支持 AES-GCM 和 ChaCha20-Poly1305（启用 `chacha` 特性）。
- **批量并行加密**：异步引擎 `AsyncQSealEngine` 提供 `encrypt_batch` 接口，可在 `parallel` 特性下并行运行。
- **自动密钥轮换**：基于使用次数或有效期自动更新密钥。
- **安全存储**：`EncryptedKeyContainer` 与 `KeyFileStorage`，保护磁盘上的密钥。
- **高级同步 API**：`QSealEngine` 自动管理密钥、轮换、签名与验证。
- **异步并发 API**：`AsyncQSealEngine` 支持多线程安全调用。
- **混合加密**：`HybridRsaKyber` 提供双重安全保障。
- **认证加解密**：可选签名与签名验证，防止篡改。
- **流式处理**：分块加解密大数据，支持进度报告。
- **可定制配置**：通过 `ConfigManager` 加载 JSON 文件或环境变量。
- **特性标志**：`traditional`、`post-quantum`、`secure-storage`、`async-engine`、`chacha`、`parallel`。

---

## 安装

在 `Cargo.toml` 中添加依赖：

```toml
[dependencies]
crypto-seal = "0.1.0"

# 可选特性：
# crypto-seal = { version = "0.1.0", features = ["secure-storage", "async-engine"] }
```

---

## 示例

### 同步引擎 (`QSealEngine`)

- 本示例展示三种初始化方式：默认配置、JSON 配置文件、环境变量。

```rust
use std::sync::Arc;
use crypto_seal::{QSealEngine, HybridRsaKyber, ConfigManager};

fn main() -> anyhow::Result<()> {
    // 方法一：默认配置
    let mut engine_default = QSealEngine::<HybridRsaKyber>::with_defaults("user_keys")?;

    // 方法二：从 JSON 配置文件
    let mut engine_file = QSealEngine::<HybridRsaKyber>::from_file("config.json", "user_keys")?;

    // 方法三：从环境变量配置
    let config = Arc::new(ConfigManager::from_env());
    let mut engine_env = QSealEngine::<HybridRsaKyber>::new(config, "user_keys")?;

    let data = b"机密信息";
    let cipher = engine_default.encrypt(data)?;
    let plain = engine_default.decrypt(&cipher)?;
    assert_eq!(plain, data);

    Ok(())
}
```

### 异步引擎 (`AsyncQSealEngine`)

```rust
use std::sync::Arc;
use crypto_seal::{AsyncQSealEngine, ConfigManager, PostQuantumKyber};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Arc::new(ConfigManager::new());
    let engine = AsyncQSealEngine::<PostQuantumKyber>::new(config, "session_keys")?;

    let cipher = engine.encrypt(b"hello")?;
    let plain = engine.decrypt(&cipher)?;
    assert_eq!(plain, b"hello");

    Ok(())
}
```

### 底层接口 (`CryptographicSystem`)

```rust
use crypto_seal::{CryptographicSystem, CryptoConfig, TraditionalRsa};

fn main() {
    let config = CryptoConfig::default();
    let (pk, sk) = TraditionalRsa::generate_keypair(&config).unwrap();
    let cipher = TraditionalRsa::encrypt(&pk, b"data", None).unwrap();
    let plain = TraditionalRsa::decrypt(&sk, &cipher.to_string(), None).unwrap();
    assert_eq!(plain, b"data");
}
```

### 流式加解密

```rust
use std::fs::File;
use crypto_seal::crypto::common::streaming::{StreamingConfig, StreamingCryptoExt};
use crypto_seal::{TraditionalRsa, CryptoConfig};

fn main() -> anyhow::Result<()> {
    let config = CryptoConfig::default();
    let (pk, sk) = TraditionalRsa::generate_keypair(&config)?;

    // 流式加密
    let mut reader = File::open("plain.txt")?;
    let mut writer = File::create("cipher.dat")?;
    // 获取明文总大小，用于进度
    let total_size = reader.metadata()?.len();
    let mut sc = StreamingConfig::default();
    sc.total_bytes = Some(total_size);
    sc.keep_in_memory = false;
    sc.progress_callback = Some(std::sync::Arc::new(move |processed, total| {
        let total = total.unwrap_or(0);
        println!("Encrypted {}/{} bytes", processed, total);
    }));
    TraditionalRsa::encrypt_stream(&pk, reader, writer, &sc, None)?;

    // 流式解密
    let mut reader2 = File::open("cipher.dat")?;
    let mut writer2 = File::create("plain_out.txt")?;
    TraditionalRsa::decrypt_stream(&sk, reader2, writer2, &sc, None)?;

    Ok(())
}
```

### 安全密钥存储

```rust
use secrecy::SecretString;
use crypto_seal::EncryptedKeyContainer;

let password = SecretString::new("mypassword".to_string());
let data = b"secret_key";
let container = EncryptedKeyContainer::new(&password, data, "my-algo")?;
let recovered = container.get_key(&password)?;
assert_eq!(recovered, data);
```

---

## 特性标志（Features）

- `traditional`：启用传统 RSA（默认）
- `post-quantum`：启用 Kyber（默认）
- `secure-storage`：启用 `EncryptedKeyContainer`
- `async-engine`：启用 `AsyncQSealEngine`
- `chacha`：启用 ChaCha20-Poly1305 AEAD 支持（替代 AES-GCM）
- `parallel`：启用异步引擎的 `encrypt_batch` 并行批量加密

---

## 配置

### JSON 配置文件

创建 `config.json`，例如：

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
    "key_storage_dir": "./q_seal_keys",
    "use_metadata_cache": true,
    "secure_delete": true,
    "file_permissions": 384
  }
}
```

### 环境变量

您可以使用以下环境变量来覆盖配置：

- `Q_SEAL_USE_TRADITIONAL`（true/false）
- `Q_SEAL_USE_PQ`（true/false）
- `Q_SEAL_RSA_BITS`（整数）
- `Q_SEAL_KYBER_PARAMETER_K`（整数）
- `Q_SEAL_USE_AUTHENTICATED_ENCRYPTION`（true/false）
- `Q_SEAL_AUTO_VERIFY_SIGNATURES`（true/false）
- `Q_SEAL_KEY_VALIDITY_DAYS`（整数）
- `Q_SEAL_MAX_KEY_USES`（整数）
- `Q_SEAL_ROTATION_START_DAYS`（整数）
- `Q_SEAL_KEY_STORAGE_DIR`（字符串）
- `Q_SEAL_USE_METADATA_CACHE`（true/false）
- `Q_SEAL_SECURE_DELETE`（true/false）
- `Q_SEAL_FILE_PERMISSIONS`（整数）

---

## 性能基准测试（Benchmarks）
本库集成了基于 `criterion` 的性能基准测试，涵盖：

- 传统 RSA、后量子 Kyber、混合加密的单次加解密
- `QSealEngine` 的单次加解密操作

执行基准测试：
```
cargo bench
```

---

## 文档与支持

- 文档：https://docs.rs/crypto-seal
- 源码：https://github.com/GlorYouth/crypto-seal
- 许可证：MPL-2.0

---

## 贡献

欢迎提交 Issue 和 Pull Request！ 