// Async engine 示例

#[cfg(not(feature = "async-engine"))]
fn main() {
    println!("示例需要启用 async-engine 特性:");
    println!("cargo run --example async_engine --features async-engine");
}

#[cfg(feature = "async-engine")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::{sync::Arc, fs};
    use crypto_seal::{ConfigManager, AsyncQSealEngine, HybridRsaKyber};

    // 初始化配置
    let config = Arc::new(ConfigManager::new());
    // 创建并发引擎，使用混合加密 HybridRsaKyber
    let engine = AsyncQSealEngine::<HybridRsaKyber>::new(config, "async_example")?;

    let data = b"Hello, Async QSeal!";
    // 执行加解密
    let cipher = engine.encrypt(data)?;
    let plain = engine.decrypt(&cipher)?;
    println!("解密: {}", String::from_utf8_lossy(&plain));

    // 清理生成的密钥目录
    let _ = fs::remove_dir_all("./keys");

    Ok(())
} 