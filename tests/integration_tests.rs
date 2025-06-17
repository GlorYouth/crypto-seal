use std::fs;
use crypto_seal::QSealEngine;
#[cfg(all(feature = "traditional", feature = "post-quantum"))]
use crypto_seal::HybridRsaKyber;

#[cfg(all(feature = "traditional", feature = "post-quantum"))]
#[test]
fn integration_sync_engine() {
    // 测试同步 QSealEngine（混合加密）
    let _ = fs::remove_dir_all("keys");
    let mut engine = QSealEngine::<HybridRsaKyber>::with_defaults("test_keys").unwrap();
    let data = b"Integration test";
    let cipher = engine.encrypt(data).unwrap();
    let plain = engine.decrypt(&cipher).unwrap();
    assert_eq!(plain, data);
    let _ = fs::remove_dir_all("keys");
}

#[cfg(feature = "async-engine")]
#[test]
fn integration_async_engine() {
    use crypto_seal::AsyncQSealEngine;
    use crypto_seal::systems::hybrid::rsa_kyber::RsaKyberCryptoSystem;
    use std::sync::Arc;
    use crypto_seal::ConfigManager; 
    // 测试并发 AsyncQSealEngine（混合加密）
    let _ = fs::remove_dir_all("keys");
    let config = Arc::new(ConfigManager::new());
    let engine = AsyncQSealEngine::<RsaKyberCryptoSystem>::new(config, "test_async").unwrap();
    let data = b"Async integration test";
    let cipher = engine.encrypt(data).unwrap();
    let plain = engine.decrypt(&cipher).unwrap();
    assert_eq!(plain, data);
    let _ = fs::remove_dir_all("keys");
} 