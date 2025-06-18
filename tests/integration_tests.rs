use seal_kit::QSealEngine;
#[cfg(all(feature = "traditional", feature = "post-quantum"))]
use seal_kit::HybridRsaKyber;

#[cfg(all(feature = "traditional", feature = "post-quantum"))]
#[test]
fn integration_sync_engine() {
    // 测试同步 QSealEngine（混合加密）
    use std::fs;
    let _ = fs::remove_dir_all("keys");
    let mut engine = QSealEngine::<HybridRsaKyber>::with_defaults("test_keys").unwrap();
    let data = b"Integration test";
    let cipher = engine.encrypt(data).unwrap();
    let plain = engine.decrypt(&cipher).unwrap();
    assert_eq!(plain, data);
    let _ = fs::remove_dir_all("keys");
}

#[cfg(all(feature = "async-engine", feature = "traditional", feature = "post-quantum"))]
#[test]
fn integration_async_engine() {
    use std::fs;
    use seal_kit::AsyncQSealEngine;
    use seal_kit::asymmetric::systems::hybrid::rsa_kyber::RsaKyberCryptoSystem;
    use std::sync::Arc;
    use seal_kit::ConfigManager; 
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