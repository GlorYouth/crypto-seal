use crypto_seal::{QSealEngine, HybridRsaKyber};
use std::sync::Arc;
use crypto_seal::ConfigManager;

#[test]
fn integration_sync_engine() {
    // 测试同步 QSealEngine（混合加密）
    let mut engine = QSealEngine::<HybridRsaKyber>::with_defaults("test_keys").unwrap();
    let data = b"Integration test";
    let cipher = engine.encrypt(data).unwrap();
    let plain = engine.decrypt(&cipher).unwrap();
    assert_eq!(plain, data);
}

#[cfg(feature = "async-engine")]
#[test]
fn integration_async_engine() {
    use crypto_seal::AsyncQSealEngine;
    use crypto_seal::crypto::systems::post_quantum::kyber::KyberCryptoSystem;

    // 测试并发 AsyncQSealEngine（后量子 Kyber）
    let config = Arc::new(ConfigManager::new());
    let engine = AsyncQSealEngine::<KyberCryptoSystem>::new(config, "test_async").unwrap();
    let data = b"Async integration test";
    let cipher = engine.encrypt(data).unwrap();
    let plain = engine.decrypt(&cipher).unwrap();
    assert_eq!(plain, data);
} 