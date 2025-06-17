use std::sync::Arc;
use tempfile::tempdir;
use crypto_seal::{TraditionalRsa, PostQuantumKyber};
use crypto_seal::rotation::{KeyRotationManager, RotationPolicy, KeyStorage};
use crypto_seal::primitives::CryptoConfig;
use crypto_seal::storage::file::KeyFileStorage;
use crypto_seal::traits::KeyStatus;

#[test]
fn test_key_rotation_flow_traditional() {
    // 准备临时目录和文件存储
    let dir = tempdir().unwrap();
    let storage: Arc<dyn KeyStorage> = Arc::new(KeyFileStorage::new(dir.path()).unwrap());
    // 设置策略：立即过期，并在使用1次后轮换，开始天数0
    let policy = RotationPolicy { validity_period_days: 0, max_usage_count: Some(1), rotation_start_days: 0 };
    let mut mgr = KeyRotationManager::<TraditionalRsa>::new(storage.clone(), policy.clone(), "rot");

    // 初始化：应创建主密钥
    mgr.initialize(&CryptoConfig::default()).unwrap();
    let meta1 = mgr.get_primary_key_metadata().unwrap().clone();
    assert!(storage.key_exists(&format!("rot-{}", meta1.id)));

    // 增加使用次数，触发轮换需求
    mgr.increment_usage_count().unwrap();
    assert!(mgr.needs_rotation());

    // 开始轮换：生成新主密钥，旧密钥变为 Rotating
    mgr.start_rotation(&CryptoConfig::default()).unwrap();
    let meta2 = mgr.get_primary_key_metadata().unwrap().clone();
    assert_ne!(meta1.id, meta2.id);
    let secondaries = mgr.get_secondary_keys();
    assert!(secondaries.iter().any(|(_,_,m)| m.id == meta1.id && m.status == KeyStatus::Rotating));

    // 完成轮换：删除旧密钥
    mgr.complete_rotation().unwrap();
    assert!(!storage.key_exists(&format!("rot-{}", meta1.id)));
}

#[test]
fn test_key_rotation_flow_kyber() {
    // 类似流程，但使用后量子 Kyber 系统
    let dir = tempdir().unwrap();
    let storage: Arc<dyn KeyStorage> = Arc::new(KeyFileStorage::new(dir.path()).unwrap());
    let policy = RotationPolicy { validity_period_days: 0, max_usage_count: Some(1), rotation_start_days: 0 };
    let mut mgr = KeyRotationManager::<PostQuantumKyber>::new(storage.clone(), policy.clone(), "rot");

    mgr.initialize(&CryptoConfig::default()).unwrap();
    let meta1 = mgr.get_primary_key_metadata().unwrap().clone();
    assert!(storage.key_exists(&format!("rot-{}", meta1.id)));

    mgr.increment_usage_count().unwrap();
    assert!(mgr.needs_rotation());

    mgr.start_rotation(&CryptoConfig::default()).unwrap();
    let meta2 = mgr.get_primary_key_metadata().unwrap().clone();
    assert_ne!(meta1.id, meta2.id);
    let secondaries = mgr.get_secondary_keys();
    assert!(secondaries.iter().any(|(_,_,m)| m.id == meta1.id && m.status == KeyStatus::Rotating));

    mgr.complete_rotation().unwrap();
    assert!(!storage.key_exists(&format!("rot-{}", meta1.id)));
} 