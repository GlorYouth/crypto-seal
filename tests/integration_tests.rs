#![cfg(all(feature = "traditional", feature = "post-quantum"))]

use seal_kit::asymmetric::systems::hybrid::rsa_kyber::RsaKyberCryptoSystem;
use seal_kit::Seal;
use secrecy::SecretString;
use std::sync::Arc;
use tempfile::tempdir;

#[test]
fn integration_sync_engine() {
    // Setup
    let dir = tempdir().unwrap();
    let seal_path = dir.path().join("sync.seal");
    let password = SecretString::new("sync-password".to_string().into_boxed_str());
    let seal = Seal::create(&seal_path, &password).unwrap();

    // Test encryption/decryption
    let mut engine = seal
        .asymmetric_sync_engine::<RsaKyberCryptoSystem>(password.clone())
        .unwrap();
    let data = b"Integration test for sync engine";
    let cipher = engine.encrypt(data).unwrap();
    let plain = engine.decrypt(&cipher).unwrap();
    assert_eq!(plain, data);

    // Test reopening and decryption
    let seal2 = Seal::open(&seal_path, &password).unwrap();
    let engine2 = seal2
        .asymmetric_sync_engine::<RsaKyberCryptoSystem>(password)
        .unwrap();
    let plain_after_reopen = engine2.decrypt(&cipher).unwrap();
    assert_eq!(plain_after_reopen, data);
}

#[cfg(feature = "async-engine")]
#[tokio::test]
async fn integration_async_engine() {
    // Setup
    let dir = tempdir().unwrap();
    let seal_path = dir.path().join("async.seal");
    let password = SecretString::new("async-password".to_string().into_boxed_str());
    let seal = Seal::create(&seal_path, &password).unwrap();

    // Test encryption/decryption
    let mut engine = seal
        .asymmetric_async_engine::<RsaKyberCryptoSystem>(password.clone())
        .await
        .unwrap();
    let data = b"Async integration test";
    let cipher = engine.encrypt(data).await.unwrap();
    let plain = engine.decrypt(&cipher).await.unwrap();
    assert_eq!(plain, data);

    // Test reopening and decryption
    let seal2 = Seal::open(&seal_path, &password).unwrap();
    let engine2 = seal2
        .asymmetric_async_engine::<RsaKyberCryptoSystem>(password)
        .await
        .unwrap();
    let plain_after_reopen = engine2.decrypt(&cipher).await.unwrap();
    assert_eq!(plain_after_reopen, data);
} 