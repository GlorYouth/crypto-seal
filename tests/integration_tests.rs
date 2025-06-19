#![cfg(all(feature = "traditional", feature = "post-quantum"))]

use seal_kit::Seal;
use seal_kit::asymmetric::systems::hybrid::rsa_kyber::RsaKyberCryptoSystem;
use seal_kit::common::config::StreamingConfig;
use seal_kit::symmetric::systems::aes_gcm::AesGcmSystem;
use secrecy::SecretString;
use std::io::Cursor;
use tempfile::tempdir;

#[test]
fn integration_sync_engine() {
    // Setup
    let dir = tempdir().unwrap();
    let seal_path = dir.path().join("sync.seal");
    let password = SecretString::new("sync-password".into());
    let seal = Seal::create(&seal_path, &password).unwrap();

    // Test one-shot encryption/decryption
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
        .asymmetric_sync_engine::<RsaKyberCryptoSystem>(password.clone())
        .unwrap();
    let plain_after_reopen = engine2.decrypt(&cipher).unwrap();
    assert_eq!(plain_after_reopen, data);

    // Test streaming encryption/decryption
    let stream_data = b"Some very long data for sync streaming";
    let mut reader = Cursor::new(stream_data);
    let mut encrypted_writer = Cursor::new(Vec::new());
    let config = StreamingConfig::default();

    engine
        .encrypt_stream::<AesGcmSystem, _, _>(&mut reader, &mut encrypted_writer, &config)
        .unwrap();

    let mut encrypted_reader = Cursor::new(encrypted_writer.into_inner());
    let mut decrypted_writer = Cursor::new(Vec::new());
    engine2
        .decrypt_stream::<AesGcmSystem, _, _>(&mut encrypted_reader, &mut decrypted_writer, &config)
        .unwrap();

    assert_eq!(decrypted_writer.into_inner(), stream_data.to_vec());
}

#[cfg(feature = "async-engine")]
#[tokio::test]
async fn integration_async_engine() {
    // Setup
    let dir = tempdir().unwrap();
    let seal_path = dir.path().join("async.seal");
    let password = SecretString::new("async-password".into());
    let seal = Seal::create(&seal_path, &password).unwrap();

    // Test one-shot encryption/decryption
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
        .asymmetric_async_engine::<RsaKyberCryptoSystem>(password.clone())
        .await
        .unwrap();
    let plain_after_reopen = engine2.decrypt(&cipher).await.unwrap();
    assert_eq!(plain_after_reopen, data);

    // Test streaming encryption/decryption
    let stream_data = b"Some very long data for async streaming";
    let mut reader = Cursor::new(stream_data);
    let mut encrypted_writer = Cursor::new(Vec::new());
    let config = StreamingConfig::default();

    engine
        .encrypt_stream::<AesGcmSystem, _, _>(&mut reader, &mut encrypted_writer, &config)
        .await
        .unwrap();

    let mut encrypted_reader = Cursor::new(encrypted_writer.into_inner());
    let mut decrypted_writer = Cursor::new(Vec::new());
    engine2
        .decrypt_stream::<AesGcmSystem, _, _>(&mut encrypted_reader, &mut decrypted_writer, &config)
        .await
        .unwrap();

    assert_eq!(decrypted_writer.into_inner(), stream_data.to_vec());
}
