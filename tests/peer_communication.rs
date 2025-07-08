use seal_kit::{
    common::rotation::RotationPolicy,
    error::Error,
    peer::{
        connector::InMemoryConnector,
        registry::PeerRegistry,
        Peer,
    },
};
use seal_flow::{
    algorithms::{asymmetric::Kyber1024, symmetric::Aes256Gcm},
    secrecy::SecretBox,
};
use std::sync::Arc;
use tempfile::tempdir;

#[tokio::test]
async fn test_peer_to_peer_communication() -> Result<(), Error> {
    // 1. Setup the shared environment (simulated network)
    let registry = Arc::new(PeerRegistry::new());
    let connector = Arc::new(InMemoryConnector::new(registry.clone()));

    // 2. Create Peer A
    let dir_a = tempdir()?;
    let peer_a = Arc::new(Peer::new(
        "peer-a",
        dir_a.path(),
        SecretBox::new(b"password-a".to_vec().into_boxed_slice()),
        RotationPolicy::default(),
        connector.clone(),
    )?);
    registry.register(peer_a.clone());

    // 3. Create Peer B
    let dir_b = tempdir()?;
    let peer_b = Arc::new(Peer::new(
        "peer-b",
        dir_b.path(),
        SecretBox::new(b"password-b".to_vec().into_boxed_slice()),
        RotationPolicy::default(),
        connector.clone(),
    )?);
    registry.register(peer_b.clone());

    // 4. Peer A encrypts a message for Peer B
    let plaintext = b"Hello, Peer B! This is a secret message from A.".to_vec();
    let ciphertext = peer_a
        .encrypt_for::<Kyber1024, Aes256Gcm>("peer-b", &plaintext)
        .await?;

    // 5. Peer B decrypts the message from Peer A
    let decrypted_plaintext = peer_b.decrypt(&ciphertext)?;

    // 6. Assert the roundtrip was successful
    assert_eq!(plaintext, decrypted_plaintext);

    Ok(())
} 