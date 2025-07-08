pub mod connector;
pub mod registry;

use crate::{
    common::{
        provider::FileSystemKeyProvider,
        rotation::{RotatingKeyManager, RotationPolicy},
        sealer::SealRotator,
    },
    contract::PublicKeyBundle,
    error::Error,
    peer::connector::PeerConnector,
};
use chrono::Utc;
use dashmap::DashMap;
use seal_flow::{
    algorithms::traits::{AsymmetricAlgorithm, SymmetricAlgorithm},
    keys::AsymmetricPublicKey,
    prelude::*,
    seal::HybridSeal,
    secrecy::SecretBox,
};
use base64::{engine::general_purpose, Engine};
use std::{path::Path, sync::Arc};

/// Represents a self-contained peer in a peer-to-peer network, capable of
/// securely communicating with other peers.
pub struct Peer<C: PeerConnector> {
    pub id: String,
    rotator: Arc<SealRotator>,
    connector: Arc<C>,
    remote_bundle_cache: DashMap<String, PublicKeyBundle>,
}

impl<C: PeerConnector + Send + Sync> Peer<C> {
    /// Creates a new `Peer`.
    ///
    /// # Arguments
    ///
    /// * `id`: A unique identifier for this peer (e.g., "peer-a.com").
    /// * `storage_dir`: The directory to store this peer's encrypted private keys.
    /// * `password`: The master password to protect the key store.
    /// * `policy`: The key rotation policy for this peer.
    /// * `connector`: The connector used to fetch public keys from other peers.
    pub fn new<P: AsRef<Path>>(
        id: &str,
        storage_dir: P,
        password: SecretBox<[u8]>,
        policy: RotationPolicy,
        connector: Arc<C>,
    ) -> Result<Self, Error> {
        let key_provider = Arc::new(FileSystemKeyProvider::new(storage_dir, password)?);
        let key_manager = Arc::new(RotatingKeyManager::new(key_provider, id, policy)?);
        let rotator = Arc::new(SealRotator::new(key_manager));

        Ok(Self {
            id: id.to_string(),
            rotator,
            connector,
            remote_bundle_cache: DashMap::new(),
        })
    }

    /// Generates a `PublicKeyBundle` for this peer, which can be shared with
    /// others to allow them to encrypt messages for this peer.
    pub fn get_public_key_bundle<A: AsymmetricAlgorithm>(&self) -> Result<PublicKeyBundle, Error> {
        self.rotator.get_public_key_bundle::<A>()
    }

    /// Encrypts a message for a remote peer.
    ///
    /// This method automatically handles fetching and caching the recipient's
    /// public key, providing 0-RTT encryption for subsequent messages.
    pub async fn encrypt_for<A, S>(
        &self,
        remote_peer_id: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Error>
    where
        A: AsymmetricAlgorithm + Send + Sync,
        S: SymmetricAlgorithm,
    {
        // 1. Check cache for a valid, non-expired key bundle.
        if let Some(bundle) = self.remote_bundle_cache.get(remote_peer_id) {
            if bundle.algorithm == A::name() && bundle.expires_at > Utc::now() {
                let key_bytes =
                    general_purpose::URL_SAFE_NO_PAD.decode(&bundle.public_key)?;
                let public_key = AsymmetricPublicKey::new(key_bytes);
                let ciphertext = HybridSeal::new()
                    .encrypt::<S>(public_key, bundle.key_id.clone())
                    .with_algorithm::<A>()
                    .to_vec(plaintext)?;
                return Ok(ciphertext);
            }
        }

        // 2. If not in cache or expired, fetch it via the connector.
        let bundle = self.connector.fetch_bundle::<A>(remote_peer_id).await?;

        // --- Validate the bundle ---
        if bundle.algorithm != A::name() {
            return Err(Error::PeerError(format!(
                "Mismatched algorithm from peer {}",
                remote_peer_id
            )));
        }
        if bundle.expires_at <= Utc::now() {
            return Err(Error::PeerError(format!(
                "Stale bundle from peer {}",
                remote_peer_id
            )));
        }

        let key_bytes =
            general_purpose::URL_SAFE_NO_PAD.decode(&bundle.public_key)?;
        let public_key = AsymmetricPublicKey::new(key_bytes);

        // 3. Perform encryption
        let ciphertext = HybridSeal::new()
            .encrypt::<S>(public_key, bundle.key_id.clone())
            .with_algorithm::<A>()
            .to_vec(plaintext)?;

        // 4. Update cache
        self.remote_bundle_cache
            .insert(remote_peer_id.to_string(), bundle);

        Ok(ciphertext)
    }

    /// Decrypts a message that was encrypted for this peer.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        self.rotator
            .hybrid_unsealer()
            .unseal(ciphertext)?
            .finalize()
    }
}