//! Provides a high-level sealer for peer-to-peer communication.
use std::sync::Arc;

use crate::{
    common::{
        provider::RemoteKeyProvider, rotation::RotatingKeyManager, sealer::hybrid::HybridUnsealer,
    },
    error::Error,
};
use seal_flow::{
    algorithms::traits::{AsymmetricAlgorithm, SymmetricAlgorithm},
    seal::{traits::InMemoryEncryptor, HybridSeal},
};

/// A high-level sealer for peer-to-peer communication, enabling a peer to
/// encrypt messages for other peers and decrypt messages sent to it.
///
/// This struct combines the functionality of remote key fetching for encryption
/// and local key management for decryption.
#[derive(Clone)]
pub struct PeerSealer {
    /// Provides public keys of remote peers for encryption.
    remote_provider: RemoteKeyProvider,
    /// Manages this peer's own private keys for decryption.
    key_manager: Arc<RotatingKeyManager>,
}

impl PeerSealer {
    /// Creates a new `PeerSealer`.
    ///
    /// # Arguments
    ///
    /// * `remote_provider`: The provider for fetching and caching remote peer public keys.
    /// * `key_manager`: The manager for this peer's own cryptographic keys.
    pub fn new(remote_provider: RemoteKeyProvider, key_manager: Arc<RotatingKeyManager>) -> Self {
        Self {
            remote_provider,
            key_manager,
        }
    }

    /// Encrypts a message for a specific remote peer using hybrid encryption.
    ///
    /// This method performs a 0-RTT encryption if the peer's public key is already
    /// cached by the `RemoteKeyProvider`.
    ///
    /// # Arguments
    ///
    /// * `peer_url`: The unique identifier of the recipient peer.
    /// * `plaintext`: The data to encrypt.
    pub fn encrypt_for<A, S>(&self, peer_url: &str, plaintext: &[u8]) -> Result<Vec<u8>, Error>
    where
        A: AsymmetricAlgorithm,
        S: SymmetricAlgorithm,
    {
        // 1. Fetch the recipient's public key using the 0-RTT provider.
        let (key_id, public_key) = self.remote_provider.get_public_key::<A>(peer_url)?;

        // 2. Use the fetched key to perform hybrid encryption.
        let ciphertext = HybridSeal::new()
            .encrypt::<S>(public_key, key_id)
            .with_algorithm::<A>()
            .to_vec(plaintext)?;

        Ok(ciphertext)
    }

    /// Prepares a decryption operation by providing a `HybridUnsealer`.
    ///
    /// The returned `HybridUnsealer` is configured with this peer's key manager.
    /// The caller is responsible for starting the decryption, finding the correct
    /// private key, and finalizing the operation.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // 1. Get the unsealer
    /// let unsealer = peer_sealer.unsealer();
    ///
    /// // 2. Start decryption
    /// let pending_decryption = unsealer.unseal(ciphertext)?;
    ///
    /// // 3. Caller must determine which key_id was used (e.g., by parsing the header)
    /// let key_id = "some-key-id-from-ciphertext-header";
    /// let private_key = key_manager.get_asymmetric_private_key(key_id)?;
    ///
    /// // 4. Finalize with the private key
    /// let plaintext = pending_decryption.finalize(private_key)?;
    /// ```
    pub fn unsealer(&self) -> HybridUnsealer {
        HybridUnsealer {
            inner: HybridSeal::new()
                .decrypt()
                .with_key_provider(self.key_manager.clone()),
        }
    }
}
