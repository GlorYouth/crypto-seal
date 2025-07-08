//! Provides a high-level client-side sealer for performing hybrid encryption.

use crate::client::provider::RemoteKeyProvider;
use std::sync::Arc;
use crate::error::Error;
use seal_flow::seal::HybridSeal;
use seal_flow::algorithms::traits::{AsymmetricAlgorithm, SymmetricAlgorithm};
use seal_flow::seal::traits::InMemoryEncryptor;

/// A client-side sealer that simplifies hybrid encryption by automatically
/// managing public key retrieval and caching.
///
/// It uses a `RemoteKeyProvider` to fetch the latest public key from a
/// server endpoint.
pub struct ClientSealer {
    provider: Arc<RemoteKeyProvider>,
}

impl ClientSealer {
    /// Creates a new `ClientSealer` with the given key provider.
    ///
    /// # Arguments
    ///
    /// * `provider`: An `Arc<RemoteKeyProvider>` that will be used to fetch
    ///   encryption keys.
    pub fn new(provider: Arc<RemoteKeyProvider>) -> Self {
        Self { provider }
    }

    /// Encrypts the given plaintext using a key fetched from the remote provider.
    ///
    /// # Type Parameters
    ///
    /// * `A`: The asymmetric algorithm (KEM) to use for key encapsulation.
    /// * `S`: The symmetric algorithm (DEM) to use for bulk data encryption.
    ///
    /// # Arguments
    ///
    /// * `plaintext`: The data to be encrypted.
    ///
    /// # Returns
    ///
    /// A `Result` containing the ciphertext or an `Error`.
    pub fn encrypt<A, S>(&self, plaintext: &[u8]) -> Result<Vec<u8>, Error>
    where
        A: AsymmetricAlgorithm,
        S: SymmetricAlgorithm,
    {
        // 1. Fetch the latest public key from the provider.
        let (key_id, public_key) = self.provider.get_public_key::<A>()?;

        // 2. Use the fetched key to perform hybrid encryption.
        let ciphertext = HybridSeal::new()
            .encrypt::<S>(public_key, key_id)
            .with_algorithm::<A>()
            .to_vec(plaintext)?;

        Ok(ciphertext)
    }
} 