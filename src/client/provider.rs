//! Provides a key provider that fetches public keys from a remote server.

use crate::contract::PublicKeyBundle;
use crate::error::Error;
use base64::Engine;
use chrono::Utc;
use seal_flow::algorithms::traits::{AsymmetricAlgorithm};
use seal_flow::prelude::{AsymmetricPublicKey, Key};
use std::sync::{Arc, Mutex};

/// A key provider that retrieves public keys from a remote server endpoint.
///
/// It caches the key locally to reduce network latency and handles fetching
/// a new key when the cached one expires. This component is designed for
/// client-side use and does not handle private keys.
pub struct RemoteKeyProvider {
    /// The remote server's base URL.
    server_url: String,
    /// The cached public key bundle. The Mutex is used for interior mutability.
    cache: Arc<Mutex<Option<PublicKeyBundle>>>,
}

impl RemoteKeyProvider {
    /// Creates a new `RemoteKeyProvider`.
    ///
    /// # Arguments
    ///
    /// * `server_url`: The base URL of the `seal-kit` server's public key endpoint.
    pub fn new(server_url: impl Into<String>) -> Self {
        Self {
            server_url: server_url.into(),
            cache: Arc::new(Mutex::new(None)),
        }
    }

    /// Retrieves a public key for the specified asymmetric algorithm.
    ///
    /// This method first checks for a valid (non-expired) cached key. If not found,
    /// it fetches a new `PublicKeyBundle` from the remote server and updates the cache.
    pub fn get_public_key<A: AsymmetricAlgorithm>(
        &self,
    ) -> Result<(String, AsymmetricPublicKey), Error> {
        let cache = self.cache.lock().unwrap();

        let bundle = match &*cache {
            Some(bundle) if bundle.expires_at > Utc::now() => {
                println!("Using cached key: {}", bundle.key_id);
                bundle.clone()
            }
            _ => {
                println!("Cache miss or expired, fetching new key...");
                drop(cache); // Drop the lock before the potentially slow network call
                let new_bundle = self.fetch_and_cache_key::<A>()?;
                new_bundle
            }
        };

        let key_bytes = base64::engine::general_purpose::STANDARD.decode(&bundle.public_key)?;
        let public_key = AsymmetricPublicKey::new(key_bytes);

        Ok((bundle.key_id, public_key))
    }

    /// Simulates fetching a new `PublicKeyBundle` from the server and caching it.
    ///
    /// In a real implementation, this would be an actual network request.
    fn fetch_and_cache_key<A: AsymmetricAlgorithm>(&self) -> Result<PublicKeyBundle, Error> {
        println!(
            "Simulating fetch from: {}/public_key/{}",
            self.server_url,
            A::name()
        );

        // Simulate generating a key on the server side.
        let (pk, _) = A::generate_keypair()?;

        let bundle = PublicKeyBundle {
            key_id: format!("{}-simulated-key-{}", A::name(), Utc::now().timestamp()),
            algorithm: A::name().to_string(),
            public_key: base64::engine::general_purpose::STANDARD.encode(pk.to_bytes()),
            issued_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
        };

        let mut cache = self.cache.lock().unwrap();
        *cache = Some(bundle.clone());

        Ok(bundle)
    }
} 