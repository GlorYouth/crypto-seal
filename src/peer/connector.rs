use crate::{
    contract::PublicKeyBundle,
    error::Error,
    peer::registry::PeerRegistry,
};
use async_trait::async_trait;
use seal_flow::algorithms::traits::AsymmetricAlgorithm;
use std::sync::Arc;

#[async_trait]
pub trait PeerConnector: Send + Sync + 'static {
    async fn fetch_bundle<A: AsymmetricAlgorithm + Send + Sync>(
        &self,
        remote_peer_id: &str,
    ) -> Result<PublicKeyBundle, Error>;
}

pub struct InMemoryConnector {
    registry: Arc<PeerRegistry<Self>>,
}

impl InMemoryConnector {
    pub fn new(registry: Arc<PeerRegistry<Self>>) -> Self {
        Self { registry }
    }
}

#[async_trait]
impl PeerConnector for InMemoryConnector {
    async fn fetch_bundle<A: AsymmetricAlgorithm + Send + Sync>(
        &self,
        remote_peer_id: &str,
    ) -> Result<PublicKeyBundle, Error> {
        self.registry.get_bundle::<A>(remote_peer_id)
    }
}