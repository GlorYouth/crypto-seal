use crate::{
    contract::PublicKeyBundle,
    error::Error,
    peer::{connector::PeerConnector, Peer},
};
use dashmap::DashMap;
use std::{marker::PhantomData, sync::Arc};
use seal_flow::algorithms::traits::{AsymmetricAlgorithm, SymmetricAlgorithm};

pub struct PeerRegistry<C: PeerConnector> {
    peers: DashMap<String, Arc<Peer<C>>>,
    _marker: PhantomData<C>,
}

impl<C: PeerConnector> Default for PeerRegistry<C> {
    fn default() -> Self {
        Self {
            peers: Default::default(),
            _marker: PhantomData,
        }
    }
}

impl<C: PeerConnector> PeerRegistry<C> {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn register(&self, peer: Arc<Peer<C>>) {
        self.peers.insert(peer.id.clone(), peer);
    }

    pub fn get_bundle<A: AsymmetricAlgorithm, S: SymmetricAlgorithm>(
        &self,
        peer_id: &str,
    ) -> Result<PublicKeyBundle, Error> {
        self.peers
            .get(peer_id)
            .ok_or_else(|| Error::PeerNotFound(peer_id.to_string()))?
            .value()
            .get_public_key_bundle::<A, S>()
    }
} 