use crate::{
    contract::PublicKeyBundle,
    error::Error,
    peer::{connector::PeerConnector, Peer},
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use seal_flow::algorithms::traits::AsymmetricAlgorithm;
use std::marker::PhantomData;

pub struct PeerRegistry<C: PeerConnector> {
    peers: Mutex<HashMap<String, Arc<Peer<C>>>>,
    _marker: PhantomData<C>,
}

impl<C: PeerConnector + Send + Sync> Default for PeerRegistry<C> {
    fn default() -> Self {
        Self {
            peers: Default::default(),
            _marker: PhantomData,
        }
    }
}

impl<C: PeerConnector + Send + Sync> PeerRegistry<C> {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn register(&self, peer: Arc<Peer<C>>) {
        let mut peers = self.peers.lock().unwrap();
        peers.insert(peer.id.clone(), peer);
    }

    pub fn get_bundle<A: AsymmetricAlgorithm>(
        &self,
        peer_id: &str,
    ) -> Result<PublicKeyBundle, Error> {
        let peers = self.peers.lock().unwrap();
        peers
            .get(peer_id)
            .ok_or_else(|| Error::PeerNotFound(peer_id.to_string()))?
            .get_public_key_bundle::<A>()
    }
} 