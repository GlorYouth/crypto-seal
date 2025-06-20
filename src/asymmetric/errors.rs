use crate::asymmetric::systems::{
    hybrid::rsa_kyber::RsaKyberSystemError, post_quantum::kyber::KyberSystemError,
    traditional::rsa::RsaSystemError,
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AsymmetricError {
    #[error("RSA error: {0}")]
    Rsa(#[from] RsaSystemError),
    #[error("Kyber error: {0}")]
    Kyber(#[from] KyberSystemError),
    #[error("Hybrid RSA/Kyber error: {0}")]
    RsaKyber(#[from] RsaKyberSystemError),
    #[error("Signature is missing where required")]
    SignatureMissing,
}
