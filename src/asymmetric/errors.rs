use thiserror::Error;

#[derive(Error, Debug)]
pub enum AsymmetricError {
    #[error("RSA error: {0}")]
    Rsa(#[from] crate::asymmetric::systems::traditional::rsa::RsaSystemError),
    #[error("Kyber error: {0}")]
    Kyber(#[from] crate::asymmetric::systems::post_quantum::kyber::KyberSystemError),
    #[error("Hybrid RSA/Kyber error: {0}")]
    RsaKyber(#[from] crate::asymmetric::systems::hybrid::rsa_kyber::RsaKyberSystemError),
    #[error("Signature error: {0}")]
    Signature(String),
    #[error("Verification failed: {0}")]
    Verification(String),
}
