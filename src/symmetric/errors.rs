use crate::symmetric::systems::aes_gcm::AesGcmSystemError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SymmetricError {
    #[error("AES-GCM System error: {0}")]
    AesGcm(#[from] AesGcmSystemError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parallel Operation error: {0}")]
    ParallelOperation(String),

    #[error("Async Join error: {0}")]
    AsyncTask(#[from] tokio::task::JoinError),
}
