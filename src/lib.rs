//! # Seal-Kit: Modern and High-Level Cryptography
//!
//! `seal-kit` is a cryptographic library that provides a high-level, fluent API 
//! for symmetric and hybrid encryption workflows, built on top of `seal-flow`.
//!
//! It aims to simplify complex cryptographic operations, reduce boilerplate, and prevent
//! common misuse by offering a secure, opinionated, and easy-to-use interface.
//!
//! ## Core Concepts
//!
//! - **`SymmetricSeal`**: A factory for performing symmetric encryption and decryption.
//! - **`HybridSeal`**: A factory for performing hybrid encryption (combining asymmetric and symmetric crypto) and digital signatures.
//! - **`KeyProvider`**: A trait for integrating with key management systems. `seal-kit` provides
//!   implementations for common storage backends.
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use seal_kit::prelude::*;
//! use seal_kit::SymmetricSeal;
//! use seal_kit::algorithms::symmetric::Aes256Gcm;
//!
//! fn main() -> Result<()> {
//!     let key = Aes256Gcm::generate_key()?;
//!     let key_id = "my-key-v1".to_string();
//!     let plaintext = b"Hello, Seal-Kit!";
//!
//!     // Encrypt
//!     let ciphertext = SymmetricSeal::new()
//!         .encrypt(SymmetricKey::new(key.clone()), key_id.clone())
//!         .to_vec::<Aes256Gcm>(plaintext)?;
//!
//!     // Decrypt
//!     let decrypted = SymmetricSeal::new()
//!         .decrypt()
//!         .slice(&ciphertext)?
//!         .with_key(SymmetricKey::new(key))?;
//!
//!     assert_eq!(plaintext, &decrypted[..]);
//!     println!("Symmetric roundtrip successful!");
//!     Ok(())
//! }
//! ```

// --- Core API Factories ---
// Re-export the main entry points from `seal-flow`.
pub use seal_flow::seal::{HybridSeal, SymmetricSeal};

// --- Prelude ---
// A collection of the most commonly used traits, structs, and enums.
pub mod prelude {
    pub use seal_flow::prelude::*;
}

// --- Algorithms ---
// Re-export all available cryptographic algorithm definitions.
pub mod algorithms {
    pub use seal_flow::algorithms::*;
}

pub mod error;


/// The version of the `seal-kit` crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod contract;
pub mod client;
pub mod server;
pub mod sealer;