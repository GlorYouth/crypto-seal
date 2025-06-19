//!
//! # 兼容性矩阵测试
//!
//! 该模块验证了 `seal-kit` 各种加密与解密模式之间的互操作性。
//! 它确保了对于给定的加密算法，一种模式（如内存、流式）的输出
//! 可以被逻辑上等价的其他模式正确解密。
//!
//! 测试结构：
//! - 为每种非对称算法创建一个模块 (e.g., `rsa_kyber_768`)。
//! - 在每个模块中，为每种加密方法创建一个测试函数 (e.g., `seal_bytes_compatibility`)。
//! - 在每个测试函数内部，使用 `tokio::task::JoinSet` 并发测试所有解密方法的兼容性。
//!

#![cfg(feature = "secure-storage")]

use seal_kit::common::traits::AsymmetricAlgorithm;
use seal_kit::{Error, Seal, SealMode};
use secrecy::SecretString;
use std::io::Cursor;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::task::JoinSet;

const TEST_DATA: &[u8] = b"This is a comprehensive compatibility matrix test!";
const LARGE_TEST_DATA: &[u8] = &[0x42; 1024 * 1024]; // 1MB
const AAD: &[u8] = b"Authenticated Extra Data";

/// 辅助函数：创建一个临时的 Seal 实例，并轮换到指定的非对称密钥。
fn setup_seal_with_key(
    algorithm: AsymmetricAlgorithm,
) -> (Arc<Seal>, tempfile::TempDir, SecretString) {
    let dir = tempdir().unwrap();
    let seal_path = dir.path().join("my_seal.seal");
    let password = SecretString::from("test-password-matrix");
    let seal = Seal::create(&seal_path, &password).unwrap();
    seal.rotate_asymmetric_key(algorithm, &password).unwrap();
    (seal, dir, password)
}

/// 定义解密操作的枚举，以便在测试中进行分发。
#[derive(Debug, Clone, Copy)]
enum DecryptOp {
    UnsealBytes,
    UnsealStream,
    ParUnsealBytes,
    ParUnsealStream,
    UnsealStreamAsync,
    ParUnsealStreamAsync,
}

/// 在独立的 task 中执行解密操作并返回结果。
async fn perform_decryption(
    op: DecryptOp,
    seal: Arc<Seal>,
    password: SecretString,
    ciphertext: Vec<u8>,
) -> Result<Vec<u8>, Error> {
    let engine = seal.engine(SealMode::Hybrid, &password).unwrap();
    match op {
        DecryptOp::UnsealBytes => engine.unseal_bytes(&ciphertext, Some(AAD)),
        DecryptOp::UnsealStream => {
            let mut source = Cursor::new(ciphertext);
            let mut dest = Cursor::new(Vec::new());
            engine.unseal_stream(&mut source, &mut dest, Some(AAD))?;
            Ok(dest.into_inner())
        }
        DecryptOp::ParUnsealBytes => engine.par_unseal_bytes(&ciphertext, Some(AAD)),
        DecryptOp::ParUnsealStream => {
            let mut source = Cursor::new(ciphertext);
            let mut dest = Cursor::new(Vec::new());
            engine.par_unseal_stream(&mut source, &mut dest, Some(AAD))?;
            Ok(dest.into_inner())
        }
        DecryptOp::UnsealStreamAsync => {
            let source = Cursor::new(ciphertext);
            let dest = Cursor::new(Vec::new());
            let final_dest = engine.unseal_stream_async(source, dest, Some(AAD)).await?;
            Ok(final_dest.into_inner())
        }
        DecryptOp::ParUnsealStreamAsync => {
            let source = Cursor::new(ciphertext);
            let dest = Cursor::new(Vec::new());
            let final_dest = engine
                .par_unseal_stream_async(source, dest, Some(AAD))
                .await?;
            Ok(final_dest.into_inner())
        }
    }
}

/// RsaKyber768 算法的兼容性测试矩阵
mod rsa_kyber_768 {
    use super::*;

    const ALGORITHM: AsymmetricAlgorithm = AsymmetricAlgorithm::RsaKyber768;

    #[tokio::test]
    async fn seal_bytes_compatibility() {
        let (seal, _tmpdir, password) = setup_seal_with_key(ALGORITHM);
        let ciphertext = {
            let mut engine = seal.engine(SealMode::Hybrid, &password).unwrap();
            engine.seal_bytes(TEST_DATA, Some(AAD)).unwrap()
        };

        let mut set = JoinSet::new();
        let ops = [
            DecryptOp::UnsealBytes,
            DecryptOp::UnsealStream,
            DecryptOp::ParUnsealBytes,
            DecryptOp::ParUnsealStream,
            DecryptOp::UnsealStreamAsync,
            DecryptOp::ParUnsealStreamAsync,
        ];

        for op in ops {
            set.spawn(perform_decryption(
                op,
                seal.clone(),
                password.clone(),
                ciphertext.clone(),
            ));
        }

        while let Some(res) = set.join_next().await {
            let decrypted = res.unwrap().unwrap();
            assert_eq!(decrypted, TEST_DATA);
        }
    }

    #[tokio::test]
    async fn par_seal_bytes_compatibility() {
        let (seal, _tmpdir, password) = setup_seal_with_key(ALGORITHM);
        let ciphertext = {
            let mut engine = seal.engine(SealMode::Hybrid, &password).unwrap();
            engine.par_seal_bytes(LARGE_TEST_DATA, Some(AAD)).unwrap()
        };

        let mut set = JoinSet::new();
        let ops = [
            DecryptOp::UnsealBytes,
            DecryptOp::UnsealStream,
            DecryptOp::ParUnsealBytes,
            DecryptOp::ParUnsealStream,
            DecryptOp::UnsealStreamAsync,
            DecryptOp::ParUnsealStreamAsync,
        ];

        for op in ops {
            set.spawn(perform_decryption(
                op,
                seal.clone(),
                password.clone(),
                ciphertext.clone(),
            ));
        }

        while let Some(res) = set.join_next().await {
            let decrypted = res.unwrap().unwrap();
            assert_eq!(decrypted, LARGE_TEST_DATA);
        }
    }

    #[tokio::test]
    async fn seal_stream_compatibility() {
        let (seal, _tmpdir, password) = setup_seal_with_key(ALGORITHM);
        let ciphertext = {
            let mut engine = seal.engine(SealMode::Hybrid, &password).unwrap();
            let mut source = Cursor::new(LARGE_TEST_DATA);
            let mut dest = Cursor::new(Vec::new());
            engine
                .seal_stream(&mut source, &mut dest, Some(AAD))
                .unwrap();
            dest.into_inner()
        };

        let mut set = JoinSet::new();
        let ops = [
            DecryptOp::UnsealBytes,
            DecryptOp::UnsealStream,
            DecryptOp::ParUnsealBytes,
            DecryptOp::ParUnsealStream,
            DecryptOp::UnsealStreamAsync,
            DecryptOp::ParUnsealStreamAsync,
        ];

        for op in ops {
            set.spawn(perform_decryption(
                op,
                seal.clone(),
                password.clone(),
                ciphertext.clone(),
            ));
        }

        while let Some(res) = set.join_next().await {
            let decrypted = res.unwrap().unwrap();
            assert_eq!(decrypted, LARGE_TEST_DATA);
        }
    }

    #[tokio::test]
    async fn par_seal_stream_compatibility() {
        let (seal, _tmpdir, password) = setup_seal_with_key(ALGORITHM);
        let ciphertext = {
            let mut engine = seal.engine(SealMode::Hybrid, &password).unwrap();
            let mut source = Cursor::new(LARGE_TEST_DATA);
            let mut dest = Cursor::new(Vec::new());
            engine
                .par_seal_stream(&mut source, &mut dest, Some(AAD))
                .unwrap();
            dest.into_inner()
        };

        let mut set = JoinSet::new();
        // 经过验证，所有模式都应该是兼容的
        let ops = [
            DecryptOp::UnsealBytes,
            DecryptOp::UnsealStream,
            DecryptOp::ParUnsealBytes,
            DecryptOp::ParUnsealStream,
            DecryptOp::UnsealStreamAsync,
            DecryptOp::ParUnsealStreamAsync,
        ];

        for op in ops {
            set.spawn(perform_decryption(
                op,
                seal.clone(),
                password.clone(),
                ciphertext.clone(),
            ));
        }

        while let Some(res) = set.join_next().await {
            let decrypted = res.unwrap().unwrap();
            assert_eq!(decrypted, LARGE_TEST_DATA);
        }
    }

    #[tokio::test]
    async fn seal_stream_async_compatibility() {
        let (seal, _tmpdir, password) = setup_seal_with_key(ALGORITHM);
        let ciphertext = {
            let mut engine = seal.engine(SealMode::Hybrid, &password).unwrap();
            let source = Cursor::new(LARGE_TEST_DATA);
            let dest = Cursor::new(Vec::new());
            let final_dest = engine
                .seal_stream_async(source, dest, Some(AAD))
                .await
                .unwrap();
            final_dest.into_inner()
        };

        let mut set = JoinSet::new();
        let ops = [
            DecryptOp::UnsealBytes,
            DecryptOp::UnsealStream,
            DecryptOp::ParUnsealBytes,
            DecryptOp::ParUnsealStream,
            DecryptOp::UnsealStreamAsync,
            DecryptOp::ParUnsealStreamAsync,
        ];

        for op in ops {
            set.spawn(perform_decryption(
                op,
                seal.clone(),
                password.clone(),
                ciphertext.clone(),
            ));
        }

        while let Some(res) = set.join_next().await {
            let decrypted = res.unwrap().unwrap();
            assert_eq!(decrypted, LARGE_TEST_DATA);
        }
    }

    #[tokio::test]
    async fn par_seal_stream_async_compatibility() {
        let (seal, _tmpdir, password) = setup_seal_with_key(ALGORITHM);
        let ciphertext = {
            let mut engine = seal.engine(SealMode::Hybrid, &password).unwrap();
            let source = Cursor::new(LARGE_TEST_DATA);
            let dest = Cursor::new(Vec::new());
            let final_dest = engine
                .par_seal_stream_async(source, dest, Some(AAD))
                .await
                .unwrap();
            final_dest.into_inner()
        };

        let mut set = JoinSet::new();
        // 经过验证，所有模式都应该是兼容的
        let ops = [
            DecryptOp::UnsealBytes,
            DecryptOp::UnsealStream,
            DecryptOp::ParUnsealBytes,
            DecryptOp::ParUnsealStream,
            DecryptOp::UnsealStreamAsync,
            DecryptOp::ParUnsealStreamAsync,
        ];

        for op in ops {
            set.spawn(perform_decryption(
                op,
                seal.clone(),
                password.clone(),
                ciphertext.clone(),
            ));
        }

        while let Some(res) = set.join_next().await {
            let decrypted = res.unwrap().unwrap();
            assert_eq!(decrypted, LARGE_TEST_DATA);
        }
    }
}

/// Rsa2048 算法的兼容性测试矩阵
/// 这部分代码与 rsa_kyber_768 基本相同，只是改变了 ALGORITHM 常量。
/// 这验证了测试矩阵对于不同的底层加密算法都是稳健的。
mod rsa_2048 {
    use super::*;

    const ALGORITHM: AsymmetricAlgorithm = AsymmetricAlgorithm::Rsa2048;

    #[tokio::test]
    async fn seal_bytes_compatibility() {
        let (seal, _tmpdir, password) = setup_seal_with_key(ALGORITHM);
        let ciphertext = {
            let mut engine = seal.engine(SealMode::Hybrid, &password).unwrap();
            engine.seal_bytes(TEST_DATA, Some(AAD)).unwrap()
        };

        let mut set = JoinSet::new();
        let ops = [
            DecryptOp::UnsealBytes,
            DecryptOp::UnsealStream,
            DecryptOp::ParUnsealBytes,
            DecryptOp::ParUnsealStream,
            DecryptOp::UnsealStreamAsync,
            DecryptOp::ParUnsealStreamAsync,
        ];

        for op in ops {
            set.spawn(perform_decryption(
                op,
                seal.clone(),
                password.clone(),
                ciphertext.clone(),
            ));
        }

        while let Some(res) = set.join_next().await {
            let decrypted = res.unwrap().unwrap();
            assert_eq!(decrypted, TEST_DATA);
        }
    }

    #[tokio::test]
    async fn par_seal_bytes_compatibility() {
        let (seal, _tmpdir, password) = setup_seal_with_key(ALGORITHM);
        let ciphertext = {
            let mut engine = seal.engine(SealMode::Hybrid, &password).unwrap();
            engine.par_seal_bytes(LARGE_TEST_DATA, Some(AAD)).unwrap()
        };

        let mut set = JoinSet::new();
        let ops = [
            DecryptOp::UnsealBytes,
            DecryptOp::UnsealStream,
            DecryptOp::ParUnsealBytes,
            DecryptOp::ParUnsealStream,
            DecryptOp::UnsealStreamAsync,
            DecryptOp::ParUnsealStreamAsync,
        ];

        for op in ops {
            set.spawn(perform_decryption(
                op,
                seal.clone(),
                password.clone(),
                ciphertext.clone(),
            ));
        }

        while let Some(res) = set.join_next().await {
            let decrypted = res.unwrap().unwrap();
            assert_eq!(decrypted, LARGE_TEST_DATA);
        }
    }

    #[tokio::test]
    async fn seal_stream_compatibility() {
        let (seal, _tmpdir, password) = setup_seal_with_key(ALGORITHM);
        let ciphertext = {
            let mut engine = seal.engine(SealMode::Hybrid, &password).unwrap();
            let mut source = Cursor::new(LARGE_TEST_DATA);
            let mut dest = Cursor::new(Vec::new());
            engine
                .seal_stream(&mut source, &mut dest, Some(AAD))
                .unwrap();
            dest.into_inner()
        };

        let mut set = JoinSet::new();
        let ops = [
            DecryptOp::UnsealBytes,
            DecryptOp::UnsealStream,
            DecryptOp::ParUnsealBytes,
            DecryptOp::ParUnsealStream,
            DecryptOp::UnsealStreamAsync,
            DecryptOp::ParUnsealStreamAsync,
        ];

        for op in ops {
            set.spawn(perform_decryption(
                op,
                seal.clone(),
                password.clone(),
                ciphertext.clone(),
            ));
        }

        while let Some(res) = set.join_next().await {
            let decrypted = res.unwrap().unwrap();
            assert_eq!(decrypted, LARGE_TEST_DATA);
        }
    }

    #[tokio::test]
    async fn par_seal_stream_compatibility() {
        let (seal, _tmpdir, password) = setup_seal_with_key(ALGORITHM);
        let ciphertext = {
            let mut engine = seal.engine(SealMode::Hybrid, &password).unwrap();
            let mut source = Cursor::new(LARGE_TEST_DATA);
            let mut dest = Cursor::new(Vec::new());
            engine
                .par_seal_stream(&mut source, &mut dest, Some(AAD))
                .unwrap();
            dest.into_inner()
        };

        let mut set = JoinSet::new();
        // 经过验证，所有模式都应该是兼容的
        let ops = [
            DecryptOp::UnsealBytes,
            DecryptOp::UnsealStream,
            DecryptOp::ParUnsealBytes,
            DecryptOp::ParUnsealStream,
            DecryptOp::UnsealStreamAsync,
            DecryptOp::ParUnsealStreamAsync,
        ];

        for op in ops {
            set.spawn(perform_decryption(
                op,
                seal.clone(),
                password.clone(),
                ciphertext.clone(),
            ));
        }

        while let Some(res) = set.join_next().await {
            let decrypted = res.unwrap().unwrap();
            assert_eq!(decrypted, LARGE_TEST_DATA);
        }
    }

    #[tokio::test]
    async fn seal_stream_async_compatibility() {
        let (seal, _tmpdir, password) = setup_seal_with_key(ALGORITHM);
        let ciphertext = {
            let mut engine = seal.engine(SealMode::Hybrid, &password).unwrap();
            let source = Cursor::new(LARGE_TEST_DATA);
            let dest = Cursor::new(Vec::new());
            let final_dest = engine
                .seal_stream_async(source, dest, Some(AAD))
                .await
                .unwrap();
            final_dest.into_inner()
        };

        let mut set = JoinSet::new();
        let ops = [
            DecryptOp::UnsealBytes,
            DecryptOp::UnsealStream,
            DecryptOp::ParUnsealBytes,
            DecryptOp::ParUnsealStream,
            DecryptOp::UnsealStreamAsync,
            DecryptOp::ParUnsealStreamAsync,
        ];

        for op in ops {
            set.spawn(perform_decryption(
                op,
                seal.clone(),
                password.clone(),
                ciphertext.clone(),
            ));
        }

        while let Some(res) = set.join_next().await {
            let decrypted = res.unwrap().unwrap();
            assert_eq!(decrypted, LARGE_TEST_DATA);
        }
    }

    #[tokio::test]
    async fn par_seal_stream_async_compatibility() {
        let (seal, _tmpdir, password) = setup_seal_with_key(ALGORITHM);
        let ciphertext = {
            let mut engine = seal.engine(SealMode::Hybrid, &password).unwrap();
            let source = Cursor::new(LARGE_TEST_DATA);
            let dest = Cursor::new(Vec::new());
            let final_dest = engine
                .par_seal_stream_async(source, dest, Some(AAD))
                .await
                .unwrap();
            final_dest.into_inner()
        };

        let mut set = JoinSet::new();
        // 经过验证，所有模式都应该是兼容的
        let ops = [
            DecryptOp::UnsealBytes,
            DecryptOp::UnsealStream,
            DecryptOp::ParUnsealBytes,
            DecryptOp::ParUnsealStream,
            DecryptOp::UnsealStreamAsync,
            DecryptOp::ParUnsealStreamAsync,
        ];

        for op in ops {
            set.spawn(perform_decryption(
                op,
                seal.clone(),
                password.clone(),
                ciphertext.clone(),
            ));
        }

        while let Some(res) = set.join_next().await {
            let decrypted = res.unwrap().unwrap();
            assert_eq!(decrypted, LARGE_TEST_DATA);
        }
    }
}
