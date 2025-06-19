//!
//! 矩阵兼容性测试
//!
//! 这个模块的目的是验证不同加密模式（普通、并行、流式、并行流式）的输出之间是互不兼容的。
//! 例如，使用 `seal_to_bytes` 加密的数据，不应该能被 `unseal_stream` 或任何其他流式解密方法解密。
//!

#![cfg(feature = "secure-storage")]

use seal_kit::{Seal, SealMode};
use secrecy::SecretString;
use std::io::Cursor;
use tempfile::tempdir;

// 辅助函数：创建一个临时的 Seal 实例并返回一个解锁的 engine
fn setup_engine() -> seal_kit::SealEngine {
    let dir = tempdir().unwrap();
    let seal_path = dir.path().join("my_seal.seal");
    let password = SecretString::from("test-password".to_string());

    let seal = Seal::create(&seal_path, &password).unwrap();
    seal.engine(SealMode::Hybrid, &password).unwrap()
}

// === 同步模式不兼容性测试 ===

#[test]
#[cfg(feature = "parallel")]
fn test_par_seal_bytes_incompatible_with_par_unseal_stream() {
    let mut engine = setup_engine();
    let plaintext = vec![0xAB; 4096];

    // 1. 使用内存并行加密 (par_seal_bytes)
    let ciphertext = engine.par_seal_bytes(&plaintext, None).unwrap();

    // 2. 尝试使用流式并行解密 (par_unseal_stream)，应失败
    let mut source = Cursor::new(ciphertext);
    let mut dest = Cursor::new(Vec::new());
    let result = engine.par_unseal_stream(&mut source, &mut dest, None);

    assert!(
        result.is_err(),
        "par_seal_bytes 的输出不应能被 par_unseal_stream 解密"
    );
}

#[test]
#[cfg(feature = "parallel")]
fn test_par_seal_stream_incompatible_with_par_unseal_bytes() {
    let mut engine = setup_engine();
    let plaintext = vec![0xCD; 4096];

    // 1. 使用流式并行加密 (par_seal_stream)
    let ciphertext = {
        let mut source = Cursor::new(plaintext);
        let mut dest = Cursor::new(Vec::new());
        engine.par_seal_stream(&mut source, &mut dest, None).unwrap();
        dest.into_inner()
    };

    // 2. 尝试使用内存并行解密 (par_unseal_bytes)，应失败
    let result = engine.par_unseal_bytes(&ciphertext, None);

    assert!(
        result.is_err(),
        "par_seal_stream 的输出不应能被 par_unseal_bytes 解密"
    );
}

#[test]
fn test_seal_bytes_incompatible_with_unseal_stream() {
    let mut engine = setup_engine();
    let plaintext = vec![0xEF; 1024];

    // 1. 使用内存加密 (seal_bytes)
    let ciphertext = engine.seal_bytes(&plaintext, None).unwrap();

    // 2. 尝试使用流式解密 (unseal_stream)，应失败
    let mut source = Cursor::new(ciphertext);
    let mut dest = Cursor::new(Vec::new());
    let result = engine.unseal_stream(&mut source, &mut dest, None);

    assert!(
        result.is_err(),
        "seal_bytes 的输出不应能被 unseal_stream 解密"
    );
}

#[test]
fn test_seal_stream_incompatible_with_unseal_bytes() {
    let mut engine = setup_engine();
    let plaintext = vec![0x12; 1024];

    // 1. 使用流式加密 (seal_stream)
    let ciphertext = {
        let mut source = Cursor::new(plaintext);
        let mut dest = Cursor::new(Vec::new());
        engine.seal_stream(&mut source, &mut dest, None).unwrap();
        dest.into_inner()
    };

    // 2. 尝试使用内存解密 (unseal_bytes)，应失败
    let result = engine.unseal_bytes(&ciphertext, None);

    assert!(
        result.is_err(),
        "seal_stream 的输出不应能被 unseal_bytes 解密"
    );
}

// === 异步/同步混合模式不兼容性测试 ===

#[tokio::test]
#[cfg(all(feature = "async-engine", feature = "parallel"))]
async fn test_par_seal_bytes_incompatible_with_par_unseal_stream_async() {
    let mut engine = setup_engine();
    let plaintext = vec![0x34; 4096];

    // 1. 使用同步内存并行加密
    let ciphertext = engine.par_seal_bytes(&plaintext, None).unwrap();

    // 2. 尝试使用异步并行流式解密，应失败
    let source = Cursor::new(ciphertext);
    let dest = Cursor::new(Vec::new());
    let result = engine.par_unseal_stream_async(source, dest, None).await;

    assert!(
        result.is_err(),
        "par_seal_bytes 的输出不应能被 par_unseal_stream_async 解密"
    );
}

#[cfg(all(feature = "async-engine", feature = "parallel"))]
async fn test_par_seal_stream_async_incompatible_with_par_unseal_bytes() {
    let mut engine = setup_engine();
    let plaintext = vec![0x56; 4096];

    // 1. 使用异步并行流式加密
    let ciphertext = {
        let source = Cursor::new(plaintext);
        let dest = Cursor::new(Vec::new());
        let final_dest = engine
            .par_seal_stream_async(source, dest, None)
            .await
            .unwrap();
        final_dest.into_inner()
    };

    // 2. 尝试使用同步内存并行解密，应失败
    let result = engine.par_unseal_bytes(&ciphertext, None);

    assert!(
        result.is_err(),
        "par_seal_stream_async 的输出不应能被 par_unseal_bytes 解密"
    );
} 