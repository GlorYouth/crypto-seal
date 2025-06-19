//!
//! 集成测试
//!
//! 这个模块包含了 `seal-kit` 的端到端集成测试。
//! 它验证了从创建保险库到加密、解密、密钥轮换以及不同模式间兼容性的完整流程。
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

// === 核心功能测试 ===

#[test]
fn test_seal_engine_bytes_roundtrip() {
    let mut engine = setup_engine();
    let data = b"some important data to seal".to_vec();
    let aad = b"additional authenticated data";

    // 加密
    let ciphertext = engine.seal_bytes(&data, Some(aad)).unwrap();

    // 使用同一个引擎解密
    let decrypted = engine.unseal_bytes(&ciphertext, Some(aad)).unwrap();
    assert_eq!(data, decrypted);
}

#[tokio::test]
async fn test_seal_engine_stream_roundtrip() {
    let mut engine = setup_engine();
    let data = b"some long streaming data to seal".to_vec();
    let aad = b"streaming aad";

    // 同步流式加密
    let mut source = Cursor::new(data.clone());
    let mut dest = Cursor::new(Vec::new());
    engine
        .seal_stream(&mut source, &mut dest, Some(aad))
        .unwrap();
    let ciphertext = dest.into_inner();

    // 同步流式解密
    let mut source = Cursor::new(ciphertext.clone());
    let mut dest = Cursor::new(Vec::new());
    engine
        .unseal_stream(&mut source, &mut dest, Some(aad))
        .unwrap();
    assert_eq!(data, dest.into_inner());

    // 异步流式解密
    let source = Cursor::new(ciphertext);
    let dest = Cursor::new(Vec::new());
    let final_dest = engine
        .unseal_stream_async(source, dest, Some(aad))
        .await
        .unwrap();
    assert_eq!(data, final_dest.into_inner());
}

#[cfg(feature = "parallel")]
#[tokio::test]
async fn test_seal_engine_parallel_roundtrip() {
    let mut engine = setup_engine();
    let data = vec![0xAB; 1024 * 1024]; // 1MB of data
    let aad = b"parallel aad";

    // 并行加密
    let ciphertext = engine.par_seal_bytes(&data, Some(aad)).unwrap();

    // 并行解密
    let decrypted = engine.par_unseal_bytes(&ciphertext, Some(aad)).unwrap();
    assert_eq!(data, decrypted);

    // 异步并行流式解密
    let source = Cursor::new(ciphertext);
    let dest = Cursor::new(Vec::new());
    let final_dest = engine
        .par_unseal_stream_async(source, dest, Some(aad))
        .await
        .unwrap();
    let decrypted_from_stream = final_dest.into_inner();

    // 注意：并行加密（par_seal_bytes）的输出格式与并行流（par_unseal_stream）的格式不兼容。
    // par_seal_bytes 直接加密 payload，而 par_seal_stream 会将 payload 分块加密。
    // 因此，这里我们只验证 par_unseal_bytes 和 par_unseal_stream_async 的兼容性。
    // 我们需要一个单独的测试来验证 par_seal_stream 和 par_unseal_stream_async 的兼容性。
    // 实际上，par_unseal_bytes 内部可以被视为一个特殊的流，所以它能解密 par_seal_bytes 的输出是合理的。
    // 但是 par_unseal_stream_async 期望的是分块的流。
    // 为了简单起见，我们在这里只验证对称的 roundtrip。更复杂的交叉兼容性测试如下。
    assert_eq!(data, decrypted_from_stream);
}

// === 兼容性矩阵测试 ===
// 验证不同实现方式（同步/异步）的相同模式之间是兼容的。

#[cfg(feature = "parallel")]
#[tokio::test]
async fn test_matrix_par_seal_stream_compatibility() {
    let mut engine = setup_engine();
    let data = vec![0xBC; 1024 * 1024]; // 1MB
    let aad = Some(b"matrix_par_stream".as_slice());

    // 1. 使用同步并行流加密
    let ciphertext = {
        let mut source = Cursor::new(data.clone());
        let mut dest = Cursor::new(Vec::new());
        engine.par_seal_stream(&mut source, &mut dest, aad).unwrap();
        dest.into_inner()
    };

    // 2. 使用同步并行流解密
    {
        let mut source = Cursor::new(ciphertext.clone());
        let mut dest = Cursor::new(Vec::new());
        engine
            .par_unseal_stream(&mut source, &mut dest, aad)
            .unwrap();
        assert_eq!(
            data,
            dest.into_inner(),
            "par_seal_stream -> par_unseal_stream failed"
        );
    }

    // 3. 使用异步并行流解密
    {
        let source = Cursor::new(ciphertext);
        let dest = Cursor::new(Vec::new());
        let final_dest = engine
            .par_unseal_stream_async(source, dest, aad)
            .await
            .unwrap();
        assert_eq!(
            data,
            final_dest.into_inner(),
            "par_seal_stream -> par_unseal_stream_async failed"
        );
    }
}

#[tokio::test]
async fn test_matrix_async_seal_stream_compatibility() {
    let mut engine = setup_engine();
    let data = vec![0xCD; 1024 * 256]; // 256KB
    let aad = Some(b"matrix_async_stream".as_slice());

    // 1. 使用异步流加密
    let ciphertext = {
        let source = Cursor::new(data.clone());
        let dest = Cursor::new(Vec::new());
        let final_dest = engine.seal_stream_async(source, dest, aad).await.unwrap();
        final_dest.into_inner()
    };

    // 2. 使用同步流解密
    {
        let mut source = Cursor::new(ciphertext.clone());
        let mut dest = Cursor::new(Vec::new());
        engine.unseal_stream(&mut source, &mut dest, aad).unwrap();
        assert_eq!(
            data,
            dest.into_inner(),
            "seal_stream_async -> unseal_stream failed"
        );
    }

    // 3. 使用异步流解密
    {
        let source = Cursor::new(ciphertext);
        let dest = Cursor::new(Vec::new());
        let final_dest = engine.unseal_stream_async(source, dest, aad).await.unwrap();
        assert_eq!(
            data,
            final_dest.into_inner(),
            "seal_stream_async -> unseal_stream_async failed"
        );
    }
}

#[test]
fn test_hybrid_rsakyber_signed_roundtrip() {
    use seal_kit::common::traits::AsymmetricAlgorithm;

    let dir = tempdir().unwrap();
    let seal_path = dir.path().join("my_seal.seal");
    let password = SecretString::from("test-password".to_string());
    let seal = Seal::create(&seal_path, &password).unwrap();

    // 修改配置以使用 RsaKyber768
    seal.commit_payload(&password, |payload| {
        payload.config.crypto.primary_asymmetric_algorithm = AsymmetricAlgorithm::RsaKyber768;
    })
    .unwrap();

    let mut engine = seal.engine(SealMode::Hybrid, &password).unwrap();
    let data = b"This data must be signed and verified.".to_vec();
    let aad = b"authenticated-encryption";

    // 加密（内部会签名）
    let ciphertext = engine.seal_bytes(&data, Some(aad)).unwrap();

    // 解密（内部会验证签名）
    let decrypted = engine.unseal_bytes(&ciphertext, Some(aad)).unwrap();
    assert_eq!(data, decrypted);
}

#[test]
fn test_hybrid_rsakyber_tampered_ciphertext_fails_verification() {
    use seal_kit::common::traits::AsymmetricAlgorithm;

    let dir = tempdir().unwrap();
    let seal_path = dir.path().join("my_seal.seal");
    let password = SecretString::from("test-password".to_string());
    let seal = Seal::create(&seal_path, &password).unwrap();

    // 修改配置以使用 RsaKyber768
    seal.commit_payload(&password, |payload| {
        payload.config.crypto.primary_asymmetric_algorithm = AsymmetricAlgorithm::RsaKyber768;
    })
    .unwrap();

    let mut engine = seal.engine(SealMode::Hybrid, &password).unwrap();
    let data = b"This data must be signed and verified.".to_vec();
    let aad = b"authenticated-encryption";

    let mut ciphertext = engine.seal_bytes(&data, Some(aad)).unwrap();

    // 篡改密文的一个字节
    // Header 在前，我们篡改数据部分
    let len = ciphertext.len();
    ciphertext[len - 10] ^= 0xff;

    let result = engine.unseal_bytes(&ciphertext, Some(aad));
    assert!(result.is_err());

    // 确认错误是签名验证失败
    if let Err(e) = result {
        assert!(matches!(e, seal_kit::Error::Verification(_)));
    }
}
