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
fn setup_engine() -> (seal_kit::SealEngine, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let seal_path = dir.path().join("my_seal.seal");
    let password = SecretString::from("test-password".to_string());

    let seal = Seal::create_encrypted(&seal_path, &password).unwrap();

    // 显式轮换密钥到 RsaKyber768
    seal.rotate_asymmetric_key(
        seal_kit::common::traits::AsymmetricAlgorithm::RsaKyber768,
        &password,
    )
    .unwrap();

    // 现在获取 engine，它会使用已经存在的密钥
    let engine = seal.engine(SealMode::Hybrid, &password).unwrap();
    (engine, dir)
}

// === 核心功能测试 ===

#[test]
fn test_seal_engine_bytes_roundtrip() {
    let (mut engine, _tmpdir) = setup_engine();
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
    let (mut engine, _tmpdir) = setup_engine();
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
    let (mut engine, _tmpdir) = setup_engine();
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
    let (mut engine, _tmpdir) = setup_engine();
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
    let (mut engine, _tmpdir) = setup_engine();
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
    let (mut engine, _tmpdir) = setup_engine();
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
    let (mut engine, _tmpdir) = setup_engine();
    let data = b"This data must be signed and verified.".to_vec();
    let aad = b"authenticated-encryption";

    let mut ciphertext = engine.seal_bytes(&data, Some(aad)).unwrap();

    // 篡改密文的一个字节
    // Header 在前，我们篡改数据部分
    let len = ciphertext.len();
    ciphertext[len - 10] ^= 0xff;

    let result = engine.unseal_bytes(&ciphertext, Some(aad));

    // 我们只关心它是否失败，具体的错误类型可能因篡改位置而异
    // （可能是签名错误，也可能是解密错误）。
    assert!(
        result.is_err(),
        "Tampered ciphertext should always fail to decrypt"
    );
}

// === 新增测试用例 ===

#[test]
fn test_manual_key_rotation() {
    use seal_kit::common::traits::AsymmetricAlgorithm;

    let dir = tempdir().unwrap();
    let seal_path = dir.path().join("my_seal.seal");
    let password = SecretString::from("test-password".to_string());
    let data = b"data for rotation test".to_vec();

    // 1. 创建并使用 RSA-2048
    let seal = Seal::create_encrypted(&seal_path, &password).unwrap();
    seal.rotate_asymmetric_key(
        AsymmetricAlgorithm::Rsa2048,
        &password,
    )
    .unwrap();
    let ciphertext_rsa = seal
        .engine(SealMode::Hybrid, &password)
        .unwrap()
        .seal_bytes(&data, None)
        .unwrap();

    // 2. 轮换到 Kyber-768
    seal.rotate_asymmetric_key(
        AsymmetricAlgorithm::Kyber768,
        &password,
    )
    .unwrap();
    let ciphertext_kyber = seal
        .engine(SealMode::Hybrid, &password)
        .unwrap()
        .seal_bytes(&data, None)
        .unwrap();

    assert_ne!(ciphertext_rsa, ciphertext_kyber, "Ciphertexts should differ after key rotation");

    // 3. 重新打开 Seal，验证它能解密两种密文
    let reopened_seal = Seal::open_encrypted(&seal_path, &password).unwrap();
    let engine = reopened_seal
        .engine(SealMode::Hybrid, &password)
        .unwrap();

    assert_eq!(
        data,
        engine.unseal_bytes(&ciphertext_rsa, None).unwrap(),
        "Should decrypt data sealed with old (RSA) key"
    );
    assert_eq!(
        data,
        engine.unseal_bytes(&ciphertext_kyber, None).unwrap(),
        "Should decrypt data sealed with new (Kyber) key"
    );
}

#[test]
fn test_open_and_change_password() {
    let dir = tempdir().unwrap();
    let seal_path = dir.path().join("my_seal.seal");
    let old_password = SecretString::from("old-password".to_string());
    let new_password = SecretString::from("new-password".to_string());

    // 1. 用旧密码创建一个 Seal
    Seal::create_encrypted(&seal_path, &old_password).unwrap();

    // 2. 用旧密码打开，然后修改密码
    let seal = Seal::open_encrypted(&seal_path, &old_password).unwrap();
    seal.change_password(&old_password, &new_password).unwrap();

    // 3. 尝试用旧密码打开，应该失败
    let result = Seal::open_encrypted(&seal_path, &old_password);
    assert!(
        result.is_err(),
        "Opening with old password should fail after change"
    );

    // 4. 用新密码打开，应该成功
    Seal::open_encrypted(&seal_path, &new_password).unwrap();
}

mod plaintext_mode_tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_plaintext_creation_and_seal_unseal() {
        let dir = tempdir().unwrap();
        let seal_path = dir.path().join("plaintext.seal");
        let password = SecretString::from("a-dummy-password-that-will-be-ignored");

        // 1. 创建明文保险库
        let seal = Seal::create_plaintext(&seal_path).unwrap();

        // 轮换密钥，即使是明文模式，密钥管理依然有效
        seal.rotate_asymmetric_key(
            seal_kit::common::traits::AsymmetricAlgorithm::Rsa2048,
            &password, // 密码在内部 commit_payload 中仍需传递，但存储时会被忽略
        )
        .unwrap();

        let data = b"plaintext mode data";
        let mut engine = seal.engine(SealMode::Hybrid, &password).unwrap();
        
        // 加密和解密
        let ciphertext = engine.seal_bytes(data, None).unwrap();
        let decrypted = engine.unseal_bytes(&ciphertext, None).unwrap();
        
        assert_eq!(data.as_ref(), decrypted.as_slice());
    }

    #[test]
    fn test_plaintext_is_actually_plaintext() {
        let dir = tempdir().unwrap();
        let seal_path = dir.path().join("plaintext.seal");

        let seal = Seal::create_plaintext(&seal_path).unwrap();
        let password = SecretString::from("dummy");
        seal.rotate_asymmetric_key(
            seal_kit::common::traits::AsymmetricAlgorithm::Rsa2048,
            &password
        ).unwrap();
        
        // 读取文件内容并验证它是可读的 JSON
        let content = fs::read_to_string(seal_path).unwrap();
        let json_value: serde_json::Value = serde_json::from_str(&content).expect("File content should be valid JSON");

        // 验证 JSON 中包含预期的字段
        assert!(json_value.get("master_seed").is_some());
        assert!(json_value.get("key_registry").is_some());
        assert!(json_value.get("config").is_some());
    }

    #[test]
    fn test_cannot_open_plaintext_as_encrypted() {
        let dir = tempdir().unwrap();
        let seal_path = dir.path().join("plaintext.seal");
        let password = SecretString::from("dummy-password");

        // 1. 创建一个明文保险库
        Seal::create_plaintext(&seal_path).unwrap();

        // 2. 尝试用加密模式打开它，应该失败
        let result = Seal::open_encrypted(&seal_path, &password);
        assert!(result.is_err(), "Should not be able to open a plaintext vault in encrypted mode");
    }

    #[test]
    fn test_cannot_open_encrypted_as_plaintext() {
        let dir = tempdir().unwrap();
        let seal_path = dir.path().join("encrypted.seal");
        let password = SecretString::from("real-password");

        // 1. 创建一个加密保险库
        Seal::create_encrypted(&seal_path, &password).unwrap();

        // 2. 尝试用明文模式打开它，应该失败
        let result = Seal::open_plaintext(&seal_path);
        assert!(result.is_err(), "Should not be able to open an encrypted vault in plaintext mode");
    }
}
